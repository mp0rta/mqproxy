//! The loop core (spec §5.3 "Loop core and `Io`", §5.5 "One loop iteration"):
//! the synchronous sequencing shared by the production driver and the fakes.
//! It owns the per-socket latches, the driver deadlines, the resolver queue,
//! the `EMFILE` retry, the shutdown cap and the step-10 wait decision, and
//! never touches an fd.

use super::deadlines::{Deadlines, Expired};
use super::io::{Io, IoEvent, ListenerKey, RecvBatch, RecvStop, SockKey, TcpSock, UdpSock, Wait};
use super::resolver::ResolverQueue;
use crate::app::{App, DialError, Host, IoRequest, IoResult};
use crate::ids::{DialOpId, ListenerId, SocketOpId, TcpId, UdpSocketId};
use crate::shard::Shard;
use mq_transport_api::{Time, TransportOps};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;

/// spec §5.5 step 2: UDP bytes per socket per iteration.
pub const UDP_RX_BUDGET: usize = 1 << 20;
/// spec §5.5 step 5: TCP bytes per socket per direction per iteration.
pub const TCP_IO_BUDGET: usize = 256 * 1024;
/// Accepts per listener per iteration (the backlog is 64).
const ACCEPT_BATCH: usize = 64;
const EMFILE: i32 = 24;
const ENFILE: i32 = 23;

/// What `iteration` tells the caller.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Next {
    Continue,
    Exit(i32),
}

/// spec §5.3: a socket's latched edges; set by an edge, cleared by `WouldBlock`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct Latch {
    pub readable: bool,
    pub writable: bool,
}

const BOTH: Latch = Latch {
    readable: true,
    writable: true,
};

/// spec §5.3 `DriverConfig`: the parts the loop core uses.
#[derive(Copy, Clone, Debug)]
pub struct LoopConfig {
    /// After `EMFILE`/`ENFILE` on accept.
    pub emfile_retry: Duration,
    /// From the shutdown signal to exit 0.
    pub shutdown_cap: Duration,
}

impl Default for LoopConfig {
    fn default() -> Self {
        LoopConfig {
            emfile_retry: Duration::from_millis(100),
            shutdown_cap: Duration::from_secs(2),
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum Kind {
    Tcp(TcpId),
    Udp,
    Listener,
}

#[derive(Copy, Clone, Debug)]
enum DialState {
    /// Queued or running in the resolver.
    Resolving,
    /// `start_connect` issued (to the first resolved address).
    Connecting(SocketAddr),
}

/// spec §5.3: the loop core.
pub struct LoopCore<I: Io, T: TransportOps, A: App> {
    io: I,
    shard: Shard<T, A>,
    cfg: LoopConfig,
    deadlines: Deadlines,
    resolver: ResolverQueue,
    socks: HashMap<SockKey, Kind>,
    latches: HashMap<SockKey, Latch>,
    tcp: BTreeMap<TcpId, TcpSock>,
    udp: BTreeMap<UdpSocketId, UdpSock>,
    listeners: BTreeMap<ListenerId, ListenerKey>,
    dials: HashMap<DialOpId, DialState>,
    /// Results received but not yet delivered (step 8 → step 3); runnable work.
    held: VecDeque<(SocketOpId, io::Result<(UdpSock, SocketAddr)>)>,
    next_wait: Wait,
    shutdown_hook: Option<Box<dyn FnOnce()>>,
    shutting_down: bool,
    cap_hit: bool,
    batch: RecvBatch,
    /// Round-robin start for step 5.
    rr: usize,
    send_errors: u64,
    last_err_log: HashMap<UdpSocketId, Time>,
}

impl<I: Io, T: TransportOps, A: App> LoopCore<I, T, A> {
    pub fn new(io: I, shard: Shard<T, A>, cfg: LoopConfig) -> Self {
        LoopCore {
            io,
            shard,
            cfg,
            deadlines: Deadlines::default(),
            resolver: ResolverQueue::default(),
            socks: HashMap::new(),
            latches: HashMap::new(),
            tcp: BTreeMap::new(),
            udp: BTreeMap::new(),
            listeners: BTreeMap::new(),
            dials: HashMap::new(),
            held: VecDeque::new(),
            next_wait: Wait::Yield,
            shutdown_hook: None,
            shutting_down: false,
            cap_hit: false,
            batch: RecvBatch::default(),
            rr: 0,
            send_errors: 0,
            last_err_log: HashMap::new(),
        }
    }

    /// spec §5.3: the primary UDP socket.
    pub fn attach_primary_udp(&mut self, s: UdpSock, id: UdpSocketId) {
        self.register(s.0, Kind::Udp);
        self.udp.insert(id, s);
    }
    /// spec §5.3: a listener and the shard id it reports accepts under.
    pub fn attach_listener(&mut self, l: ListenerKey, id: ListenerId) {
        self.register(l.0, Kind::Listener);
        self.listeners.insert(id, l);
    }
    /// spec §5.3: runs right after `on_shutdown_signal` (removes redirect rules).
    pub fn on_shutdown(&mut self, hook: impl FnOnce() + 'static) {
        self.shutdown_hook = Some(Box::new(hook));
    }
    /// spec §5.2: `Shard::start`, the driver's first call.
    pub fn start(&mut self) {
        let now = self.io.now();
        self.shard.start(now);
    }
    /// spec §5.3: starts the shard, then loops until the exit status.
    pub fn run(mut self) -> (i32, Shard<T, A>) {
        self.start();
        loop {
            if let Next::Exit(code) = self.iteration() {
                return (code, self.shard);
            }
        }
    }

    /// spec §5.3: every socket starts with both latches set.
    fn register(&mut self, k: SockKey, kind: Kind) {
        self.socks.insert(k, kind);
        self.latches.insert(k, BOTH);
    }
    fn unregister(&mut self, k: SockKey) {
        self.socks.remove(&k);
        self.latches.remove(&k);
    }
    fn lat(&self, k: SockKey) -> Latch {
        self.latches.get(&k).copied().unwrap_or_default()
    }
    fn set_lat(&mut self, k: SockKey, f: impl FnOnce(&mut Latch)) {
        if let Some(l) = self.latches.get_mut(&k) {
            f(l);
        }
    }

    /// spec §5.5: one loop iteration, steps 1–10. Step 10's wait is
    /// performed at the start of the next iteration, as step 1's "take the
    /// ready list", so events a harness queues between iterations are seen.
    pub fn iteration(&mut self) -> Next {
        // 1. The ready list, completions and signals; latches. Driver
        // deadlines expire here on every iteration, sleeping or not.
        let mut errors = Vec::new();
        let mut results = Vec::new();
        let mut shutdown = false;
        for ev in self.io.wait(self.next_wait) {
            match ev {
                IoEvent::Readable(k) => self.set_lat(k, |l| l.readable = true),
                IoEvent::Writable(k) => self.set_lat(k, |l| l.writable = true),
                IoEvent::Error(k) => match self.socks.get(&k) {
                    Some(Kind::Tcp(tcp)) => errors.push(*tcp),
                    // The next recv/accept reports it.
                    Some(_) => self.set_lat(k, |l| l.readable = true),
                    None => {}
                },
                ev @ (IoEvent::Resolved { .. } | IoEvent::Connected { .. }) => results.push(ev),
                IoEvent::Timer => {}
                IoEvent::Shutdown => shutdown = true,
            }
        }
        let now = self.io.now();
        let expired = self.deadlines.expire(now);
        for e in &expired {
            // The retry is a latch update: the accept below sees it.
            if let Expired::ListenerRetry(lid) = e {
                if let Some(&l) = self.listeners.get(lid) {
                    self.set_lat(l.0, |l| l.readable = true);
                }
            }
        }

        // 2. UDP first, so ACKs are seen before new data is written.
        self.udp_rx(now);

        // 3. Accepts, socket errors, dial results, socket-open results,
        // expired driver deadlines, a shutdown signal.
        self.accepts(now);
        for tcp in errors {
            if let Some(&s) = self.tcp.get(&tcp) {
                let kind = self.io.socket_error(s);
                self.shard.on_tcp_error(now, tcp, kind);
            }
        }
        for ev in results {
            self.dial_result(now, ev);
        }
        while let Some((op, r)) = self.held.pop_front() {
            self.udp_opened(now, op, r);
        }
        for e in expired {
            self.expired(now, e);
        }
        if shutdown && !self.shutting_down {
            self.shutting_down = true;
            self.shard.on_shutdown_signal(now);
            if let Some(hook) = self.shutdown_hook.take() {
                hook();
            }
            self.deadlines
                .set(Expired::ShutdownCap, now + self.cfg.shutdown_cap);
        }

        // 4.
        self.shard.drive(now);
        // 5.
        self.tcp_io(now);
        // 6.
        self.shard.drive(now);
        self.udp_tx(now);
        // 7.
        if self.shard.resume_pending() {
            self.shard.drive(now);
            self.udp_tx(now);
        }
        // 8.
        while let Some(r) = self.shard.poll_io_request() {
            self.execute(now, r);
        }
        // 9.
        if let Some(code) = self.shard.exit_status() {
            return Next::Exit(code);
        }
        if self.cap_hit {
            return Next::Exit(0); // spec §5.3: exit 0 after a signal, as C does
        }
        // 10.
        self.next_wait = if self.runnable() {
            Wait::Yield
        } else {
            match [self.shard.next_timeout(), self.deadlines.earliest()]
                .into_iter()
                .flatten()
                .min()
            {
                Some(t) => Wait::Until(t),
                None => Wait::Forever,
            }
        };
        Next::Continue
    }

    /// spec §5.5 step 2: GRO batches, 1 MiB per socket.
    fn udp_rx(&mut self, now: Time) {
        let socks: Vec<(UdpSocketId, UdpSock)> = self.udp.iter().map(|(i, s)| (*i, *s)).collect();
        for (id, s) in socks {
            if !self.lat(s.0).readable {
                continue;
            }
            self.batch.buf.clear();
            self.batch.metas.clear();
            let r = self.io.recv_udp(s, &mut self.batch, UDP_RX_BUDGET);
            for m in &self.batch.metas {
                self.shard
                    .on_udp_rx(now, id, m.src, &self.batch.buf[m.range.clone()]);
            }
            match r {
                Ok(RecvStop::Budget) => {}
                Ok(RecvStop::Drained) => self.set_lat(s.0, |l| l.readable = false),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.set_lat(s.0, |l| l.readable = false)
                }
                // ponytail: the latch is kept (ICMP errors are one-shot); a
                // persistent error would spin — clear it if one shows up.
                Err(e) => log::debug!("udp recv: {e}"),
            }
        }
    }

    /// spec §5.3: accepts while the shard is accepting; `EMFILE`/`ENFILE`
    /// pauses the listener for `emfile_retry`.
    fn accepts(&mut self, now: Time) {
        let ls: Vec<(ListenerId, ListenerKey)> =
            self.listeners.iter().map(|(i, l)| (*i, *l)).collect();
        for (lid, l) in ls {
            for _ in 0..ACCEPT_BATCH {
                if !self.shard.accepting() || !self.lat(l.0).readable {
                    break;
                }
                match self.io.accept(l) {
                    Ok((s, meta)) => match self.shard.on_accepted(now, lid, meta) {
                        Some(tcp) => self.add_tcp(tcp, s),
                        None => self.io.close_tcp(s, false), // at the socket cap
                    },
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        self.set_lat(l.0, |l| l.readable = false);
                        break;
                    }
                    Err(e) if matches!(e.raw_os_error(), Some(EMFILE | ENFILE)) => {
                        self.set_lat(l.0, |l| l.readable = false);
                        self.deadlines
                            .set(Expired::ListenerRetry(lid), now + self.cfg.emfile_retry);
                        break;
                    }
                    Err(e) => log::debug!("accept: {e}"), // e.g. ECONNABORTED: next one
                }
            }
        }
    }

    fn add_tcp(&mut self, tcp: TcpId, s: TcpSock) {
        self.register(s.0, Kind::Tcp(tcp));
        self.tcp.insert(tcp, s);
    }

    /// spec §5.3: resolve, then connect to the first address only.
    fn dial_result(&mut self, now: Time, ev: IoEvent) {
        match ev {
            IoEvent::Resolved { op, r } => {
                if !self.resolver.finished(&mut self.io, op) {
                    return; // abandoned: its slot is freed, the result dropped
                }
                if !matches!(self.dials.get(&op), Some(DialState::Resolving)) {
                    return;
                }
                match r.ok().and_then(|v| v.first().copied()) {
                    Some(a) => {
                        self.dials.insert(op, DialState::Connecting(a));
                        self.io.start_connect(op, a);
                    }
                    None => self.fail_dial(now, op, DialError::Dns),
                }
            }
            IoEvent::Connected { op, r } => match (self.dials.get(&op).copied(), r) {
                (Some(DialState::Connecting(a)), Ok(s)) => {
                    self.dials.remove(&op);
                    self.deadlines.cancel(Expired::Dial(op));
                    match self.shard.on_dial_result(now, op, Ok(a)) {
                        Some(tcp) => self.add_tcp(tcp, s),
                        None => self.io.close_tcp(s, false),
                    }
                }
                (Some(DialState::Connecting(_)), Err(e)) => {
                    self.fail_dial(now, op, connect_error(&e))
                }
                // Cancelled or timed out: a late socket is closed.
                (_, Ok(s)) => self.io.close_tcp(s, false),
                (_, Err(_)) => {}
            },
            _ => {}
        }
    }

    fn fail_dial(&mut self, now: Time, op: DialOpId, e: DialError) {
        self.dials.remove(&op);
        self.deadlines.cancel(Expired::Dial(op));
        self.shard.on_dial_result(now, op, Err(e));
    }

    fn udp_opened(&mut self, now: Time, op: SocketOpId, r: io::Result<(UdpSock, SocketAddr)>) {
        match r {
            Ok((s, local)) => match self.shard.on_udp_socket(now, op, Ok(local)) {
                Some(id) => {
                    self.register(s.0, Kind::Udp);
                    self.udp.insert(id, s);
                }
                None => self.io.close_udp(s), // cancelled meanwhile
            },
            Err(e) => {
                self.shard.on_udp_socket(now, op, Err(e.kind()));
            }
        }
    }

    /// spec §5.3 "Driver deadlines".
    fn expired(&mut self, now: Time, e: Expired) {
        match e {
            Expired::Dial(op) => {
                match self.dials.remove(&op) {
                    // The resolver slot stays occupied until the result returns.
                    Some(DialState::Resolving) => self.resolver.cancel(op),
                    Some(DialState::Connecting(_)) => self.io.cancel_connect(op),
                    None => return,
                }
                self.shard.on_dial_result(now, op, Err(DialError::Timeout));
            }
            Expired::ListenerRetry(_) => {} // latch set in step 1
            Expired::ShutdownCap => self.cap_hit = true,
        }
    }

    /// spec §5.5 step 5: latch ∧ interest, re-queried with the buffer slice
    /// before every call; round-robin; 256 KiB per socket per direction.
    fn tcp_io(&mut self, now: Time) {
        let mut socks: Vec<(TcpId, TcpSock)> = self.tcp.iter().map(|(i, s)| (*i, *s)).collect();
        if socks.is_empty() {
            return;
        }
        let start = self.rr % socks.len();
        socks.rotate_left(start);
        self.rr = self.rr.wrapping_add(1);
        for (tcp, s) in socks {
            let mut budget = TCP_IO_BUDGET;
            while budget > 0 && self.lat(s.0).readable && self.shard.tcp_interest(tcp).read {
                let buf = self.shard.tcp_rx_buf(tcp);
                if buf.is_empty() {
                    break;
                }
                let n = buf.len().min(budget);
                let r = self.io.read(s, &mut buf[..n]);
                self.shard.tcp_rx_commit(now, tcp, r);
                match r {
                    IoResult::Bytes(n) if n > 0 => budget -= n,
                    IoResult::WouldBlock => {
                        self.set_lat(s.0, |l| l.readable = false);
                        break;
                    }
                    _ => break, // Eof / Error end this direction for the iteration
                }
            }
            let mut budget = TCP_IO_BUDGET;
            while budget > 0 && self.lat(s.0).writable && self.shard.tcp_interest(tcp).write {
                let buf = self.shard.tcp_tx_buf(tcp);
                if buf.is_empty() {
                    break;
                }
                let n = buf.len().min(budget);
                let r = self.io.write(s, &buf[..n]);
                self.shard.tcp_tx_commit(now, tcp, r);
                match r {
                    IoResult::Bytes(n) if n > 0 => budget -= n,
                    IoResult::WouldBlock => {
                        self.set_lat(s.0, |l| l.writable = false);
                        break;
                    }
                    _ => break,
                }
            }
        }
    }

    /// spec §5.5 step 6: send and commit for each pending socket whose
    /// writable latch is set. Never commits zero datagrams.
    fn udp_tx(&mut self, now: Time) {
        let ids: Vec<UdpSocketId> = self.shard.pending_transmit().collect();
        for id in ids {
            let Some(&s) = self.udp.get(&id) else {
                continue;
            };
            while self.lat(s.0).writable {
                let Some(t) = self.shard.peek_transmit(id) else {
                    break;
                };
                let total = t.payload.len().div_ceil(t.segment_size.max(1));
                if total == 0 {
                    break;
                }
                match self.io.send_udp(s, &t) {
                    Ok(n) => {
                        if n > 0 {
                            self.shard.transmit_done(id, n);
                        }
                        if n < total {
                            self.set_lat(s.0, |l| l.writable = false);
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        self.set_lat(s.0, |l| l.writable = false);
                        break;
                    }
                    Err(e) => {
                        // spec §5.3: dropped and committed; QUIC sees loss.
                        self.shard.transmit_done(id, total);
                        self.send_errors += 1;
                        let last = self.last_err_log.get(&id).copied();
                        if last.is_none_or(|t| now - t >= Duration::from_secs(1)) {
                            self.last_err_log.insert(id, now);
                            log::warn!("udp send: {e} ({} errors)", self.send_errors);
                        }
                    }
                }
            }
        }
    }

    /// spec §5.5 step 8.
    fn execute(&mut self, now: Time, r: IoRequest) {
        match r {
            IoRequest::Dial {
                op,
                target,
                deadline,
            } => {
                self.deadlines.set(Expired::Dial(op), now + deadline);
                match target.host {
                    // C resolves only domains (mq_server.c:441).
                    Host::Ip(ip) => {
                        let a = SocketAddr::new(ip, target.port);
                        self.dials.insert(op, DialState::Connecting(a));
                        self.io.start_connect(op, a);
                    }
                    Host::Domain(h) => {
                        self.dials.insert(op, DialState::Resolving);
                        self.resolver.submit(&mut self.io, op, h, target.port);
                    }
                }
            }
            IoRequest::CancelDial { op } => {
                self.deadlines.cancel(Expired::Dial(op));
                match self.dials.remove(&op) {
                    Some(DialState::Resolving) => self.resolver.cancel(op),
                    Some(DialState::Connecting(_)) => self.io.cancel_connect(op),
                    None => {}
                }
            }
            IoRequest::OpenUdpSocket { op, local_ip } => {
                let r = self.io.open_udp(local_ip);
                self.held.push_back((op, r));
            }
            IoRequest::CancelUdpSocket { op } => {
                if let Some(i) = self.held.iter().position(|h| h.0 == op) {
                    if let Some((_, Ok((s, _)))) = self.held.remove(i) {
                        self.io.close_udp(s);
                    }
                }
            }
            IoRequest::CloseUdpSocket { sock } => {
                if let Some(s) = self.udp.remove(&sock) {
                    self.unregister(s.0);
                    self.last_err_log.remove(&sock);
                    self.io.close_udp(s);
                }
            }
            IoRequest::TcpShutdownWrite { tcp } => {
                if let Some(&s) = self.tcp.get(&tcp) {
                    if let Err(e) = self.io.shutdown_write(s) {
                        log::debug!("shutdown(SHUT_WR): {e}");
                    }
                }
            }
            IoRequest::TcpClose { tcp, abort } => {
                if let Some(s) = self.tcp.remove(&tcp) {
                    self.unregister(s.0);
                    self.io.close_tcp(s, abort);
                }
            }
        }
    }

    /// spec §5.5 step 10: runnable work remains.
    fn runnable(&self) -> bool {
        !self.held.is_empty()
            || self.shard.has_runnable_work()
            || self.io.has_pending_work()
            || self.tcp.iter().any(|(id, s)| {
                let (l, i) = (self.lat(s.0), self.shard.tcp_interest(*id));
                (l.readable && i.read) || (l.writable && i.write)
            })
            || self.udp.values().any(|s| self.lat(s.0).readable)
            || (self.shard.accepting() && self.listeners.values().any(|l| self.lat(l.0).readable))
            || self
                .shard
                .pending_transmit()
                .any(|id| self.udp.get(&id).is_some_and(|s| self.lat(s.0).writable))
    }

    // --- Harness accessors (spec §8.1) ---

    pub fn shard(&self) -> &Shard<T, A> {
        &self.shard
    }
    pub fn shard_mut(&mut self) -> &mut Shard<T, A> {
        &mut self.shard
    }
    pub fn io(&self) -> &I {
        &self.io
    }
    pub fn io_mut(&mut self) -> &mut I {
        &mut self.io
    }
    /// The driver's earliest deadline.
    pub fn earliest_deadline(&self) -> Option<Time> {
        self.deadlines.earliest()
    }
    /// The wait step 10 chose; the next iteration's step 1 performs it.
    pub fn next_wait(&self) -> Wait {
        self.next_wait
    }
    pub fn latch(&self, k: SockKey) -> Option<Latch> {
        self.latches.get(&k).copied()
    }
    pub fn resolver(&self) -> &ResolverQueue {
        &self.resolver
    }
    pub fn udp_sock(&self, id: UdpSocketId) -> Option<UdpSock> {
        self.udp.get(&id).copied()
    }
    /// UDP send errors other than `WouldBlock` (spec §5.3 counter).
    pub fn udp_send_errors(&self) -> u64 {
        self.send_errors
    }
}

/// spec §5.3 `io::Error → DialError` (C `srv_map_errno`) for connects;
/// resolve failures are `Dns`, the deadline `Timeout`, `Limit` only the cap.
fn connect_error(e: &io::Error) -> DialError {
    match e.kind() {
        ErrorKind::TimedOut => DialError::Timeout,
        _ => DialError::Refused, // ConnectionRefused and everything else
    }
}
