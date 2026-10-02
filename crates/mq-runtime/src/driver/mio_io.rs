//! `MioIo`: the production `Io` (spec §5.3) — an edge-triggered `mio::Poll`
//! waited on through a `current_thread` tokio runtime, a `timerfd` for
//! microsecond deadlines, the resolver on the runtime's blocking pool, and
//! signal / shutdown self-pipes.

use super::io::{
    Io, IoEvent, ListenerKey, RecvBatch, RecvMeta, RecvStop, Resolver, SockKey, TcpSock, UdpSock,
    Wait,
};
use crate::app::{AcceptMeta, IoResult, ListenKind};
use crate::ids::DialOpId;
use mio::net::TcpStream;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use mq_linux::{MAX_GSO_BYTES, MAX_GSO_SEGMENTS, TimerFd, UdpSocket};
use mq_transport_api::{Time, Transmit};
use signal_hook::SigId;
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const TIMER: Token = Token(0);
const SIGNALS: Token = Token(1);
const SHUTDOWN: Token = Token(2);
const FIRST_KEY: u64 = 3;
/// spec §5.3: zero-timeout drains per `wait` before yielding to the loop.
const DRAIN_BOUND: usize = 8;
const EVENTS_CAP: usize = 1024;
/// `recv_batch` room per call: 16 slots of 65535 bytes.
const RECV_SPACE: usize = 16 * 65535;
const EIO: i32 = 5;
const EINVAL: i32 = 22;

/// The `Poll`'s epoll fd, for `AsyncFd`.
struct PollFd(Poll);

impl AsRawFd for PollFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[derive(Default, Debug)]
struct StatsInner {
    iterations: AtomicU64,
    max_empty: AtomicU64,
}

/// spec §8.1 spin check: loop counters readable from another thread.
#[derive(Clone, Default, Debug)]
pub struct Stats(Arc<StatsInner>);

impl Stats {
    /// Loop iterations so far (one `wait` per iteration, step 1).
    pub fn iterations(&self) -> u64 {
        self.0.iterations.load(Relaxed)
    }
    /// The most zero-event drains in a row inside one blocking `wait`.
    pub fn max_consecutive_empty_drains(&self) -> u64 {
        self.0.max_empty.load(Relaxed)
    }
}

/// spec §5.3: stops one driver as a signal would; `Send`.
#[derive(Clone, Debug)]
pub struct ShutdownHandle(Arc<UnixStream>);

impl ShutdownHandle {
    pub fn trigger(&self) {
        // Non-blocking: a full pipe is already a pending shutdown.
        let _ = (&*self.0).write(&[1]);
    }
}

enum Sock {
    Udp { s: UdpSocket, gso: bool },
    Tcp(TcpStream),
    Connecting(DialOpId, TcpStream),
    Listener(TcpListener, ListenKind),
}

/// spec §5.3: the production `Io`.
pub struct MioIo {
    /// `Option` so `Drop` can `shutdown_background` it (spec §5.3: a running
    /// `getaddrinfo` must not hold up the exit).
    rt: Option<Runtime>,
    /// Owns the `Poll`; dropped after the runtime.
    afd: Option<AsyncFd<PollFd>>,
    events: Events,
    /// (token, readable, writable, error) of one drain.
    ready: Vec<(Token, bool, bool, bool)>,
    /// One `Sender` is kept so `recv()` never yields `None` (which would spin).
    tx: UnboundedSender<IoEvent>,
    rx: UnboundedReceiver<IoEvent>,
    stats: Stats,
    timer: TimerFd,
    signals: Option<(UnixStream, Vec<SigId>)>,
    shutdown_rx: UnixStream,
    shutdown: ShutdownHandle,
    socks: HashMap<SockKey, Sock>,
    connects: HashMap<DialOpId, SockKey>,
    next_key: u64,
    pending: bool,
    resolver: Arc<dyn Resolver>,
    /// `recv_batch` slots, allocated once.
    scratch: Vec<u8>,
    scratch_metas: Vec<mq_linux::RecvMeta>,
}

fn pipe() -> io::Result<(UnixStream, UnixStream)> {
    let (r, w) = UnixStream::pair()?;
    r.set_nonblocking(true)?;
    w.set_nonblocking(true)?;
    Ok((r, w))
}

fn drain_pipe(mut r: &UnixStream) {
    let mut b = [0u8; 64];
    while matches!(r.read(&mut b), Ok(n) if n > 0) {}
}

impl MioIo {
    /// spec §5.3. `install_signal_handlers`: SIGTERM/SIGINT become `Shutdown`.
    pub fn new(resolver: Arc<dyn Resolver>, install_signal_handlers: bool) -> io::Result<MioIo> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let poll = Poll::new()?;
        let reg = poll.registry();
        let timer = TimerFd::new()?;
        reg.register(&mut SourceFd(&timer.as_raw_fd()), TIMER, Interest::READABLE)?;
        let (shutdown_rx, w) = pipe()?;
        reg.register(
            &mut SourceFd(&shutdown_rx.as_raw_fd()),
            SHUTDOWN,
            Interest::READABLE,
        )?;
        let signals = if install_signal_handlers {
            let (r, w) = pipe()?;
            reg.register(&mut SourceFd(&r.as_raw_fd()), SIGNALS, Interest::READABLE)?;
            let mut ids = Vec::new();
            for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
                ids.push(signal_hook::low_level::pipe::register(sig, w.try_clone()?)?);
            }
            Some((r, ids))
        } else {
            None
        };
        let afd = {
            let _g = rt.enter();
            AsyncFd::with_interest(PollFd(poll), tokio::io::Interest::READABLE)?
        };
        let (tx, rx) = unbounded_channel();
        Ok(MioIo {
            rt: Some(rt),
            afd: Some(afd),
            events: Events::with_capacity(EVENTS_CAP),
            ready: Vec::new(),
            tx,
            rx,
            stats: Stats::default(),
            timer,
            signals,
            shutdown_rx,
            shutdown: ShutdownHandle(Arc::new(w)),
            socks: HashMap::new(),
            connects: HashMap::new(),
            next_key: FIRST_KEY,
            pending: false,
            resolver,
            scratch: Vec::new(),
            scratch_metas: Vec::new(),
        })
    }

    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    fn registry(&self) -> &Registry {
        self.afd.as_ref().expect("live poll").get_ref().0.registry()
    }

    /// Registers for read and write (spec §5.3: once, edge-triggered).
    fn insert(&mut self, mut sock: Sock) -> io::Result<SockKey> {
        let key = SockKey(self.next_key);
        let tok = Token(key.0 as usize);
        let rw = Interest::READABLE | Interest::WRITABLE;
        let reg = self.registry();
        match &mut sock {
            Sock::Udp { s, .. } => reg.register(&mut SourceFd(&s.as_raw_fd()), tok, rw),
            Sock::Tcp(s) | Sock::Connecting(_, s) => reg.register(s, tok, rw),
            Sock::Listener(l, _) => {
                reg.register(&mut SourceFd(&l.as_raw_fd()), tok, Interest::READABLE)
            }
        }?;
        self.next_key += 1;
        self.socks.insert(key, sock);
        Ok(key)
    }

    fn remove(&mut self, key: SockKey) -> Option<Sock> {
        let mut sock = self.socks.remove(&key)?;
        let reg = self.registry();
        let _ = match &mut sock {
            Sock::Udp { s, .. } => reg.deregister(&mut SourceFd(&s.as_raw_fd())),
            Sock::Tcp(s) | Sock::Connecting(_, s) => reg.deregister(s),
            Sock::Listener(l, _) => reg.deregister(&mut SourceFd(&l.as_raw_fd())),
        };
        Some(sock)
    }

    /// spec §5.3 `bind_udp`.
    pub fn bind_udp(&mut self, addr: SocketAddr) -> io::Result<(UdpSock, SocketAddr)> {
        let s = UdpSocket::bind(addr)?;
        let local = s.local_addr()?;
        Ok((UdpSock(self.insert(Sock::Udp { s, gso: true })?), local))
    }

    /// spec §5.3 `listen`: an already-bound listener and its kind.
    pub fn add_listener(&mut self, l: TcpListener, kind: ListenKind) -> io::Result<ListenerKey> {
        Ok(ListenerKey(self.insert(Sock::Listener(l, kind))?))
    }

    /// One zero-timeout poll, mapped into `out`. True when it filled `events`.
    fn drain_once(&mut self, out: &mut Vec<IoEvent>) -> bool {
        let afd = self.afd.as_mut().expect("live poll");
        if let Err(e) = afd.get_mut().0.poll(&mut self.events, Some(Duration::ZERO)) {
            if e.kind() != ErrorKind::Interrupted {
                log::error!("epoll_wait: {e}");
            }
            return false;
        }
        let mut ready = std::mem::take(&mut self.ready);
        ready.clear();
        ready.extend(
            self.events
                .iter()
                .map(|e| (e.token(), e.is_readable(), e.is_writable(), e.is_error())),
        );
        let full = ready.len() >= self.events.capacity();
        for &(tok, r, w, err) in &ready {
            self.map_event(tok, r, w, err, out);
        }
        self.ready = ready;
        full
    }

    /// spec §5.3 event mapping.
    fn map_event(&mut self, tok: Token, r: bool, w: bool, err: bool, out: &mut Vec<IoEvent>) {
        match tok {
            TIMER => {
                let _ = self.timer.read_expirations();
                out.push(IoEvent::Timer);
            }
            SIGNALS => {
                if let Some((p, _)) = &self.signals {
                    drain_pipe(p);
                }
                out.push(IoEvent::Shutdown);
            }
            SHUTDOWN => {
                drain_pipe(&self.shutdown_rx);
                out.push(IoEvent::Shutdown);
            }
            Token(k) => {
                let key = SockKey(k as u64);
                match self.socks.get(&key) {
                    // A pending connect first: ERR+OUT on a refusal is its result.
                    Some(Sock::Connecting(..)) => {
                        if w || err {
                            self.finish_connect(key, out);
                        }
                    }
                    Some(s) => {
                        if err {
                            if !matches!(s, Sock::Tcp(_)) {
                                log::debug!("EPOLLERR on UDP socket or listener {key:?}");
                            }
                            out.push(IoEvent::Error(key));
                        }
                        // HUP/RDHUP alone map to nothing.
                        if r {
                            out.push(IoEvent::Readable(key));
                        }
                        if w {
                            out.push(IoEvent::Writable(key));
                        }
                    }
                    None => {}
                }
            }
        }
    }

    /// spec §5.3: `SO_ERROR` decides a connect on its writable (or error) edge.
    fn finish_connect(&mut self, key: SockKey, out: &mut Vec<IoEvent>) {
        let Some(Sock::Connecting(op, s)) = self.socks.get(&key) else {
            return;
        };
        let op = *op;
        let r = match mq_linux::so_error(s) {
            Ok(None) => match s.peer_addr() {
                Ok(_) => Ok(()),
                // Not connected yet: a spurious edge; wait for the next.
                Err(e) if e.kind() == ErrorKind::NotConnected => return,
                Err(e) => Err(e),
            },
            Ok(Some(e)) | Err(e) => Err(e),
        };
        self.connects.remove(&op);
        match r {
            Ok(()) => {
                if let Some(Sock::Connecting(_, s)) = self.socks.remove(&key) {
                    self.socks.insert(key, Sock::Tcp(s));
                }
                out.push(IoEvent::Connected {
                    op,
                    r: Ok(TcpSock(key)),
                });
            }
            Err(e) => {
                self.remove(key);
                out.push(IoEvent::Connected { op, r: Err(e) });
            }
        }
    }

    fn take_completions(&mut self, out: &mut Vec<IoEvent>) {
        while let Ok(e) = self.rx.try_recv() {
            out.push(e);
        }
    }

    /// spec §5.3: `Until`/`Forever` — loop until at least one event.
    fn wait_blocking(&mut self, out: &mut Vec<IoEvent>) {
        let mut empty = 0u64;
        loop {
            let r: io::Result<Option<IoEvent>> = {
                let rt = self.rt.as_ref().expect("live runtime");
                let afd = self.afd.as_ref().expect("live poll");
                let rx = &mut self.rx;
                rt.block_on(async {
                    tokio::select! {
                        r = afd.readable() => {
                            r?.clear_ready();
                            Ok(None)
                        }
                        c = rx.recv() => Ok(c),
                    }
                })
            };
            match r {
                Ok(c) => out.extend(c),
                Err(e) => {
                    // The epoll fd itself failed: exit rather than spin.
                    log::error!("driver poll fd: {e}");
                    out.push(IoEvent::Shutdown);
                    return;
                }
            }
            self.take_completions(out);
            // Cleared first, then drained: an edge between the two is not lost.
            let before = out.len();
            let mut drains = 0;
            self.pending = loop {
                drains += 1;
                if !self.drain_once(out) {
                    break false;
                }
                if drains == DRAIN_BOUND {
                    break true;
                }
            };
            if out.len() == before {
                empty += 1;
                self.stats.0.max_empty.fetch_max(empty, Relaxed);
            } else {
                empty = 0;
            }
            if !out.is_empty() {
                return;
            }
        }
    }

    fn tcp(&mut self, s: TcpSock) -> Option<&mut TcpStream> {
        match self.socks.get_mut(&s.0) {
            Some(Sock::Tcp(t)) => Some(t),
            _ => None,
        }
    }
}

impl Drop for MioIo {
    fn drop(&mut self) {
        if let Some((_, ids)) = &self.signals {
            for id in ids {
                signal_hook::low_level::unregister(*id);
            }
        }
        // spec §5.3: the runtime first (never waits for a running resolve),
        // then the `AsyncFd` and its `Poll`.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
        self.afd.take();
    }
}

fn io_result(r: io::Result<usize>, read: bool) -> IoResult {
    match r {
        Ok(0) if read => IoResult::Eof,
        Ok(n) => IoResult::Bytes(n),
        Err(e) if e.kind() == ErrorKind::WouldBlock => IoResult::WouldBlock,
        Err(e) => IoResult::Error(e.kind()),
    }
}

fn retry<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            r => return r,
        }
    }
}

impl Io for MioIo {
    fn now(&self) -> Time {
        Time::from_micros(mq_linux::now_monotonic_micros())
    }

    fn wait(&mut self, w: Wait) -> Vec<IoEvent> {
        // Step 1 of every iteration is this call: it counts iterations.
        self.stats.0.iterations.fetch_add(1, Relaxed);
        let mut out = Vec::new();
        match w {
            Wait::Yield => {
                self.take_completions(&mut out);
                // One driver turn: the reactor and the waker of the channel.
                self.rt
                    .as_ref()
                    .expect("live runtime")
                    .block_on(tokio::task::yield_now());
                self.pending = self.drain_once(&mut out);
            }
            Wait::Until(t) => {
                if let Err(e) = self.timer.arm_at_micros(t.as_micros()) {
                    log::error!("timerfd arm: {e}");
                }
                self.wait_blocking(&mut out);
            }
            Wait::Forever => {
                if let Err(e) = self.timer.disarm() {
                    log::error!("timerfd disarm: {e}");
                }
                self.wait_blocking(&mut out);
            }
        }
        out
    }

    fn has_pending_work(&self) -> bool {
        self.pending
    }

    fn accept(&mut self, l: ListenerKey) -> io::Result<(TcpSock, AcceptMeta)> {
        let Some(Sock::Listener(lst, kind)) = self.socks.get(&l.0) else {
            return Err(ErrorKind::NotFound.into());
        };
        let kind = *kind;
        let (s, peer) = retry(|| lst.accept())?;
        s.set_nonblocking(true)?;
        let local = s.local_addr()?;
        // spec §5.3: by listener kind.
        let original_dst = match kind {
            ListenKind::Plain => None,
            ListenKind::Redirect => mq_linux::original_dst(&s)
                .inspect_err(|e| log::debug!("SO_ORIGINAL_DST: {e}"))
                .ok(),
            ListenKind::Tproxy => Some(local),
        };
        let key = self.insert(Sock::Tcp(TcpStream::from_std(s)))?;
        Ok((
            TcpSock(key),
            AcceptMeta {
                peer,
                local,
                original_dst,
            },
        ))
    }

    fn read(&mut self, s: TcpSock, buf: &mut [u8]) -> IoResult {
        debug_assert!(!buf.is_empty());
        match self.tcp(s) {
            Some(t) => io_result(retry(|| t.read(buf)), true),
            None => IoResult::Error(ErrorKind::NotConnected),
        }
    }

    fn write(&mut self, s: TcpSock, buf: &[u8]) -> IoResult {
        match self.tcp(s) {
            Some(t) => io_result(retry(|| t.write(buf)), false),
            None => IoResult::Error(ErrorKind::NotConnected),
        }
    }

    fn recv_udp(&mut self, u: UdpSock, out: &mut RecvBatch, budget: usize) -> io::Result<RecvStop> {
        let Some(Sock::Udp { s, .. }) = self.socks.get(&u.0) else {
            return Err(ErrorKind::NotFound.into());
        };
        // `recv_batch` fills fixed 65535-byte slots; the datagrams are
        // copied out compactly so `out` holds the whole budget densely.
        if self.scratch.is_empty() {
            self.scratch = vec![0; RECV_SPACE];
        }
        let mut used = 0;
        loop {
            if used >= budget {
                return Ok(RecvStop::Budget);
            }
            self.scratch_metas.clear();
            let r = s.recv_batch(&mut self.scratch, &mut self.scratch_metas);
            let dgrams = self.scratch_metas.len();
            for m in self.scratch_metas.drain(..) {
                let start = out.buf.len();
                out.buf.extend_from_slice(&self.scratch[m.range]);
                out.metas.push(RecvMeta {
                    src: m.src,
                    local: m.local,
                    range: start..out.buf.len(),
                });
            }
            match r {
                // At least one byte per datagram: zero-length datagrams must not escape the budget.
                Ok(n) => used += n.max(dgrams),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(RecvStop::Drained),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn send_udp(&mut self, u: UdpSock, t: &Transmit<'_>) -> io::Result<usize> {
        let Some(Sock::Udp { s, gso }) = self.socks.get_mut(&u.0) else {
            return Err(ErrorKind::NotFound.into());
        };
        let s = &*s;
        send_split(
            gso,
            t,
            |c, seg| s.send_gso(t.dst, seg, c),
            |d| s.send_one(t.dst, d),
        )
    }

    fn start_resolve(&mut self, op: DialOpId, host: String, port: u16) {
        let (resolver, tx) = (self.resolver.clone(), self.tx.clone());
        // spec §5.3: on the runtime's blocking pool, back through the channel.
        self.rt
            .as_ref()
            .expect("live runtime")
            .spawn_blocking(move || {
                let r = resolver.resolve(&host, port);
                let _ = tx.send(IoEvent::Resolved { op, r });
            });
    }

    fn start_connect(&mut self, op: DialOpId, addr: SocketAddr) {
        let r = TcpStream::connect(addr).and_then(|s| self.insert(Sock::Connecting(op, s)));
        match r {
            Ok(key) => {
                self.connects.insert(op, key);
            }
            // Synchronous failure (ECONNREFUSED, EMFILE): through the channel.
            Err(e) => {
                let _ = self.tx.send(IoEvent::Connected { op, r: Err(e) });
            }
        }
    }

    fn cancel_connect(&mut self, op: DialOpId) {
        if let Some(key) = self.connects.remove(&op) {
            self.remove(key); // closes it
        }
    }

    fn open_udp(&mut self, local_ip: IpAddr) -> io::Result<(UdpSock, SocketAddr)> {
        self.bind_udp(SocketAddr::new(local_ip, 0))
    }

    fn shutdown_write(&mut self, s: TcpSock) -> io::Result<()> {
        match self.tcp(s) {
            Some(t) => t.shutdown(Shutdown::Write),
            None => Err(ErrorKind::NotConnected.into()),
        }
    }

    fn close_tcp(&mut self, s: TcpSock, abort: bool) {
        if let Some(Sock::Tcp(t) | Sock::Connecting(_, t)) = self.remove(s.0) {
            if abort {
                if let Err(e) = mq_linux::set_linger_zero(&t) {
                    log::debug!("SO_LINGER: {e}");
                }
            }
        }
    }

    fn close_udp(&mut self, s: UdpSock) {
        self.remove(s.0);
    }

    fn socket_error(&mut self, s: TcpSock) -> ErrorKind {
        match self.tcp(s).map(|t| mq_linux::so_error(&*t)) {
            Some(Ok(Some(e))) => e.kind(),
            _ => ErrorKind::Other,
        }
    }
}

/// spec §5.3 GSO: splits `t` into ≤64-segment / ≤65507-byte calls. GSO is
/// turned off (`*gso = false`) only when a well-formed call fails with `EIO`
/// or `EINVAL`; that call is then resent one datagram at a time, as is
/// everything after. Ok(n) = datagrams sent, `n < total` only on WouldBlock;
/// Err(WouldBlock) when none were sent. Any other error is returned as is:
/// the caller drops and commits the whole transmit (sent prefix included) and
/// counts it (`LoopCore` owns the send-error counter). SP2 spec §4.1: a
/// single datagram is always a plain send, since `UDP_SEGMENT` rejects a
/// segment above the egress MTU (`EMSGSIZE`) that a plain send fragments.
fn send_split(
    gso: &mut bool,
    t: &Transmit<'_>,
    mut send_gso: impl FnMut(&[u8], usize) -> io::Result<()>,
    mut send_one: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<usize> {
    let seg = t.segment_size.max(1);
    if t.payload.len() <= seg {
        return send_one(t.payload).map(|()| 1);
    }
    let per_call = (MAX_GSO_BYTES / seg).clamp(1, MAX_GSO_SEGMENTS);
    let wb = |e: &io::Error| e.kind() == ErrorKind::WouldBlock;
    let partial = |sent: usize, e: io::Error| if sent > 0 { Ok(sent) } else { Err(e) };
    let mut sent = 0;
    for chunk in t.payload.chunks(per_call * seg) {
        if *gso {
            match send_gso(chunk, seg) {
                Ok(()) => {
                    sent += chunk.len().div_ceil(seg);
                    continue;
                }
                Err(e) if wb(&e) => return partial(sent, e),
                // An oversized call (one segment above 65507 bytes) is the
                // caller's bug, not a reason to turn GSO off.
                Err(e)
                    if matches!(e.raw_os_error(), Some(EIO | EINVAL))
                        && chunk.len() <= MAX_GSO_BYTES =>
                {
                    log::warn!("GSO send failed ({e}); GSO off for this socket");
                    *gso = false;
                }
                Err(e) => return Err(e),
            }
        }
        for d in chunk.chunks(seg) {
            match send_one(d) {
                Ok(()) => sent += 1,
                Err(e) if wb(&e) => return partial(sent, e),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const EINVAL: i32 = 22;
    const EMSGSIZE: i32 = 90;

    fn tx(seg: usize, n: usize) -> Vec<u8> {
        vec![7u8; seg * n]
    }

    #[test]
    fn splits_at_segment_and_byte_limits() {
        let p = tx(1200, 100);
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 1200,
            payload: &p,
        };
        let calls = RefCell::new(Vec::new());
        let mut gso = true;
        let r = send_split(
            &mut gso,
            &t,
            |c, seg| {
                calls.borrow_mut().push((c.len(), seg));
                Ok(())
            },
            |_| panic!("no single sends while GSO works"),
        );
        assert_eq!(r.unwrap(), 100);
        // 65507 / 1200 = 54 segments per call.
        assert_eq!(*calls.borrow(), vec![(54 * 1200, 1200), (46 * 1200, 1200)]);
        let small = tx(100, 100);
        let t = Transmit {
            segment_size: 100,
            payload: &small,
            ..t
        };
        calls.borrow_mut().clear();
        send_split(
            &mut gso,
            &t,
            |c, _| {
                calls.borrow_mut().push((c.len(), 0));
                Ok(())
            },
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(*calls.borrow(), vec![(6400, 0), (3600, 0)]); // 64 segments max
    }

    #[test]
    fn gso_off_after_einval_on_well_formed_batch() {
        let p = tx(1200, 10);
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 1200,
            payload: &p,
        };
        let mut gso = true;
        let singles = RefCell::new(0);
        let r = send_split(
            &mut gso,
            &t,
            |_, _| Err(io::Error::from_raw_os_error(EINVAL)),
            |d| {
                assert_eq!(d.len(), 1200);
                *singles.borrow_mut() += 1;
                Ok(())
            },
        );
        assert_eq!(r.unwrap(), 10, "the failed batch is resent individually");
        assert!(!gso, "GSO turned off for the socket");
        assert_eq!(*singles.borrow(), 10);
        // From then on: individual sends only.
        let r = send_split(&mut gso, &t, |_, _| panic!("GSO stays off"), |_| Ok(()));
        assert_eq!(r.unwrap(), 10);
    }

    #[test]
    fn oversized_single_datagram_error_is_returned_gso_stays_on() {
        // SP2 spec §4.1: one datagram goes through `send_one`; its error is the caller's.
        let p = vec![0u8; 70_000];
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 70_000,
            payload: &p,
        };
        let mut gso = true;
        let r = send_split(
            &mut gso,
            &t,
            |_, _| panic!("a single datagram bypasses GSO"),
            |_| Err(io::Error::from_raw_os_error(EMSGSIZE)),
        );
        assert_eq!(r.unwrap_err().raw_os_error(), Some(EMSGSIZE));
        assert!(gso, "GSO stays on");
    }

    #[test]
    fn oversized_batch_is_caller_bug_not_gso_off() {
        // Two segments, each above the 65507-byte limit: no split can make them legal.
        let p = vec![0u8; 2 * 70_000];
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 70_000,
            payload: &p,
        };
        let mut gso = true;
        let r = send_split(
            &mut gso,
            &t,
            |_, _| Err(io::Error::from_raw_os_error(EINVAL)),
            |_| panic!("no fallback for a caller bug"),
        );
        assert_eq!(r.unwrap_err().raw_os_error(), Some(EINVAL));
        assert!(gso, "GSO stays on");
    }

    #[test]
    fn send_split_single_datagram_uses_send_one() {
        // SP2 spec §4.1: `UDP_SEGMENT` rejects a segment above the egress MTU.
        let p = vec![1u8; 3_000];
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 3_000,
            payload: &p,
        };
        let mut gso = true;
        let singles = RefCell::new(0);
        let r = send_split(
            &mut gso,
            &t,
            |_, _| panic!("send_gso never"),
            |d| {
                assert_eq!(d.len(), 3_000);
                *singles.borrow_mut() += 1;
                Ok(())
            },
        );
        assert_eq!(r.unwrap(), 1);
        assert_eq!(*singles.borrow(), 1);
        assert!(gso);
    }

    #[test]
    fn send_split_multi_still_gso() {
        let p = tx(1_200, 2);
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 1_200,
            payload: &p,
        };
        let calls = RefCell::new(Vec::new());
        let mut gso = true;
        let r = send_split(
            &mut gso,
            &t,
            |c, seg| {
                calls.borrow_mut().push((c.len(), seg));
                Ok(())
            },
            |_| panic!("two segments go through GSO"),
        );
        assert_eq!(r.unwrap(), 2);
        assert_eq!(*calls.borrow(), vec![(2_400, 1_200)]);
    }

    #[test]
    fn would_block_mid_batch_reports_the_sent_prefix() {
        let p = tx(1000, 100); // 65 per call
        let t = Transmit {
            dst: "127.0.0.1:9".parse().unwrap(),
            segment_size: 1000,
            payload: &p,
        };
        let mut first = true;
        let mut gso = true;
        let r = send_split(
            &mut gso,
            &t,
            |_, _| {
                if std::mem::take(&mut first) {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            },
            |_| unreachable!(),
        );
        assert_eq!(r.unwrap(), 64);
        let r = send_split(
            &mut gso,
            &t,
            |_, _| Err(io::ErrorKind::WouldBlock.into()),
            |_| unreachable!(),
        );
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(gso);
    }

    #[test]
    fn empty_datagrams_are_charged_against_the_budget() {
        let mut io = MioIo::new(Arc::new(super::super::io::StdResolver), false).unwrap();
        let (u, addr) = io.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..40 {
            tx.send_to(&[], addr).unwrap();
        }
        let mut b = RecvBatch::default();
        // 16 bytes of budget: one batch of 16 empty datagrams spends it.
        let r = io.recv_udp(u, &mut b, 16).unwrap();
        assert!(matches!(r, RecvStop::Budget), "{r:?}");
        assert_eq!(b.metas.len(), 16);
        assert!(b.metas.iter().all(|m| m.range.is_empty()));
        let r = io.recv_udp(u, &mut b, 1 << 20).unwrap();
        assert!(matches!(r, RecvStop::Drained), "{r:?}");
        assert_eq!(b.metas.len(), 40);
    }
}
