//! The shard-pair harness (spec §8.1 "Shard pair"): a server shard and a
//! client shard, each with the real xquic `Transport` inside a `LoopCore`
//! over a `FakeIo` (auto-advance off) on virtual time, each on its own thread
//! (`Transport` is `!Send`: one engine per thread, spec §4.6). The test thread
//! owns the clock and the `Fabric`. `Pair::step` runs one
//! `LoopCore::iteration` on the server, then one on the client, carrying the
//! UDP each side sent through the fabric into the other side's `FakeIo`
//! (`take_sent_udp` → `Fabric::push` → `pop_ready` → `inject_udp`). Only one
//! side runs at a time, so a run is deterministic.
//!
//! App code outside a callback runs only through `Shard::with_app` on the
//! shard's thread, between steps (`Node::with_app`, sent over the side's
//! command channel). Every app is wrapped in a `Tap` that records the
//! transport events it saw and the UDP sockets it opened. The harness plays
//! the TCP endpoints through `FakeIo`: the origin on the server side
//! (`Origin`), the local applications on the client side (`Node::accept`).

use mq_proxy::client::{Client, SOCKS5, TRANSPARENT};
use mq_proxy::config::{ClientConfig, ServerConfig};
use mq_proxy::server::Server;
use mq_runtime::driver::{Io, ListenerKey, LoopConfig, LoopCore, Next, TcpSock, UdpSock, Wait};
use mq_runtime::testing::{FakeIo, Op};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, Shard, SocketOpId, TcpEnd, TcpId,
    TimerId, UdpSocketId,
};
use mq_transport::Transport;
use mq_transport_api::fabric::{Fabric, Packet};
use mq_transport_api::{
    CongestionControl, ConnConfig, ConnId, Event, Role, Scheduler, StreamError, StreamId, Time,
    TransportConfig,
};
use mq_wire::frames::{AddrType, AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Virtual time at which both sides start.
pub const T0: Time = Time(1_000_000);
pub const MS: Duration = Duration::from_millis(1);
pub const SEC: Duration = Duration::from_secs(1);

pub fn server_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 4433))
}
/// The client's primary UDP socket.
pub fn client_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 1, 2], 50000))
}
/// The client's second `--path` address (`FakeIo::open_udp` picks the port).
pub const CLIENT_IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 3));
/// Where every origin lives (the server dials it; `Origin` answers).
pub fn origin_addr() -> SocketAddr {
    SocketAddr::from(([10, 9, 9, 9], 7))
}

fn cert(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs")).join(name)
}

pub fn transport_cfg(role: Role, max_conns: u32) -> TransportConfig {
    TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
    }
}

pub fn server_role() -> Role {
    Role::Server {
        cert: cert("test.crt"),
        key: cert("test.key"),
    }
}

/// The client settings the ports use: token "secret", reconnect off (as the
/// C fixtures), a 1 s maximum backoff for the reconnect cases.
pub fn client_cfg() -> ClientConfig {
    ClientConfig {
        server: server_addr(),
        paths: vec![client_addr().ip()],
        token: "secret".into(),
        reconnect: false,
        reconnect_max_backoff: SEC,
        ..ClientConfig::default()
    }
}

pub fn server_cfg() -> ServerConfig {
    ServerConfig {
        token: "secret".into(),
        ..ServerConfig::default()
    }
}

// --- Tap ---

/// Wraps an app: records every transport event (with its time) and every
/// UDP socket the app opened, then forwards.
pub struct Tap<A> {
    pub inner: A,
    pub events: Vec<(Time, Event)>,
    udp: Vec<(UdpSocketId, SocketAddr)>,
}

impl<A> Tap<A> {
    pub fn new(inner: A) -> Tap<A> {
        Tap {
            inner,
            events: Vec::new(),
            udp: Vec::new(),
        }
    }

    pub fn count(&self, pred: impl Fn(&Event) -> bool) -> usize {
        self.events.iter().filter(|(_, e)| pred(e)).count()
    }

    /// Connections seen (`ConnEstablished` or `NewConn`) and not yet closed, oldest first.
    pub fn open_conns(&self) -> Vec<ConnId> {
        let mut v: Vec<ConnId> = Vec::new();
        for (_, e) in &self.events {
            match e {
                Event::ConnEstablished(c) | Event::NewConn(c) if !v.contains(c) => v.push(*c),
                Event::ConnClosed(c, _) => v.retain(|x| x != c),
                _ => {}
            }
        }
        v
    }

    /// Connections that reported `ConnEstablished`, in order.
    pub fn established(&self) -> Vec<ConnId> {
        (self.events.iter())
            .filter_map(|(_, e)| match e {
                Event::ConnEstablished(c) => Some(*c),
                _ => None,
            })
            .collect()
    }

    pub fn closed(&self, c: ConnId) -> usize {
        self.count(|e| matches!(e, Event::ConnClosed(x, _) if *x == c))
    }
}

impl<A: App> App for Tap<A> {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        self.inner.on_start(cx)
    }
    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        self.events.push((cx.now(), ev.clone()));
        self.inner.on_transport_event(cx, ev)
    }
    fn on_accepted(&mut self, cx: &mut Cx<'_>, l: ListenerTag, tcp: TcpId, meta: AcceptMeta) {
        self.inner.on_accepted(cx, l, tcp, meta)
    }
    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        self.inner.on_tcp_data(cx, tcp)
    }
    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        self.inner.on_tcp_end(cx, tcp, end)
    }
    fn on_dial_result(&mut self, cx: &mut Cx<'_>, op: DialOpId, r: Result<TcpId, DialError>) {
        self.inner.on_dial_result(cx, op, r)
    }
    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        if let Ok(s) = r {
            self.udp.push(s);
        }
        self.inner.on_udp_socket(cx, op, r)
    }
    fn on_udp_rx(&mut self, cx: &mut Cx<'_>, sock: UdpSocketId, peer: SocketAddr, data: &[u8]) {
        self.inner.on_udp_rx(cx, sock, peer, data)
    }
    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        self.inner.on_timer(cx, id)
    }
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.inner.on_shutdown(cx)
    }
}

// --- Origin ---

/// How the server side's origin answers dials.
#[derive(Clone, Debug)]
pub enum OriginMode {
    /// Resolutions and connects wait for the test (it reads `FakeIo::ops`).
    Manual,
    /// Resolve, connect, and echo every byte written.
    Echo,
    /// Resolve; connects fail with `ConnectionRefused`.
    Refuse,
    /// Resolve, connect, offer these bytes, then EOF.
    Send(Vec<u8>),
    /// Resolve, connect, then only take what is written.
    Sink,
}

/// The origin, played on the server's `FakeIo` after every iteration.
pub struct Origin {
    pub mode: OriginMode,
    /// Sockets connected so far, in order.
    pub socks: Vec<TcpSock>,
    echoed: HashMap<TcpSock, usize>,
    seen: usize,
}

impl Origin {
    fn new() -> Origin {
        Origin {
            mode: OriginMode::Manual,
            socks: Vec::new(),
            echoed: HashMap::new(),
            seen: 0,
        }
    }

    /// True when it queued an event.
    fn step(&mut self, io: &mut FakeIo) -> bool {
        let ops = io.ops()[self.seen..].to_vec();
        self.seen += ops.len();
        if matches!(self.mode, OriginMode::Manual) {
            return false;
        }
        let mut acted = false;
        for op in ops {
            match op {
                Op::StartResolve(op, _, port) => {
                    io.resolve(op, Ok(vec![SocketAddr::new(origin_addr().ip(), port)]));
                    acted = true;
                }
                Op::StartConnect(op, _) => {
                    acted = true;
                    if let OriginMode::Refuse = self.mode {
                        io.connect_err(op, ErrorKind::ConnectionRefused);
                        continue;
                    }
                    let s = io.connect_ok(op);
                    self.socks.push(s);
                    self.echoed.insert(s, 0);
                    if let OriginMode::Send(b) = &self.mode {
                        io.tcp_feed(s, b);
                        io.tcp_eof(s);
                    }
                }
                _ => {}
            }
        }
        if let OriginMode::Echo = self.mode {
            for s in &self.socks {
                let done = self.echoed[s];
                if io.tcp_closed(*s).is_none() {
                    let w = io.tcp_written(*s);
                    if w.len() > done {
                        io.tcp_feed(*s, &w[done..]);
                        self.echoed.insert(*s, w.len());
                        acted = true;
                    }
                }
            }
        }
        acted
    }
}

// --- Node: one side, on its own thread ---

type Core<A> = LoopCore<FakeIo, Transport, Tap<A>>;

/// One side: its `LoopCore`, the UDP sockets it has, its listeners, its origin.
pub struct Node<A: App> {
    core: Core<A>,
    socks: Vec<(UdpSock, SocketAddr)>,
    udp_seen: usize,
    listeners: HashMap<ListenerTag, ListenerKey>,
    peers: u16,
    pub origin: Origin,
    /// The status of a `Next::Exit`; the side stops iterating.
    pub exit: Option<i32>,
}

struct Out {
    packets: Vec<Packet>,
    next: Option<Time>,
    addrs: Vec<SocketAddr>,
}

impl<A: App> Node<A> {
    pub fn now(&self) -> Time {
        self.core.io().now()
    }
    pub fn core(&self) -> &Core<A> {
        &self.core
    }
    pub fn io(&self) -> &FakeIo {
        self.core.io()
    }
    pub fn io_mut(&mut self) -> &mut FakeIo {
        self.core.io_mut()
    }
    pub fn shard(&self) -> &Shard<Transport, Tap<A>> {
        self.core.shard()
    }
    pub fn transport(&self) -> &Transport {
        self.core.shard().transport()
    }
    pub fn tap(&self) -> &Tap<A> {
        self.core.shard().app()
    }
    pub fn app(&self) -> &A {
        &self.tap().inner
    }
    /// App code with a `Cx`, at the side's current time (spec §8.1: the only way).
    pub fn with_app<R>(&mut self, f: impl FnOnce(&mut A, &mut Cx<'_>) -> R) -> R {
        let now = self.now();
        self.core
            .shard_mut()
            .with_app(now, |t, cx| f(&mut t.inner, cx))
    }
    /// The UDP sockets in use (the primary first).
    pub fn udp_socks(&self) -> Vec<(UdpSock, SocketAddr)> {
        self.socks.clone()
    }
    /// A local application connects to the listener tagged `tag`.
    pub fn accept(&mut self, tag: ListenerTag, original_dst: Option<SocketAddr>) -> TcpSock {
        let l = self.listeners[&tag];
        self.peers += 1;
        let peer = SocketAddr::from(([127, 0, 0, 1], 30000 + self.peers));
        let local = SocketAddr::from(([127, 0, 0, 1], 1080));
        self.core.io_mut().push_accept(
            l,
            AcceptMeta {
                peer,
                local,
                original_dst,
            },
        )
    }

    fn step(&mut self, now: Time, inbound: Vec<Packet>) -> Out {
        self.core.io_mut().set_now(now);
        for p in inbound {
            if let Some(&(s, _)) = self.socks.iter().find(|(_, a)| *a == p.to) {
                self.core.io_mut().inject_udp(s, p.from, &p.data);
            }
        }
        if self.exit.is_none() {
            if let Next::Exit(c) = self.core.iteration() {
                self.exit = Some(c);
            }
        }
        let acted = self.origin.step(self.core.io_mut());
        let opened = self.tap().udp[self.udp_seen..].to_vec();
        self.udp_seen += opened.len();
        for (id, local) in opened {
            if let Some(s) = self.core.udp_sock(id) {
                self.socks.push((s, local));
            }
        }
        let mut packets = Vec::new();
        for &(s, from) in &self.socks {
            for (to, data) in self.core.io_mut().take_sent_udp(s) {
                packets.push(Packet { from, to, data });
            }
        }
        let next = match (self.exit, acted, self.core.next_wait()) {
            (Some(_), _, _) => None,
            (_, true, _) | (_, _, Wait::Yield) => Some(now),
            (_, _, Wait::Until(t)) => Some(t.max(now)),
            (_, _, Wait::Forever) => None,
        };
        Out {
            packets,
            next,
            addrs: self.socks.iter().map(|s| s.1).collect(),
        }
    }
}

type Cmd<A> = Box<dyn FnOnce(&mut Node<A>) + Send>;

/// The test thread's handle on one side's thread.
pub struct Side<A: App> {
    tx: Option<mpsc::Sender<Cmd<A>>>,
    thread: Option<JoinHandle<()>>,
    addrs: Vec<SocketAddr>,
}

impl<A: App + 'static> Side<A> {
    /// Builds the transport and (with `make`) the app on a new thread, binds
    /// the primary UDP socket at `local` and one listener per tag, and starts
    /// the shard at `T0`.
    pub fn spawn(
        cfg: TransportConfig,
        local: SocketAddr,
        listeners: Vec<ListenerTag>,
        make: impl FnOnce() -> A + Send + 'static,
    ) -> Side<A> {
        let (tx, rx) = mpsc::channel::<Cmd<A>>();
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let t = Transport::new(cfg).expect("Transport::new");
            let mut shard = Shard::new(t, Tap::new(make()), local, 7);
            let mut io = FakeIo::new();
            io.set_auto_advance(false);
            io.set_now(T0);
            let primary = io.add_udp(local);
            let mut keyed = HashMap::new();
            let mut ids = Vec::new();
            for tag in listeners {
                ids.push((shard.add_listener(tag), io.add_listener()));
                keyed.insert(tag, ids.last().expect("pushed").1);
            }
            let pid = shard.primary_udp();
            let mut core = LoopCore::new(io, shard, LoopConfig::default());
            core.attach_primary_udp(primary, pid);
            for (id, key) in ids {
                core.attach_listener(key, id);
            }
            core.start();
            let mut node = Node {
                core,
                socks: vec![(primary, local)],
                udp_seen: 0,
                listeners: keyed,
                peers: 0,
                origin: Origin::new(),
                exit: None,
            };
            ready_tx.send(()).expect("test thread alive");
            while let Ok(cmd) = rx.recv() {
                cmd(&mut node);
            }
            // The transport drops here, on its own thread.
        });
        ready_rx.recv().expect("side thread failed during setup");
        Side {
            tx: Some(tx),
            thread: Some(thread),
            addrs: vec![local],
        }
    }

    /// Runs `f` on the side's thread and returns its result.
    pub fn call<R: Send + 'static>(&self, f: impl FnOnce(&mut Node<A>) -> R + Send + 'static) -> R {
        let (rtx, rrx) = mpsc::channel();
        let cmd: Cmd<A> = Box::new(move |n| {
            let _ = rtx.send(f(n));
        });
        self.tx
            .as_ref()
            .expect("live")
            .send(cmd)
            .expect("side alive");
        rrx.recv().expect("side thread panicked")
    }

    fn step(&mut self, now: Time, inbound: Vec<Packet>) -> (Vec<Packet>, Option<Time>) {
        let out = self.call(move |n| n.step(now, inbound));
        self.addrs = out.addrs;
        (out.packets, out.next)
    }

    fn owns(&self, a: SocketAddr) -> bool {
        self.addrs.contains(&a)
    }
}

impl<A: App> Drop for Side<A> {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The real `Server` (cap `max_conns`) at `server_addr()`.
pub fn spawn_server(cfg: ServerConfig, max_conns: u32) -> Side<Server> {
    Side::spawn(
        transport_cfg(server_role(), max_conns),
        server_addr(),
        Vec::new(),
        move || Server::new(cfg),
    )
}

/// The real `Client` at `client_addr()` with SOCKS5 and transparent listeners.
pub fn spawn_client(cfg: ClientConfig) -> Side<Client> {
    let mut tc = transport_cfg(Role::Client, 0);
    tc.scheduler = cfg.scheduler;
    Side::spawn(tc, client_addr(), vec![SOCKS5, TRANSPARENT], move || {
        Client::new(cfg)
    })
}

/// The `SilentClient` of spec §8.1: `RawClient` with `silent` set.
pub fn spawn_silent() -> Side<RawClient> {
    spawn_raw(true)
}

/// A `RawClient` (token "secret") at `client_addr()`.
pub fn spawn_raw(silent: bool) -> Side<RawClient> {
    Side::spawn(
        transport_cfg(Role::Client, 0),
        client_addr(),
        Vec::new(),
        move || {
            let mut r = RawClient::new(server_addr(), b"secret");
            r.silent = silent;
            r
        },
    )
}

// --- Pair ---

/// Both sides, the fabric between them and the virtual clock.
pub struct Pair<S: App, C: App> {
    pub srv: Side<S>,
    pub cli: Side<C>,
    pub fabric: Fabric,
    pub now: Time,
    /// Datagrams are dropped in both directions.
    pub blackhole: bool,
    /// When `Some`, every datagram sent is appended with its time.
    pub wire: Option<Vec<(Time, Packet)>>,
    /// Datagrams to an address neither side owns (e.g. a closed socket), dropped.
    pub unrouted: u64,
}

impl<S: App + 'static, C: App + 'static> Pair<S, C> {
    pub fn new(srv: Side<S>, cli: Side<C>) -> Pair<S, C> {
        Pair {
            srv,
            cli,
            fabric: Fabric::new(),
            now: T0,
            blackhole: false,
            wire: None,
            unrouted: 0,
        }
    }

    pub fn with_server<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Node<S>) -> R + Send + 'static,
    ) -> R {
        self.srv.call(f)
    }

    pub fn with_client<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Node<C>) -> R + Send + 'static,
    ) -> R {
        self.cli.call(f)
    }

    /// Packets ready now, split into (to the server, to the client); others are dropped.
    fn ready(&mut self) -> (Vec<Packet>, Vec<Packet>) {
        let (mut s, mut c) = (Vec::new(), Vec::new());
        while let Some(p) = self.fabric.pop_ready(self.now) {
            if self.srv.owns(p.to) {
                s.push(p);
            } else if self.cli.owns(p.to) {
                c.push(p);
            } else {
                self.unrouted += 1;
            }
        }
        (s, c)
    }

    fn push(&mut self, out: Vec<Packet>) {
        if let Some(w) = &mut self.wire {
            w.extend(out.iter().map(|p| (self.now, p.clone())));
        }
        if !self.blackhole {
            for p in out {
                self.fabric.push(self.now, p);
            }
        }
    }

    /// One lockstep step at `now`: deliver what is ready, one iteration on
    /// the server, then (with the server's output delivered) one on the
    /// client. Returns the earliest time either side or the fabric wants to run.
    pub fn step(&mut self) -> Option<Time> {
        let now = self.now;
        let (to_s, mut to_c) = self.ready();
        let (out, next_s) = self.srv.step(now, to_s);
        self.push(out);
        let (late_s, more_c) = self.ready();
        to_c.extend(more_c);
        let (out, next_c) = self.cli.step(now, to_c);
        // The server sends nothing to itself, so this is empty; requeue anyway.
        for p in late_s {
            self.fabric.push(now, p);
        }
        self.push(out);
        [next_s, next_c, self.fabric.next_delivery()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Steps, jumping the clock to the next wake-up when both sides are idle,
    /// until `cond` holds (checked after every step) or `limit` of virtual
    /// time has passed. Virtual time only: nothing sleeps.
    pub fn run_until(&mut self, limit: Duration, mut cond: impl FnMut(&mut Self) -> bool) -> bool {
        let end = self.now + limit;
        let mut spins = 0u32;
        loop {
            let next = self.step();
            if cond(self) {
                return true;
            }
            let next = next.unwrap_or(end).max(self.now);
            if next == self.now && self.now < end {
                spins += 1;
                assert!(spins < 200_000, "busy loop at {:?}", self.now);
                continue;
            }
            spins = 0;
            if self.now >= end {
                return false;
            }
            self.now = next.min(end);
        }
    }

    /// Runs for `d` of virtual time.
    pub fn run_for(&mut self, d: Duration) {
        self.run_until(d, |_| false);
    }

    /// Bytes the client side wrote to its local socket `s`.
    pub fn app_written(&self, s: TcpSock) -> Vec<u8> {
        self.with_client(move |n| n.io().tcp_written(s))
    }

    /// `Some(abort)` once the client side closed its local socket `s`.
    pub fn app_closed(&self, s: TcpSock) -> Option<bool> {
        self.with_client(move |n| n.io().tcp_closed(s))
    }

    /// The client side's open connections, oldest first.
    pub fn client_conns(&self) -> Vec<ConnId> {
        self.with_client(|n| n.tap().open_conns())
    }

    /// The server side's open connections, oldest first.
    pub fn server_conns(&self) -> Vec<ConnId> {
        self.with_server(|n| n.tap().open_conns())
    }

    /// `Cx::close_conn` on the client side (C `mq_conn_close`).
    pub fn close_client_conn(&self, c: ConnId) {
        self.with_client(move |n| n.with_app(|_, cx| cx.close_conn(c)));
    }

    /// `(server, client)` live stream slots of their connections.
    pub fn stream_counts(&self, srv: ConnId, cli: ConnId) -> (u32, u32) {
        (
            self.with_server(move |n| n.transport().stream_count(srv)),
            self.with_client(move |n| n.transport().stream_count(cli)),
        )
    }
}

impl<C: App + 'static> Pair<Server, C> {
    pub fn auth_attempts(&self) -> u64 {
        self.with_server(|n| n.app().auth_attempts())
    }

    /// The server's origin answers dials this way from now on.
    pub fn origin(&self, mode: OriginMode) {
        self.with_server(move |n| n.origin.mode = mode);
    }

    /// The origin sockets connected so far.
    pub fn origin_socks(&self) -> Vec<TcpSock> {
        self.with_server(|n| n.origin.socks.clone())
    }

    /// `Op::StartConnect`s the server's `FakeIo` saw.
    pub fn server_connects(&self) -> usize {
        self.with_server(|n| {
            (n.io().ops().iter())
                .filter(|o| matches!(o, Op::StartConnect(..)))
                .count()
        })
    }
}

impl<S: App + 'static> Pair<S, Client> {
    /// A local application connects to the SOCKS5 listener and sends the
    /// greeting, a CONNECT to `target` and `extra`, in one write.
    pub fn socks_open(&self, target: SocketAddr, extra: &[u8]) -> TcpSock {
        let mut b = socks5_connect(target);
        b.extend_from_slice(extra);
        self.with_client(move |n| {
            let s = n.accept(SOCKS5, None);
            n.io_mut().tcp_feed(s, &b);
            s
        })
    }

    /// Bytes written by the local application on `s`.
    pub fn app_send(&self, s: TcpSock, b: &[u8]) {
        let b = b.to_vec();
        self.with_client(move |n| n.io_mut().tcp_feed(s, &b));
    }
}

impl<S: App + 'static> Pair<S, RawClient> {
    /// `RawClient::connect`; with `authenticate`, runs until the OK `AUTH_RESPONSE`.
    pub fn raw_connect(&mut self, authenticate: bool) -> ConnId {
        let c = self.with_client(move |n| n.with_app(|r, cx| r.connect(cx, authenticate)));
        if authenticate {
            assert!(
                self.run_until(5 * SEC, move |p| p
                    .with_client(move |n| n.app().auth_status(c))
                    == Some(0)),
                "not authenticated"
            );
        }
        c
    }

    /// A data stream on `c` carrying `bytes`.
    pub fn raw_open(&self, c: ConnId, bytes: &[u8], fin: bool) -> StreamId {
        let b = bytes.to_vec();
        self.with_client(move |n| {
            n.with_app(|r, cx| {
                let s = r.open_stream(cx, c);
                r.send(cx, s, &b, fin);
                s
            })
        })
    }

    pub fn raw_send(&self, s: StreamId, bytes: &[u8], fin: bool) {
        let b = bytes.to_vec();
        self.with_client(move |n| n.with_app(|r, cx| r.send(cx, s, &b, fin)));
    }

    pub fn raw_stream(&self, s: StreamId) -> RawStream {
        self.with_client(move |n| n.app().stream(s))
    }

    /// Runs until `s` holds a complete `CONNECT_TCP_RESPONSE`: (status, code, the bytes after it).
    pub fn raw_response(&mut self, s: StreamId) -> (u8, u64, Vec<u8>) {
        assert!(
            self.run_until(5 * SEC, move |p| connect_response(&p.raw_stream(s).rx)
                .is_some()),
            "no response: {:?}",
            self.raw_stream(s)
        );
        let rx = self.raw_stream(s).rx;
        let (st, code, n) = connect_response(&rx).expect("complete");
        (st, code, rx[n..].to_vec())
    }
}

// --- Test apps ---

/// One stream of a `RawClient`.
#[derive(Clone, Debug, Default)]
pub struct RawStream {
    pub rx: Vec<u8>,
    pub fin: bool,
    /// `stream_recv` returned `Reset`.
    pub reset: bool,
    /// `StreamClosed` was seen.
    pub closed: bool,
    tx: Vec<u8>,
    tx_fin: bool,
    fin_sent: bool,
}

#[derive(Clone, Debug)]
pub struct RawConn {
    pub authenticate: bool,
    pub ctrl: Option<StreamId>,
    pub closed: bool,
}

/// spec §8.1: a client app below the real `Client` — it opens connections
/// and streams on command, sends and receives raw bytes, and on each
/// connection's first stream sends the C `AUTH_REQUEST` (or, unauthenticated,
/// one `0x00` byte, as C's `preauth` case, and never authenticates).
/// Received bytes are read on every `StreamReadable` (the app-owned stream
/// rule, spec §5.4). Commands run through `Node::with_app`.
///
/// `silent` makes it the `SilentClient` of spec §8.1: it connects at start,
/// opens the control stream and never authenticates.
pub struct RawClient {
    server: SocketAddr,
    token: Vec<u8>,
    pub silent: bool,
    pub conns: HashMap<ConnId, RawConn>,
    pub streams: HashMap<StreamId, RawStream>,
}

impl RawClient {
    pub fn new(server: SocketAddr, token: &[u8]) -> RawClient {
        RawClient {
            server,
            token: token.to_vec(),
            silent: false,
            conns: HashMap::new(),
            streams: HashMap::new(),
        }
    }

    pub fn connect(&mut self, cx: &mut Cx<'_>, authenticate: bool) -> ConnId {
        let cfg = ConnConfig {
            peer: self.server,
            sni: "mqproxy",
            idle_timeout: Some(Duration::from_secs(30)),
        };
        let c = cx.connect(&cfg).expect("connect");
        let conn = RawConn {
            authenticate,
            ctrl: None,
            closed: false,
        };
        self.conns.insert(c, conn);
        c
    }

    pub fn open_stream(&mut self, cx: &mut Cx<'_>, c: ConnId) -> StreamId {
        let s = cx.open_stream(c).expect("open_stream");
        self.streams.insert(s, RawStream::default());
        s
    }

    pub fn send(&mut self, cx: &mut Cx<'_>, s: StreamId, bytes: &[u8], fin: bool) {
        let st = self.streams.get_mut(&s).expect("known stream");
        st.tx.extend_from_slice(bytes);
        st.tx_fin |= fin;
        flush(cx, s, st);
    }

    pub fn recv(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let Some(st) = self.streams.get_mut(&s) else {
            return;
        };
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match cx.stream_recv(s, &mut buf) {
                Ok((n, fin)) => {
                    st.rx.extend_from_slice(&buf[..n]);
                    st.fin |= fin;
                    if fin || n == 0 {
                        return;
                    }
                }
                Err(StreamError::Reset) if !st.reset => {
                    st.reset = true;
                    cx.stream_reset(s);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    pub fn reset(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        cx.stream_reset(s);
    }

    pub fn close_conn(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        cx.close_conn(c);
    }

    pub fn stream(&self, s: StreamId) -> RawStream {
        self.streams.get(&s).cloned().unwrap_or_default()
    }

    /// The `AUTH_RESPONSE` status on `c`'s control stream, once complete.
    pub fn auth_status(&self, c: ConnId) -> Option<u8> {
        let s = self.conns.get(&c)?.ctrl?;
        AuthResp::decode(&self.streams.get(&s)?.rx)
            .ok()
            .map(|(r, _)| r.status)
    }
}

fn flush(cx: &mut Cx<'_>, s: StreamId, st: &mut RawStream) {
    if st.fin_sent || (st.tx.is_empty() && !st.tx_fin) {
        return;
    }
    if let Ok(n) = cx.stream_send(s, &st.tx, st.tx_fin) {
        st.tx.drain(..n.min(st.tx.len()));
        st.fin_sent = st.tx.is_empty() && st.tx_fin;
    }
}

impl App for RawClient {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        if self.silent {
            self.connect(cx, false);
        }
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::ConnEstablished(c) => {
                let Some(k) = self.conns.get(&c).filter(|k| k.ctrl.is_none()) else {
                    return;
                };
                let bytes = if k.authenticate {
                    auth_request(&self.token)
                } else {
                    vec![0x00] // C `preauth_on_state`'s nudge: never a complete AUTH_REQUEST
                };
                let s = self.open_stream(cx, c);
                self.conns.get_mut(&c).expect("known").ctrl = Some(s);
                self.send(cx, s, &bytes, false);
            }
            Event::ConnClosed(c, _) => {
                if let Some(k) = self.conns.get_mut(&c) {
                    k.closed = true;
                }
            }
            Event::NewStream(_, s, _) => cx.stream_reset(s),
            Event::StreamReadable(s) => self.recv(cx, s),
            Event::StreamWritable(s) => {
                if let Some(st) = self.streams.get_mut(&s) {
                    flush(cx, s, st);
                }
            }
            Event::StreamClosed(s) => {
                if let Some(st) = self.streams.get_mut(&s) {
                    st.closed = true;
                }
            }
            Event::NewConn(_) | Event::MpReady(_) => {}
            Event::DatagramReadable(_) => {} // wired with the UDP lane
        }
    }

    fn on_accepted(&mut self, cx: &mut Cx<'_>, _l: ListenerTag, tcp: TcpId, _m: AcceptMeta) {
        cx.tcp_close(tcp);
    }
    fn on_tcp_data(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId) {}
    fn on_tcp_end(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId, _end: TcpEnd) {}
    fn on_dial_result(&mut self, _cx: &mut Cx<'_>, _op: DialOpId, _r: Result<TcpId, DialError>) {}
    fn on_udp_socket(
        &mut self,
        _cx: &mut Cx<'_>,
        _op: SocketOpId,
        _r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
    }
    fn on_udp_rx(&mut self, _cx: &mut Cx<'_>, _s: UdpSocketId, _p: SocketAddr, _d: &[u8]) {}
    fn on_timer(&mut self, _cx: &mut Cx<'_>, _id: TimerId) {}
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        cx.request_exit(0);
    }
}

// --- Wire bytes ---

/// The C `AUTH_REQUEST` (version 1, client id "client-1", features 0).
pub fn auth_request(token: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 512];
    let n = AuthReq {
        version: 1,
        client_id: b"client-1",
        auth_token: token,
        features: 0,
    }
    .encode(&mut b)
    .expect("fits");
    b[..n].to_vec()
}

/// Stream type 0x01 then `CONNECT_TCP_REQUEST` to an IPv4 target (C `open_tcp_data_stream`).
pub fn connect_request(target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(a) = target else {
        panic!("IPv4 target");
    };
    encode_connect(AddrType::Ipv4, &a.ip().octets(), a.port())
}

/// Stream type 0x01 then `CONNECT_TCP_REQUEST` to a domain.
pub fn connect_request_domain(host: &str, port: u16) -> Vec<u8> {
    encode_connect(AddrType::Domain, host.as_bytes(), port)
}

fn encode_connect(address_type: AddrType, host: &[u8], port: u16) -> Vec<u8> {
    let mut b = [0u8; 512];
    b[0] = 0x01;
    let n = ConnectTcpReq {
        flags: 0,
        address_type,
        host,
        port,
    }
    .encode(&mut b[1..])
    .expect("fits");
    b[..1 + n].to_vec()
}

/// A complete `CONNECT_TCP_RESPONSE` at the start of `rx`: (status, error code, its length).
pub fn connect_response(rx: &[u8]) -> Option<(u8, u64, usize)> {
    ConnectTcpResp::decode(rx)
        .ok()
        .map(|(r, n)| (r.status, r.error_code, n))
}

/// SOCKS5 greeting (no auth) and a CONNECT to an IPv4 target, in one write.
pub fn socks5_connect(target: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(a) = target else {
        panic!("IPv4 target");
    };
    let mut b = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01];
    b.extend_from_slice(&a.ip().octets());
    b.extend_from_slice(&a.port().to_be_bytes());
    b
}

/// The greeting reply then the SOCKS5 success reply.
pub const SOCKS5_OK: [u8; 12] = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

/// Deterministic payload (C bulk origin: byte i is `i & 0xff`).
pub fn bulk(n: usize) -> Vec<u8> {
    (0..n).map(|i| i as u8).collect()
}
