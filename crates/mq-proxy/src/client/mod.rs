//! spec §6.2: the client — one tunnel connection with its control stream,
//! ingress glue, data-stream opens, paths, reconnect, metrics and shutdown.
//!
//! ```text
//! Connecting ──→ Authing ──→ Serving
//!     │             │           │
//!     └─────────────┴───────────┴──→ Backoff ──→ Connecting   (reconnect enabled)
//!                                  └→ Closed                   (--no-reconnect: terminal)
//! ```
//! `conn == None` is Backoff (or Closed when `terminal`); a held conn without a
//! control stream is Connecting, with one but not `authed` is Authing.

pub mod backoff;
pub mod gateway;
mod ingress_glue;
mod paths;
pub mod pending;
mod udp_assoc;
mod udp_session;

use crate::app_stream::{self, CHUNK, Recv};
use crate::config::ClientConfig;
use crate::ingress::{INGRESS_CAP, socks5_assoc_reply, target_from_original_dst};
use crate::metrics::format_metrics;
use crate::udp::SessionEnd;
use backoff::Backoff;
use gateway::Gateway;
use ingress_glue::{Fed, Ingress, kind_of};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, Host, ListenerTag, SocketOpId, StreamPreread, Target,
    TcpEnd, TcpId, TimerId, UdpSocketId,
};
use mq_transport_api::{ConnConfig, ConnId, ConnProto, Event, StreamId};
use mq_wire::frames::{
    AddrType, AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp, DecodeError, FEAT_UDP_RELAY,
    MAX_FRAME, STREAM_TYPE_CONNECT_TCP, TcpErr,
};
use paths::Paths;
use pending::{IngressKind, Pending, PendingOpen};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use udp_assoc::Assoc;
use udp_session::Sessions;

/// spec §6.1: the listener tags the binary registers.
pub const SOCKS5: ListenerTag = ListenerTag(1);
pub const HTTP_CONNECT: ListenerTag = ListenerTag(2);
pub const TRANSPARENT: ListenerTag = ListenerTag(3);
/// SP3 spec §5.1: the fetch listener.
pub const FETCH: ListenerTag = ListenerTag(4);

/// spec §6.2: the TLS server name, as C.
const SNI: &str = "mqproxy";
/// spec §6.2: wire limits of `client_id` / `auth_token` (C `char[64]` / `char[256]`).
const MAX_CLIENT_ID: usize = 63;
const MAX_TOKEN: usize = 255;
const MAX_HOST: usize = 255;

/// What an app timer is for.
#[derive(Copy, Clone, Debug)]
enum Tm {
    Auth,
    Reconnect,
    Metrics,
    Ingress(TcpId),
    Pending,
    /// SP2 spec §6.3: a UDP session's RESP deadline, by sid.
    UdpResp(u32),
}

/// spec §6.2: the control stream.
struct Ctrl {
    s: StreamId,
    /// Unsent rest of `AUTH_REQUEST`.
    tx: Vec<u8>,
    /// `AUTH_RESPONSE` bytes so far.
    rx: Vec<u8>,
}

/// The current connection.
struct Conn {
    id: ConnId,
    ctrl: Option<Ctrl>,
    authed: bool,
    auth_timer: Option<TimerId>,
    /// `close_conn` was called; the exit is taken at `ConnClosed`.
    closing: bool,
}

/// spec §6.2 "Open": a data stream awaiting its `CONNECT_TCP_RESPONSE` (app-owned).
struct Open {
    tcp: TcpId,
    kind: IngressKind,
    /// Unsent rest of the type byte + `CONNECT_TCP_REQUEST`.
    tx: Vec<u8>,
    /// Response bytes so far, then whatever followed it (the preread).
    rx: Vec<u8>,
}

/// SP2 spec §6.2: whether UDP ASSOCIATE is served, per client.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum UdpAvail {
    /// Before auth of the current connection; ASSOCIATE accepted optimistically.
    Unknown,
    Available,
    /// ASSOCIATE refused with REP 0x07.
    Unavailable,
}

/// spec §6.2: the client app.
pub struct Client {
    cfg: ClientConfig,
    client_id: Vec<u8>,
    token: Vec<u8>,
    backoff: Backoff,
    pending: Pending,
    conn: Option<Conn>,
    /// spec §6.2 `--no-reconnect`: the tunnel was lost; `Closed` for good.
    terminal: bool,
    shutting_down: bool,
    reconnect: Option<TimerId>,
    ingress: HashMap<TcpId, Ingress>,
    opens: HashMap<StreamId, Open>,
    paths: Paths,
    timers: HashMap<TimerId, Tm>,
    udp: UdpAvail,
    /// SP2 spec §6.3: the UDP associations, by control socket.
    assocs: HashMap<TcpId, Assoc>,
    /// SP2 spec §6.3: the UDP sessions.
    sess: Sessions,
    /// SP3 spec §5: the fetch gateway, with its own H3 tunnel.
    gw: Option<Gateway>,
}

/// spec §6.2: truncate to the wire limit with a warning (C truncates silently).
fn truncated(s: &str, max: usize, flag: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.len() > max {
        log::warn!("mq_client: {flag} is longer than {max} bytes; truncated");
    }
    b[..b.len().min(max)].to_vec()
}

/// spec §6.5: the `mq.conn` / `mq.path` lines of `conn`; nothing without one.
fn log_conn_metrics(cx: &Cx<'_>, conn: Option<ConnId>) {
    if let Some(st) = conn.and_then(|c| cx.conn_stats(c).ok()) {
        for l in format_metrics(Some(&st)) {
            log::info!("{l}");
        }
    }
}

/// spec §6.1: the ingress error reply (if any), then close.
fn refuse(cx: &mut Cx<'_>, tcp: TcpId, kind: IngressKind, e: TcpErr) {
    if let Some(b) = kind.error_reply(e) {
        let _ = cx.tcp_write(tcp, &b);
    }
    cx.tcp_close(tcp);
}

/// SP2 spec §6.1: bytes on an association's control socket are discarded.
fn discard(cx: &mut Cx<'_>, tcp: TcpId) {
    let n = cx.tcp_rx(tcp).len();
    cx.tcp_consume(tcp, n);
}

/// spec §6.2: stream type `0x01` then `CONNECT_TCP_REQUEST` (flags 0), as C sends it.
fn connect_request(target: &Target) -> Vec<u8> {
    let (address_type, host): (AddrType, Vec<u8>) = match &target.host {
        Host::Ip(IpAddr::V4(a)) => (AddrType::Ipv4, a.octets().to_vec()),
        Host::Ip(IpAddr::V6(a)) => (AddrType::Ipv6, a.octets().to_vec()),
        Host::Domain(d) => (
            AddrType::Domain,
            d.as_bytes()[..d.len().min(MAX_HOST)].to_vec(),
        ),
    };
    let mut buf = vec![0u8; MAX_FRAME];
    buf[0] = STREAM_TYPE_CONNECT_TCP as u8;
    let n = ConnectTcpReq {
        flags: 0,
        address_type,
        host: &host,
        port: target.port,
    }
    .encode(&mut buf[1..])
    .expect("host is capped, so the frame fits 512 bytes");
    buf.truncate(1 + n);
    buf
}

impl Client {
    pub fn new(cfg: ClientConfig) -> Client {
        Client {
            client_id: truncated(&cfg.client_id, MAX_CLIENT_ID, "--client-id"),
            token: truncated(&cfg.token, MAX_TOKEN, "--token"),
            backoff: Backoff::new(cfg.reconnect_max_backoff),
            pending: Pending::new(cfg.pending_deadline),
            conn: None,
            terminal: false,
            shutting_down: false,
            reconnect: None,
            ingress: HashMap::new(),
            opens: HashMap::new(),
            paths: Paths::new(&cfg, "mq_client"),
            timers: HashMap::new(),
            udp: UdpAvail::Unknown,
            assocs: HashMap::new(),
            sess: Sessions::new(),
            gw: cfg.gateway.map(|_| Gateway::new(&cfg)),
            cfg,
        }
    }

    /// SP3 spec §5: the fetch gateway, when `--gateway` is set.
    #[cfg(feature = "test-support")]
    pub fn gateway(&self) -> Option<&Gateway> {
        self.gw.as_ref()
    }

    /// SP2 spec §6.3: the source an association locked.
    #[cfg(feature = "test-support")]
    pub fn udp_learned(&self, control: TcpId) -> Option<SocketAddr> {
        self.assocs.get(&control).and_then(|a| a.learned)
    }

    /// SP2 spec §6.5: the client's UDP counters.
    #[cfg(feature = "test-support")]
    pub fn udp_counters(&self) -> crate::udp::Counters {
        self.sess.counters
    }

    /// SP2 spec §6.3: DST entries carrying a `failed_at` (the negative cache).
    #[cfg(feature = "test-support")]
    pub fn udp_negcache_len(&self) -> usize {
        let entries = self.assocs.values().flat_map(|a| a.dsts.values());
        entries.filter(|e| e.failed_at.is_some()).count()
    }

    fn timer(&mut self, cx: &mut Cx<'_>, after: std::time::Duration, tm: Tm) -> TimerId {
        let id = cx.set_timer(after);
        self.timers.insert(id, tm);
        id
    }

    fn cancel(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        cx.cancel_timer(id);
        self.timers.remove(&id);
    }

    /// The connection the event names, if it is the current one.
    fn current(&self, c: ConnId) -> bool {
        self.conn.as_ref().is_some_and(|k| k.id == c)
    }

    /// The current connection, if `Serving`.
    fn serving(&self) -> Option<ConnId> {
        self.conn
            .as_ref()
            .filter(|c| c.authed && !c.closing)
            .map(|c| c.id)
    }

    /// spec §6.2 Connecting.
    fn connect(&mut self, cx: &mut Cx<'_>) {
        let cfg = ConnConfig {
            peer: self.cfg.server,
            sni: SNI,
            idle_timeout: self.cfg.keepalive_idle,
            proto: ConnProto::Raw,
        };
        match cx.connect(&cfg) {
            Ok(id) => {
                self.conn = Some(Conn {
                    id,
                    ctrl: None,
                    authed: false,
                    auth_timer: None,
                    closing: false,
                });
            }
            Err(e) => {
                log::error!("mq_client: connect failed ({e})");
                self.conn_gone(cx);
            }
        }
    }

    /// spec §6.2: close the connection; the exit follows at `ConnClosed`.
    fn close(&mut self, cx: &mut Cx<'_>) {
        if let Some(c) = self.conn.as_mut().filter(|c| !c.closing) {
            c.closing = true;
            cx.close_conn(c.id);
        }
    }

    /// spec §6.2: `ConnEstablished` → open the control stream, send `AUTH_REQUEST`.
    fn on_established(&mut self, cx: &mut Cx<'_>) {
        let Some(conn) = self.conn.as_ref().filter(|c| c.ctrl.is_none()) else {
            return;
        };
        let s = match cx.open_stream(conn.id) {
            Ok(s) => s,
            Err(e) => {
                log::error!("mq_client: failed to open control stream ({e})");
                return self.close(cx);
            }
        };
        let mut tx = vec![0u8; MAX_FRAME];
        let n = AuthReq {
            version: 1,
            client_id: &self.client_id,
            auth_token: &self.token,
            features: 0,
        }
        .encode(&mut tx)
        .expect("fields are truncated to their limits");
        tx.truncate(n);
        let timer = self.timer(cx, self.cfg.auth_deadline, Tm::Auth);
        let conn = self.conn.as_mut().expect("checked above");
        conn.auth_timer = Some(timer);
        let ctrl = conn.ctrl.insert(Ctrl {
            s,
            tx,
            rx: Vec::new(),
        });
        if !app_stream::flush(cx, s, &mut ctrl.tx, false) {
            log::error!("mq_client: send AUTH_REQUEST failed");
            self.close(cx);
        }
    }

    /// spec §6.2 "Auth": read the `AUTH_RESPONSE`; after auth, drain and discard.
    fn ctrl_readable(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let Some(conn) = self.conn.as_mut() else {
            return;
        };
        if conn.authed {
            if !app_stream::drain(cx, s) {
                log::warn!("mq_client: control stream reset");
                self.close(cx);
            }
            return;
        }
        let ctrl = conn
            .ctrl
            .as_mut()
            .expect("ctrl_readable on the control stream");
        let features = loop {
            match app_stream::recv(cx, s, &mut ctrl.rx, CHUNK) {
                Recv::Blocked => return,
                Recv::Failed => {
                    log::warn!("mq_client: control stream reset before AUTH_RESPONSE");
                    return self.close(cx);
                }
                Recv::Data { n, fin } => match AuthResp::decode(&ctrl.rx) {
                    // spec §6.2: frames are at most 512 bytes, complete or not.
                    Ok((_, used)) if used > MAX_FRAME => {
                        log::warn!("mq_client: AUTH_RESPONSE malformed");
                        break None;
                    }
                    Ok((r, _)) if r.is_ok() => break Some(r.features),
                    Ok((r, _)) => {
                        log::warn!("mq_client: auth refused (error {})", r.error_code);
                        break None;
                    }
                    Err(DecodeError::Short) if !fin && ctrl.rx.len() < MAX_FRAME => {
                        if n == 0 {
                            return;
                        }
                    }
                    Err(_) => {
                        log::warn!("mq_client: AUTH_RESPONSE malformed");
                        break None;
                    }
                },
            }
        };
        let Some(features) = features else {
            // spec §6.2 "Auth refused": pending requests fail, as in C.
            self.set_udp(cx, UdpAvail::Unavailable);
            for o in self.pending.drain() {
                refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
            }
            return self.close(cx);
        };
        // Serving.
        conn.authed = true;
        ctrl.rx = Vec::new();
        let (id, timer) = (conn.id, conn.auth_timer.take());
        if let Some(t) = timer {
            self.cancel(cx, t);
        }
        self.backoff.on_serving(cx.now());
        log::info!("mq_client: authenticated");
        // SP2 spec §6.2: the server relays UDP and datagrams fit on the connection;
        // shutting down, the AUTH_RESPONSE of the closing connection admits nothing.
        let relay = features & FEAT_UDP_RELAY != 0 && cx.datagram_mss(id) > 0;
        let avail = if relay && !self.shutting_down {
            UdpAvail::Available
        } else {
            UdpAvail::Unavailable
        };
        self.set_udp(cx, avail);
        if !app_stream::drain(cx, s) {
            return self.close(cx);
        }
        for o in self.pending.drain() {
            self.open(cx, id, o.tcp, o.kind, &o.target);
        }
        if avail == UdpAvail::Available {
            self.udp_available(cx);
        }
    }

    /// spec §6.1/§6.2: a complete ingress request.
    fn request(&mut self, cx: &mut Cx<'_>, tcp: TcpId, kind: IngressKind, target: Target) {
        if self.terminal || self.shutting_down {
            return refuse(cx, tcp, kind, TcpErr::ConnRefused);
        }
        if let Some(conn) = self.serving() {
            return self.open(cx, conn, tcp, kind, &target);
        }
        // spec §6.2 "Pending requests": read interest stays off; rx holds the preread.
        let open = PendingOpen {
            tcp,
            target,
            kind,
            enqueued_at: cx.now(),
        };
        match self.pending.push(open) {
            Ok(()) => {
                self.timer(cx, self.cfg.pending_deadline, Tm::Pending);
            }
            Err(_) => {
                log::warn!("mq_client: tcp_open queue full, rejecting");
                refuse(cx, tcp, kind, TcpErr::ConnRefused);
            }
        }
    }

    /// spec §6.2 "Open": a data stream with the type byte and `CONNECT_TCP_REQUEST`.
    fn open(&mut self, cx: &mut Cx<'_>, conn: ConnId, tcp: TcpId, kind: IngressKind, t: &Target) {
        let s = match cx.open_stream(conn) {
            Ok(s) => s,
            Err(e) => {
                log::error!("mq_client: open data stream failed ({e})");
                return refuse(cx, tcp, kind, TcpErr::ConnRefused);
            }
        };
        let mut open = Open {
            tcp,
            kind,
            tx: connect_request(t),
            rx: Vec::new(),
        };
        if !app_stream::flush(cx, s, &mut open.tx, false) {
            refuse(cx, tcp, kind, TcpErr::ConnRefused);
            return cx.stream_reset(s);
        }
        self.opens.insert(s, open);
    }

    /// spec §6.2/§5.4: a stream awaiting its response is read 1 KiB at a time.
    fn open_readable(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let Some(o) = self.opens.get_mut(&s) else {
            return;
        };
        let fin = loop {
            match app_stream::recv(cx, s, &mut o.rx, CHUNK) {
                Recv::Blocked => return,
                Recv::Failed => {
                    // Peer reset: treated like an error response (already reset).
                    let o = self.opens.remove(&s).expect("present");
                    return refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
                }
                Recv::Data { n, fin } => match ConnectTcpResp::decode(&o.rx) {
                    Err(DecodeError::Short) if !fin && o.rx.len() < MAX_FRAME => {
                        if n == 0 {
                            return;
                        }
                    }
                    _ => break fin,
                },
            }
        };
        let o = self.opens.remove(&s).expect("present");
        match ConnectTcpResp::decode(&o.rx) {
            // spec §6.2: frames are at most 512 bytes; over that is malformed.
            Ok((r, used)) if r.is_ok() && used <= MAX_FRAME => {
                if let Some(b) = o.kind.success_reply() {
                    let _ = cx.tcp_write(o.tcp, &b);
                }
                let preread = StreamPreread {
                    bytes: &o.rx[used..],
                    fin,
                };
                if cx.start_relay(o.tcp, s, preread).is_err() {
                    log::error!("mq_client: begin relay failed");
                    cx.tcp_abort(o.tcp);
                    cx.stream_reset(s);
                }
            }
            Ok((r, used)) if used <= MAX_FRAME => {
                let e = r.error().unwrap_or(TcpErr::ConnRefused);
                refuse(cx, o.tcp, o.kind, e);
                cx.stream_reset(s);
            }
            Ok(_) | Err(_) => {
                log::warn!("mq_client: CONNECT_TCP_RESPONSE malformed/oversized");
                refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
                cx.stream_reset(s);
            }
        }
    }

    /// SP2 spec §6.1: UDP ASSOCIATE — an app UDP socket on the IP the control
    /// connection arrived on; the reply waits for it. The control socket keeps
    /// read interest and the 8 KiB `rx_limit` of `on_accepted`.
    fn associate(&mut self, cx: &mut Cx<'_>, tcp: TcpId, meta: AcceptMeta) {
        discard(cx, tcp);
        // An IPv4 client of a `[::]` listener arrives v4-mapped.
        let op = cx.open_app_udp_socket(meta.local.ip().to_canonical());
        let peer_ip = meta.peer.ip().to_canonical();
        self.assocs.insert(tcp, Assoc::new(op, peer_ip));
    }

    /// SP2 spec §6.2: `Unavailable` ends every association, sessions included.
    fn set_udp(&mut self, cx: &mut Cx<'_>, avail: UdpAvail) {
        self.udp = avail;
        if avail == UdpAvail::Unavailable {
            let all: Vec<TcpId> = self.assocs.keys().copied().collect();
            for tcp in all {
                self.end_assoc(cx, tcp);
                cx.tcp_close(tcp);
            }
        }
    }

    /// spec §6.2: every exit — handshake failure, auth timeout or refusal,
    /// control stream closed, tunnel lost — taken at `ConnClosed`.
    fn conn_gone(&mut self, cx: &mut Cx<'_>) {
        if let Some(t) = self.conn.take().and_then(|c| c.auth_timer) {
            self.cancel(cx, t);
        }
        // Relays were closed by the shard's sweep; in-flight opens fail, as in C.
        for (_, o) in self.opens.drain() {
            refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
        }
        self.udp_conn_gone(cx);
        self.paths.on_conn_closed(cx);
        if self.shutting_down {
            self.set_udp(cx, UdpAvail::Unavailable);
            return self.maybe_exit(cx);
        }
        if self.cfg.reconnect {
            self.set_udp(cx, UdpAvail::Unknown);
            let rnd = cx.rng().next_u64();
            let d = self.backoff.next_delay(cx.now(), rnd);
            log::info!(
                "mq_client: tunnel down; reconnecting in {} ms",
                d.as_millis()
            );
            self.reconnect = Some(self.timer(cx, d, Tm::Reconnect));
        } else {
            log::warn!("mq_client: tunnel down; reconnect disabled");
            self.terminal = true;
            self.set_udp(cx, UdpAvail::Unavailable);
            for o in self.pending.drain() {
                refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
            }
        }
    }

    /// spec §6.5: the `mq.conn` / `mq.path` lines of the held connection.
    fn dump_metrics(&self, cx: &Cx<'_>) {
        log_conn_metrics(cx, self.conn.as_ref().map(|c| c.id));
    }

    /// SP3 spec §5.9: shutting down, exit once both tunnels are gone (or never existed).
    fn maybe_exit(&self, cx: &mut Cx<'_>) {
        if self.shutting_down
            && self.conn.is_none()
            && self.gw.as_ref().is_none_or(Gateway::tunnel_gone)
        {
            cx.request_exit(0);
        }
    }

    fn ctrl_of(&self, s: StreamId) -> bool {
        self.conn
            .as_ref()
            .and_then(|c| c.ctrl.as_ref())
            .is_some_and(|k| k.s == s)
    }
}

impl App for Client {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        if let Some(every) = self.cfg.metrics_interval {
            self.timer(cx, every, Tm::Metrics);
        }
        // SP3 spec §5.7: the raw tunnel only with a TCP ingress; it connects
        // before the gateway's tunnel.
        if self.cfg.has_tcp_ingress {
            self.connect(cx);
        }
        if let Some(g) = self.gw.as_mut() {
            g.on_start(cx);
        }
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        // SP3 spec §5.8: the gateway's tunnel and every H3 event go to the gateway.
        let ev = match self.gw.as_mut() {
            Some(g) => match g.on_transport_event(cx, ev) {
                Some(ev) => ev,
                None => return self.maybe_exit(cx),
            },
            None => ev,
        };
        match ev {
            Event::ConnEstablished(c) if self.current(c) => self.on_established(cx),
            // spec §6.5: the stats line is per ConnClosed; a synchronous
            // connect failure also reaches `conn_gone`, but has no connection.
            Event::ConnClosed(c, _) if self.current(c) => {
                self.udp_log_stats();
                self.conn_gone(cx);
            }
            Event::MpReady(c) if self.current(c) => self.paths.on_mp_ready(cx, c),
            // spec §6.2: the protocol has no server-initiated streams.
            Event::NewStream(_, s, _) => cx.stream_reset(s),
            Event::StreamReadable(s) if self.ctrl_of(s) => self.ctrl_readable(cx, s),
            Event::StreamReadable(s) if self.sess.by_stream.contains_key(&s) => {
                self.session_readable(cx, s)
            }
            Event::StreamReadable(s) => self.open_readable(cx, s),
            Event::DatagramReadable(c) if self.current(c) => self.udp_inbound(cx, c),
            Event::StreamWritable(s) if self.ctrl_of(s) => {
                let ctrl = self.conn.as_mut().and_then(|c| c.ctrl.as_mut());
                let ctrl = ctrl.expect("ctrl_of");
                if !app_stream::flush(cx, s, &mut ctrl.tx, false) {
                    self.close(cx);
                }
            }
            Event::StreamWritable(s) if self.sess.by_stream.contains_key(&s) => {
                self.session_writable(cx, s)
            }
            Event::StreamWritable(s) => {
                if let Some(o) = self.opens.get_mut(&s)
                    && !app_stream::flush(cx, s, &mut o.tx, false)
                {
                    let o = self.opens.remove(&s).expect("present");
                    refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
                    cx.stream_reset(s);
                }
            }
            Event::StreamClosed(s) if self.ctrl_of(s) => {
                log::warn!("mq_client: control stream closed");
                self.close(cx);
            }
            // SP2 spec §6.4: the facade released it; nothing to reset.
            Event::StreamClosed(s) if self.sess.by_stream.contains_key(&s) => {
                let sid = self.sess.by_stream[&s];
                self.end_session(cx, sid, SessionEnd::Closed, false);
            }
            Event::StreamClosed(s) => {
                // spec §6.2: closed before the response → CONN_REFUSED, as in C.
                if let Some(o) = self.opens.remove(&s) {
                    refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
                    cx.stream_reset(s);
                }
            }
            _ => {} // events for a stale connection
        }
    }

    fn on_accepted(&mut self, cx: &mut Cx<'_>, l: ListenerTag, tcp: TcpId, meta: AcceptMeta) {
        if l == FETCH
            && let Some(g) = self.gw.as_mut()
        {
            return g.on_accepted(cx, tcp, meta);
        }
        let Some(kind) = kind_of(l) else {
            return cx.tcp_close(tcp);
        };
        // spec §6.1/§6.2: the 8 KiB parse cap; a pending request then holds
        // at most 8 KiB of preread, the rest waits in the kernel for the relay.
        cx.tcp_set_rx_limit(tcp, INGRESS_CAP);
        if kind == IngressKind::Transparent {
            // spec §6.1: the target is the original destination, IPv4 only.
            return match target_from_original_dst(&meta) {
                Some(t) => {
                    cx.tcp_set_read(tcp, false);
                    self.request(cx, tcp, kind, t);
                }
                None => {
                    log::warn!("mq_client: no IPv4 original destination; closing");
                    cx.tcp_close(tcp);
                }
            };
        }
        let timer = self.timer(cx, self.cfg.ingress_deadline, Tm::Ingress(tcp));
        let ing = Ingress::new(kind, timer, meta).expect("not transparent");
        self.ingress.insert(tcp, ing);
    }

    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if let Some(g) = self.gw.as_mut().filter(|g| g.owns_tcp(tcp)) {
            return g.on_tcp_data(cx, tcp);
        }
        if self.assocs.contains_key(&tcp) {
            return discard(cx, tcp);
        }
        let udp = self.udp != UdpAvail::Unavailable && !self.shutting_down;
        let Some(ing) = self.ingress.get_mut(&tcp) else {
            return; // read interest is off once the request is complete
        };
        let fed = ing.feed(cx, tcp, udp);
        if matches!(fed, Fed::Wait) {
            return;
        }
        let ing = self.ingress.remove(&tcp).expect("present");
        self.cancel(cx, ing.timer);
        match fed {
            Fed::Done(target) => self.request(cx, tcp, ing.kind, target),
            Fed::Associate => self.associate(cx, tcp, ing.meta),
            Fed::Wait | Fed::Closed => {}
        }
    }

    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        if let Some(g) = self.gw.as_mut().filter(|g| g.owns_tcp(tcp)) {
            return g.on_tcp_end(cx, tcp, end);
        }
        if let Some(ing) = self.ingress.remove(&tcp) {
            self.cancel(cx, ing.timer);
            if end == TcpEnd::ReadEof {
                cx.tcp_close(tcp); // the request can no longer complete
            }
            return;
        }
        // SP2 spec §6.1: the control connection's end is the association's (RFC 1928 §7).
        if self.assocs.contains_key(&tcp) {
            self.end_assoc(cx, tcp);
            if end == TcpEnd::ReadEof {
                cx.tcp_close(tcp);
            }
            return;
        }
        match end {
            // spec §6.2: a pending request that read EOF stays pending (the shard keeps the EOF).
            TcpEnd::ReadEof => {}
            TcpEnd::Error(_) => {
                self.pending.remove(&tcp);
                // spec §6.2: a socket error while the open is in flight resets the stream.
                let s = self
                    .opens
                    .iter()
                    .find(|(_, o)| o.tcp == tcp)
                    .map(|(s, _)| *s);
                if let Some(s) = s {
                    self.opens.remove(&s);
                    cx.stream_reset(s);
                }
            }
        }
    }

    fn on_tcp_writable(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if let Some(g) = self.gw.as_mut().filter(|g| g.owns_tcp(tcp)) {
            g.on_tcp_writable(cx, tcp);
        }
    }

    fn on_dial_result(&mut self, _cx: &mut Cx<'_>, _op: DialOpId, _r: Result<TcpId, DialError>) {
        // The client never dials.
    }

    fn on_resolve_result(
        &mut self,
        _cx: &mut Cx<'_>,
        op: DialOpId,
        _r: Result<SocketAddr, DialError>,
    ) {
        // The client never resolves.
        log::debug!("mq_client: unexpected resolve result {op:?}");
    }

    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        let assoc = self.assocs.iter_mut().find(|(_, a)| a.open_op == Some(op));
        let Some((&tcp, a)) = assoc else {
            // SP3 spec §5.7: the raw tunnel's paths first, then the gateway's;
            // an op owned by neither is closed by the raw `Paths`.
            if !self.paths.owns(op)
                && let Some(g) = self.gw.as_mut()
                && g.on_udp_socket(cx, op, r)
            {
                return;
            }
            let conn = self.conn.as_ref().filter(|c| !c.closing).map(|c| c.id);
            return self.paths.on_udp_socket(cx, conn, op, r);
        };
        // SP2 spec §6.1: the ASSOCIATE reply.
        a.open_op = None;
        match r {
            Ok((sock, local)) => {
                a.sock = Some(sock);
                let _ = cx.tcp_write(tcp, &socks5_assoc_reply(local));
            }
            Err(k) => {
                log::warn!("mq_client: cannot open the UDP socket of an association: {k}");
                self.assocs.remove(&tcp);
                refuse(cx, tcp, IngressKind::Socks5, TcpErr::Ok); // REP 0x01
            }
        }
    }

    fn on_udp_rx(&mut self, cx: &mut Cx<'_>, sock: UdpSocketId, peer: SocketAddr, d: &[u8]) {
        // ponytail: linear in associations; index them by socket if a client holds many.
        let assoc = self.assocs.iter_mut().find(|(_, a)| a.sock == Some(sock));
        // SP2 spec §6.3: the source check, then the sessions.
        if let Some((&tcp, a)) = assoc
            && a.accept_source(peer)
        {
            self.udp_outbound(cx, tcp, d);
        }
    }

    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        let Some(tm) = self.timers.remove(&id) else {
            // SP3 spec §5.8: not the client's own; the gateway's, if anyone's.
            if let Some(g) = self.gw.as_mut() {
                g.on_timer(cx, id);
            }
            return;
        };
        match tm {
            Tm::Auth => {
                if let Some(c) = self.conn.as_mut() {
                    c.auth_timer = None;
                }
                log::warn!("mq_client: no AUTH_RESPONSE within the auth deadline");
                self.close(cx);
            }
            Tm::Reconnect => {
                self.reconnect = None;
                self.connect(cx);
            }
            Tm::Metrics => {
                if let Some(every) = self.cfg.metrics_interval {
                    self.timer(cx, every, Tm::Metrics);
                }
                // spec §6.5: nothing without a connection, as C `cli_metrics_tick`;
                // SP3 spec §5.7: then the gateway tunnel's block.
                self.dump_metrics(cx);
                if let Some(g) = self.gw.as_ref() {
                    g.dump_metrics(cx);
                }
            }
            Tm::Ingress(tcp) => {
                if self.ingress.remove(&tcp).is_some() {
                    log::info!("mq_client: ingress request not complete in time; closing");
                    cx.tcp_close(tcp);
                }
            }
            Tm::Pending => {
                for o in self.pending.expire(cx.now()) {
                    refuse(cx, o.tcp, o.kind, TcpErr::Timeout);
                }
            }
            Tm::UdpResp(sid) => {
                log::warn!("mq_udp_cli: session {sid}: no UDP_SESSION_RESP in time");
                self.end_session(cx, sid, SessionEnd::Closed, true);
            }
        }
    }

    /// spec §6.6: dump the `mq.path` lines, stop accepting, close; exit 0 at `ConnClosed`.
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        cx.set_accepting(false);
        // SP2 spec §6.4: associations close like a control-socket EOF.
        self.set_udp(cx, UdpAvail::Unavailable);
        if let Some(t) = self.reconnect.take() {
            self.cancel(cx, t);
        }
        self.dump_metrics(cx);
        self.close(cx);
        if let Some(g) = self.gw.as_mut() {
            g.on_shutdown(cx);
        }
        // SP3 spec §5.9: replaces the early exit for "no raw conn".
        self.maybe_exit(cx);
    }
}
