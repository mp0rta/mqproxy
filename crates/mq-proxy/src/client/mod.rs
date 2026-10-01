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
mod ingress_glue;
mod paths;
pub mod pending;

use crate::app_stream::{self, CHUNK, Recv};
use crate::config::ClientConfig;
use crate::ingress::{INGRESS_CAP, target_from_original_dst};
use crate::metrics::format_metrics;
use backoff::Backoff;
use ingress_glue::{Fed, Ingress, kind_of};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, Host, ListenerTag, SocketOpId, StreamPreread, Target,
    TcpEnd, TcpId, TimerId, UdpSocketId,
};
use mq_transport_api::{ConnConfig, ConnId, Event, StreamId};
use mq_wire::frames::{
    AddrType, AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp, DecodeError, MAX_FRAME,
    STREAM_TYPE_CONNECT_TCP, TcpErr,
};
use paths::Paths;
use pending::{IngressKind, Pending, PendingOpen};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

/// spec §6.1: the listener tags the binary registers.
pub const SOCKS5: ListenerTag = ListenerTag(1);
pub const HTTP_CONNECT: ListenerTag = ListenerTag(2);
pub const TRANSPARENT: ListenerTag = ListenerTag(3);

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
}

/// spec §6.2: truncate to the wire limit with a warning (C truncates silently).
fn truncated(s: &str, max: usize, flag: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.len() > max {
        log::warn!("mq_client: {flag} is longer than {max} bytes; truncated");
    }
    b[..b.len().min(max)].to_vec()
}

/// spec §6.1: the ingress error reply (if any), then close.
fn refuse(cx: &mut Cx<'_>, tcp: TcpId, kind: IngressKind, e: TcpErr) {
    if let Some(b) = kind.error_reply(e) {
        let _ = cx.tcp_write(tcp, &b);
    }
    cx.tcp_close(tcp);
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
            paths: Paths::new(&cfg),
            timers: HashMap::new(),
            cfg,
        }
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
        let ok = loop {
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
                        break false;
                    }
                    Ok((r, _)) if r.is_ok() => break true,
                    Ok((r, _)) => {
                        log::warn!("mq_client: auth refused (error {})", r.error_code);
                        break false;
                    }
                    Err(DecodeError::Short) if !fin && ctrl.rx.len() < MAX_FRAME => {
                        if n == 0 {
                            return;
                        }
                    }
                    Err(_) => {
                        log::warn!("mq_client: AUTH_RESPONSE malformed");
                        break false;
                    }
                },
            }
        };
        if !ok {
            // spec §6.2 "Auth refused": pending requests fail, as in C.
            for o in self.pending.drain() {
                refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
            }
            return self.close(cx);
        }
        // Serving.
        conn.authed = true;
        ctrl.rx = Vec::new();
        let (id, timer) = (conn.id, conn.auth_timer.take());
        if let Some(t) = timer {
            self.cancel(cx, t);
        }
        self.backoff.on_serving(cx.now());
        log::info!("mq_client: authenticated");
        if !app_stream::drain(cx, s) {
            return self.close(cx);
        }
        for o in self.pending.drain() {
            self.open(cx, id, o.tcp, o.kind, &o.target);
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
        self.paths.on_conn_closed(cx);
        if self.shutting_down {
            return cx.request_exit(0);
        }
        if self.cfg.reconnect {
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
            for o in self.pending.drain() {
                refuse(cx, o.tcp, o.kind, TcpErr::ConnRefused);
            }
        }
    }

    /// spec §6.5: the `mq.conn` / `mq.path` lines of the held connection.
    fn dump_metrics(&self, cx: &Cx<'_>) {
        if let Some(st) = self.conn.as_ref().and_then(|c| cx.conn_stats(c.id).ok()) {
            for l in format_metrics(Some(&st)) {
                log::info!("{l}");
            }
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
        self.connect(cx);
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::ConnEstablished(c) if self.current(c) => self.on_established(cx),
            Event::ConnClosed(c, _) if self.current(c) => self.conn_gone(cx),
            Event::MpReady(c) if self.current(c) => self.paths.on_mp_ready(cx, c),
            // spec §6.2: the protocol has no server-initiated streams.
            Event::NewStream(_, s, _) => cx.stream_reset(s),
            Event::StreamReadable(s) if self.ctrl_of(s) => self.ctrl_readable(cx, s),
            Event::StreamReadable(s) => self.open_readable(cx, s),
            Event::StreamWritable(s) if self.ctrl_of(s) => {
                let ctrl = self.conn.as_mut().and_then(|c| c.ctrl.as_mut());
                let ctrl = ctrl.expect("ctrl_of");
                if !app_stream::flush(cx, s, &mut ctrl.tx, false) {
                    self.close(cx);
                }
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
        let ing = Ingress::new(kind, timer).expect("not transparent");
        self.ingress.insert(tcp, ing);
    }

    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(ing) = self.ingress.get_mut(&tcp) else {
            return; // read interest is off once the request is complete
        };
        let fed = ing.feed(cx, tcp);
        if matches!(fed, Fed::Wait) {
            return;
        }
        let ing = self.ingress.remove(&tcp).expect("present");
        self.cancel(cx, ing.timer);
        if let Fed::Done(target) = fed {
            self.request(cx, tcp, ing.kind, target);
        }
    }

    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        if let Some(ing) = self.ingress.remove(&tcp) {
            self.cancel(cx, ing.timer);
            if end == TcpEnd::ReadEof {
                cx.tcp_close(tcp); // the request can no longer complete
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

    fn on_dial_result(&mut self, _cx: &mut Cx<'_>, _op: DialOpId, _r: Result<TcpId, DialError>) {
        // The client never dials.
    }

    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        let conn = self.conn.as_ref().filter(|c| !c.closing).map(|c| c.id);
        self.paths.on_udp_socket(cx, conn, op, r);
    }

    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        let Some(tm) = self.timers.remove(&id) else {
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
                // spec §6.5: nothing without a connection, as C `cli_metrics_tick`.
                self.dump_metrics(cx);
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
        }
    }

    /// spec §6.6: dump the `mq.path` lines, stop accepting, close; exit 0 at `ConnClosed`.
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        cx.set_accepting(false);
        if let Some(t) = self.reconnect.take() {
            self.cancel(cx, t);
        }
        if self.conn.is_none() {
            return cx.request_exit(0);
        }
        self.dump_metrics(cx);
        self.close(cx);
    }
}
