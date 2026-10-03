//! spec §6.3: the server — per connection a control stream (auth), then data
//! streams that each carry one `CONNECT_TCP_REQUEST`, dial the origin and hand
//! off to a relay. Every stream the app holds follows the app-owned stream
//! rule (spec §5.4): each `StreamReadable` is answered with `stream_recv`.
//!
//! ```text
//! control:  Authing ──ok──→ Settled            (drained; Reset/Closed → close conn)
//!              └──bad/malformed──→ Refused      (ERROR+FIN, close conn after 1 s)
//!
//! data:     Request ──req──→ Dialling ──Ok(tcp)──→ Responding ──sent──→ relay (released)
//!              │                 │      └─Err(e)──→ Retiring (ERROR+FIN, drained)
//!              └──── Reset / StreamClosed / deadline / malformed → stream_reset (released)
//! ```
//! A `UDP_SESSION_OPEN` (type 0x02) takes the stream to `udp_session.rs` (SP2 spec §7.1).
//! Each held stream (control included) takes one of the connection's 4096
//! budget entries until it is released; relaying streams take none.

mod udp_session;

use crate::app_stream::{self, CHUNK, Recv};
use crate::config::ServerConfig;
use crate::metrics::format_metrics;
use crate::udp::preopen::PreOpen;
use crate::udp::send::MssCache;
use crate::udp::{Counters, host_of};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, RELAY_BUF, SocketOpId, StreamPreread,
    Target, TcpEnd, TcpId, TimerId, UdpSocketId,
};
use mq_transport_api::{ConnId, Event, StreamId, StreamInfo, StreamKind};
use mq_wire::frames::{
    AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp, DecodeError, FEAT_UDP_RELAY, MAX_FRAME,
    STATUS_ERROR, STATUS_OK, STREAM_TYPE_CONNECT_TCP, STREAM_TYPE_UDP_SESSION, TcpErr,
    UdpSessionOpen,
};
use mq_wire::varint;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;
use udp_session::SrvSession;

/// spec §6.3 "Auth accepted": as C `MQ_SERVER_ID`.
const SERVER_ID: &[u8] = b"mqproxy-server";
/// spec §6.3: the wire limit of `auth_token` (C `char[256]`).
const MAX_TOKEN: usize = 255;
/// spec §6.3: app-held streams per connection, control included.
const STREAM_BUDGET: usize = 4096;
/// spec §6.3: request and auth buffers.
const REQ_BUF: usize = 1024;
/// spec §6.3 "Auth refused": time for the response to be delivered.
const REFUSED_CLOSE: Duration = Duration::from_secs(1);

/// What an app timer is for.
#[derive(Copy, Clone, Debug)]
enum Tm {
    /// The auth deadline, or the delayed close after a refusal.
    Conn(ConnId),
    Request(StreamId),
    Metrics,
    /// SP2 spec §7.2: a UDP session's idle timer (sids are per connection).
    UdpIdle(ConnId, u32),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CtrlSt {
    Authing,
    Settled,
    Refused,
}

/// spec §6.3: the control stream (QUIC stream id 0).
struct Ctrl {
    s: StreamId,
    st: CtrlSt,
    /// `AUTH_REQUEST` bytes so far.
    rx: Vec<u8>,
    /// Unsent rest of `AUTH_RESPONSE`, and whether it ends with FIN.
    tx: Vec<u8>,
    fin: bool,
}

struct Conn {
    ctrl: Option<Ctrl>,
    /// Auth deadline, then (after a refusal) the delayed close.
    timer: Option<TimerId>,
    /// spec §6.3: budget entries in use.
    held: usize,
    closing: bool,
    /// SP2 spec §7.1: admitted UDP sessions by sid, at most 1024.
    udp: HashMap<u32, SrvSession>,
    /// SP2 spec §7.2: datagrams for sids not yet `Live`.
    preopen: PreOpen,
    /// SP2 spec §5: the connection's datagram MSS reading.
    mss: MssCache,
    /// SP2 spec §7.3: this connection's UDP counters.
    counters: Counters,
}

impl Conn {
    fn authed(&self) -> bool {
        self.ctrl.as_ref().is_some_and(|c| c.st == CtrlSt::Settled)
    }
}

/// spec §6.3: the phases of an app-held data stream.
#[derive(Copy, Clone, Debug)]
enum Phase {
    /// Awaiting the `CONNECT_TCP_REQUEST` (1 KiB, 10 s).
    Request(TimerId),
    Dialling(DialOpId),
    /// The OK response is not yet fully accepted.
    Responding(TcpId),
    /// The error response was sent with FIN; held until the peer finishes.
    Retiring,
    /// SP2 spec §7.1: the stream of the connection's UDP session `sid`.
    Udp(u32),
}

struct Data {
    conn: ConnId,
    phase: Phase,
    /// The request so far, then the early payload (preread, at most `RELAY_BUF`).
    rx: Vec<u8>,
    /// The peer's FIN was read.
    fin: bool,
    /// Unsent rest of the response.
    tx: Vec<u8>,
}

/// The parsed request.
enum Parsed {
    Wait,
    Bad,
    /// A request whose target cannot be dialled: answered, not reset (as C).
    Undialable(usize),
    Dial(usize, Target),
    /// SP2 spec §7.1: `UDP_SESSION_OPEN` — sid, target (`None`: undialable,
    /// answered `DnsFailed` after the other gates), requested idle (ms).
    UdpOpen(u32, Option<Target>, u64),
}

/// spec §6.3: the server app.
pub struct Server {
    cfg: ServerConfig,
    token: Vec<u8>,
    conns: HashMap<ConnId, Conn>,
    data: HashMap<StreamId, Data>,
    dials: HashMap<DialOpId, StreamId>,
    /// SP2 spec §7.1: in-flight resolves and socket opens of UDP sessions.
    resolves: HashMap<DialOpId, (ConnId, u32)>,
    socket_opens: HashMap<SocketOpId, (ConnId, u32)>,
    /// SP2 spec §7.2: the socket of each `Live` session.
    udp_socks: HashMap<UdpSocketId, (ConnId, u32)>,
    /// SP2 spec §7.2: the `datagram_recv` scratch.
    rx: Vec<u8>,
    timers: HashMap<TimerId, Tm>,
    /// spec §6.5: the most recently accepted connection (C `last_conn`).
    active: Option<ConnId>,
    auth_attempts: u64,
    shutting_down: bool,
}

/// spec §6.3: `CONNECT_TCP_RESPONSE`, no message.
fn tcp_resp(status: u8, e: TcpErr) -> Vec<u8> {
    let mut b = vec![0u8; MAX_FRAME];
    let n = ConnectTcpResp {
        status,
        error_code: e as u64,
        message: b"",
    }
    .encode(&mut b)
    .expect("fits");
    b.truncate(n);
    b
}

/// spec §6.3 dial error table (C `srv_map_errno` maps unclassified errors to CONN_REFUSED).
fn map_dial_error(e: DialError) -> TcpErr {
    match e {
        DialError::Dns => TcpErr::DnsFailed,
        DialError::Refused | DialError::Other => TcpErr::ConnRefused,
        DialError::Timeout => TcpErr::Timeout,
        DialError::Limit => TcpErr::PolicyDenied,
    }
}

/// spec §6.3: stream type then `CONNECT_TCP_REQUEST` (or, SP2 spec §7.1,
/// `UDP_SESSION_OPEN`), as C `srv_data_header_readable`.
fn parse_request(buf: &[u8], fin: bool) -> Parsed {
    // spec §6.2: a header (discriminator + frame) over 512 bytes never fits
    // C's 512-byte frame buffer, complete or not.
    let wait = if fin || buf.len() >= MAX_FRAME {
        Parsed::Bad
    } else {
        Parsed::Wait
    };
    let Ok((ty, tl)) = varint::decode(buf) else {
        return wait;
    };
    match ty {
        STREAM_TYPE_CONNECT_TCP => {
            let (req, used) = match ConnectTcpReq::decode(&buf[tl..]) {
                Ok((r, used)) if tl + used <= MAX_FRAME => (r, tl + used),
                Err(DecodeError::Short) => return wait,
                _ => return Parsed::Bad,
            };
            // C `srv_resolve_target`: a wrong address length or an unusable name is DNS_FAILED.
            match host_of(req.address_type, req.host) {
                Some(host) => Parsed::Dial(
                    used,
                    Target {
                        host,
                        port: req.port,
                    },
                ),
                None => Parsed::Undialable(used),
            }
        }
        STREAM_TYPE_UDP_SESSION => {
            let o = match UdpSessionOpen::decode(&buf[tl..]) {
                Ok((o, used)) if tl + used <= MAX_FRAME => o,
                Err(DecodeError::Short) => return wait,
                _ => return Parsed::Bad,
            };
            let target = host_of(o.address_type, o.host).map(|host| Target { host, port: o.port });
            Parsed::UdpOpen(o.session_id, target, o.idle_timeout_ms)
        }
        _ => Parsed::Bad,
    }
}

impl Server {
    /// spec §6.3: the configured token is truncated to 255 bytes with a warning.
    pub fn new(cfg: ServerConfig) -> Server {
        let t = cfg.token.as_bytes();
        if t.len() > MAX_TOKEN {
            log::warn!("mq_server: --token is longer than {MAX_TOKEN} bytes; truncated");
        }
        Server {
            token: t[..t.len().min(MAX_TOKEN)].to_vec(),
            conns: HashMap::new(),
            data: HashMap::new(),
            dials: HashMap::new(),
            resolves: HashMap::new(),
            socket_opens: HashMap::new(),
            udp_socks: HashMap::new(),
            rx: Vec::new(),
            timers: HashMap::new(),
            active: None,
            auth_attempts: 0,
            shutting_down: false,
            cfg,
        }
    }

    /// Complete `AUTH_REQUEST`s seen (C `auth_attempts`), malformed ones included.
    #[cfg(feature = "test-support")]
    pub fn auth_attempts(&self) -> u64 {
        self.auth_attempts
    }

    /// spec §6.5: the most recently accepted connection, while it is open.
    #[cfg(feature = "test-support")]
    pub fn active_conn(&self) -> Option<ConnId> {
        self.active
    }

    /// spec §6.3: stream-budget entries `c` holds (control stream included).
    #[cfg(feature = "test-support")]
    pub fn held(&self, c: ConnId) -> Option<usize> {
        self.conns.get(&c).map(|k| k.held)
    }

    fn timer(&mut self, cx: &mut Cx<'_>, after: Duration, tm: Tm) -> TimerId {
        let id = cx.set_timer(after);
        self.timers.insert(id, tm);
        id
    }

    fn cancel(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        cx.cancel_timer(id);
        self.timers.remove(&id);
    }

    /// Close a connection once; `ConnClosed` follows.
    fn close(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        let Some(conn) = self.conns.get_mut(&c).filter(|k| !k.closing) else {
            return;
        };
        conn.closing = true;
        if let Some(t) = conn.timer.take() {
            self.cancel(cx, t);
        }
        cx.close_conn(c);
    }

    /// The connection whose control stream is `s`.
    fn ctrl_conn(&self, s: StreamId) -> Option<ConnId> {
        self.conns
            .iter()
            .find(|(_, k)| k.ctrl.as_ref().is_some_and(|x| x.s == s))
            .map(|(c, _)| *c)
    }

    fn on_new_conn(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        // spec §6.3 auth deadline: from NewConn.
        let timer = self.timer(cx, self.cfg.auth_deadline, Tm::Conn(c));
        self.conns.insert(
            c,
            Conn {
                ctrl: None,
                timer: Some(timer),
                held: 0,
                closing: false,
                udp: HashMap::new(),
                preopen: PreOpen::default(),
                mss: MssCache::new(),
                counters: Counters::default(),
            },
        );
        // spec §6.5: C sets `last_conn` at acceptance, before auth.
        self.active = Some(c);
        if self.shutting_down {
            self.close(cx, c);
        }
    }

    fn on_conn_closed(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        if !self.conns.contains_key(&c) {
            return;
        }
        let gone: Vec<StreamId> = self
            .data
            .iter()
            .filter(|(_, d)| d.conn == c)
            .map(|(s, _)| *s)
            .collect();
        for s in gone {
            // The streams died with the connection: no reset. Before the
            // connection goes: a UDP session's end needs its table.
            self.drop_data(cx, s, false);
        }
        let conn = self.conns.remove(&c).expect("present");
        // SP2 spec §7.3: once per connection, after its sessions were reaped.
        udp_session::log_stats(&conn.counters);
        if let Some(t) = conn.timer {
            self.cancel(cx, t);
        }
        if self.active == Some(c) {
            self.active = None;
        }
        if self.shutting_down && self.conns.is_empty() {
            cx.request_exit(0);
        }
    }

    /// spec §6.3: control stream, data stream, or reset.
    fn on_new_stream(&mut self, cx: &mut Cx<'_>, c: ConnId, s: StreamId, info: StreamInfo) {
        let Some(conn) = self.conns.get_mut(&c).filter(|k| !k.closing) else {
            return cx.stream_reset(s);
        };
        if info.kind == StreamKind::Uni {
            return cx.stream_reset(s); // the protocol has none
        }
        if info.quic_id == 0 && conn.ctrl.is_none() {
            conn.held += 1;
            conn.ctrl = Some(Ctrl {
                s,
                st: CtrlSt::Authing,
                rx: Vec::new(),
                tx: Vec::new(),
                fin: false,
            });
            return;
        }
        if !conn.authed() || conn.held >= STREAM_BUDGET {
            return cx.stream_reset(s);
        }
        conn.held += 1;
        let t = self.timer(cx, self.cfg.request_deadline, Tm::Request(s));
        self.data.insert(
            s,
            Data {
                conn: c,
                phase: Phase::Request(t),
                rx: Vec::new(),
                fin: false,
                tx: Vec::new(),
            },
        );
    }

    /// spec §6.3 Auth; after it the control stream is drained (§5.4).
    fn ctrl_readable(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        let conn = self.conns.get_mut(&c).expect("ctrl_conn");
        let ctrl = conn.ctrl.as_mut().expect("ctrl_conn");
        let s = ctrl.s;
        if ctrl.st != CtrlSt::Authing {
            if !app_stream::drain(cx, s) {
                log::warn!("mq_server: control stream reset");
                self.close(cx, c);
            }
            return;
        }
        let ok = loop {
            let cap = REQ_BUF - ctrl.rx.len();
            match app_stream::recv(cx, s, &mut ctrl.rx, cap) {
                Recv::Blocked => return,
                Recv::Failed => {
                    log::warn!("mq_server: control stream reset before AUTH_REQUEST");
                    return self.close(cx, c);
                }
                Recv::Data { n, fin } => match AuthReq::decode(&ctrl.rx) {
                    // spec §6.3: constant-time compare against the truncated token.
                    Ok((r, used)) if used <= MAX_FRAME => {
                        break bool::from(r.auth_token.ct_eq(&self.token));
                    }
                    // spec §6.2: frames are at most 512 bytes, complete or not.
                    Err(DecodeError::Short) if !fin && ctrl.rx.len() < MAX_FRAME => {
                        if n == 0 {
                            return;
                        }
                    }
                    Ok(_) | Err(_) => {
                        log::warn!("mq_server: AUTH_REQUEST malformed/oversized, rejecting");
                        break false;
                    }
                },
            }
        };
        self.auth_attempts += 1;
        let mut tx = vec![0u8; MAX_FRAME];
        let n = AuthResp {
            status: if ok { STATUS_OK } else { STATUS_ERROR },
            error_code: u64::from(!ok), // AUTH_FAILED
            server_id: SERVER_ID,
            // spec §7.3: as C, only an accepted auth advertises the capability.
            features: if ok && self.cfg.udp_enabled {
                FEAT_UDP_RELAY
            } else {
                0
            },
        }
        .encode(&mut tx)
        .expect("fits");
        tx.truncate(n);
        ctrl.rx = Vec::new();
        ctrl.tx = tx;
        ctrl.fin = !ok;
        ctrl.st = if ok { CtrlSt::Settled } else { CtrlSt::Refused };
        let flushed = app_stream::flush(cx, s, &mut ctrl.tx, ctrl.fin);
        if let Some(t) = conn.timer.take() {
            self.cancel(cx, t);
        }
        if ok {
            log::info!("mq_server: auth OK");
        } else {
            // spec §6.3 "Auth refused": FIN, then close 1 s later.
            log::warn!("mq_server: auth FAILED");
            let t = self.timer(cx, REFUSED_CLOSE, Tm::Conn(c));
            self.conns.get_mut(&c).expect("present").timer = Some(t);
        }
        if !flushed {
            return self.close(cx, c);
        }
        self.ctrl_readable(cx, c); // drain whatever followed
    }

    /// spec §6.3/§5.4: every app-held phase answers `StreamReadable` with `stream_recv`.
    fn data_readable(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        loop {
            let Some(d) = self.data.get_mut(&s) else {
                return;
            };
            let r = match d.phase {
                Phase::Retiring => {
                    if !app_stream::drain(cx, s) {
                        self.drop_data(cx, s, false);
                    }
                    return;
                }
                Phase::Request(_) => {
                    let cap = REQ_BUF - d.rx.len();
                    app_stream::recv(cx, s, &mut d.rx, cap)
                }
                // Early payload; once full (or after FIN) only zero-capacity probes.
                Phase::Dialling(_) | Phase::Responding(_) => {
                    let cap = if d.fin {
                        0
                    } else {
                        CHUNK.min(RELAY_BUF - d.rx.len())
                    };
                    app_stream::recv(cx, s, &mut d.rx, cap)
                }
                // SP2 spec §5 "Reading a session stream": bytes are discarded.
                Phase::Udp(_) => {
                    d.rx.clear();
                    app_stream::recv(cx, s, &mut d.rx, CHUNK)
                }
            };
            let (n, fin) = match r {
                Recv::Blocked => return,
                Recv::Failed => return self.drop_data(cx, s, false), // reset by `recv`
                Recv::Data { n, fin } => (n, fin),
            };
            d.fin |= fin;
            if let Phase::Udp(_) = d.phase
                && fin
            {
                return self.drop_data(cx, s, true); // SP2 spec §7.1: the client ended it
            }
            if let Phase::Request(_) = d.phase {
                match parse_request(&d.rx, d.fin) {
                    Parsed::Wait => {}
                    Parsed::Bad => {
                        log::warn!("mq_server: data stream request malformed/oversized, resetting");
                        return self.drop_data(cx, s, true);
                    }
                    Parsed::Undialable(used) => {
                        d.rx.drain(..used);
                        self.respond_error(cx, s, tcp_resp(STATUS_ERROR, TcpErr::DnsFailed));
                        continue;
                    }
                    Parsed::Dial(used, target) => {
                        d.rx.drain(..used);
                        self.dial(cx, s, target);
                        continue;
                    }
                    // SP2 spec §7.1: a client never sends FIN with its OPEN.
                    Parsed::UdpOpen(..) if d.fin => {
                        log::warn!("mq_udp_srv: UDP_SESSION_OPEN with FIN, resetting");
                        return self.drop_data(cx, s, true);
                    }
                    Parsed::UdpOpen(sid, target, idle) => {
                        self.udp_open(cx, s, sid, target, idle);
                        continue;
                    }
                }
            }
            if n == 0 || fin {
                return;
            }
        }
    }

    fn dial(&mut self, cx: &mut Cx<'_>, s: StreamId, target: Target) {
        let op = cx.dial(target, self.cfg.dial_deadline);
        self.dials.insert(op, s);
        let d = self.data.get_mut(&s).expect("present");
        if let Phase::Request(t) = std::mem::replace(&mut d.phase, Phase::Dialling(op)) {
            self.cancel(cx, t);
        }
    }

    /// spec §6.3: error response with FIN, never followed by a reset; the
    /// stream retires. SP2 spec §7.1: a UDP session's error RESP too.
    fn respond_error(&mut self, cx: &mut Cx<'_>, s: StreamId, resp: Vec<u8>) {
        let d = self.data.get_mut(&s).expect("present");
        if let Phase::Request(t) = std::mem::replace(&mut d.phase, Phase::Retiring) {
            self.cancel(cx, t);
        }
        let d = self.data.get_mut(&s).expect("present");
        d.rx = Vec::new();
        d.tx = resp;
        if !app_stream::flush(cx, s, &mut d.tx, true) {
            self.drop_data(cx, s, true);
        }
    }

    /// spec §6.3: the OK response must be accepted in full before the relay starts.
    fn send_ok(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let d = self.data.get_mut(&s).expect("present");
        let Phase::Responding(tcp) = d.phase else {
            return;
        };
        if !app_stream::flush(cx, s, &mut d.tx, false) {
            return self.drop_data(cx, s, true);
        }
        if !d.tx.is_empty() {
            return; // the rest on StreamWritable
        }
        let d = self.release(s).expect("present");
        let preread = StreamPreread {
            bytes: &d.rx,
            fin: d.fin,
        };
        if cx.start_relay(tcp, s, preread).is_err() {
            log::error!("mq_server: begin relay failed");
            cx.tcp_abort(tcp);
            cx.stream_reset(s);
        }
    }

    /// Remove a data stream and return its budget entry.
    fn release(&mut self, s: StreamId) -> Option<Data> {
        let d = self.data.remove(&s)?;
        if let Some(c) = self.conns.get_mut(&d.conn) {
            c.held -= 1;
        }
        Some(d)
    }

    /// spec §6.3: end an app-held data stream — cancel its timer or dial,
    /// dispose of its socket, optionally reset it, release its entry.
    fn drop_data(&mut self, cx: &mut Cx<'_>, s: StreamId, reset: bool) {
        let Some(d) = self.release(s) else {
            return;
        };
        match d.phase {
            Phase::Request(t) => self.cancel(cx, t),
            Phase::Dialling(op) => {
                self.dials.remove(&op);
                cx.cancel_dial(op);
            }
            Phase::Responding(tcp) => cx.tcp_abort(tcp),
            Phase::Retiring => {}
            Phase::Udp(sid) => self.end_session(cx, d.conn, sid),
        }
        if reset {
            cx.stream_reset(s);
        }
    }

    fn on_writable(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        if let Some(d) = self.data.get_mut(&s) {
            match d.phase {
                Phase::Responding(_) => self.send_ok(cx, s),
                Phase::Retiring if !app_stream::flush(cx, s, &mut d.tx, true) => {
                    self.drop_data(cx, s, true);
                }
                // SP2 spec §7.1: the rest of the RESP OK; a failure reaps.
                Phase::Udp(_) if !app_stream::flush(cx, s, &mut d.tx, false) => {
                    self.drop_data(cx, s, true);
                }
                _ => {}
            }
        } else if let Some(c) = self.ctrl_conn(s) {
            let ctrl = self.conns.get_mut(&c).and_then(|k| k.ctrl.as_mut());
            let ctrl = ctrl.expect("ctrl_conn");
            if !app_stream::flush(cx, s, &mut ctrl.tx, ctrl.fin) {
                self.close(cx, c);
            }
        }
    }

    /// spec §6.5: the lines of the most recently accepted connection, if open.
    fn dump_metrics(&self, cx: &Cx<'_>) {
        if let Some(st) = self.active.and_then(|c| cx.conn_stats(c).ok()) {
            for l in format_metrics(Some(&st)) {
                log::info!("{l}");
            }
        }
    }
}

impl App for Server {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        if let Some(every) = self.cfg.metrics_interval {
            self.timer(cx, every, Tm::Metrics);
        }
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::NewConn(c, _) => self.on_new_conn(cx, c),
            Event::ConnClosed(c, _) => self.on_conn_closed(cx, c),
            Event::NewStream(c, s, info) => self.on_new_stream(cx, c, s, info),
            Event::StreamReadable(s) if self.data.contains_key(&s) => self.data_readable(cx, s),
            Event::StreamReadable(s) => {
                if let Some(c) = self.ctrl_conn(s) {
                    self.ctrl_readable(cx, c);
                }
            }
            Event::StreamWritable(s) => self.on_writable(cx, s),
            Event::StreamClosed(s) if self.data.contains_key(&s) => self.drop_data(cx, s, true),
            Event::StreamClosed(s) => {
                if let Some(c) = self.ctrl_conn(s) {
                    log::warn!("mq_server: control stream closed");
                    self.close(cx, c);
                }
            }
            // Client-only events.
            Event::ConnEstablished(_) | Event::MpReady(_) => {}
            Event::DatagramReadable(c) => self.udp_inbound(cx, c),
            // H3 requests are handled from Task 6.x on (spec §6).
            Event::H3Request(..)
            | Event::H3Readable(_)
            | Event::H3Writable(_)
            | Event::H3Closed(..) => {}
        }
    }

    fn on_accepted(&mut self, cx: &mut Cx<'_>, _l: ListenerTag, tcp: TcpId, _meta: AcceptMeta) {
        cx.tcp_close(tcp); // the server has no TCP listeners in SP1
    }

    fn on_tcp_data(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId) {
        // A dialled socket is relayed (or aborted) as soon as its result arrives.
    }

    fn on_tcp_end(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId, _end: TcpEnd) {
        // spec §5.4: ReadEof is kept across start_relay; an Error while the OK
        // response is still being written leaves a dead id that start_relay rejects.
    }

    fn on_dial_result(&mut self, cx: &mut Cx<'_>, op: DialOpId, r: Result<TcpId, DialError>) {
        let Some(s) = self.dials.remove(&op) else {
            // Not wanted any more: dispose of a late socket.
            if let Ok(tcp) = r {
                cx.tcp_abort(tcp);
            }
            return;
        };
        match r {
            Ok(tcp) => {
                let d = self.data.get_mut(&s).expect("dialling stream");
                d.phase = Phase::Responding(tcp);
                d.tx = tcp_resp(STATUS_OK, TcpErr::Ok);
                self.send_ok(cx, s);
            }
            Err(e) => {
                log::warn!("mq_server: dial failed ({e:?})");
                self.respond_error(cx, s, tcp_resp(STATUS_ERROR, map_dial_error(e)));
            }
        }
    }

    fn on_resolve_result(
        &mut self,
        cx: &mut Cx<'_>,
        op: DialOpId,
        r: Result<SocketAddr, DialError>,
    ) {
        self.udp_resolved(cx, op, r);
    }

    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        // Only UDP session sockets: the server opens no path sockets.
        self.udp_socket(cx, op, r);
    }

    fn on_udp_rx(&mut self, cx: &mut Cx<'_>, sock: UdpSocketId, peer: SocketAddr, data: &[u8]) {
        self.udp_reply(cx, sock, peer, data);
    }

    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        let Some(tm) = self.timers.remove(&id) else {
            return;
        };
        match tm {
            Tm::Conn(c) => {
                let Some(conn) = self.conns.get_mut(&c) else {
                    return;
                };
                conn.timer = None;
                if !conn.ctrl.as_ref().is_some_and(|k| k.st == CtrlSt::Refused) {
                    log::warn!("mq_server: no AUTH_REQUEST within the auth deadline");
                }
                self.close(cx, c);
            }
            Tm::Request(s) => {
                log::info!("mq_server: no CONNECT_TCP_REQUEST in time, resetting");
                self.drop_data(cx, s, true);
            }
            Tm::Metrics => {
                if let Some(every) = self.cfg.metrics_interval {
                    self.timer(cx, every, Tm::Metrics);
                }
                // spec §6.5: silent without a connection, as C `srv_metrics_tick`.
                self.dump_metrics(cx);
            }
            Tm::UdpIdle(c, sid) => self.udp_idle(cx, c, sid),
        }
    }

    /// spec §6.6: close every connection; exit 0 once all reported `ConnClosed`.
    /// SP2 spec §7.2: it reaps nothing itself — each `ConnClosed` reaps that
    /// connection's UDP sessions and logs its stats line, once.
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        if self.conns.is_empty() {
            return cx.request_exit(0);
        }
        let all: Vec<ConnId> = self.conns.keys().copied().collect();
        for c in all {
            self.close(cx, c);
        }
    }
}
