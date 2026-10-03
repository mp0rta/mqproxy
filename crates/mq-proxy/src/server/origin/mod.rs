//! SP3 spec §7: the origin bridge — hyper 1.x client `conn` API + rustls,
//! polled from the shard with the `Dirty` waker and `ShardExec` (§7.1); no
//! tokio task or channel on the data path.

mod body;
mod errors;
mod events;
mod exec;
#[cfg(feature = "test-support")]
pub mod host;
mod key;
mod pipe;
mod request;
mod response;
pub mod tls;

pub use body::{UploadBody, UploadBuf};
pub use events::{Accepted, BridgeEvents};
pub use exec::Dirty;
use exec::ShardExec;
use pipe::{HyperIo, PipeHandle};
pub use tls::{TlsSetupError, build_client_config, install_ring, native_roots};

use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use mq_http::headers::{HttpVer, Method, status_from_curl};
use mq_runtime::{Cx, DialError, DialOpId, Target, TcpEnd, TcpId, TimerId};
use mq_transport_api::{H3ReqId, Time};
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(feature = "test-support")]
use std::collections::HashSet;
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// spec §8: the pinned hyper line (`hyper = "~1.10"`), for the startup log.
pub const HYPER_VERSION: &str = "1.10";
/// spec §7.1/§9.3: each direction of the pipe.
pub const PIPE_CAP: usize = 64 * 1024;
/// spec §6.3/§9.3: one request's `UploadBuf`.
pub const UPLOAD_CAP: usize = 256 * 1024;
/// spec §7.7: idle expiry (curl's default `MAXAGE_CONN`).
pub const IDLE_MAX: Duration = Duration::from_secs(118);
/// spec §7.7: the idle sweep interval.
pub const SWEEP: Duration = Duration::from_secs(10);
/// spec §7.3 step 4: pump iterations per callback.
pub const PUMP_CAP: usize = 16;
/// spec §7.3/§7.4: one `tcp_write` slice, one upload frame.
pub const SLICE: usize = 16 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

/// The negotiated protocol of an origin conn.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OriginProto {
    H1,
    H2,
}

impl OriginProto {
    /// The `mq.req` `origin_protocol` value.
    pub fn metric(self) -> &'static str {
        match self {
            OriginProto::H1 => "h1",
            OriginProto::H2 => "h2",
        }
    }
}

/// The request body as intake saw it (§6.2 step 8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Known(u64),
    Unknown,
}

/// A synchronous `start` failure → 502 `origin-start-failed` (§6.2 step 9).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartErr {
    BadAuthority,
    BadPath,
}

/// The bridge's timers (refinement of §6.7's `Tm::Origin*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OriginTimer {
    Connect(H3ReqId),
    Pump,
    Idle,
}

#[derive(Copy, Clone, Debug)]
pub struct OriginCfg {
    /// DNS + TCP + TLS under one deadline (§7.2 step 4).
    pub connect_timeout: Duration,
    /// `SWEEP` in production; tests use 200 ms.
    pub sweep: Duration,
}

pub struct StartReq {
    pub h3: H3ReqId,
    pub scheme: Scheme,
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
    pub method: Method,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub ver: HttpVer,
    pub body: BodyKind,
    pub upload: Rc<RefCell<UploadBuf>>,
}

/// The origin's response head, normalised (§7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayHead {
    pub status: u16,
    /// `http/1.0` | `http/1.1` | `h2`.
    pub version: &'static str,
    pub proto: OriginProto,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub content_encoding: Option<Vec<u8>>,
    pub cl: Option<u64>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlsOutcome {
    Ok,
    VerifyFail,
    ConnectFail,
    Na,
}

/// An origin failure, mapped per §7.6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginFailure {
    pub curl: u32,
    pub status: u16,
    pub tls: TlsOutcome,
    /// The negotiated version; `None` before negotiation (§6.6 logs
    /// `origin_protocol` for a transfer that failed after negotiating).
    pub proto: Option<OriginProto>,
    pub upstream_protocol: bool,
    pub start_failed: bool,
    /// For the §8 warn line.
    pub cause: String,
}

/// A transfer the origin completed (§6.6 inputs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub reused: bool,
    pub connect_ms: i64,
    pub tls: TlsOutcome,
    pub delivered: u64,
    pub cl: Option<u64>,
}

/// An origin conn's id: `index` into `Origin.conns`, valid while the slot's
/// generation equals `generation` (`gen` is reserved in edition 2024).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct OriginConnId {
    index: u32,
    generation: u32,
}

/// The own generational table (`mq_transport::Slots` is `pub(crate)` there).
/// A slot keeps its generation on removal, so a reused slot never
/// revalidates a stale id.
struct Conns<T>(Vec<(u32, Option<T>)>);

#[allow(dead_code)] // Tasks 5.2–5.6c
impl<T> Conns<T> {
    fn insert(&mut self, make: impl FnOnce(OriginConnId) -> T) -> OriginConnId {
        // ponytail: linear free-slot scan; a free list if conns ever number in the thousands.
        let index = match self.0.iter().position(|(_, c)| c.is_none()) {
            Some(i) => i,
            None => {
                self.0.push((0, None));
                self.0.len() - 1
            }
        };
        let slot = &mut self.0[index];
        slot.0 = slot.0.wrapping_add(1);
        let id = OriginConnId {
            index: index as u32,
            generation: slot.0,
        };
        slot.1 = Some(make(id));
        id
    }

    fn get(&self, id: OriginConnId) -> Option<&T> {
        match self.0.get(id.index as usize) {
            Some((g, Some(c))) if *g == id.generation => Some(c),
            _ => None,
        }
    }

    fn get_mut(&mut self, id: OriginConnId) -> Option<&mut T> {
        match self.0.get_mut(id.index as usize) {
            Some((g, Some(c))) if *g == id.generation => Some(c),
            _ => None,
        }
    }

    fn remove(&mut self, id: OriginConnId) -> Option<T> {
        match self.0.get_mut(id.index as usize) {
            Some((g, c)) if *g == id.generation => c.take(),
            _ => None,
        }
    }

    /// The live ids, a snapshot (the pump may remove conns while iterating).
    fn ids(&self) -> Vec<OriginConnId> {
        let live = self.0.iter().enumerate().filter(|(_, (_, c))| c.is_some());
        live.map(|(i, (g, _))| OriginConnId {
            index: i as u32,
            generation: *g,
        })
        .collect()
    }
}

impl<T> Default for Conns<T> {
    fn default() -> Self {
        Conns(Vec::new())
    }
}

/// The negotiated protocol is a property of the conn, not of the key (§7.1).
type ConnKey = (Scheme, String, u16);
/// Reusable conns by key, several per key (§7.7).
type Pool = HashMap<ConnKey, Vec<OriginConnId>>;

// The §7.1 state below is filled by Tasks 5.2–5.6c.

/// Where a request's record lives (§7.1 lookups).
#[allow(dead_code)] // Tasks 5.2–5.6c
#[derive(Copy, Clone, Debug)]
enum Where {
    Dial(DialOpId),
    Conn(OriginConnId),
}

type H1Conn = http1::Connection<HyperIo, UploadBody>;
type H2Conn = http2::Connection<HyperIo, UploadBody, ShardExec>;

/// The hyper handshake's result, either protocol.
#[allow(dead_code)] // Tasks 5.2–5.6c
enum Handshaked {
    H1(http1::SendRequest<UploadBody>, Pin<Box<H1Conn>>),
    H2(http2::SendRequest<UploadBody>, Pin<Box<H2Conn>>),
}

#[allow(dead_code)] // Tasks 5.2–5.6c
enum Driver {
    /// The TLS handshake runs through the socket; hyper's end of the pipe
    /// waits here for the hyper handshake (§7.2 step 4).
    Tls(HyperIo),
    Handshaking(Pin<Box<dyn Future<Output = hyper::Result<Handshaked>>>>),
    H1(Pin<Box<H1Conn>>),
    H2(Pin<Box<H2Conn>>),
    /// A completed `Connection` is never polled again (hyper's task is not fused).
    Completed,
}

#[allow(dead_code)] // Tasks 5.2–5.6c
enum Sender {
    H1(http1::SendRequest<UploadBody>),
    H2(http2::SendRequest<UploadBody>),
}

/// hyper's `TrySendError` has `pub(crate)` fields and no constructor: the
/// bridge maps it through `take_message()` + `into_error()`, and
/// `send_request`'s `hyper::Error` with `returned: None` (§7.1).
#[allow(dead_code)] // Tasks 5.2–5.6c
struct SendFailure {
    err: hyper::Error,
    returned: Option<Request<UploadBody>>,
}

type ResponseFut = Pin<Box<dyn Future<Output = Result<Response<Incoming>, SendFailure>>>>;

#[allow(dead_code)] // Tasks 5.2–5.6c
struct StoredRequest {
    method: Method,
    scheme: Scheme,
    authority: Vec<u8>,
    path: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Always present; bodiless = `fin && empty`.
    body: Rc<RefCell<UploadBuf>>,
}

#[allow(dead_code)] // Tasks 5.2–5.6c
enum ConnectingPayload {
    Stored(StoredRequest),
    /// Handed back by `try_send_request` (h1 retry), re-sent as is.
    Ready(Request<UploadBody>),
}

/// The bridge's record of a request's origin side (§7.1, §7.7). Owned by the
/// bridge — never by the gateway's `GwReq`: it outlives the `GwReq` removed
/// at `H3Closed` until hyper lets go of the body.
#[allow(dead_code)] // Tasks 5.2–5.6c
enum OriginReq {
    Connecting {
        h3: H3ReqId,
        key: ConnKey,
        /// Gives the ALPN list of the dial (§7.2 step 1).
        ver: HttpVer,
        started_at: Time,
        /// `OriginTimer::Connect`, armed at the dial result.
        timer: Option<TimerId>,
        payload: ConnectingPayload,
        retried: bool,
    },
    Assigned {
        h3: H3ReqId,
        fut: Option<ResponseFut>,
        body: Option<Incoming>,
        upload: Rc<RefCell<UploadBuf>>,
        /// `None` when assigned from `ConnectingPayload::Ready`.
        stored: Option<StoredRequest>,
        head_seen: bool,
        reused: bool,
        retried: bool,
        /// A `Partial` frame waits on the H3 side: no further body frame is
        /// polled until `Origin::resume` (§7.5).
        held: bool,
        /// Body bytes handed to `on_body_frame`.
        delivered: u64,
        /// The head's single numeric `content-length`.
        cl: Option<u64>,
    },
    /// Waits for `released`.
    Ended {
        upload: Rc<RefCell<UploadBuf>>,
        since: Time,
    },
}

#[allow(dead_code)] // Tasks 5.2–5.6c
struct OriginConn {
    id: OriginConnId,
    key: ConnKey,
    tcp: TcpId,
    tls: Option<rustls::ClientConnection>,
    io: PipeHandle,
    proto: Option<OriginProto>,
    driver: Driver,
    /// `Some` only in H1/H2.
    send: Option<Sender>,
    /// The `Connecting` requester while in `Tls`/`Handshaking` (§7.2).
    pending: Option<OriginReq>,
    /// `Assigned` / `Ended` records once the conn is up.
    reqs: Vec<OriginReq>,
    /// TLS ciphertext staging (§7.3).
    out: Vec<u8>,
    tcp_eof: bool,
    /// h1.
    busy: bool,
    /// h2 only: `Assigned` + `Ended`-unreleased records.
    active: u32,
    /// h2 (§7.7).
    draining: bool,
    idle_since: Option<Time>,
    connect_ms: i64,
    /// Test gate (5.1b `hold_public_poll`): pump step 2 skips the public
    /// `Connection` future but still polls the executor tasks.
    hold_public: bool,
}

#[allow(dead_code)] // Tasks 5.2–5.6c
pub struct Origin {
    cfg: OriginCfg,
    tls: Arc<rustls::ClientConfig>,
    dirty: Arc<Dirty>,
    exec: ShardExec,
    conns: Conns<OriginConn>,
    pool: Pool,
    /// Conns removed from the pool that still carry `Assigned` records (§7.7).
    closing: Vec<OriginConnId>,
    by_tcp: HashMap<TcpId, OriginConnId>,
    by_h3: HashMap<H3ReqId, Where>,
    /// `Connecting` records while dialling.
    dials: HashMap<DialOpId, OriginReq>,
    timers: HashMap<TimerId, OriginTimer>,
    idle_timer: Option<TimerId>,
    /// Conns whose pipe was marked dead, kept past their removal (`pipe_dead`).
    #[cfg(feature = "test-support")]
    dead_marked: HashSet<OriginConnId>,
}

impl Origin {
    pub fn new(cfg: OriginCfg, tls: Arc<rustls::ClientConfig>, dirty: Arc<Dirty>) -> Origin {
        Origin {
            cfg,
            tls,
            dirty,
            exec: ShardExec::default(),
            conns: Conns::default(),
            pool: Pool::new(),
            closing: Vec::new(),
            by_tcp: HashMap::new(),
            by_h3: HashMap::new(),
            dials: HashMap::new(),
            timers: HashMap::new(),
            idle_timer: None,
            #[cfg(feature = "test-support")]
            dead_marked: HashSet::new(),
        }
    }

    /// spec §7.7 "every removal": the conn's reads and writes fail from now on.
    fn mark_pipe_dead(&mut self, id: OriginConnId) {
        if let Some(c) = self.conns.get(id) {
            c.io.mark_dead();
            #[cfg(feature = "test-support")]
            self.dead_marked.insert(id);
        }
    }

    /// The only constructor of an `UploadBuf`: it carries the bridge's `Dirty` (§7.4).
    pub fn new_upload(&self, cl: Option<u64>) -> Rc<RefCell<UploadBuf>> {
        Rc::new(RefCell::new(UploadBuf::new(cl, self.dirty.clone())))
    }

    /// spec §7.2 steps 1 and 3 (the pool hit of step 2 is Task 5.5b). The
    /// authority passes the bridge's split and `http::uri::Authority`, which
    /// also rejects `"<>\^`, backtick, `{|}` and non-ASCII (§7.4, §12).
    pub fn start(&mut self, cx: &mut Cx<'_>, req: StartReq) -> Result<(), StartErr> {
        let (host, port) = key::split_authority(req.scheme, &req.authority)
            .map_err(|()| StartErr::BadAuthority)?;
        http::uri::Authority::try_from(req.authority.as_slice())
            .map_err(|_| StartErr::BadAuthority)?;
        let key = (req.scheme, key::host_key(&host), port);
        let op = cx.dial(Target { host, port }, self.cfg.connect_timeout);
        self.by_h3.insert(req.h3, Where::Dial(op));
        let stored = StoredRequest {
            method: req.method,
            scheme: req.scheme,
            authority: req.authority,
            path: req.path,
            headers: req.headers,
            body: req.upload,
        };
        let rec = OriginReq::Connecting {
            h3: req.h3,
            key,
            ver: req.ver,
            started_at: cx.now(),
            timer: None,
            payload: ConnectingPayload::Stored(stored),
            retried: false,
        };
        self.dials.insert(op, rec);
        Ok(())
    }

    /// spec §7.3: steps 1–3 repeated while the `Dirty` flag was set or any
    /// buffer changed, at most `PUMP_CAP` rounds (then a zero-delay
    /// `OriginTimer::Pump` re-enters); step 5 settles after every call.
    pub fn pump(&mut self, cx: &mut Cx<'_>, ev: &mut dyn BridgeEvents) {
        let waker = Waker::from(self.dirty.clone());
        let mut tcx = Context::from_waker(&waker);
        let mut rounds = 0;
        loop {
            self.dirty.take();
            let mut changed = false;
            for id in self.conns.ids() {
                changed |= self.tcp_to_pipe(cx, id, ev);
            }
            // Step 2 in the §7.3 order: handshakes and public `Connection`s,
            // then the executor tasks, then the exchanges.
            for id in self.conns.ids() {
                changed |= self.poll_driver(cx, id, &mut tcx, ev);
            }
            changed |= self.exec.poll_all(&mut tcx);
            for id in self.conns.ids() {
                changed |= self.poll_exchanges(cx, id, &mut tcx, ev);
            }
            for id in self.conns.ids() {
                changed |= self.pipe_to_tcp(cx, id);
            }
            changed |= self.refill(cx, ev);
            if !(changed | self.dirty.take()) {
                break;
            }
            rounds += 1;
            if rounds == PUMP_CAP {
                // The shard's runnable check cannot see `Dirty` (§7.3 step 4).
                if !self.timers.values().any(|t| *t == OriginTimer::Pump) {
                    let t = cx.set_timer(Duration::ZERO);
                    self.timers.insert(t, OriginTimer::Pump);
                }
                break;
            }
        }
        self.settle(cx);
    }

    /// §7.7 settling point (Task 5.5a).
    fn settle(&mut self, _cx: &mut Cx<'_>) {}

    /// The gateway drained a `Partial` frame: the next pump polls the body again.
    pub fn resume(&mut self, h3: H3ReqId) {
        let Some(&Where::Conn(id)) = self.by_h3.get(&h3) else {
            return;
        };
        let Some(c) = self.conns.get_mut(id) else {
            return;
        };
        for rec in &mut c.reqs {
            if let OriginReq::Assigned { h3: x, held, .. } = rec
                && *x == h3
            {
                *held = false;
            }
        }
    }

    /// `H3Closed` (§7.7 cancel). While `Connecting` the record is dropped: a
    /// pending dial is cancelled, a handshaking conn is removed as class D.
    /// (`Assigned`: Task 5.5a.)
    pub fn cancel(&mut self, cx: &mut Cx<'_>, h3: H3ReqId) {
        match self.by_h3.get(&h3).copied() {
            Some(Where::Dial(op)) => {
                if let Some(rec) = self.dials.remove(&op) {
                    self.drop_connecting(cx, rec);
                    cx.cancel_dial(op);
                }
            }
            Some(Where::Conn(id)) => {
                let Some(c) = self.conns.get_mut(id) else {
                    return;
                };
                if c.pending.as_ref().and_then(OriginReq::connecting_h3) == Some(h3) {
                    let rec = c.pending.take().expect("checked");
                    self.drop_connecting(cx, rec);
                    self.remove(cx, id, Removal::D);
                }
            }
            None => {}
        }
    }

    /// §7.7 shutdown (Task 5.6c).
    pub fn shutdown(&mut self, _cx: &mut Cx<'_>) {}

    /// Returns whether `op` was the bridge's (§7.2 steps 4–5).
    pub fn on_dial_result(
        &mut self,
        cx: &mut Cx<'_>,
        op: DialOpId,
        r: Result<TcpId, DialError>,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(rec) = self.dials.remove(&op) else {
            return false;
        };
        let https = rec.https();
        match r {
            Ok(tcp) => self.connected(cx, tcp, rec, ev),
            // §6.2 step 9: the socket cap is 502 origin-start-failed.
            Err(DialError::Limit) => self.fail(cx, rec, start_failed("socket limit"), ev),
            Err(e) => {
                let curl = match e {
                    DialError::Dns => 6,
                    DialError::Timeout => 28,
                    DialError::Refused | DialError::Other | DialError::Limit => 7,
                };
                let f = connect_failure(https, curl, format!("dial: {e:?}"));
                self.fail(cx, rec, f, ev);
            }
        }
        true
    }

    /// Returns whether `tcp` was the bridge's; the pump moves the bytes.
    pub fn on_tcp_data(
        &mut self,
        _cx: &mut Cx<'_>,
        tcp: TcpId,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        self.by_tcp.contains_key(&tcp)
    }

    /// Returns whether `tcp` was the bridge's; the pump flushes what waits.
    pub fn on_tcp_writable(
        &mut self,
        _cx: &mut Cx<'_>,
        tcp: TcpId,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        self.by_tcp.contains_key(&tcp)
    }

    /// Returns whether `tcp` was the bridge's. `ReadEof` is published by the
    /// pump once the buffered bytes were processed. A socket error while the
    /// requester is still `Connecting` is `curl:35` at once (§7.3; `curl:56`
    /// in the transient hyper handshake); after it, class E without
    /// `tcp_abort` — the shard already closed the socket.
    pub fn on_tcp_end(
        &mut self,
        cx: &mut Cx<'_>,
        tcp: TcpId,
        end: TcpEnd,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(&id) = self.by_tcp.get(&tcp) else {
            return false;
        };
        let c = self.conns.get_mut(id).expect("by_tcp names a live conn");
        match end {
            TcpEnd::ReadEof => c.tcp_eof = true,
            TcpEnd::Error(k) if c.pending.is_some() => {
                let curl = if matches!(c.driver, Driver::Tls(_)) {
                    35
                } else {
                    56
                };
                let cause = format!("socket error during the handshake: {k:?}");
                self.fail_conn(cx, id, curl, cause, ev);
            }
            TcpEnd::Error(_) => self.remove(cx, id, Removal::E { abort: false }),
        }
        true
    }

    /// false = not the bridge's timer. `Connect` fires `curl:28` for a
    /// requester still `Connecting` on its conn (§7.2 step 4).
    pub fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId, ev: &mut dyn BridgeEvents) -> bool {
        let Some(t) = self.timers.remove(&id) else {
            return false;
        };
        if let OriginTimer::Connect(h3) = t
            && let Some(&Where::Conn(conn)) = self.by_h3.get(&h3)
            && let Some(c) = self.conns.get_mut(conn)
            && let Some(OriginReq::Connecting { timer, .. }) = &mut c.pending
            && *timer == Some(id)
        {
            *timer = None;
            self.fail_conn(cx, conn, 28, "connect deadline".into(), ev);
        }
        true
    }

    /// §7.2 step 4: the record moves to the new conn's `pending`; the
    /// deadline timer covers the TLS and hyper handshakes.
    fn connected(
        &mut self,
        cx: &mut Cx<'_>,
        tcp: TcpId,
        mut rec: OriginReq,
        ev: &mut dyn BridgeEvents,
    ) {
        let OriginReq::Connecting {
            h3,
            key,
            ver,
            started_at,
            timer,
            ..
        } = &mut rec
        else {
            unreachable!("dials hold Connecting records");
        };
        let (h3, key, started_at) = (*h3, key.clone(), *started_at);
        let tls = if key.0 == Scheme::Https {
            let Some(name) = key::server_name(&key.1) else {
                cx.tcp_abort(tcp); // class E′, before the conn exists
                let f = connect_failure(true, 6, format!("invalid server name {}", key.1));
                return self.fail(cx, rec, f, ev);
            };
            let alpn = key::alpn_for(key.0, *ver).iter().map(|a| a.to_vec());
            match rustls::ClientConnection::new_with_alpn(self.tls.clone(), name, alpn.collect()) {
                Ok(c) => Some(c),
                Err(e) => {
                    cx.tcp_abort(tcp);
                    return self.fail(cx, rec, connect_failure(true, 35, e.to_string()), ev);
                }
            }
        } else {
            None
        };
        cx.tcp_set_rx_limit(tcp, PIPE_CAP);
        let t = cx.set_timer((started_at + self.cfg.connect_timeout) - cx.now());
        self.timers.insert(t, OriginTimer::Connect(h3));
        *timer = Some(t);
        let plain = tls.is_none();
        let (hyper_io, io) = pipe::pipe();
        let id = self.conns.insert(|id| OriginConn {
            id,
            key: key.clone(),
            tcp,
            tls,
            io,
            proto: None,
            driver: Driver::Tls(hyper_io),
            send: None,
            pending: Some(rec),
            reqs: Vec::new(),
            out: Vec::new(),
            tcp_eof: false,
            busy: false,
            active: 0,
            draining: false,
            idle_since: None,
            connect_ms: 0,
            hold_public: false,
        });
        self.pool.entry(key).or_default().push(id);
        self.by_tcp.insert(tcp, id);
        self.by_h3.insert(h3, Where::Conn(id));
        if plain {
            // C used CONNECT_TIME_T: the TCP dial's duration.
            self.begin_hyper(cx, id, OriginProto::H1);
        }
    }

    /// §7.3 step 1, TCP → pipe. TLS: `reader()` first, `read_tls` only with
    /// bytes and `wants_read` (a zero-byte read would mark EOF inside
    /// rustls); a TLS error ends the handshake (`curl:35`/`60`, E′) or, after
    /// it, the conn (class E). `rx_eof` is published only once `tcp_rx` and
    /// rustls are empty. Returns whether bytes moved.
    fn tcp_to_pipe(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        if self.closing.contains(&id) {
            return false; // its socket is gone (class E)
        }
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let tcp = c.tcp;
        let Some(tls) = c.tls.as_mut() else {
            let n = c.io.push_rx(cx.tcp_rx(tcp));
            if n > 0 {
                cx.tcp_consume(tcp, n);
            }
            let eof = c.tcp_eof && cx.tcp_rx(tcp).is_empty() && c.io.set_eof();
            return n > 0 || eof;
        };
        let connecting = matches!(c.driver, Driver::Tls(_));
        let mut moved = drain_plaintext(tls, &c.io);
        let mut failed = None;
        while tls.wants_read() && !cx.tcp_rx(tcp).is_empty() {
            let mut rx = cx.tcp_rx(tcp);
            match tls.read_tls(&mut rx) {
                Ok(0) => break,
                Ok(n) => cx.tcp_consume(tcp, n),
                // A full deframer buffer during the handshake: no deadline wait.
                Err(e) if connecting => {
                    failed = Some(rustls::Error::General(e.to_string()));
                    break;
                }
                // "received plaintext buffer full": backpressure (§7.3).
                Err(_) => break,
            }
            moved = true;
            if let Err(e) = tls.process_new_packets() {
                failed = Some(e);
                break;
            }
            moved |= drain_plaintext(tls, &c.io);
        }
        if let Some(e) = failed {
            if connecting {
                let curl = match e {
                    rustls::Error::InvalidCertificate(_) => 60,
                    _ => 35,
                };
                self.fail_conn(cx, id, curl, e.to_string(), ev);
            } else {
                // Fatal and sticky in rustls: the socket is useless (§7.3).
                self.remove(cx, id, Removal::E { abort: true });
            }
            return true;
        }
        let eof = c.tcp_eof && cx.tcp_rx(tcp).is_empty();
        if connecting && !tls.is_handshaking() {
            let proto = match tls.alpn_protocol() {
                Some(b"h2") => OriginProto::H2,
                _ => OriginProto::H1,
            };
            self.begin_hyper(cx, id, proto);
            moved = true;
        } else if connecting && eof {
            let cause = "EOF during the TLS handshake".to_string();
            self.fail_conn(cx, id, 35, cause, ev);
            return true;
        }
        if eof {
            let c = self.conns.get_mut(id).expect("live conn");
            let tls = c.tls.as_mut().expect("TLS conn");
            // `Err` while rustls's plaintext is full: retried on a later pump.
            let _ = tls.read_tls(&mut &[][..]);
            moved |= drain_plaintext(tls, &c.io);
        }
        moved
    }

    /// §7.3 step 3, pipe → TCP, in slices of ≤ `SLICE`. TLS: `write_tls`
    /// whenever `wants_write`, plaintext fed while `out` < 64 KiB. Returns
    /// whether bytes moved.
    fn pipe_to_tcp(&mut self, cx: &mut Cx<'_>, id: OriginConnId) -> bool {
        if self.closing.contains(&id) {
            return false;
        }
        let Some(OriginConn {
            tcp, tls, io, out, ..
        }) = self.conns.get_mut(id)
        else {
            return false;
        };
        let tcp = *tcp;
        let Some(tls) = tls else {
            let mut moved = false;
            while io.with_tx(SLICE, |s| match cx.tcp_write(tcp, s) {
                Ok(()) => s.len(),
                Err(_) => 0,
            }) > 0
            {
                moved = true;
            }
            return moved;
        };
        let before = out.len();
        let mut fed = false;
        loop {
            while tls.wants_write() && tls.write_tls(out).is_ok() {}
            if out.len() >= PIPE_CAP
                || io.with_tx(SLICE, |s| tls.writer().write(s).unwrap_or(0)) == 0
            {
                break;
            }
            fed = true;
        }
        let staged = out.len();
        flush_out(cx, tcp, out);
        fed || staged != before || out.len() != staged
    }

    /// `Tls` → `Handshaking`: `connect_ms` is taken now and hyper gets its
    /// end of the pipe, with the §7.2 builder settings.
    fn begin_hyper(&mut self, cx: &mut Cx<'_>, id: OriginConnId, proto: OriginProto) {
        let exec = self.exec.clone();
        let c = self.conns.get_mut(id).expect("live conn");
        let Driver::Tls(io) = std::mem::replace(&mut c.driver, Driver::Completed) else {
            unreachable!("begin_hyper runs once, from Tls");
        };
        if let Some(OriginReq::Connecting { started_at, .. }) = &c.pending {
            c.connect_ms = (cx.now() - *started_at).as_millis() as i64;
        }
        c.proto = Some(proto);
        c.driver = Driver::Handshaking(match proto {
            OriginProto::H1 => Box::pin(async move {
                let (send, conn) = http1::Builder::new()
                    .max_buf_size(64 * 1024)
                    .max_headers(256)
                    .handshake(io)
                    .await?;
                Ok(Handshaked::H1(send, Box::pin(conn)))
            }),
            OriginProto::H2 => Box::pin(async move {
                let (send, conn) = http2::Builder::new(exec)
                    .max_header_list_size(128 * 1024)
                    .handshake(io)
                    .await?;
                Ok(Handshaked::H2(send, Box::pin(conn)))
            }),
        });
    }

    /// §7.3 step 2 for one conn's driver: a `Handshaking` future (done →
    /// `H1`/`H2` + `send`, the requester assigned and its request sent;
    /// `Err` → `curl:56`, class E′), then the public `Connection` unless held
    /// (5.1b `hold_public_poll`); its completion → `Completed`, `send`
    /// dropped (§7.7). Returns whether the driver changed.
    fn poll_driver(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        tcx: &mut Context<'_>,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let mut changed = false;
        if let Driver::Handshaking(fut) = &mut c.driver {
            match fut.as_mut().poll(tcx) {
                Poll::Pending => return false,
                Poll::Ready(Err(e)) => {
                    self.fail_conn(cx, id, 56, e.to_string(), ev);
                    return true;
                }
                Poll::Ready(Ok(hs)) => {
                    (c.driver, c.send) = match hs {
                        Handshaked::H1(s, conn) => (Driver::H1(conn), Some(Sender::H1(s))),
                        Handshaked::H2(s, conn) => (Driver::H2(conn), Some(Sender::H2(s))),
                    };
                    self.assign(cx, id, ev);
                    changed = true;
                }
            }
        }
        let c = self.conns.get_mut(id).expect("live conn");
        if c.hold_public {
            return changed;
        }
        let done = match &mut c.driver {
            Driver::H1(conn) => conn.as_mut().poll(tcx).is_ready(),
            Driver::H2(conn) => conn.as_mut().poll(tcx).is_ready(),
            _ => false,
        };
        if done {
            c.driver = Driver::Completed;
            c.send = None;
        }
        changed || done
    }

    /// §7.7: the conn's `pending` requester → `Assigned` and its request is
    /// sent (§7.4: built now, in the conn's URI form); `Tm::OriginConnect`
    /// is cancelled.
    fn assign(&mut self, cx: &mut Cx<'_>, id: OriginConnId, ev: &mut dyn BridgeEvents) {
        let c = self.conns.get_mut(id).expect("live conn");
        let Some(OriginReq::Connecting {
            h3,
            timer,
            payload,
            retried,
            ..
        }) = c.pending.take()
        else {
            return;
        };
        if let Some(t) = timer {
            cx.cancel_timer(t);
            self.timers.remove(&t);
        }
        let ConnectingPayload::Stored(stored) = payload else {
            unreachable!("Ready is the h1 retry's payload (Task 5.5b)");
        };
        let proto = c.proto.expect("negotiated");
        let Ok(req) = request::build_request(&stored, proto) else {
            self.by_h3.remove(&h3);
            ev.on_failure(cx, h3, start_failed("request build"), false);
            return;
        };
        let send = c.send.as_mut().expect("H1/H2 driver");
        let fut = send_request(send, req, false);
        match proto {
            OriginProto::H2 => c.active += 1,
            OriginProto::H1 => {
                c.busy = true;
                c.io.reset_rx_since_send();
            }
        }
        c.idle_since = None;
        c.reqs.push(OriginReq::Assigned {
            h3,
            fut: Some(fut),
            body: None,
            upload: stored.body.clone(),
            stored: Some(stored),
            head_seen: false,
            reused: false,
            retried,
            held: false,
            delivered: 0,
            cl: None,
        });
    }

    /// §7.3 step 2 for one conn's exchanges (§7.5): the response future →
    /// `on_response` (or `head_error` / the §7.6 mapping → `on_failure`),
    /// then body frames one at a time until `Pending`, a `Partial` answer
    /// (`held`), the end or an error. An exchange that ended becomes `Ended`.
    fn poll_exchanges(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        tcx: &mut Context<'_>,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let (Some(proto), https) = (c.proto, c.key.0 == Scheme::Https) else {
            return false;
        };
        let mut changed = false;
        for rec in &mut c.reqs {
            let OriginReq::Assigned {
                h3,
                fut,
                body,
                upload,
                head_seen,
                reused,
                held,
                delivered,
                cl,
                ..
            } = rec
            else {
                continue;
            };
            let h3 = *h3;
            let mut ended = false;
            if let Some(f) = fut
                && let Poll::Ready(r) = f.as_mut().poll(tcx)
            {
                *fut = None;
                changed = true;
                match r {
                    Ok(resp) => {
                        let (parts, incoming) = resp.into_parts();
                        match response::normalise(&parts) {
                            Ok(head) => {
                                (*head_seen, *cl, *body) = (true, head.cl, Some(incoming));
                                ev.on_response(cx, h3, head);
                            }
                            Err(e) => {
                                drop(incoming);
                                let f = errors::head_error(e, proto, https);
                                ev.on_failure(cx, h3, f, false);
                                ended = true;
                            }
                        }
                    }
                    // A hand-back (`returned`) is the h1 retry's (Task 5.5b).
                    Err(SendFailure { err, returned }) => {
                        drop(returned);
                        let rx = c.io.rx_since_send();
                        let f = failure(&err, false, proto, rx, https);
                        ev.on_failure(cx, h3, f, false);
                        ended = true;
                    }
                }
            }
            while !*held && let Some(b) = body {
                match Pin::new(b).poll_frame(tcx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(frame))) => {
                        changed = true;
                        // Trailers are dropped (§7.5).
                        let Ok(data) = frame.into_data() else {
                            continue;
                        };
                        if data.is_empty() {
                            continue;
                        }
                        *delivered += data.len() as u64;
                        *held = matches!(ev.on_body_frame(cx, h3, &data), Accepted::Partial(_));
                    }
                    Poll::Ready(None) => {
                        *body = None;
                        let tls = if https {
                            TlsOutcome::Ok
                        } else {
                            TlsOutcome::Na
                        };
                        let done = Completion {
                            reused: *reused,
                            connect_ms: c.connect_ms,
                            tls,
                            delivered: *delivered,
                            cl: *cl,
                        };
                        ev.on_body_end(cx, h3, done);
                        ended = true;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        *body = None;
                        let rx = c.io.rx_since_send();
                        ev.on_failure(cx, h3, failure(&e, true, proto, rx, https), true);
                        ended = true;
                    }
                }
            }
            if ended {
                // §7.7: settling (Task 5.5a) drops it once `released`.
                let upload = upload.clone();
                *rec = OriginReq::Ended {
                    upload,
                    since: cx.now(),
                };
                changed = true;
            }
        }
        changed
    }

    /// §7.4: the uploads hyper found empty before their fin are refilled by
    /// the gateway (`want_h3`); a refill that added nothing changes nothing.
    fn refill(&mut self, cx: &mut Cx<'_>, ev: &mut dyn BridgeEvents) -> bool {
        let mut wanted = Vec::new();
        for id in self.conns.ids() {
            for rec in &self.conns.get(id).expect("live conn").reqs {
                if let OriginReq::Assigned { h3, upload, .. } = rec
                    && std::mem::take(&mut upload.borrow_mut().want_h3)
                {
                    wanted.push((*h3, upload.clone()));
                }
            }
        }
        let mut changed = false;
        for (h3, upload) in wanted {
            let state = |u: &UploadBuf| (u.data.len(), u.fin, u.is_aborted());
            let before = state(&upload.borrow());
            ev.want_h3(cx, h3);
            changed |= state(&upload.borrow()) != before;
        }
        changed
    }

    /// A `Connecting` record leaves the bridge: its deadline timer and
    /// `by_h3` entry go with it.
    fn drop_connecting(&mut self, cx: &mut Cx<'_>, rec: OriginReq) -> Option<H3ReqId> {
        let OriginReq::Connecting { h3, timer, .. } = rec else {
            return None;
        };
        if let Some(t) = timer {
            cx.cancel_timer(t);
            self.timers.remove(&t);
        }
        self.by_h3.remove(&h3);
        Some(h3)
    }

    /// A `Connecting` failure (§7.7): the record is dropped with `f`.
    fn fail(
        &mut self,
        cx: &mut Cx<'_>,
        rec: OriginReq,
        f: OriginFailure,
        ev: &mut dyn BridgeEvents,
    ) {
        if let Some(h3) = self.drop_connecting(cx, rec) {
            ev.on_failure(cx, h3, f, false);
        }
    }

    /// A `Connecting` failure on a conn: class E′, then the requester fails.
    fn fail_conn(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        curl: u32,
        cause: String,
        ev: &mut dyn BridgeEvents,
    ) {
        let Some(c) = self.conns.get_mut(id) else {
            return;
        };
        let https = c.key.0 == Scheme::Https;
        let rec = c.pending.take();
        self.remove(cx, id, Removal::EPrime);
        if let Some(rec) = rec {
            self.fail(cx, rec, connect_failure(https, curl, cause), ev);
        }
    }

    /// §7.7 "every removal": the pipe is marked dead before the conn leaves
    /// the table, `by_tcp` and `pool` forget it, then the class's socket
    /// action. A class-E conn with an `Assigned` record waits in `closing`,
    /// where hyper reports each exchange from the dead pipe. (Task 5.5a adds
    /// the other classes.)
    fn remove(&mut self, cx: &mut Cx<'_>, id: OriginConnId, class: Removal) {
        self.mark_pipe_dead(id);
        let Some(c) = self.conns.get(id) else {
            return;
        };
        let (tcp, key) = (c.tcp, c.key.clone());
        let keep = matches!(class, Removal::E { .. })
            && c.reqs
                .iter()
                .any(|r| matches!(r, OriginReq::Assigned { .. }));
        self.by_tcp.remove(&tcp);
        if let Some(v) = self.pool.get_mut(&key) {
            v.retain(|&x| x != id);
            if v.is_empty() {
                self.pool.remove(&key);
            }
        }
        match class {
            Removal::D | Removal::EPrime | Removal::E { abort: true } => cx.tcp_abort(tcp),
            Removal::E { abort: false } => {}
        }
        if keep {
            self.closing.push(id);
        } else {
            self.conns.remove(id);
        }
    }
}

/// The §7.7 removal classes this task produces.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Removal {
    /// The `pending` requester was cancelled during `Tls`/`Handshaking`.
    D,
    /// A `Connecting` failure that already owns a socket.
    EPrime,
    /// The socket is useless: `on_tcp_end(Error)` (`abort: false`, the
    /// shard already closed it) or a fatal TLS error after the handshake.
    E { abort: bool },
}

impl OriginReq {
    fn connecting_h3(&self) -> Option<H3ReqId> {
        match self {
            OriginReq::Connecting { h3, .. } => Some(*h3),
            _ => None,
        }
    }

    fn https(&self) -> bool {
        matches!(self, OriginReq::Connecting { key, .. } if key.0 == Scheme::Https)
    }
}

/// §7.6: a connect-phase failure; `origin_tls` = `verify_fail` for `curl:60`,
/// `connect_fail` for https, `na` for http.
fn connect_failure(https: bool, curl: u32, cause: String) -> OriginFailure {
    let tls = match (curl, https) {
        (60, _) => TlsOutcome::VerifyFail,
        (_, true) => TlsOutcome::ConnectFail,
        (_, false) => TlsOutcome::Na,
    };
    OriginFailure {
        curl,
        status: status_from_curl(curl),
        tls,
        proto: None,
        upstream_protocol: false,
        start_failed: false,
        cause,
    }
}

/// §6.2 step 9: 502 `origin-start-failed`, not a §7.6 error.
fn start_failed(cause: &str) -> OriginFailure {
    OriginFailure {
        curl: 0,
        status: 502,
        tls: TlsOutcome::Na,
        proto: None,
        upstream_protocol: false,
        start_failed: true,
        cause: cause.into(),
    }
}

/// §7.6 for an exchange on a negotiated conn, with hyper's error text.
fn failure(
    e: &hyper::Error,
    after_head: bool,
    proto: OriginProto,
    rx_since_send: u64,
    https: bool,
) -> OriginFailure {
    let c = errors::classify(e);
    OriginFailure {
        cause: e.to_string(),
        ..errors::map_error(c, after_head, proto, rx_since_send, https)
    }
}

/// §7.4/§7.7: `try_send_request` on a reused h1 conn (hyper may hand the
/// request back), `send_request` otherwise; the future is boxed as §7.1.
fn send_request(send: &mut Sender, req: Request<UploadBody>, reused: bool) -> ResponseFut {
    let plain = |err| SendFailure {
        err,
        returned: None,
    };
    match send {
        Sender::H1(s) if reused => {
            let f = s.try_send_request(req);
            Box::pin(async move {
                f.await.map_err(|mut e| SendFailure {
                    returned: e.take_message(),
                    err: e.into_error(),
                })
            })
        }
        Sender::H1(s) => {
            let f = s.send_request(req);
            Box::pin(async move { f.await.map_err(plain) })
        }
        Sender::H2(s) => {
            let f = s.send_request(req);
            Box::pin(async move { f.await.map_err(plain) })
        }
    }
}

/// §7.3 step 1: rustls's plaintext → `rx` while the pipe has room; a
/// `close_notify` (`Ok(0)`) or a close_notify-less EOF (`UnexpectedEof`,
/// after the buffered plaintext) publishes `rx_eof`. Returns whether
/// anything moved.
fn drain_plaintext(tls: &mut rustls::ClientConnection, io: &PipeHandle) -> bool {
    let mut buf = [0u8; SLICE];
    let mut moved = false;
    loop {
        let room = io.rx_room().min(SLICE);
        if room == 0 {
            return moved;
        }
        match tls.reader().read(&mut buf[..room]) {
            Ok(0) => return io.set_eof() || moved,
            Ok(n) => {
                io.push_rx(&buf[..n]);
                moved = true;
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return io.set_eof() || moved,
            Err(_) => return moved, // WouldBlock: nothing buffered
        }
    }
}

/// §7.3 step 3: `tcp_write` is all-or-nothing, so `out` goes in slices of
/// ≤ `SLICE` until one does not fit; the rest waits for `on_tcp_writable`.
fn flush_out(cx: &mut Cx<'_>, tcp: TcpId, out: &mut Vec<u8>) {
    let mut sent = 0;
    for chunk in out.chunks(SLICE) {
        if cx.tcp_write(tcp, chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    out.drain(..sent);
}

/// A live record's state (test-support; an `Ended` record has no `h3`).
#[cfg(feature = "test-support")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordState {
    Connecting,
    Assigned,
}

#[cfg(feature = "test-support")]
impl Origin {
    /// Conns in the pool, every key.
    pub fn pool_len(&self) -> usize {
        self.pool.values().map(Vec::len).sum()
    }

    pub fn closing_len(&self) -> usize {
        self.closing.len()
    }

    /// Executor tasks spawned and not finished.
    pub fn task_count(&self) -> usize {
        self.exec.len()
    }

    /// Whether the conn's pipe was marked dead; still answerable after removal.
    pub fn pipe_dead(&self, id: OriginConnId) -> bool {
        self.dead_marked.contains(&id)
    }

    pub fn idle_timer_armed(&self) -> bool {
        self.idle_timer.is_some()
    }

    /// `None` once the record is `Ended` or dropped.
    pub fn record_state(&self, h3: H3ReqId) -> Option<RecordState> {
        let rec = match *self.by_h3.get(&h3)? {
            Where::Dial(op) => self.dials.get(&op),
            Where::Conn(id) => {
                let c = self.conns.get(id)?;
                c.pending.iter().chain(&c.reqs).find(|r| match r {
                    OriginReq::Connecting { h3: x, .. } | OriginReq::Assigned { h3: x, .. } => {
                        *x == h3
                    }
                    OriginReq::Ended { .. } => false,
                })
            }
        };
        match rec? {
            OriginReq::Connecting { .. } => Some(RecordState::Connecting),
            OriginReq::Assigned { .. } => Some(RecordState::Assigned),
            OriginReq::Ended { .. } => None,
        }
    }

    pub fn ended_records(&self, id: OriginConnId) -> usize {
        self.conns.get(id).map_or(0, |c| {
            c.reqs
                .iter()
                .filter(|r| matches!(r, OriginReq::Ended { .. }))
                .count()
        })
    }

    pub fn conn_of(&self, h3: H3ReqId) -> Option<OriginConnId> {
        match self.by_h3.get(&h3)? {
            Where::Conn(id) => Some(*id),
            Where::Dial(_) => None,
        }
    }

    pub fn connect_ms(&self, id: OriginConnId) -> Option<i64> {
        self.conns.get(id).map(|c| c.connect_ms)
    }

    /// While set, the pump skips the conn's public `Connection` future (5.6c);
    /// the caller pumps after clearing it, as after `resume`.
    pub fn hold_public_poll(&mut self, id: OriginConnId, on: bool) {
        if let Some(c) = self.conns.get_mut(id) {
            c.hold_public = on;
        }
    }

    /// Whether hyper called `poll_shutdown` on the conn's pipe.
    pub fn tx_shutdown(&self, id: OriginConnId) -> bool {
        self.conns.get(id).is_some_and(|c| c.io.tx_shutdown())
    }

    /// Pushes `fut` onto the bridge's executor.
    pub fn spawn_test_task(&mut self, fut: Pin<Box<dyn Future<Output = ()>>>) {
        hyper::rt::Executor::execute(&self.exec, fut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_runtime::testing::{RecordingApp, ScriptedTransport};
    use mq_runtime::{Host, Shard};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn conn_table_generational_ids_go_stale() {
        let mut t = Conns::<&str>::default();
        let a = t.insert(|_| "a");
        let b = t.insert(|_| "b");
        assert_ne!(a, b);
        assert_eq!(t.remove(a), Some("a"));
        assert_eq!(t.get_mut(a), None, "removed id is stale");
        assert_eq!(t.remove(a), None);
        let mut seen = None;
        let c = t.insert(|id| {
            seen = Some(id);
            "c"
        });
        assert_eq!(seen, Some(c), "the value is built with its own id");
        assert_eq!(c.index, a.index, "the free slot is reused");
        assert_ne!(c, a, "under a new generation");
        assert_eq!(t.get_mut(a), None, "the stale id does not revalidate");
        assert_eq!(t.remove(a), None, "nor remove the new occupant");
        assert_eq!(t.get_mut(c).copied(), Some("c"));
        assert_eq!(t.get_mut(b).copied(), Some("b"));
    }

    fn test_origin() -> Origin {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let cfg = OriginCfg {
            connect_timeout: Duration::from_secs(10),
            sweep: SWEEP,
        };
        Origin::new(cfg, Arc::new(tls), Arc::new(Dirty::default()))
    }

    /// `TcpId`s are minted only by a shard: one dial result.
    fn some_tcp() -> TcpId {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let now = Time::from_micros(1);
        let target = Target {
            host: Host::Ip(addr.ip()),
            port: 80,
        };
        let op = sh.with_app(now, |_, cx| cx.dial(target, Duration::from_secs(1)));
        sh.on_dial_result(now, op, Ok(addr)).expect("a live dial")
    }

    fn bare_conn(id: OriginConnId) -> OriginConn {
        let (hyper_io, io) = pipe::pipe();
        OriginConn {
            id,
            key: (Scheme::Http, "o.test".into(), 80),
            tcp: some_tcp(),
            tls: None,
            io,
            proto: None,
            driver: Driver::Tls(hyper_io),
            send: None,
            pending: None,
            reqs: Vec::new(),
            out: Vec::new(),
            tcp_eof: false,
            busy: false,
            active: 0,
            draining: false,
            idle_since: None,
            connect_ms: 0,
            hold_public: false,
        }
    }

    #[test]
    fn pipe_dead_survives_conn_removal() {
        let mut origin = test_origin();
        let id = origin.conns.insert(bare_conn);
        assert!(!origin.pipe_dead(id), "never marked");
        origin.mark_pipe_dead(id);
        assert!(origin.pipe_dead(id));
        origin.conns.remove(id);
        assert!(origin.pipe_dead(id), "still answerable after removal");
        let reused = origin.conns.insert(bare_conn);
        assert!(
            !origin.pipe_dead(reused),
            "a reused slot is a different conn"
        );
    }

    fn start_req(origin: &Origin, authority: &str) -> StartReq {
        StartReq {
            h3: H3ReqId::from_slot(mq_transport_api::SlotId::new(0, 1)).unwrap(),
            scheme: Scheme::Https,
            authority: authority.as_bytes().to_vec(),
            path: b"/".to_vec(),
            method: mq_http::headers::parse_method(b"GET").unwrap(),
            headers: Vec::new(),
            ver: HttpVer::Default,
            body: BodyKind::None,
            upload: origin.new_upload(None),
        }
    }

    #[test]
    fn start_rejects_authority_http_refuses() {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let mut origin = test_origin();
        sh.with_app(Time::from_micros(1), |_, cx| {
            for a in ["a{b", "é.test"] {
                assert!(
                    mq_http::headers::uri_field_ok(a.as_bytes()),
                    "{a}: the intake lets it through"
                );
                let req = start_req(&origin, a);
                assert_eq!(origin.start(cx, req), Err(StartErr::BadAuthority), "{a}");
            }
            let req = start_req(&origin, "u@h");
            assert_eq!(
                origin.start(cx, req),
                Err(StartErr::BadAuthority),
                "userinfo"
            );
            let req = start_req(&origin, "o.test");
            assert_eq!(origin.start(cx, req), Ok(()));
        });
        let dials = std::iter::from_fn(|| sh.poll_io_request())
            .filter(|r| matches!(r, mq_runtime::IoRequest::Dial { .. }))
            .count();
        assert_eq!(dials, 1, "only the good authority dials");
    }

    /// 5.1b gap: callbacks for ids the bridge does not own are declined.
    #[test]
    fn foreign_ids_are_declined() {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let mut origin = test_origin();
        let tcp = some_tcp();
        let mut ev = NoEvents;
        sh.with_app(Time::from_micros(1), |_, cx| {
            let timer = cx.set_timer(Duration::from_secs(1));
            let target = Target {
                host: mq_runtime::Host::Ip(addr.ip()),
                port: 80,
            };
            let op = cx.dial(target, Duration::from_secs(1));
            assert!(!origin.on_dial_result(cx, op, Ok(tcp), &mut ev));
            assert!(!origin.on_tcp_data(cx, tcp, &mut ev));
            assert!(!origin.on_tcp_writable(cx, tcp, &mut ev));
            assert!(!origin.on_tcp_end(cx, tcp, TcpEnd::ReadEof, &mut ev));
            assert!(!origin.on_timer(cx, timer, &mut ev));
        });
    }

    /// A sink no test here expects to be called.
    struct NoEvents;
    impl BridgeEvents for NoEvents {
        fn on_response(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: RelayHead) {
            unreachable!()
        }
        fn on_body_frame(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: &[u8]) -> Accepted {
            unreachable!()
        }
        fn on_body_end(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: Completion) {
            unreachable!()
        }
        fn on_failure(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: OriginFailure, _: bool) {
            unreachable!()
        }
        fn want_h3(&mut self, _: &mut Cx<'_>, _: H3ReqId) {
            unreachable!()
        }
    }

    /// Records failures only.
    #[derive(Default)]
    struct Failures(Vec<(H3ReqId, OriginFailure)>);
    impl BridgeEvents for Failures {
        fn on_response(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: RelayHead) {
            unreachable!()
        }
        fn on_body_frame(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: &[u8]) -> Accepted {
            unreachable!()
        }
        fn on_body_end(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: Completion) {
            unreachable!()
        }
        fn on_failure(&mut self, _: &mut Cx<'_>, h3: H3ReqId, f: OriginFailure, _: bool) {
            self.0.push((h3, f));
        }
        fn want_h3(&mut self, _: &mut Cx<'_>, _: H3ReqId) {
            unreachable!()
        }
    }

    /// 5.2 gap: an `Err` from the hyper handshake future is `curl:56`, class
    /// E′. The producer: h2's handshake writes the client preface, which a
    /// dead pipe refuses (no peer can make the h1 handshake fail).
    #[test]
    fn hyper_handshake_err_is_56() {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let mut origin = test_origin();
        let mut ev = Failures::default();
        let req = start_req(&origin, "o.test");
        let h3 = req.h3;
        sh.with_app(Time::from_micros(1), |_, cx| {
            origin.start(cx, req).unwrap();
            let rec = origin.dials.drain().next().unwrap().1;
            let id = origin.conns.insert(|id| OriginConn {
                pending: Some(rec),
                ..bare_conn(id)
            });
            origin.by_h3.insert(h3, Where::Conn(id));
            origin.conns.get(id).unwrap().io.mark_dead();
            origin.begin_hyper(cx, id, OriginProto::H2);
            origin.pump(cx, &mut ev);
            assert!(origin.conns.get(id).is_none(), "class E′: removed");
        });
        let [(x, f)] = &ev.0[..] else {
            panic!("{:?}", ev.0)
        };
        assert_eq!(*x, h3);
        // `bare_conn` is keyed http://: `na`.
        assert_eq!((f.curl, f.status, f.tls), (56, 502, TlsOutcome::Na));
        assert!(origin.by_h3.is_empty(), "the record is dropped");
    }

    #[test]
    fn new_upload_carries_the_bridge_dirty() {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let dirty = Arc::new(Dirty::default());
        let cfg = OriginCfg {
            connect_timeout: Duration::from_secs(10),
            sweep: SWEEP,
        };
        let origin = Origin::new(cfg, Arc::new(tls), dirty.clone());
        let up = origin.new_upload(Some(5));
        assert_eq!(up.borrow().cl, Some(5));
        assert!(!dirty.take());
        up.borrow_mut().abort();
        assert!(
            dirty.take(),
            "the buffer's abort marks the bridge's own Dirty"
        );
    }
}
