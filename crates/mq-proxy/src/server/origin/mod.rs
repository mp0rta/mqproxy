//! SP3 spec §7: the origin bridge — hyper 1.x client `conn` API + rustls,
//! polled from the shard with the `Dirty` waker and `ShardExec` (§7.1); no
//! tokio task or channel on the data path.

mod accounting;
mod body;
mod errors;
mod events;
mod exec;
#[cfg(feature = "test-support")]
pub mod host;
mod key;
mod pipe;
mod pump;
mod request;
mod response;
pub mod tls;

use accounting::{ConnAccounting, SweepClass};
pub use body::{UploadBody, UploadBuf};
#[cfg(feature = "test-support")]
pub use errors::ErrClass;
pub use events::{Accepted, BridgeEvents};
pub use exec::Dirty;
use exec::ShardExec;
use pipe::{HyperIo, PipeHandle};
pub use tls::{TlsSetupError, build_client_config, install_ring, native_roots};

use http::{Request, Response};
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
/// spec §6.2/§6.4: the gateway's caps on a forwarded header set, both
/// directions (C `MQ_GWS_MAX_HDRS` and its arena slots): more than 64, a
/// name ≥ 128 or a value ≥ 1024 bytes; dropped headers do not count, as in C.
pub(crate) const MAX_FWD: usize = 64;
pub(crate) const NAME_CAP: usize = 128;
pub(crate) const VAL_CAP: usize = 1024;

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
    /// Handed back by `try_send_request` (h1 retry), re-sent as is, with
    /// its upload for the new `Assigned` record.
    Ready(Request<UploadBody>, Rc<RefCell<UploadBuf>>),
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
        /// The exchange reached its body end with the upload complete; an
        /// h1 conn is closed as class C otherwise (§7.7).
        clean: bool,
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
    /// h1: the conn has an `Assigned` record.
    busy: bool,
    /// `active`, `draining` (h2) and retirement (§7.7).
    acct: ConnAccounting,
    /// In `closing` as class B: its `tcp_close` waits for the last
    /// `Assigned` record to end (§7.7).
    close_due: bool,
    idle_since: Option<Time>,
    connect_ms: i64,
    /// Step 1 last stopped with the pipe full: rustls may hold decrypted
    /// plaintext (`wants_read` is then false) or `tcp_rx` bytes, which move
    /// once hyper frees room (§7.3 step 4 liveness).
    rx_blocked: bool,
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
    /// `classify` of every hyper error an exchange reported (`error_classes`).
    #[cfg(feature = "test-support")]
    classes: Vec<errors::ErrClass>,
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
            #[cfg(feature = "test-support")]
            classes: Vec::new(),
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

    /// spec §7.2 steps 1–3. The authority passes the bridge's split and
    /// `http::uri::Authority`, which also rejects `"<>\^`, backtick, `{|}`
    /// and non-ASCII (§7.4, §12).
    pub fn start(&mut self, cx: &mut Cx<'_>, req: StartReq) -> Result<(), StartErr> {
        let (host, port) = key::split_authority(req.scheme, &req.authority)
            .map_err(|()| StartErr::BadAuthority)?;
        http::uri::Authority::try_from(req.authority.as_slice())
            .map_err(|_| StartErr::BadAuthority)?;
        let key = (req.scheme, key::host_key(&host), port);
        let stored = StoredRequest {
            method: req.method,
            scheme: req.scheme,
            authority: req.authority,
            path: req.path,
            headers: req.headers,
            body: req.upload,
        };
        if let Some(id) = self.pool_hit(&key, req.ver) {
            let c = self.conns.get_mut(id).expect("pooled conns are live");
            let r = request::build_request(&stored, c.proto.expect("a hit is negotiated"))?;
            c.exchange(req.h3, r, stored.body.clone(), Some(stored), true, false);
            self.by_h3.insert(req.h3, Where::Conn(id));
            return Ok(());
        }
        let rec = OriginReq::Connecting {
            h3: req.h3,
            key,
            ver: req.ver,
            started_at: cx.now(),
            timer: None,
            payload: ConnectingPayload::Stored(stored),
            retried: false,
        };
        self.dial(cx, Target { host, port }, rec);
        Ok(())
    }

    /// §7.2 step 2: a pooled conn under `key` whose protocol the request
    /// accepts, with `send` open — h1: `!busy` and `is_ready()` asked here,
    /// not taken from the last settling; h2: `!draining` (as of the last
    /// settling) and `active < current_max_send_streams()`.
    fn pool_hit(&self, key: &ConnKey, ver: HttpVer) -> Option<OriginConnId> {
        let ids = self.pool.get(key)?;
        ids.iter().copied().find(|&id| {
            let c = self.conns.get(id).expect("pooled conns are live");
            c.proto.is_some_and(|p| key::accepts(ver, p)) && c.takes_request()
        })
    }

    /// §7.2 step 3: `rec` (`Connecting`) waits in `dials` for the result.
    fn dial(&mut self, cx: &mut Cx<'_>, target: Target, rec: OriginReq) {
        let h3 = rec.connecting_h3().expect("a Connecting record");
        let op = cx.dial(target, self.cfg.connect_timeout);
        self.by_h3.insert(h3, Where::Dial(op));
        self.dials.insert(op, rec);
    }

    /// §7.7 h1 retry: the record left its conn (`Assigned` → `Connecting`)
    /// and dials a fresh h1-only conn, its deadline from now; never again.
    fn retry(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, key: ConnKey, payload: ConnectingPayload) {
        let target = Target {
            host: key::host_of(&key.1),
            port: key.2,
        };
        let rec = OriginReq::Connecting {
            h3,
            key,
            ver: HttpVer::H1,
            started_at: cx.now(),
            timer: None,
            payload,
            retried: true,
        };
        self.dial(cx, target, rec);
    }

    /// `H3Closed` (§7.7 cancel): the `by_h3` entry goes. While `Connecting`
    /// the record is dropped: a pending dial is cancelled, a handshaking conn
    /// is removed as class D. `Assigned` → `Ended` (the response future and
    /// `Incoming` dropped). A lookup that lands on an `Ended` record, or on a
    /// conn already gone, is a no-op.
    pub fn cancel(&mut self, cx: &mut Cx<'_>, h3: H3ReqId) {
        match self.by_h3.remove(&h3) {
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
                } else if let Some(rec) = c.reqs.iter_mut().find(|r| r.assigned_h3() == Some(h3)) {
                    rec.end(cx.now(), false);
                }
            }
            None => {}
        }
    }

    /// §7.7 shutdown: class E for every conn, dials cancelled, the executor
    /// list dropped. No event: the gateway resets every request (§6.6).
    pub fn shutdown(&mut self, cx: &mut Cx<'_>) {
        for (op, rec) in std::mem::take(&mut self.dials) {
            self.drop_connecting(cx, rec);
            cx.cancel_dial(op);
        }
        for id in self.conns.ids() {
            if let Some(rec) = self.conns.get_mut(id).and_then(|c| c.pending.take()) {
                self.drop_connecting(cx, rec);
            }
            self.remove(cx, id, Removal::E { abort: true });
        }
        self.exec.clear();
    }

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
        if t == OriginTimer::Idle {
            self.idle_timer = None;
            self.sweep(cx);
        }
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
            acct: ConnAccounting::default(),
            close_due: false,
            idle_since: None,
            connect_ms: 0,
            hold_public: false,
            rx_blocked: false,
        });
        self.pool.entry(key).or_default().push(id);
        self.by_tcp.insert(tcp, id);
        self.by_h3.insert(h3, Where::Conn(id));
        if plain {
            // C used CONNECT_TIME_T: the TCP dial's duration.
            self.begin_hyper(cx, id, OriginProto::H1);
        }
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
    /// the table, `by_tcp` and `pool` forget it, then the class's one socket
    /// action. A class-B/E conn with an `Assigned` record waits in `closing`
    /// (hyper reports each exchange; B's `tcp_close` is deferred to the
    /// settling where the last one ended); any other conn is dropped with
    /// its records. A conn already in `closing` (shutdown) gets no second
    /// socket action, unless its class-B `tcp_close` is still deferred.
    fn remove(&mut self, cx: &mut Cx<'_>, id: OriginConnId, class: Removal) {
        self.mark_pipe_dead(id);
        let Some(c) = self.conns.get_mut(id) else {
            return;
        };
        let (tcp, key) = (c.tcp, c.key.clone());
        let acted = self.closing.contains(&id) && !c.close_due;
        let keep = matches!(class, Removal::B | Removal::E { .. })
            && c.reqs.iter().any(|r| r.assigned_h3().is_some());
        c.close_due = keep && class == Removal::B;
        match class {
            _ if acted => {}
            Removal::A | Removal::C => cx.tcp_close(tcp),
            Removal::B if !keep => cx.tcp_close(tcp),
            Removal::D | Removal::EPrime | Removal::E { abort: true } => cx.tcp_abort(tcp),
            Removal::B | Removal::E { abort: false } => {}
        }
        self.by_tcp.remove(&tcp);
        if let Some(v) = self.pool.get_mut(&key) {
            v.retain(|&x| x != id);
            if v.is_empty() {
                self.pool.remove(&key);
            }
        }
        self.closing.retain(|&x| x != id);
        if keep {
            self.closing.push(id);
        } else {
            self.conns.remove(id);
        }
    }

    /// §7.7 idle sweep (`OriginTimer::Idle`): per pooled conn, expiry
    /// (class A) or h2 retirement (class E).
    fn sweep(&mut self, cx: &mut Cx<'_>) {
        let now = cx.now();
        let ids: Vec<_> = self.pool.values().flatten().copied().collect();
        for id in ids {
            let c = self.conns.get(id).expect("pooled conns are live");
            let newest_ended = c.reqs.iter().filter_map(OriginReq::ended_since).max();
            let class =
                accounting::sweep_class(&c.acct, c.idle_since, newest_ended, now, self.cfg.sweep);
            match class {
                SweepClass::A => self.remove(cx, id, Removal::A),
                SweepClass::E => self.remove(cx, id, Removal::E { abort: true }),
                SweepClass::Keep => {}
            }
        }
    }
}

impl OriginConn {
    /// §7.2 step 2, the protocol aside: `send` open — h1: `!busy` and
    /// `is_ready()`; h2: a stream under the peer's limit, not draining.
    fn takes_request(&self) -> bool {
        match (&self.send, &self.driver) {
            (Some(Sender::H1(s)), _) => !self.busy && !s.is_closed() && s.is_ready(),
            (Some(Sender::H2(s)), Driver::H2(conn)) => {
                !s.is_closed() && self.acct.h2_hit_allowed(conn.current_max_send_streams())
            }
            _ => false,
        }
    }
}

/// The §7.7 removal classes, one socket action each.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Removal {
    /// Idle expiry: `tcp_close`.
    A,
    /// `Completed` with no record left; h1 close after its last `Incoming`
    /// ended: `tcp_close`, deferred while an `Assigned` record remains.
    B,
    /// An h1 conn not to be pooled: `tcp_close`.
    C,
    /// The `pending` requester was cancelled during `Tls`/`Handshaking`.
    D,
    /// A `Connecting` failure that already owns a socket.
    EPrime,
    /// The socket is useless: `on_tcp_end(Error)` (`abort: false`, the
    /// shard already closed it) or a fatal TLS error after the handshake.
    E { abort: bool },
}

impl OriginReq {
    /// §7.7: `Assigned` → `Ended` at any end of the exchange, with the
    /// upload aborted when it is not complete (§6.3: `!fin`); `clean` = a
    /// body end, kept only while the upload is not aborted. The response
    /// future and `Incoming` are dropped here, with no `UploadBuf` borrow held.
    fn end(&mut self, now: Time, clean: bool) {
        let OriginReq::Assigned { upload, .. } = self else {
            return;
        };
        let upload = upload.clone();
        let whole = {
            let mut u = upload.borrow_mut();
            if !u.fin {
                u.abort();
            }
            !u.is_aborted()
        };
        *self = OriginReq::Ended {
            upload,
            since: now,
            clean: clean && whole,
        };
    }

    fn assigned_h3(&self) -> Option<H3ReqId> {
        match self {
            OriginReq::Assigned { h3, .. } => Some(*h3),
            _ => None,
        }
    }

    fn ended_since(&self) -> Option<Time> {
        match self {
            OriginReq::Ended { since, .. } => Some(*since),
            _ => None,
        }
    }

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

/// A live record's state (test-support; an `Ended` record has no `h3`).
#[cfg(feature = "test-support")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecordState {
    Connecting,
    Assigned,
}

/// An `Ended` record as `Origin::ended` reports it (test-support).
#[cfg(feature = "test-support")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EndedRecord {
    pub since: Time,
    /// The upload reached its fin.
    pub fin: bool,
    pub aborted: bool,
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

    /// The conn's `Ended` records: when they ended and their upload's state.
    pub fn ended(&self, id: OriginConnId) -> Vec<EndedRecord> {
        let Some(c) = self.conns.get(id) else {
            return Vec::new();
        };
        let ended = c.reqs.iter().filter_map(|r| match r {
            OriginReq::Ended { upload, since, .. } => {
                let u = upload.borrow();
                Some(EndedRecord {
                    since: *since,
                    fin: u.fin,
                    aborted: u.is_aborted(),
                })
            }
            _ => None,
        });
        ended.collect()
    }

    /// `draining` as of the last settling (§7.7).
    pub fn draining(&self, id: OriginConnId) -> bool {
        self.conns.get(id).is_some_and(|c| c.acct.draining())
    }

    pub fn idle_since(&self, id: OriginConnId) -> Option<Time> {
        self.conns.get(id).and_then(|c| c.idle_since)
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

    /// Whether the conn is pooled and would take a request now (§7.2 step 2).
    pub fn reusable(&self, id: OriginConnId) -> bool {
        self.pool.values().flatten().any(|&x| x == id)
            && self.conns.get(id).is_some_and(OriginConn::takes_request)
    }

    /// `classify` of every hyper error an exchange reported, in order: the
    /// response future's (handed-back requests included) and the body's.
    pub fn error_classes(&self) -> &[ErrClass] {
        &self.classes
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

    pub(super) fn test_origin() -> Origin {
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

    pub(super) fn bare_conn(id: OriginConnId) -> OriginConn {
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
            acct: ConnAccounting::default(),
            close_due: false,
            idle_since: None,
            connect_ms: 0,
            hold_public: false,
            rx_blocked: false,
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
    pub(super) struct NoEvents;
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

    /// spec §7.2 step 2: a `!busy` h1 conn is a hit only while
    /// `send.is_ready()`, asked in the lookup itself. The producer: a
    /// handshaken conn whose `Connection` was never polled (hyper's
    /// dispatcher has not asked for a request yet) — no exchange through
    /// the pump can leave an idle conn in that state.
    #[test]
    fn h1_is_ready_rechecked_in_pool_lookup() {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let mut origin = test_origin();
        let req = |origin: &Origin, n| StartReq {
            h3: h3(n),
            scheme: Scheme::Http,
            ..start_req(origin, "o.test")
        };
        sh.with_app(Time::from_micros(1), |_, cx| {
            let id = origin.conns.insert(bare_conn);
            let key = origin.conns.get(id).unwrap().key.clone();
            origin.pool.entry(key).or_default().push(id);
            origin.hold_public_poll(id, true);
            origin.begin_hyper(cx, id, OriginProto::H1);
            origin.pump(cx, &mut NoEvents);
            let c = origin.conns.get(id).unwrap();
            assert!(matches!(&c.send, Some(Sender::H1(s)) if !s.is_ready()));
            assert!(!c.busy);
            origin.start(cx, req(&origin, 1)).unwrap();
            assert!(
                matches!(origin.by_h3[&h3(1)], Where::Dial(_)),
                "not ready: a dial"
            );
            origin.hold_public_poll(id, false);
            origin.pump(cx, &mut NoEvents);
            origin.start(cx, req(&origin, 2)).unwrap();
            assert!(
                matches!(origin.by_h3[&h3(2)], Where::Conn(x) if x == id),
                "ready: a hit"
            );
        });
    }

    fn assigned(h3: H3ReqId, upload: &Rc<RefCell<UploadBuf>>) -> OriginReq {
        OriginReq::Assigned {
            h3,
            fut: None,
            body: None,
            upload: upload.clone(),
            stored: None,
            head_seen: false,
            reused: false,
            retried: false,
            held: false,
            delivered: 0,
            cl: None,
        }
    }

    fn h3(n: u32) -> H3ReqId {
        H3ReqId::from_slot(mq_transport_api::SlotId::new(n, 1)).unwrap()
    }

    /// spec §6.3/§7.7: the `Assigned` → `Ended` rule aborts the upload only
    /// when it has not reached its fin.
    #[test]
    fn end_aborts_only_an_incomplete_upload() {
        let origin = test_origin();
        let (whole, cut) = (origin.new_upload(None), origin.new_upload(None));
        whole.borrow_mut().fin = true;
        for (up, abort) in [(&whole, false), (&cut, true)] {
            let mut rec = assigned(h3(0), up);
            rec.end(Time(5), true);
            assert_eq!(rec.ended_since(), Some(Time(5)));
            assert_eq!(up.borrow().is_aborted(), abort);
            assert!(
                matches!(rec, OriginReq::Ended { clean, .. } if clean == !abort),
                "a cut upload is never a clean end"
            );
        }
    }

    /// spec §7.7: an exchange's end leaves an `Ended` record that only the
    /// settling drops, once `released`; an unreleased one stays and counts.
    #[test]
    fn ended_record_exists_between_body_end_and_settle() {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let mut origin = test_origin();
        let (done, stuck) = (origin.new_upload(None), origin.new_upload(None));
        done.borrow_mut().fin = true;
        let hyper_owned = UploadBody::new(&stuck);
        let id = origin.conns.insert(|id| OriginConn {
            reqs: vec![assigned(h3(0), &done), assigned(h3(1), &stuck)],
            acct: ConnAccounting {
                active: 2,
                ..ConnAccounting::default()
            },
            ..bare_conn(id)
        });
        let ended = |o: &Origin| {
            o.conns
                .get(id)
                .unwrap()
                .reqs
                .iter()
                .filter_map(OriginReq::ended_since)
                .count()
        };
        sh.with_app(Time(7), |_, cx| {
            for rec in &mut origin.conns.get_mut(id).unwrap().reqs {
                rec.end(cx.now(), true);
            }
            assert_eq!(ended(&origin), 2, "Ended between the end and the settling");
            origin.settle(cx);
            assert_eq!(ended(&origin), 1, "the released one is dropped");
            let acct = origin.conns.get(id).unwrap().acct;
            assert_eq!((acct.active, acct.ended_unreleased), (1, 1));
            drop(hyper_owned);
            origin.settle(cx);
            assert_eq!(ended(&origin), 0);
            assert_eq!(origin.conns.get(id).unwrap().acct.active, 0);
        });
    }
}
