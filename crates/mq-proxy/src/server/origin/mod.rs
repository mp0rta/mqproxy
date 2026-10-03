//! SP3 spec §7: the origin bridge — hyper 1.x client `conn` API + rustls,
//! polled from the shard with the `Dirty` waker and `ShardExec` (§7.1); no
//! tokio task or channel on the data path.

mod body;
mod events;
mod exec;
mod pipe;

pub use body::{UploadBody, UploadBuf};
pub use events::{Accepted, BridgeEvents};
pub use exec::Dirty;
use exec::ShardExec;
use pipe::{HyperIo, PipeHandle};

use http::{Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use mq_http::headers::{HttpVer, Method};
use mq_runtime::{Cx, DialError, DialOpId, TcpEnd, TcpId, TimerId};
use mq_transport_api::{H3ReqId, Time};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
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
    Tls,
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
        }
    }

    /// The only constructor of an `UploadBuf`: it carries the bridge's `Dirty` (§7.4).
    pub fn new_upload(&self, cl: Option<u64>) -> Rc<RefCell<UploadBuf>> {
        Rc::new(RefCell::new(UploadBuf::new(cl, self.dirty.clone())))
    }

    /// spec §7.2 (Task 5.2).
    pub fn start(&mut self, _cx: &mut Cx<'_>, _req: StartReq) -> Result<(), StartErr> {
        Ok(())
    }

    /// spec §7.3 (Tasks 5.2/5.4).
    pub fn pump(&mut self, _cx: &mut Cx<'_>, _ev: &mut dyn BridgeEvents) {}

    /// The gateway drained a `Partial` frame: polling the body resumes (Task 5.5).
    pub fn resume(&mut self, _h3: H3ReqId) {}

    /// `H3Closed` (§7.7 cancel; Task 5.5).
    pub fn cancel(&mut self, _cx: &mut Cx<'_>, _h3: H3ReqId) {}

    /// §7.7 shutdown (Task 5.6c).
    pub fn shutdown(&mut self, _cx: &mut Cx<'_>) {}

    /// Returns whether `op` was the bridge's (Task 5.2).
    pub fn on_dial_result(
        &mut self,
        _cx: &mut Cx<'_>,
        _op: DialOpId,
        _r: Result<TcpId, DialError>,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        false
    }

    /// Returns whether `tcp` was the bridge's (Task 5.2).
    pub fn on_tcp_data(
        &mut self,
        _cx: &mut Cx<'_>,
        _tcp: TcpId,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        false
    }

    /// Returns whether `tcp` was the bridge's (Task 5.4).
    pub fn on_tcp_writable(
        &mut self,
        _cx: &mut Cx<'_>,
        _tcp: TcpId,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        false
    }

    /// Returns whether `tcp` was the bridge's (Task 5.2).
    pub fn on_tcp_end(
        &mut self,
        _cx: &mut Cx<'_>,
        _tcp: TcpId,
        _end: TcpEnd,
        _ev: &mut dyn BridgeEvents,
    ) -> bool {
        false
    }

    /// false = not the bridge's timer (Tasks 5.2/5.4/5.6c).
    pub fn on_timer(&mut self, _cx: &mut Cx<'_>, _id: TimerId, _ev: &mut dyn BridgeEvents) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
