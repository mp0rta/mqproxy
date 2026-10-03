//! `OriginHost` (test-support): an `App` that owns an `Origin` and a recording
//! `BridgeEvents` sink, so tests drive the bridge as the gateway would — every
//! routed callback, `start` and `cancel` pump afterwards (spec §6.7).

use super::{
    Accepted, BodyKind, BridgeEvents, Completion, Dirty, Origin, OriginCfg, OriginFailure,
    RelayHead, Scheme, StartReq, UPLOAD_CAP, UploadBuf,
};
use mq_http::headers::{HttpVer, parse_method, parse_target};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, SocketOpId, TcpEnd, TcpId, TimerId,
    UdpSocketId,
};
use mq_transport_api::{Event, H3ReqId, SlotId};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

/// The request body a test asks for; the host builds and refills the `UploadBuf`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BodySpec {
    None,
    /// That many bytes under a `content-length`.
    Known(u64),
    /// That many bytes, no `content-length`.
    Unknown(u64),
    /// That many bytes, no `content-length`, and nothing more from H3: no
    /// fin, so hyper's next poll after them finds the upload `Pending`.
    Stalled(u64),
}

/// A request as plain `Send` data; `start` turns it into a `StartReq`.
#[derive(Clone, Debug)]
pub struct StartSpec {
    pub method: &'static str,
    /// `http(s)://authority/path`.
    pub url: String,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub ver: HttpVer,
    pub body: BodySpec,
}

/// Upload byte `i` of every request body: a pattern, so reordering shows.
pub fn upload_byte(i: u64) -> u8 {
    (i % 251) as u8
}

/// One `BridgeEvents` callback with its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEv {
    Response(H3ReqId, RelayHead),
    /// The whole frame offered, whatever the answer.
    Frame(H3ReqId, Vec<u8>),
    End(H3ReqId, Completion),
    Failure(H3ReqId, OriginFailure, bool),
    WantH3(H3ReqId),
}

struct Upload {
    buf: Rc<RefCell<UploadBuf>>,
    /// Bytes buffered so far.
    off: u64,
    total: u64,
    /// `BodySpec::Stalled`: the fin never comes.
    stalled: bool,
}

impl Upload {
    /// Tops the buffer up to `UPLOAD_CAP`, `fin` once the whole body is in.
    fn fill(&mut self) {
        let mut b = self.buf.borrow_mut();
        let room = (UPLOAD_CAP - b.data.len()) as u64;
        let end = self.total.min(self.off + room);
        b.data.extend((self.off..end).map(upload_byte));
        self.off = end;
        b.fin |= end == self.total && !self.stalled;
    }
}

#[derive(Default)]
struct RecordedEvents {
    log: Vec<BridgeEv>,
    accepts: VecDeque<Accepted>,
    uploads: HashMap<H3ReqId, Upload>,
}

impl BridgeEvents for RecordedEvents {
    fn on_response(&mut self, _: &mut Cx<'_>, h3: H3ReqId, head: RelayHead) {
        self.log.push(BridgeEv::Response(h3, head));
    }

    /// Answers from the `push_accept` queue; `All` when it is empty.
    fn on_body_frame(&mut self, _: &mut Cx<'_>, h3: H3ReqId, data: &[u8]) -> Accepted {
        self.log.push(BridgeEv::Frame(h3, data.to_vec()));
        self.accepts.pop_front().unwrap_or(Accepted::All)
    }

    fn on_body_end(&mut self, _: &mut Cx<'_>, h3: H3ReqId, done: Completion) {
        self.log.push(BridgeEv::End(h3, done));
    }

    fn on_failure(&mut self, _: &mut Cx<'_>, h3: H3ReqId, f: OriginFailure, after_head: bool) {
        self.log.push(BridgeEv::Failure(h3, f, after_head));
    }

    fn want_h3(&mut self, _: &mut Cx<'_>, h3: H3ReqId) {
        self.log.push(BridgeEv::WantH3(h3));
        if let Some(u) = self.uploads.get_mut(&h3) {
            u.fill();
        }
    }
}

pub struct OriginHost {
    origin: Origin,
    events: RecordedEvents,
    next: u32,
}

impl OriginHost {
    /// Allocates the bridge's `Dirty`, as `Server::with_gateway` does.
    pub fn new(cfg: OriginCfg, tls: Arc<rustls::ClientConfig>) -> OriginHost {
        OriginHost {
            origin: Origin::new(cfg, tls, Arc::new(Dirty::default())),
            events: RecordedEvents::default(),
            next: 0,
        }
    }

    /// `start_unpumped` + `pump`.
    pub fn start(&mut self, cx: &mut Cx<'_>, spec: StartSpec) -> H3ReqId {
        let h3 = self.start_unpumped(cx, spec);
        self.pump(cx);
        h3
    }

    /// Builds the `StartReq` (the upload filled up to `UPLOAD_CAP`) and calls
    /// `Origin::start` without pumping. Panics on a URL or method the
    /// gateway's intake would have rejected, or on a `StartErr`.
    pub fn start_unpumped(&mut self, cx: &mut Cx<'_>, spec: StartSpec) -> H3ReqId {
        let h3 = H3ReqId::from_slot(SlotId::new(self.next, 1)).expect("generation 1");
        self.next += 1;
        let t = parse_target(spec.url.as_bytes()).expect("StartSpec.url");
        let (body, total) = match spec.body {
            BodySpec::None => (BodyKind::None, 0),
            BodySpec::Known(n) => (BodyKind::Known(n), n),
            BodySpec::Unknown(n) | BodySpec::Stalled(n) => (BodyKind::Unknown, n),
        };
        let cl = match body {
            BodyKind::Known(n) => Some(n),
            _ => None,
        };
        let mut up = Upload {
            buf: self.origin.new_upload(cl),
            off: 0,
            total,
            stalled: matches!(spec.body, BodySpec::Stalled(_)),
        };
        up.fill();
        let req = StartReq {
            h3,
            scheme: if t.scheme == "https" {
                Scheme::Https
            } else {
                Scheme::Http
            },
            authority: t.authority,
            path: t.path,
            method: parse_method(spec.method.as_bytes()).expect("StartSpec.method"),
            headers: spec.headers,
            ver: spec.ver,
            body,
            upload: up.buf.clone(),
        };
        self.events.uploads.insert(h3, up);
        if let Err(e) = self.origin.start(cx, req) {
            panic!("Origin::start({}): {e:?}", spec.url);
        }
        h3
    }

    /// `Origin::cancel` (`H3Closed`) then `pump`.
    pub fn cancel(&mut self, cx: &mut Cx<'_>, h3: H3ReqId) {
        self.origin.cancel(cx, h3);
        self.pump(cx);
    }

    /// Enqueues the next `on_body_frame` answer.
    pub fn push_accept(&mut self, a: Accepted) {
        self.events.accepts.push_back(a);
    }

    /// `Origin::resume` then `pump`.
    pub fn resume(&mut self, cx: &mut Cx<'_>, h3: H3ReqId) {
        self.origin.resume(h3);
        self.pump(cx);
    }

    pub fn pump(&mut self, cx: &mut Cx<'_>) {
        self.origin.pump(cx, &mut self.events);
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub fn origin_mut(&mut self) -> &mut Origin {
        &mut self.origin
    }

    /// The upload bytes handed to `h3`'s `UploadBuf` so far.
    pub fn upload_buffered(&self, h3: H3ReqId) -> u64 {
        self.events.uploads.get(&h3).map_or(0, |u| u.off)
    }

    pub fn events(&self) -> &[BridgeEv] {
        &self.events.log
    }
}

/// Routes per spec §6.7 (each routed callback pumps); everything else is
/// ignored — a timer the bridge declines (the `OriginLoop` limit) included.
impl App for OriginHost {
    fn on_start(&mut self, _: &mut Cx<'_>) {}
    fn on_transport_event(&mut self, _: &mut Cx<'_>, _: Event) {}
    fn on_accepted(&mut self, _: &mut Cx<'_>, _: ListenerTag, _: TcpId, _: AcceptMeta) {}

    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if self.origin.on_tcp_data(cx, tcp, &mut self.events) {
            self.pump(cx);
        }
    }

    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        if self.origin.on_tcp_end(cx, tcp, end, &mut self.events) {
            self.pump(cx);
        }
    }

    fn on_tcp_writable(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if self.origin.on_tcp_writable(cx, tcp, &mut self.events) {
            self.pump(cx);
        }
    }

    fn on_dial_result(&mut self, cx: &mut Cx<'_>, op: DialOpId, r: Result<TcpId, DialError>) {
        if self.origin.on_dial_result(cx, op, r, &mut self.events) {
            self.pump(cx);
        }
    }

    fn on_resolve_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<SocketAddr, DialError>) {
    }

    fn on_udp_socket(
        &mut self,
        _: &mut Cx<'_>,
        _: SocketOpId,
        _: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
    }

    fn on_udp_rx(&mut self, _: &mut Cx<'_>, _: UdpSocketId, _: SocketAddr, _: &[u8]) {}

    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        if self.origin.on_timer(cx, id, &mut self.events) {
            self.pump(cx);
        }
    }

    fn on_shutdown(&mut self, _: &mut Cx<'_>) {}
}

#[cfg(test)]
mod tests {
    use super::super::{OriginConnId, OriginProto, SWEEP, TlsOutcome};
    use super::*;
    use mq_runtime::Shard;
    use mq_runtime::testing::ScriptedTransport;
    use mq_transport_api::Time;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn shard() -> Shard<ScriptedTransport, OriginHost> {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let cfg = OriginCfg {
            connect_timeout: Duration::from_secs(10),
            sweep: SWEEP,
        };
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        Shard::new(t, OriginHost::new(cfg, Arc::new(tls)), addr, 7)
    }

    const NOW: Time = Time(1_000_000);

    fn get(url: &str, body: BodySpec) -> StartSpec {
        StartSpec {
            method: "GET",
            url: url.into(),
            headers: Vec::new(),
            ver: HttpVer::Default,
            body,
        }
    }

    #[test]
    fn origin_host_records_events() {
        let mut sh = shard();
        sh.with_app(NOW, |host, cx| {
            let h3 = host.start(cx, get("http://o.test/", BodySpec::None));
            host.push_accept(Accepted::Partial(2));
            host.push_accept(Accepted::Partial(0));
            let head = RelayHead {
                status: 200,
                version: "http/1.1",
                proto: OriginProto::H1,
                headers: vec![(b"a".to_vec(), b"b".to_vec())],
                content_encoding: None,
                cl: Some(4),
            };
            let done = Completion {
                reused: false,
                connect_ms: 3,
                tls: TlsOutcome::Na,
                delivered: 4,
                cl: Some(4),
            };
            let fail = OriginFailure {
                curl: 56,
                status: 502,
                tls: TlsOutcome::Na,
                proto: Some(OriginProto::H1),
                upstream_protocol: false,
                start_failed: false,
                cause: "x".into(),
            };
            let ev = &mut host.events;
            ev.on_response(cx, h3, head.clone());
            assert_eq!(ev.on_body_frame(cx, h3, b"abcd"), Accepted::Partial(2));
            assert_eq!(ev.on_body_frame(cx, h3, b"cd"), Accepted::Partial(0));
            assert_eq!(
                ev.on_body_frame(cx, h3, b"cd"),
                Accepted::All,
                "an empty queue answers All"
            );
            ev.want_h3(cx, h3);
            ev.on_body_end(cx, h3, done.clone());
            ev.on_failure(cx, h3, fail.clone(), true);
            assert_eq!(
                host.events(),
                &[
                    BridgeEv::Response(h3, head),
                    BridgeEv::Frame(h3, b"abcd".to_vec()),
                    BridgeEv::Frame(h3, b"cd".to_vec()),
                    BridgeEv::Frame(h3, b"cd".to_vec()),
                    BridgeEv::WantH3(h3),
                    BridgeEv::End(h3, done),
                    BridgeEv::Failure(h3, fail, true),
                ]
            );
            let h3b = host.start(cx, get("https://o.test/", BodySpec::None));
            assert_ne!(h3, h3b, "each start mints a fresh id");
        });
    }

    #[test]
    fn origin_host_refills_upload_from_body_spec() {
        const MIB: u64 = 1024 * 1024;
        let mut sh = shard();
        sh.with_app(NOW, |host, cx| {
            let h3 = host.start(cx, get("http://o.test/up", BodySpec::Known(MIB)));
            let buf = host.events.uploads[&h3].buf.clone();
            assert_eq!(buf.borrow().cl, Some(MIB));
            let mut got = Vec::new();
            let mut refills = 0;
            while !buf.borrow().fin {
                let mut b = buf.borrow_mut();
                assert_eq!(b.data.len(), UPLOAD_CAP, "topped up to the cap");
                // The first round leaves 10 bytes: the refill only tops up.
                let n = b.data.len() - if refills == 0 { 10 } else { 0 };
                got.extend(b.data.drain(..n));
                drop(b);
                host.events.want_h3(cx, h3);
                refills += 1;
            }
            assert_eq!(refills, 4, "256 KiB + 3 refills - 10 bytes, then fin");
            assert_eq!(buf.borrow().data.len(), 10);
            got.extend(buf.borrow_mut().data.drain(..));
            host.events.want_h3(cx, h3);
            assert!(buf.borrow().data.is_empty(), "nothing past the body");
            assert!(buf.borrow().fin);
            let want: Vec<u8> = (0..MIB).map(upload_byte).collect();
            assert!(got == want, "the body is the pattern, in order");

            let none = host.start(cx, get("http://o.test/", BodySpec::None));
            let b = host.events.uploads[&none].buf.borrow();
            assert!(b.fin && b.data.is_empty() && b.cl.is_none(), "bodiless");
            drop(b);
            let unk = host.start(cx, get("http://o.test/", BodySpec::Unknown(5)));
            let b = host.events.uploads[&unk].buf.borrow();
            assert!(
                b.fin && b.data.len() == 5 && b.cl.is_none(),
                "unknown length"
            );
            drop(b);
            let st = host.start(cx, get("http://o.test/", BodySpec::Stalled(5)));
            host.events.uploads[&st].buf.borrow_mut().data.clear();
            host.events.want_h3(cx, st);
            let b = host.events.uploads[&st].buf.borrow();
            assert!(!b.fin && b.data.is_empty() && b.cl.is_none(), "stalled");
        });
    }

    #[test]
    fn accessors_on_empty_origin() {
        let mut sh = shard();
        sh.with_app(NOW, |host, _| {
            let o = host.origin();
            let id = OriginConnId {
                index: 0,
                generation: 1,
            };
            let h3 = H3ReqId::from_slot(SlotId::new(0, 1)).expect("generation 1");
            assert_eq!(o.pool_len(), 0);
            assert_eq!(o.closing_len(), 0);
            assert_eq!(o.task_count(), 0);
            assert!(!o.pipe_dead(id));
            assert!(!o.idle_timer_armed());
            assert_eq!(o.record_state(h3), None);
            assert_eq!(o.ended_records(id), 0);
            assert_eq!(o.conn_of(h3), None);
            assert_eq!(o.connect_ms(id), None);
            host.origin_mut().hold_public_poll(id, true); // unknown conn: no-op
            host.origin_mut()
                .spawn_test_task(Box::pin(std::future::pending()));
            assert_eq!(
                host.origin().task_count(),
                1,
                "the test task is on the executor"
            );
        });
    }
}
