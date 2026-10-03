//! SP3 spec §6: the server gateway — H3 requests authenticated per request
//! and replayed to the origin through the bridge (§7), composed into
//! `Server` (§6.7). `Gateway { origin, core }`: the bridge reports into
//! `core` as a sink parameter, so pumping never borrows twice.

mod intake;

pub use super::origin::{Accepted, BridgeEvents, Completion, OriginFailure, RelayHead};
use super::origin::{BodyKind, Dirty, Origin, OriginCfg, SLICE, SWEEP, StartReq, UploadBuf};
use crate::config::GatewayConfig;
use intake::{Capture, decide};
use mq_http::headers::Method;
use mq_runtime::{Cx, DialError, DialOpId, TcpEnd, TcpId, TimerId};
use mq_transport_api::{ConnId, Event, H3Header, H3ReqId, StreamError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// spec §6.1: where a request is.
enum GwState {
    Intake,
    /// `origin.start` accepted it; the gateway's handle on its upload.
    Origin {
        upload: Rc<RefCell<UploadBuf>>,
    },
    /// The server finished with it (§6.3: its body is drained and discarded).
    Done,
}

/// spec §6.2/§6.6: recorded once intake steps 6–7 passed (`-` in `mq.req` before).
#[allow(dead_code)] // read by `mq.req` (Task 6.4)
struct ReqMeta {
    method: Method,
    authority: Vec<u8>,
    path: Vec<u8>,
    origin_is_tls: bool,
}

/// spec §6.1: one H3 request, until its `H3Closed`.
#[allow(dead_code)] // `conn`, `quic_id`, `meta`, `status`: read by `mq.req` (Task 6.4)
struct GwReq {
    conn: ConnId,
    quic_id: u64,
    authed: bool,
    state: GwState,
    meta: Option<ReqMeta>,
    /// The `:status` the gateway sent; 0 = none yet (§6.5).
    status: u16,
}

/// The gateway's request side: the bridge's `BridgeEvents` sink.
pub struct GwCore {
    cfg: GatewayConfig,
    /// The server's (truncated) token, compared at §6.2 step 4.
    token: Vec<u8>,
    reqs: HashMap<H3ReqId, GwReq>,
    /// spec §6: the most recently accepted H3 conn (the metrics tick's second block).
    last_h3: Option<ConnId>,
}

pub struct Gateway {
    origin: Origin,
    core: GwCore,
}

impl Gateway {
    /// Allocates the bridge's `Dirty` waker.
    pub(super) fn new(
        cfg: GatewayConfig,
        token: Vec<u8>,
        tls: Arc<rustls::ClientConfig>,
    ) -> Gateway {
        let ocfg = OriginCfg {
            connect_timeout: cfg.origin_connect_timeout,
            sweep: SWEEP,
        };
        Gateway {
            origin: Origin::new(ocfg, tls, Arc::new(Dirty::default())),
            core: GwCore {
                cfg,
                token,
                reqs: HashMap::new(),
                last_h3: None,
            },
        }
    }

    #[cfg(feature = "test-support")]
    pub(super) fn core_mut(&mut self) -> &mut GwCore {
        &mut self.core
    }

    pub(super) fn last_h3(&self) -> Option<ConnId> {
        self.core.last_h3
    }

    /// spec §6.7: every routed callback ends here.
    pub(super) fn pump(&mut self, cx: &mut Cx<'_>) {
        self.origin.pump(cx, &mut self.core);
    }

    /// Pumps when the callback was the bridge's.
    fn routed(&mut self, cx: &mut Cx<'_>, mine: bool) -> bool {
        if mine {
            self.pump(cx);
        }
        mine
    }

    pub(super) fn on_new_conn(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        self.core.last_h3 = Some(c);
        self.pump(cx);
    }

    pub(super) fn on_conn_closed(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        if self.core.last_h3 == Some(c) {
            self.core.last_h3 = None;
        }
        self.pump(cx);
    }

    /// `H3Request` / `H3Readable` / `H3Writable` / `H3Closed`.
    pub(super) fn on_h3_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            // spec §6.1; a request already gone (stale) is not entered.
            Event::H3Request(conn, id) => {
                if let Ok(info) = cx.h3_req_info(id) {
                    let r = GwReq {
                        conn,
                        quic_id: info.quic_id,
                        authed: false,
                        state: GwState::Intake,
                        meta: None,
                        status: 0,
                    };
                    self.core.reqs.insert(id, r);
                }
            }
            Event::H3Readable(id) => match self.core.reqs.get(&id).map(|r| &r.state) {
                Some(GwState::Intake) => self.intake(cx, id),
                Some(GwState::Done) => drain(cx, id),
                Some(GwState::Origin { .. }) | None => {} // the upload: Task 6.3
            },
            Event::H3Closed(id, _) => {
                self.core.reqs.remove(&id);
            }
            _ => {}
        }
        self.pump(cx);
    }

    /// spec §6.2: steps 1 and 9 around `decide`.
    fn intake(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        let mut c = Capture::default();
        match cx.h3_recv_headers(id, &mut |n, v| c.each(n, v)) {
            Ok(fin) => c.fin = fin,
            // No header section yet: wait for the next `H3Readable`.
            Err(StreamError::Blocked) => return,
            Err(_) => return self.core.send_error(cx, id, 400, "bad-request"),
        }
        let d = decide(&c, &self.core.token);
        let r = self.core.reqs.get_mut(&id).expect("an Intake request");
        r.authed = d.authed;
        r.meta = d.meta;
        let a = match d.outcome {
            Ok(a) => a,
            Err((status, xmq)) => return self.core.send_error(cx, id, status, xmq),
        };
        let cl = match a.body {
            BodyKind::Known(n) => Some(n),
            BodyKind::None | BodyKind::Unknown => None,
        };
        let upload = self.origin.new_upload(cl);
        upload.borrow_mut().fin = a.body == BodyKind::None;
        let req = StartReq {
            h3: id,
            scheme: a.scheme,
            authority: a.authority,
            path: a.path,
            method: a.method,
            headers: a.headers,
            ver: a.ver,
            body: a.body,
            upload: upload.clone(),
        };
        match self.origin.start(cx, req) {
            Ok(()) => r.state = GwState::Origin { upload },
            Err(_) => self.core.send_error(cx, id, 502, "origin-start-failed"),
        }
    }

    pub(super) fn on_dial_result(
        &mut self,
        cx: &mut Cx<'_>,
        op: DialOpId,
        r: Result<TcpId, DialError>,
    ) -> bool {
        let mine = self.origin.on_dial_result(cx, op, r, &mut self.core);
        self.routed(cx, mine)
    }

    pub(super) fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let mine = self.origin.on_tcp_data(cx, tcp, &mut self.core);
        self.routed(cx, mine);
    }

    pub(super) fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        let mine = self.origin.on_tcp_end(cx, tcp, end, &mut self.core);
        self.routed(cx, mine);
    }

    pub(super) fn on_tcp_writable(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let mine = self.origin.on_tcp_writable(cx, tcp, &mut self.core);
        self.routed(cx, mine);
    }

    /// false = not the bridge's timer.
    pub(super) fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) -> bool {
        let mine = self.origin.on_timer(cx, id, &mut self.core);
        self.routed(cx, mine)
    }
}

impl GwCore {
    /// spec §6.5: the error reply with FIN — a bare 404 to an unauthenticated
    /// request under masquerade — then the request is finished.
    fn send_error(&mut self, cx: &mut Cx<'_>, id: H3ReqId, status: u16, xmq: &str) {
        let Some(r) = self.reqs.get_mut(&id) else {
            return;
        };
        let h = |name: &'static str, value| H3Header {
            name: name.as_bytes(),
            value,
        };
        let masq = self.cfg.masquerade && !r.authed;
        r.status = if masq { 404 } else { status };
        let code = r.status.to_string();
        let mut hs = vec![h(":status", code.as_bytes())];
        if !masq {
            hs.push(h("x-mq-error", xmq.as_bytes()));
        }
        hs.push(h("content-length", b"0"));
        // `Blocked` on this tiny block is treated as sent (as C).
        if !matches!(
            cx.h3_send_headers(id, &hs, true),
            Ok(()) | Err(StreamError::Blocked)
        ) {
            cx.h3_reset(id);
        }
        self.finish(cx, id);
    }

    /// spec §6.3: the server is done with `id`. An upload that has not reached
    /// its fin is aborted (a complete one is left for hyper to drain); the
    /// body is drained and discarded from now on, starting at once (a
    /// coalesced headers + body + FIN gives no further `H3Readable`).
    fn finish(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        let Some(r) = self.reqs.get_mut(&id) else {
            return;
        };
        if let GwState::Origin { upload } = std::mem::replace(&mut r.state, GwState::Done) {
            let mut u = upload.borrow_mut();
            if !u.fin {
                u.abort();
            }
        }
        drain(cx, id);
    }
}

/// spec §6.3: read and discard until `Blocked`, fin or an error — this is
/// what bounds xquic's eager body queue for a finished request (§3.7).
fn drain(cx: &mut Cx<'_>, id: H3ReqId) {
    let mut scratch = [0u8; SLICE];
    while let Ok((n, false)) = cx.h3_recv_body(id, &mut scratch) {
        if n == 0 {
            break; // `(0, false)` is `Blocked` by contract; never spin on it
        }
    }
}

/// spec §6.3–§6.5: filled by Task 6.3 (all but `on_failure`'s `start_failed` arm).
impl BridgeEvents for GwCore {
    fn on_response(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: RelayHead) {}

    fn on_body_frame(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: &[u8]) -> Accepted {
        Accepted::All
    }

    fn on_body_end(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: Completion) {}

    fn on_failure(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, f: OriginFailure, _: bool) {
        // spec §6.2 step 9: the asynchronous socket cap.
        if f.start_failed {
            self.send_error(cx, h3, 502, "origin-start-failed");
        }
    }

    fn want_h3(&mut self, _: &mut Cx<'_>, _: H3ReqId) {}
}
