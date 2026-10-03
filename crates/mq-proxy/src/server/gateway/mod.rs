//! SP3 spec §6: the server gateway — H3 requests authenticated per request
//! and replayed to the origin through the bridge (§7), composed into
//! `Server` (§6.7). `Gateway { origin, core }`: the bridge reports into
//! `core` as a sink parameter, so pumping never borrows twice.

mod intake;

pub use super::origin::{Accepted, BridgeEvents, Completion, OriginFailure, RelayHead};
use super::origin::{
    BodyKind, Dirty, Origin, OriginCfg, SLICE, SWEEP, StartReq, UPLOAD_CAP, UploadBuf,
};
use crate::client::gateway::body_check_applies;
use crate::config::GatewayConfig;
use intake::{Capture, decide};
use mq_http::headers::Method;
use mq_runtime::{Cx, DialError, DialOpId, TcpEnd, TcpId, TimerId};
use mq_transport_api::{ConnId, Event, H3Header, H3ReqId, StreamError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

type Headers = Vec<(Vec<u8>, Vec<u8>)>;

/// spec §6.1: where a request is.
enum GwState {
    Intake,
    /// `origin.start` accepted it: the relay (§6.3, §6.4).
    Origin {
        upload: Rc<RefCell<UploadBuf>>,
        /// H3 body bytes taken into `upload` so far (the §6.3 CL checks).
        recvd: u64,
        /// The response head while `h3_send_headers` is `Blocked` (§6.4).
        head: Option<Headers>,
        /// The rest of the body frame `h3_send_body` did not take; the
        /// bridge polls no further frame until it is out (§6.4).
        pending: Vec<u8>,
        /// The origin body ended and passed the body check: `h3_finish`
        /// once `head` and `pending` are out.
        fin_due: bool,
    },
    /// The server finished with it (§6.3: its body is drained and discarded).
    Done,
}

/// spec §6.2/§6.6: recorded once intake steps 6–7 passed (`-` in `mq.req` before).
struct ReqMeta {
    method: Method,
    authority: Vec<u8>,
    #[allow(dead_code)] // read by `mq.req` (Task 6.4)
    path: Vec<u8>,
    #[allow(dead_code)] // read by `mq.req` (Task 6.4)
    origin_is_tls: bool,
}

/// spec §6.1: one H3 request, until its `H3Closed`.
struct GwReq {
    #[allow(dead_code)] // read by `mq.req` (Task 6.4)
    conn: ConnId,
    #[allow(dead_code)] // read by `mq.req` (Task 6.4)
    quic_id: u64,
    authed: bool,
    state: GwState,
    meta: Option<ReqMeta>,
    /// `mq.req`'s status: the one `send_error` sent, or the raw origin
    /// status (a `:status` outside 100..=599 is sent as 502, §6.4); 0 = none yet.
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
                // A coalesced headers + body notification: the body is read now.
                Some(GwState::Intake) => {
                    self.intake(cx, id);
                    self.upload(cx, id);
                }
                Some(GwState::Origin { .. }) => self.upload(cx, id),
                Some(GwState::Done) => drain(cx, id),
                None => {}
            },
            // spec §6.4: the held head and frame, then the bridge polls on.
            Event::H3Writable(id) => {
                if self.core.flush(cx, id) {
                    self.origin.resume(id);
                }
            }
            // spec §6.6 (`mq.req`: Task 6.4): a live origin request is cancelled.
            Event::H3Closed(id, _) => {
                self.core.reqs.remove(&id);
                self.origin.cancel(cx, id);
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
            Ok(()) => {
                r.state = GwState::Origin {
                    upload,
                    recvd: 0,
                    head: None,
                    pending: Vec::new(),
                    fin_due: false,
                }
            }
            Err(_) => self.core.send_error(cx, id, 502, "origin-start-failed"),
        }
    }

    /// spec §6.3 on `H3Readable`: a peer reset or a dead conn ends the
    /// request, its origin record included.
    fn upload(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        if self.core.fill(cx, id) {
            self.origin.cancel(cx, id);
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
        if matches!(r.state, GwState::Done) {
            return; // one answer per request
        }
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

    /// Never a fake FIN: the relay of a live origin exchange ends in a reset
    /// (a finished request is left alone).
    fn reset(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        if let Some(GwReq {
            state: GwState::Origin { .. },
            ..
        }) = self.reqs.get(&id)
        {
            cx.h3_reset(id);
            self.finish(cx, id);
        }
    }

    /// spec §6.3: `h3_recv_body` into the upload until `Blocked`, the
    /// 256 KiB bound or `fin`. A body shorter or longer than its declared
    /// `content-length` aborts the upload (hyper fails the origin request)
    /// and resets the request. Returns true when a receive error (`Reset`,
    /// `Conn`, `Stale`) ended it: the caller cancels the origin record.
    fn fill(&mut self, cx: &mut Cx<'_>, id: H3ReqId) -> bool {
        let Some(GwReq {
            state: GwState::Origin { upload, recvd, .. },
            ..
        }) = self.reqs.get_mut(&id)
        else {
            return false;
        };
        let mut buf = [0u8; SLICE];
        let bad = loop {
            let mut u = upload.borrow_mut();
            let room = UPLOAD_CAP - u.data.len();
            if u.fin || u.is_aborted() || room == 0 {
                break None;
            }
            match cx.h3_recv_body(id, &mut buf[..room.min(SLICE)]) {
                Ok((n, fin)) => {
                    *recvd += n as u64;
                    if u.cl.is_some_and(|cl| *recvd > cl || (fin && *recvd < cl)) {
                        break Some(false);
                    }
                    u.data.extend(&buf[..n]);
                    u.fin = fin;
                    if fin || n == 0 {
                        break None; // `(0, false)` is `Blocked` by contract
                    }
                }
                Err(StreamError::Blocked) => break None,
                Err(_) => break Some(true),
            }
        };
        let Some(ended) = bad else {
            return false;
        };
        self.reset(cx, id);
        ended
    }

    /// spec §6.4: the held head, then `pending`, then the FIN when due.
    /// Returns whether everything is out (the bridge may poll on).
    fn flush(&mut self, cx: &mut Cx<'_>, id: H3ReqId) -> bool {
        let Some(GwReq {
            state:
                GwState::Origin {
                    head,
                    pending,
                    fin_due,
                    ..
                },
            ..
        }) = self.reqs.get_mut(&id)
        else {
            return false;
        };
        let fin = *fin_due;
        match send_out(cx, id, head, pending, fin) {
            Ok(false) => false,
            Ok(true) => {
                if fin {
                    self.finish(cx, id);
                }
                true
            }
            Err(_) => {
                self.reset(cx, id);
                false
            }
        }
    }

    /// spec §6.3: the server is done with `id`. An upload that has not reached
    /// its fin is aborted (a complete one is left for hyper to drain); the
    /// body is drained and discarded from now on, starting at once (a
    /// coalesced headers + body + FIN gives no further `H3Readable`).
    fn finish(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        let Some(r) = self.reqs.get_mut(&id) else {
            return;
        };
        if let GwState::Origin { upload, .. } = std::mem::replace(&mut r.state, GwState::Done) {
            let mut u = upload.borrow_mut();
            if !u.fin {
                u.abort();
            }
        }
        drain(cx, id);
    }
}

#[cfg(feature = "test-support")]
impl GwCore {
    /// `GwReq.status` (the raw origin status once a head arrived, §6.4).
    pub fn status(&self, h3: H3ReqId) -> Option<u16> {
        self.reqs.get(&h3).map(|r| r.status)
    }

    /// The request's upload while its origin side is live.
    pub fn upload(&self, h3: H3ReqId) -> Option<Rc<RefCell<UploadBuf>>> {
        match &self.reqs.get(&h3)?.state {
            GwState::Origin { upload, .. } => Some(upload.clone()),
            _ => None,
        }
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

/// The held head, then `pending`, then `h3_finish` when `fin`: `Ok(true)`
/// when everything went out, `Ok(false)` to wait for `H3Writable`.
fn send_out(
    cx: &mut Cx<'_>,
    id: H3ReqId,
    head: &mut Option<Headers>,
    pending: &mut Vec<u8>,
    fin: bool,
) -> Result<bool, StreamError> {
    if let Some(hs) = head {
        let hs: Vec<_> = hs
            .iter()
            .map(|(name, value)| H3Header { name, value })
            .collect();
        match cx.h3_send_headers(id, &hs, false) {
            Ok(()) => *head = None,
            Err(StreamError::Blocked) => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    if !pending.is_empty() {
        match cx.h3_send_body(id, pending, false) {
            Ok(n) => drop(pending.drain(..n)),
            Err(StreamError::Blocked) => return Ok(false),
            Err(e) => return Err(e),
        }
        if !pending.is_empty() {
            return Ok(false);
        }
    }
    if fin {
        cx.h3_finish(id)?;
    }
    Ok(true)
}

/// spec §6.3–§6.5. A request no longer `Origin` (finished, or gone at
/// `H3Closed`) ignores the bridge.
impl BridgeEvents for GwCore {
    /// spec §6.4: the head goes out at once, `:status` clamped to 100..=599.
    fn on_response(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, head: RelayHead) {
        let Some(r) = self.reqs.get_mut(&h3) else {
            return;
        };
        let GwState::Origin { head: held, .. } = &mut r.state else {
            return;
        };
        r.status = head.status;
        let status = match head.status {
            s @ 100..=599 => s,
            _ => 502,
        };
        let mut hs: Headers = vec![
            (b":status".to_vec(), status.to_string().into_bytes()),
            (b"x-mq-origin-protocol".to_vec(), head.version.into()),
        ];
        hs.extend(head.headers);
        *held = Some(hs);
        self.flush(cx, h3);
    }

    /// spec §6.4: what `h3_send_body` does not take waits in `pending`.
    fn on_body_frame(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, data: &[u8]) -> Accepted {
        let Some(GwReq {
            state: GwState::Origin { head, pending, .. },
            ..
        }) = self.reqs.get_mut(&h3)
        else {
            return Accepted::All; // discarded
        };
        debug_assert!(pending.is_empty(), "the bridge holds the next frame");
        let n = match head {
            Some(_) => Ok(0),
            None => match cx.h3_send_body(h3, data, false) {
                Err(StreamError::Blocked) => Ok(0),
                r => r,
            },
        };
        match n {
            Ok(n) if n == data.len() => Accepted::All,
            Ok(n) => {
                pending.extend_from_slice(&data[n..]);
                Accepted::Partial(n)
            }
            Err(_) => {
                self.reset(cx, h3);
                Accepted::All
            }
        }
    }

    /// spec §6.4 body check (Review Focus 5): a declared `content-length`
    /// not met on a response that may carry a body is a truncation → reset.
    fn on_body_end(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, done: Completion) {
        let Some(r) = self.reqs.get_mut(&h3) else {
            return;
        };
        let applies = r
            .meta
            .as_ref()
            .is_some_and(|m| body_check_applies(&m.method, r.status));
        let GwState::Origin { fin_due, .. } = &mut r.state else {
            return;
        };
        if applies && done.cl.is_some_and(|cl| done.delivered < cl) {
            return self.reset(cx, h3);
        }
        *fin_due = true;
        self.flush(cx, h3);
    }

    /// spec §6.5: before the head, `send_error` (§6.2 step 9's socket cap,
    /// §7.5's `upstream-protocol`, else `curl:<n>`); after it, a reset.
    fn on_failure(&mut self, cx: &mut Cx<'_>, h3: H3ReqId, f: OriginFailure, after_head: bool) {
        if f.start_failed {
            return self.send_error(cx, h3, 502, "origin-start-failed");
        }
        if let Some(r) = self.reqs.get(&h3)
            && let (GwState::Origin { .. }, Some(m)) = (&r.state, &r.meta)
            && f.curl != 0
        {
            let authority = String::from_utf8_lossy(&m.authority);
            log::warn!(
                "mq_gw_server: origin {authority} curl:{} ({})",
                f.curl,
                f.cause
            );
        }
        if after_head {
            self.reset(cx, h3);
        } else if f.upstream_protocol {
            self.send_error(cx, h3, 502, "upstream-protocol");
        } else {
            self.send_error(cx, h3, f.status, &format!("curl:{}", f.curl));
        }
    }

    fn want_h3(&mut self, cx: &mut Cx<'_>, h3: H3ReqId) {
        // A receive error aborts the upload: hyper ends the record itself.
        self.fill(cx, h3);
    }
}
