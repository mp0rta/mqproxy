//! SP3 spec §6: the server gateway — H3 requests authenticated per request
//! and replayed to the origin through the bridge (§7), composed into
//! `Server` (§6.7). `Gateway { origin, core }`: the bridge reports into
//! `core` as a sink parameter, so pumping never borrows twice.

pub use super::origin::{Accepted, BridgeEvents, Completion, OriginFailure, RelayHead};
use super::origin::{Dirty, Origin, OriginCfg, SWEEP};
use crate::config::GatewayConfig;
use mq_http::headers::Method;
use mq_runtime::{Cx, DialError, DialOpId, TcpEnd, TcpId, TimerId};
use mq_transport_api::{ConnId, Event, H3ReqId};
use std::collections::HashMap;
use std::sync::Arc;

/// spec §6.1: where a request is.
#[allow(dead_code)] // Tasks 6.2–6.4
enum GwState {
    Intake,
    Origin,
    /// The server finished with it (§6.3: its body is drained and discarded).
    Done,
}

/// spec §6.2/§6.6: recorded once intake steps 6–7 passed (`-` in `mq.req` before).
#[allow(dead_code)] // Tasks 6.2–6.4
struct ReqMeta {
    method: Method,
    authority: Vec<u8>,
    path: Vec<u8>,
    origin_is_tls: bool,
}

/// spec §6.1: one H3 request, until its `H3Closed`.
#[allow(dead_code)] // Tasks 6.2–6.4
struct GwReq {
    conn: ConnId,
    quic_id: u64,
    authed: bool,
    state: GwState,
    meta: Option<ReqMeta>,
}

/// The gateway's request side: the bridge's `BridgeEvents` sink.
#[allow(dead_code)] // `cfg`: Tasks 6.2–6.4
pub struct GwCore {
    cfg: GatewayConfig,
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
    pub(super) fn new(cfg: GatewayConfig, tls: Arc<rustls::ClientConfig>) -> Gateway {
        let ocfg = OriginCfg {
            connect_timeout: cfg.origin_connect_timeout,
            sweep: SWEEP,
        };
        Gateway {
            origin: Origin::new(ocfg, tls, Arc::new(Dirty::default())),
            core: GwCore {
                cfg,
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
                    };
                    self.core.reqs.insert(id, r);
                }
            }
            Event::H3Closed(id, _) => {
                self.core.reqs.remove(&id);
            }
            _ => {}
        }
        self.pump(cx);
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

/// spec §6.3–§6.5: filled by Tasks 6.2 (`on_failure`'s `start_failed` arm) and 6.3.
impl BridgeEvents for GwCore {
    fn on_response(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: RelayHead) {}

    fn on_body_frame(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: &[u8]) -> Accepted {
        Accepted::All
    }

    fn on_body_end(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: Completion) {}

    fn on_failure(&mut self, _: &mut Cx<'_>, _: H3ReqId, _: OriginFailure, _: bool) {}

    fn want_h3(&mut self, _: &mut Cx<'_>, _: H3ReqId) {}
}
