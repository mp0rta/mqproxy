//! Per-request state (adoption spec §4.3).

use crate::send::InFlight;
use h3wire::{AbortSource, H3Code, HeaderBlockId};
use mq_transport_api::{ConnId, H3ReqId, H3ReqStats, StreamCloseStats, StreamId, Time};

/// The h3wire terminal event of a request's receive side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Terminal {
    Finished,
    Aborted { code: H3Code, source: AbortSource },
}

pub(crate) struct Req {
    pub(crate) conn: ConnId,
    pub(crate) stream: StreamId,
    pub(crate) quic_id: u64,
    /// The gateway saw `H3Request` (server) or opened it (client).
    pub(crate) known: bool,
    /// h3wire holds request state: from the first sight (server) or a successful
    /// `send_headers` (client).
    pub(crate) core: bool,
    /// The bootstrap is over: the gateway-visible block or a terminal event arrived.
    pub(crate) booted: bool,
    pub(crate) pending_block: Option<HeaderBlockId>,
    pub(crate) terminal: Option<Terminal>,
    /// The gateway has been given `fin` or `Err(Reset)`.
    pub(crate) handed: bool,
    /// The transport read failed with `Reset` before its `StreamPeerReset` popped
    /// (adoption spec §4.4).
    pub(crate) reset_code_pending: bool,
    /// Raw bytes read and not consumed by h3wire; never parsed payload.
    pub(crate) carry: Vec<u8>,
    /// The transport reported FIN after the carry; not yet fed.
    pub(crate) carry_fin: bool,
    /// The transport receive side was read to its end (FIN or `Err(Reset)`): no
    /// retirement read is owed (adoption spec §3).
    pub(crate) fin_read: bool,
    /// Closure condition 1: the transport closed the stream, or its conn (adoption spec
    /// §4.3).
    pub(crate) stream_closed: bool,
    /// The DATA frame `h3_send_body` started and has not written whole (adoption spec §4.5).
    pub(crate) frame: Option<InFlight>,
    /// `h3_finish` (or a bare `fin`) is waiting for `send_data(0, true)` to stop being
    /// `Blocked` behind queued HEADERS bytes.
    pub(crate) finish_latched: bool,
    /// `h3_send_body` returned `Blocked` behind queued HEADERS bytes: `H3Writable` once
    /// they drain.
    pub(crate) writable_wanted: bool,
    /// The peer's STOP_SENDING ended our send side.
    pub(crate) send_stopped: bool,
    /// `now` when the first HEADERS byte was accepted (adoption spec §4.6).
    pub(crate) headers_sent_at: Option<Time>,
    /// `now` when the request started (adoption spec §4.6).
    pub(crate) begin: Time,
    /// Body payload bytes delivered by `h3_recv_body` / accepted by `h3_send_body`.
    pub(crate) recv_body: u64,
    pub(crate) send_body: u64,
    /// The transport's snapshot, kept for a known request only (adoption spec §4.4).
    pub(crate) snapshot: Option<Box<StreamCloseStats>>,
}

impl Req {
    pub(crate) fn new(
        now: Time,
        conn: ConnId,
        stream: StreamId,
        quic_id: u64,
        client: bool,
    ) -> Req {
        Req {
            conn,
            stream,
            quic_id,
            known: client,
            core: !client,
            booted: false,
            pending_block: None,
            terminal: None,
            handed: false,
            reset_code_pending: false,
            carry: Vec::new(),
            carry_fin: false,
            fin_read: false,
            stream_closed: false,
            frame: None,
            finish_latched: false,
            writable_wanted: false,
            send_stopped: false,
            headers_sent_at: None,
            begin: now,
            recv_body: 0,
            send_body: 0,
            snapshot: None,
        }
    }

    pub(crate) fn aborted(&self) -> bool {
        matches!(self.terminal, Some(Terminal::Aborted { .. }))
    }

    /// h3wire ended our send side without a `StreamAborted` (adoption spec §4.5).
    pub(crate) fn stop_send(&mut self) {
        self.send_stopped = true;
        self.frame = None;
        self.finish_latched = false;
    }
}

/// The request id is the request stream's slot (adoption spec §4.1).
pub(crate) fn req_id(s: StreamId) -> H3ReqId {
    H3ReqId::from_slot(s.slot()).expect("a live slot has a nonzero generation")
}

impl Req {
    /// adoption spec §4.6. Without a snapshot, `conn_err` is the `ConnClosed` code of a
    /// request closed by the fan-out.
    pub(crate) fn stats(&self, conn_err: Option<i32>) -> H3ReqStats {
        let (fin_send_us, fin_ack_us, mp_state, stream_err, close_msg) = match &self.snapshot {
            Some(s) => (
                s.fin_send_us,
                s.fin_ack_us,
                s.mp_state,
                s.stream_err,
                s.close_msg.clone(),
            ),
            None => match conn_err {
                Some(e) => (0, 0, 0, e, Some("conn closed".to_string())),
                None => (0, 0, 0, 0, None),
            },
        };
        H3ReqStats {
            send_body: self.send_body,
            recv_body: self.recv_body,
            begin_us: self.begin.as_micros(),
            header_send_us: self.headers_sent_at.map_or(0, Time::as_micros),
            fin_send_us,
            fin_ack_us,
            mp_state,
            stream_err,
            close_msg,
        }
    }
}
