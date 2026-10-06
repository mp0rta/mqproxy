//! Per-request state (adoption spec §4.3).

use h3wire::{AbortSource, H3Code, HeaderBlockId};
use mq_transport_api::{ConnId, H3ReqId, H3ReqStats, StreamId};

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
    // send-side fields: Task C4; stats: Task C6
}

impl Req {
    pub(crate) fn new(conn: ConnId, stream: StreamId, quic_id: u64, client: bool) -> Req {
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
        }
    }

    pub(crate) fn aborted(&self) -> bool {
        matches!(self.terminal, Some(Terminal::Aborted { .. }))
    }
}

/// The request id is the request stream's slot (adoption spec §4.1).
pub(crate) fn req_id(s: StreamId) -> H3ReqId {
    H3ReqId::from_slot(s.slot()).expect("a live slot has a nonzero generation")
}

/// Task C6 fills these from `StreamCloseStats`.
pub(crate) fn no_stats() -> H3ReqStats {
    H3ReqStats {
        send_body: 0,
        recv_body: 0,
        begin_us: 0,
        header_send_us: 0,
        fin_send_us: 0,
        fin_ack_us: 0,
        mp_state: 0,
        stream_err: 0,
        close_msg: None,
    }
}
