//! spec §5: the per-connection datagram MSS cache and the fragment send policy,
//! shared by both roles.

use super::{Counters, MSS_REFRESH, UDP_MSG_HDR};
use mq_runtime::Cx;
use mq_transport_api::ConnId;
use mq_wire::udp_msg::{SplitError, split};

/// Stack room for one datagram; a larger MSS falls back to the heap.
const SCRATCH: usize = 2048;

/// One `datagram_mss` reading per connection, refreshed when it is 0 or after
/// `MSS_REFRESH` successful emits (the countdown moves only on success).
#[derive(Default)]
pub struct MssCache {
    value: usize,
    countdown: u32,
}

impl MssCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Payload bytes per datagram (`mss − 9`); 0 when the MSS is unusable (`mss ≤ 9`).
    pub fn payload(&mut self, cx: &Cx<'_>, conn: ConnId) -> usize {
        if self.value == 0 || self.countdown == 0 {
            self.value = cx.datagram_mss(conn);
            self.countdown = MSS_REFRESH;
        }
        self.value.saturating_sub(UDP_MSG_HDR)
    }

    /// One datagram was sent successfully.
    pub fn emitted(&mut self) {
        self.countdown = self.countdown.saturating_sub(1);
    }

    /// Forgets the reading (the connection changed); the next `payload` re-queries.
    pub fn invalidate(&mut self) {
        self.value = 0;
    }
}

/// Fragments `send_packet` got out and fragments whose `datagram_send` failed.
/// Both 0 means nothing was attempted (unusable MSS, or too many fragments); otherwise
/// `frags_ok + failed` is the fragment count, so a caller that advances `packet_id`
/// only for a split that ran can tell by `frags_ok + failed > 0`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SendOutcome {
    pub frags_ok: u8,
    pub failed: u8,
}

/// Splits `payload` into `hdr || slice` datagrams on `conn` and counts per spec §5.
/// A failing fragment never aborts the rest.
pub fn send_packet(
    cx: &mut Cx<'_>,
    conn: ConnId,
    mss: &mut MssCache,
    sid: u32,
    packet_id: u16,
    payload: &[u8],
    c: &mut Counters,
) -> SendOutcome {
    let mut out = SendOutcome {
        frags_ok: 0,
        failed: 0,
    };
    let mss_payload = mss.payload(cx, conn);
    if mss_payload == 0 {
        c.drops_send_fail += 1;
        return out;
    }
    let mut stack = [0u8; SCRATCH];
    let mut heap;
    let need = UDP_MSG_HDR + mss_payload.min(payload.len());
    let buf: &mut [u8] = if need <= SCRATCH {
        &mut stack[..need]
    } else {
        heap = vec![0u8; need];
        &mut heap
    };
    let res = split(sid, packet_id, payload, mss_payload, |h, slice| {
        let (head, body) = buf.split_at_mut(UDP_MSG_HDR);
        h.encode(head.try_into().expect("UDP_MSG_HDR bytes"));
        body[..slice.len()].copy_from_slice(slice);
        match cx.datagram_send(conn, &buf[..UDP_MSG_HDR + slice.len()]) {
            Ok(()) => {
                out.frags_ok += 1;
                mss.emitted();
            }
            Err(_) => {
                out.failed += 1;
                c.drops_send_fail += 1;
            }
        }
    });
    match res {
        // A split with at most one surviving fragment adds nothing.
        Ok(()) if out.frags_ok > 1 => c.frags_sent += u32::from(out.frags_ok),
        Ok(()) => {}
        Err(SplitError::TooManyFrags) => c.drops_oversize += 1,
        // Unreachable (`mss_payload > 0` above); counted as the unusable-MSS drop it would be.
        Err(SplitError::ZeroMss) => c.drops_send_fail += 1,
    }
    out
}
