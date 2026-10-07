//! QUIC DATAGRAMs: send, mss and the per-connection receive ring (SP2 spec §3.1–§3.2).

use crate::slots::ConnSlot;
use crate::{Transport, conn};
use core::ptr;
use mq_transport_api::ringbuf::RingBuf;
use mq_transport_api::{ConnId, DatagramError, Time};
use xquic_sys::*;

/// SP2 spec §3.2: one receive ring per connection.
const RX_RING: usize = 16 * 1024 * 1024;

/// `XQC_PATH_STATE_ACTIVE` (the enum is private to xquic).
const PATH_ACTIVE: u8 = 2;

fn dgram_err(r: xqc_int_t) -> DatagramError {
    match r.unsigned_abs() {
        XQC_EAGAIN => DatagramError::Blocked,
        XQC_EDGRAM_TOO_LARGE => DatagramError::TooLarge,
        XQC_EDGRAM_NOT_SUPPORTED => DatagramError::NotSupported,
        _ => DatagramError::Conn, // XQC_CLOSING and every other error
    }
}

/// The connection's xquic pointer; `None` for a stale id or a not yet bound client slot.
fn xqc_of(t: &Transport, c: ConnId) -> Option<*mut xqc_connection_t> {
    t.inner
        .conns
        .get(c.slot())
        .map(|s| s.xqc)
        .filter(|x| !x.is_null())
}

pub(crate) fn datagram_send(
    t: &mut Transport,
    now: Time,
    c: ConnId,
    data: &[u8],
) -> Result<(), DatagramError> {
    t.inner.last_now = now;
    let xqc = xqc_of(t, c).ok_or(DatagramError::Stale)?;
    // SAFETY: a live slot holds a valid connection (released in its close notification,
    // before xquic frees it); xquic copies `data` and does not write through the pointer.
    let r = t.with_engine(now, |_, _| unsafe {
        xqc_datagram_send(
            xqc,
            data.as_ptr().cast_mut().cast(),
            data.len(),
            ptr::null_mut(),
            XQC_DATA_QOS_NORMAL,
        )
    });
    if r < 0 { Err(dgram_err(r)) } else { Ok(()) }
}

/// SP2 spec §3.1: the min over active paths, re-read per call.
pub(crate) fn datagram_mss(t: &Transport, c: ConnId) -> usize {
    let Some(xqc) = xqc_of(t, c) else {
        return 0;
    };
    // SAFETY: a plain getter on a live connection.
    let conn_mss = unsafe { xqc_datagram_get_mss(xqc) };
    if conn_mss == 0 {
        return 0;
    }
    let Ok(st) = conn::conn_stats(t, c) else {
        return conn_mss;
    };
    let paths: Vec<(u8, usize)> = st
        .paths
        .iter()
        .map(|p| {
            // SAFETY: as above; an unknown or closing path reports 0.
            let mss = unsafe { xqc_datagram_get_mss_on_path(xqc, p.id) };
            (p.state as u8, mss)
        })
        .collect();
    min_active_mss(conn_mss, &paths)
}

/// The min of the active paths' mss, skipping paths that report 0; `conn_mss` when no active
/// path reported one; 0 when the connection has none.
pub(crate) fn min_active_mss(
    conn_mss: usize,
    paths: &[(u8 /* path_state */, usize /* mss_on_path */)],
) -> usize {
    if conn_mss == 0 {
        return 0;
    }
    paths
        .iter()
        .filter(|&&(state, mss)| state == PATH_ACTIVE && mss != 0)
        .map(|&(_, mss)| mss)
        .min()
        .unwrap_or(conn_mss)
}

/// SP2 spec §3.2: appends `len (LE u16) || data`, allocating the ring on the first datagram.
/// Returns false (and counts the drop) when it does not fit.
pub(crate) fn ring_push(c: &mut ConnSlot, data: &[u8]) -> bool {
    let ring = c.dgram_rx.get_or_insert_with(|| RingBuf::new(RX_RING));
    let need = 2 + data.len();
    match u16::try_from(data.len()) {
        Ok(len) if ring.space() >= need => {
            let w = ring.write_slice();
            w[..2].copy_from_slice(&len.to_le_bytes());
            w[2..need].copy_from_slice(data);
            ring.commit(need);
            true
        }
        _ => {
            c.dgram_rx_dropped += 1;
            false
        }
    }
}

/// SP2 spec §3.1: the oldest datagram into `buf`; one that does not fit is dropped, counted
/// and reported as `Some(0)`. `None` when the ring is empty.
pub(crate) fn ring_pop(c: &mut ConnSlot, buf: &mut [u8]) -> Option<usize> {
    let ring = c.dgram_rx.as_mut().filter(|r| !r.is_empty())?;
    let rec = ring.read_slice();
    let len = usize::from(u16::from_le_bytes([rec[0], rec[1]]));
    let n = match buf.get_mut(..len) {
        Some(dst) => {
            dst.copy_from_slice(&rec[2..2 + len]);
            len
        }
        None => {
            c.dgram_rx_dropped += 1;
            0
        }
    };
    ring.consume(2 + len);
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_send_error_mapping() {
        let e = |code: u32| dgram_err(-(code as xqc_int_t));
        assert_eq!(e(XQC_EAGAIN), DatagramError::Blocked);
        assert_eq!(e(XQC_EDGRAM_TOO_LARGE), DatagramError::TooLarge);
        assert_eq!(e(XQC_EDGRAM_NOT_SUPPORTED), DatagramError::NotSupported);
        assert_eq!(e(XQC_CLOSING), DatagramError::Conn);
        assert_eq!(e(XQC_EPARAM), DatagramError::Conn);
        assert_eq!(dgram_err(-1), DatagramError::Conn);
        assert_eq!(dgram_err(xqc_int_t::MIN), DatagramError::Conn);
    }

    #[test]
    fn min_active_mss_takes_min_over_active_paths() {
        assert_eq!(
            min_active_mss(1200, &[(2, 1100), (2, 1000), (2, 1150)]),
            1000
        );
    }

    #[test]
    fn min_active_mss_ignores_inactive_paths() {
        assert_eq!(min_active_mss(1200, &[(2, 1100), (1, 500), (3, 400)]), 1100);
    }

    #[test]
    fn min_active_mss_skips_zero_paths() {
        assert_eq!(min_active_mss(1200, &[(2, 0), (2, 1100)]), 1100);
        assert_eq!(min_active_mss(1200, &[(2, 0)]), 1200);
    }

    #[test]
    fn min_active_mss_no_active_path_is_conn_mss() {
        assert_eq!(min_active_mss(1200, &[]), 1200);
        assert_eq!(min_active_mss(1200, &[(1, 900)]), 1200);
    }

    #[test]
    fn min_active_mss_conn_zero_is_zero() {
        assert_eq!(min_active_mss(0, &[(2, 1100)]), 0);
    }
}
