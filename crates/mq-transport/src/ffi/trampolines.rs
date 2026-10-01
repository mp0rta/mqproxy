//! Transport and ALPN callbacks (spec §4.4, §4.7, §4.8; plan Task 4.6 table).
//!
//! Every trampoline runs inside `guard` (a panic aborts) and reaches `Inner` only through
//! `clock::current()`. The bookkeeping lives in plain `fn on_*(inner: &mut Inner, ..)`
//! functions that call no xquic function, so the `&mut Inner` they get never spans a call
//! that could re-enter a trampoline, and they are unit-testable without an engine. The
//! xquic getters/setters a trampoline needs run before or after that scope.

use super::{from_sockaddr, guard};
use crate::slots::{ConnSlot, StreamSlot};
use crate::txq::Refusal;
use crate::{Inner, clock, stream};
use core::ffi::{c_int, c_uchar, c_void};
use libc::{sockaddr, socklen_t};
use mq_transport_api::{
    CloseReason, ConnId, ErrType, Event, PathId, SlotId, StreamId, StreamInfo, StreamKind, Time,
};
use std::time::Duration;
use xquic_sys::*;

/// spec §4.2: stream slots per connection.
pub(crate) const STREAM_CEILING: u32 = 8192;
/// spec §4.2: application error code for a connection over the stream ceiling.
pub(crate) const CEILING_CLOSE_CODE: u64 = 0x1001;
/// spec §4.7: absolute lifetime of a provisional connection before closing starts.
pub(crate) const PROVISIONAL_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn slot_of(ud: *mut c_void) -> SlotId {
    SlotId::from_raw(ud as u64)
}

pub(crate) fn ud_of(s: SlotId) -> *mut c_void {
    s.as_raw() as usize as *mut c_void
}

fn conn_id(s: SlotId) -> ConnId {
    ConnId::from_slot(s).expect("live slot ids have a non-zero generation")
}

fn stream_id(s: SlotId) -> StreamId {
    StreamId::from_slot(s).expect("live slot ids have a non-zero generation")
}

/// Runs `f` on the transport that entered xquic; `default` outside a transport call.
fn with_inner<R>(default: R, f: impl FnOnce(&mut Inner) -> R) -> R {
    guard(|| {
        let p = clock::current();
        if p.is_null() {
            return default;
        }
        // SAFETY: `p` is the live Box<Inner> set by `clock::enter`; the method that entered
        // xquic holds no reference into it across the call (spec §4.8), and `f` calls no xquic
        // function, so this is the only reference for its duration.
        f(unsafe { &mut *p })
    })
}

fn now() -> Time {
    Time(clock::monotonic_ts())
}

// ── bookkeeping (spec §4.7, §4.8 slot lifetime tables) ──────────────────

/// The second, authoritative cap check (spec §4.7): refuses at `max_conns` (0 = unlimited),
/// otherwise counts the connection.
pub(crate) fn admit_established(max_conns: u32, n_counted: &mut u32) -> bool {
    if max_conns != 0 && *n_counted >= max_conns {
        return false;
    }
    *n_counted += 1;
    true
}

/// `server_accept`: both caps, then a provisional slot. `None` → refuse.
pub(crate) fn on_server_accept(
    inner: &mut Inner,
    conn: *mut xqc_connection_t,
    cid: xqc_cid_t,
    now: Time,
) -> Option<SlotId> {
    let max = inner.cfg.max_conns;
    if max != 0 && inner.n_counted >= max {
        return None;
    }
    if inner.n_provisional >= 64.max(max.saturating_mul(4)) {
        return None;
    }
    let mut slot = ConnSlot::new(true, conn, cid);
    slot.provisional = true;
    slot.provisional_deadline = Some(now + PROVISIONAL_TIMEOUT);
    inner.n_provisional += 1;
    Some(inner.conns.insert(slot))
}

/// `server_refuse`: release an accepted connection that never got an ALPN slot (never counted).
pub(crate) fn on_server_refuse(inner: &mut Inner, s: SlotId) {
    let Some(slot) = inner.conns.remove(s) else {
        return;
    };
    inner.txq.drop_conn(conn_id(s));
    if slot.provisional {
        inner.n_provisional -= 1;
    }
}

/// ALPN create notification. `false` → return -1. Server: the second cap check; a refusal
/// changes nothing. Client: records the connection pointer and cid.
pub(crate) fn on_conn_create(
    inner: &mut Inner,
    conn: *mut xqc_connection_t,
    cid: Option<xqc_cid_t>,
    s: SlotId,
) -> bool {
    let Inner {
        conns,
        n_counted,
        n_provisional,
        cfg,
        events,
        ..
    } = inner;
    let Some(slot) = conns.get_mut(s) else {
        return false;
    };
    if slot.server {
        if !admit_established(cfg.max_conns, n_counted) {
            return false;
        }
        if slot.provisional {
            *n_provisional -= 1;
        }
        slot.provisional = false;
        slot.provisional_deadline = None;
        slot.counted = true;
        events.push(Event::NewConn(conn_id(s)));
    } else {
        slot.xqc = conn;
        if let Some(cid) = cid {
            slot.cid = cid;
        }
    }
    true
}

/// ALPN close notification: the final release of an admitted (or client) connection.
pub(crate) fn on_conn_close(inner: &mut Inner, s: SlotId, reason: CloseReason) {
    let Some(slot) = inner.conns.remove(s) else {
        return;
    };
    let id = conn_id(s);
    let reason = if slot.closed_locally {
        CloseReason {
            err_type: ErrType::Unknown, // spec §4.2: known only for a close the peer sent
            ..reason
        }
    } else {
        reason
    };
    inner.events.push(Event::ConnClosed(id, reason));
    if slot.counted {
        inner.n_counted -= 1;
    }
    inner.txq.drop_conn(id);
}

/// Peer-initiated stream (null user data): ceiling check BEFORE allocating (spec §4.8).
/// `None` → return -1 (xquic marks the stream DISCARDED).
pub(crate) fn on_peer_stream_create(
    inner: &mut Inner,
    conn: SlotId,
    xs: *mut xqc_stream_t,
    quic_id: u64,
    kind: StreamKind,
) -> Option<SlotId> {
    let c = inner.conns.get_mut(conn)?;
    if c.streams >= STREAM_CEILING {
        c.pending_close = Some(CEILING_CLOSE_CODE);
        return None;
    }
    c.streams += 1;
    let s = inner
        .streams
        .insert(StreamSlot::new(conn, xs, quic_id, kind));
    let cid = conn_id(conn);
    let info = StreamInfo {
        conn: cid,
        quic_id,
        kind,
    };
    inner.events.push(Event::NewStream(cid, stream_id(s), info));
    Some(s)
}

/// Local stream (user data = the slot `open_stream` preallocated): bind, queue nothing.
pub(crate) fn on_local_stream_bind(
    inner: &mut Inner,
    s: SlotId,
    xs: *mut xqc_stream_t,
    quic_id: u64,
    kind: StreamKind,
) -> bool {
    let Some(slot) = inner.streams.get_mut(s) else {
        return false;
    };
    slot.xqc = xs;
    slot.quic_id = quic_id;
    slot.kind = kind;
    true
}

/// Stream close notification: every stream slot is released here (spec §4.8).
pub(crate) fn on_stream_close(inner: &mut Inner, s: SlotId) {
    let Some(slot) = inner.streams.remove(s) else {
        return;
    };
    if let Some(c) = inner.conns.get_mut(slot.conn) {
        c.streams -= 1;
    }
    inner.events.push(Event::StreamClosed(stream_id(s)));
}

/// spec §4.4: `strict` callbacks of a live connection may refuse (EAGAIN + blocked);
/// everything else goes to `(None, 0)` and is dropped when full.
fn on_write(
    inner: &mut Inner,
    ud: SlotId,
    path: u64,
    strict: bool,
    dst: Option<std::net::SocketAddr>,
    pkt: &[u8],
) -> isize {
    let len = pkt.len() as isize;
    let Some(dst) = dst else {
        return len; // not an IP peer: lost, like UDP
    };
    if strict && inner.conns.is_live(ud) {
        let conn = conn_id(ud);
        let key = (Some(conn), PathId(path));
        match inner.txq.push(key, dst, pkt) {
            Ok(()) => len,
            Err(why @ (Refusal::Quota | Refusal::Total)) => {
                inner.txq.record_blocked(conn, key, why);
                XQC_SOCKET_EAGAIN as isize
            }
        }
    } else {
        inner.txq.push_or_drop((None, PathId(0)), dst, pkt);
        len
    }
}

// ── trampolines ─────────────────────────────────────────────────────────

/// # Safety
/// `buf` is null or points to `size` bytes, `peer` to `peerlen` bytes, for this call.
unsafe fn write(
    ud: *mut c_void,
    path: u64,
    strict: bool,
    buf: *const c_uchar,
    size: usize,
    peer: *const sockaddr,
    peerlen: socklen_t,
) -> isize {
    if buf.is_null() {
        return size as isize;
    }
    // SAFETY: guaranteed by the caller; both are copied before return (spec §4.8).
    let (pkt, dst) = unsafe {
        (
            core::slice::from_raw_parts(buf, size),
            from_sockaddr(peer, peerlen),
        )
    };
    with_inner(size as isize, |i| {
        on_write(i, slot_of(ud), path, strict, dst, pkt)
    })
}

pub(super) unsafe extern "C" fn write_socket_ex(
    path_id: u64,
    buf: *const c_uchar,
    size: usize,
    peer: *const sockaddr,
    peerlen: socklen_t,
    ud: *mut c_void,
) -> isize {
    // SAFETY: xquic passes valid buffers for the duration of the callback.
    unsafe { write(ud, path_id, true, buf, size, peer, peerlen) }
}

pub(super) unsafe extern "C" fn write_socket(
    buf: *const c_uchar,
    size: usize,
    peer: *const sockaddr,
    peerlen: socklen_t,
    ud: *mut c_void,
) -> isize {
    // SAFETY: as in `write_socket_ex`.
    unsafe { write(ud, 0, true, buf, size, peer, peerlen) }
}

pub(super) unsafe extern "C" fn conn_send_packet_before_accept(
    buf: *const c_uchar,
    size: usize,
    peer: *const sockaddr,
    peerlen: socklen_t,
    ud: *mut c_void,
) -> isize {
    // SAFETY: as in `write_socket_ex`.
    unsafe { write(ud, 0, false, buf, size, peer, peerlen) }
}

pub(super) unsafe extern "C" fn stateless_reset(
    buf: *const c_uchar,
    size: usize,
    peer: *const sockaddr,
    peerlen: socklen_t,
    _local: *const sockaddr,
    _locallen: socklen_t,
    ud: *mut c_void,
) -> isize {
    // SAFETY: as in `write_socket_ex`.
    unsafe { write(ud, 0, false, buf, size, peer, peerlen) }
}

pub(super) unsafe extern "C" fn server_accept(
    _engine: *mut xqc_engine_t,
    conn: *mut xqc_connection_t,
    cid: *const xqc_cid_t,
    _ud: *mut c_void,
) -> c_int {
    if cid.is_null() {
        return -1;
    }
    // SAFETY: `cid` is valid for this call; copied (spec §4.8 "Borrowed data").
    let cid = unsafe { cid.read_unaligned() };
    let slot = with_inner(None, |i| on_server_accept(i, conn, cid, now()));
    match slot {
        Some(s) => {
            // SAFETY: `conn` is the connection being accepted; a plain setter.
            unsafe { xqc_conn_set_transport_user_data(conn, ud_of(s)) };
            0
        }
        None => -1,
    }
}

pub(super) unsafe extern "C" fn server_refuse(
    _engine: *mut xqc_engine_t,
    _conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    ud: *mut c_void,
) {
    with_inner((), |i| on_server_refuse(i, slot_of(ud)))
}

/// spec §4.9: the peer can retire the user SCID; keep the slot's cid current.
pub(super) unsafe extern "C" fn conn_update_cid_notify(
    _conn: *mut xqc_connection_t,
    _retire: *const xqc_cid_t,
    new_cid: *const xqc_cid_t,
    ud: *mut c_void,
) {
    if new_cid.is_null() {
        return;
    }
    // SAFETY: valid for this call; copied (unaligned read: xquic may hand any pointer).
    let cid = unsafe { new_cid.read_unaligned() };
    with_inner((), |i| {
        if let Some(slot) = i.conns.get_mut(slot_of(ud)) {
            slot.cid = cid;
        }
    })
}

pub(super) unsafe extern "C" fn ready_to_create_path_notify(
    _scid: *const xqc_cid_t,
    ud: *mut c_void,
) {
    with_inner((), |i| {
        if i.conns.is_live(slot_of(ud)) {
            i.events.push_mp_ready(&mut i.conns, conn_id(slot_of(ud)));
        }
    })
}

/// `ud` is the connection's transport user data (the slot from `server_accept` or `connect`).
pub(super) unsafe extern "C" fn conn_create_notify(
    conn: *mut xqc_connection_t,
    cid: *const xqc_cid_t,
    ud: *mut c_void,
    _proto: *mut c_void,
) -> c_int {
    // SAFETY: `cid` is null or valid for this call; copied.
    let cid = (!cid.is_null()).then(|| unsafe { cid.read_unaligned() });
    let s = slot_of(ud);
    if !with_inner(false, |i| on_conn_create(i, conn, cid, s)) {
        return -1;
    }
    // SAFETY: a plain setter on the connection being created.
    unsafe { xqc_conn_set_alp_user_data(conn, ud_of(s)) };
    0
}

/// `proto` is the ALPN user data, set only on admission.
pub(super) unsafe extern "C" fn conn_close_notify(
    conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
    proto: *mut c_void,
) -> c_int {
    // SAFETY: plain getters on the connection being destroyed.
    let (ty, errno) = unsafe { (xqc_conn_get_err_type(conn), xqc_conn_get_errno(conn)) };
    let reason = CloseReason {
        err_type: match ty {
            XQC_CONN_ERR_TYPE_TRANSPORT => ErrType::Transport,
            XQC_CONN_ERR_TYPE_APPLICATION => ErrType::Application,
            _ => ErrType::Unknown,
        },
        code: errno as u32 as u64,
    };
    with_inner((), |i| on_conn_close(i, slot_of(proto), reason));
    0
}

pub(super) unsafe extern "C" fn conn_handshake_finished(
    _conn: *mut xqc_connection_t,
    _ud: *mut c_void,
    proto: *mut c_void,
) {
    with_inner((), |i| {
        if i.conns.is_live(slot_of(proto)) {
            i.events
                .push(Event::ConnEstablished(conn_id(slot_of(proto))));
        }
    })
}

pub(super) unsafe extern "C" fn stream_create_notify(
    xs: *mut xqc_stream_t,
    ud: *mut c_void,
) -> xqc_int_t {
    // SAFETY: plain getters on the stream being created.
    let (quic_id, kind) = unsafe {
        let kind = match xqc_stream_get_direction(xs) {
            XQC_STREAM_UNI => StreamKind::Uni,
            _ => StreamKind::Bidi,
        };
        (xqc_stream_id(xs), kind)
    };
    if ud.is_null() {
        // SAFETY: a plain getter.
        let conn = slot_of(unsafe { xqc_get_conn_alp_user_data_by_stream(xs) });
        match with_inner(None, |i| on_peer_stream_create(i, conn, xs, quic_id, kind)) {
            Some(s) => {
                // SAFETY: a plain setter on the stream being created.
                unsafe { xqc_stream_set_user_data(xs, ud_of(s)) };
                0
            }
            None => -1,
        }
    } else if with_inner(false, |i| {
        on_local_stream_bind(i, slot_of(ud), xs, quic_id, kind)
    }) {
        0
    } else {
        -1
    }
}

pub(super) unsafe extern "C" fn stream_read_notify(
    _xs: *mut xqc_stream_t,
    ud: *mut c_void,
) -> xqc_int_t {
    let s = slot_of(ud);
    if s.is_none() {
        return 0; // a DISCARDED stream's RESET_STREAM (spec §4.8): not ours
    }
    let abandoned = with_inner(None, |i| {
        let abandoned = i.streams.get(s)?.abandoned;
        if !abandoned {
            i.events.push_readable(&mut i.streams, stream_id(s));
        }
        Some(abandoned)
    });
    if abandoned == Some(true) {
        // Calls xqc_stream_recv: no reference into Inner may be held here.
        guard(|| stream::drain(clock::current(), s));
    }
    0
}

pub(super) unsafe extern "C" fn stream_write_notify(
    _xs: *mut xqc_stream_t,
    ud: *mut c_void,
) -> xqc_int_t {
    let s = slot_of(ud);
    if !s.is_none() {
        with_inner((), |i| i.events.push_writable(&mut i.streams, stream_id(s)));
    }
    0
}

pub(super) unsafe extern "C" fn stream_close_notify(
    _xs: *mut xqc_stream_t,
    ud: *mut c_void,
) -> xqc_int_t {
    let s = slot_of(ud);
    if !s.is_none() {
        with_inner((), |i| on_stream_close(i, s));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_transport_api::{CongestionControl, Role, Scheduler, TransportConfig};
    use std::ffi::CString;

    fn inner(max_conns: u32) -> Inner {
        Inner::new(
            TransportConfig {
                role: Role::Server {
                    cert: "c".into(),
                    key: "k".into(),
                },
                alpn: "mqproxy-tcp/1",
                max_conns,
                scheduler: Scheduler::MinRtt,
                cc: CongestionControl::Bbr,
                realtime_offset_us: 0,
            },
            CString::new("mqproxy-tcp/1").unwrap(),
        )
    }

    fn cid() -> xqc_cid_t {
        // SAFETY: a plain C struct; all-zero is valid.
        unsafe { core::mem::zeroed() }
    }

    fn accept(i: &mut Inner) -> SlotId {
        on_server_accept(i, core::ptr::null_mut(), cid(), Time(0)).expect("accepted")
    }

    #[test]
    fn second_cap_check_refuses_when_two_half_open_pass_the_first() {
        // Two connections pass server_accept while nothing is counted yet.
        let mut i = inner(1);
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert_eq!(i.n_provisional, 2);
        let mut n = 0;
        assert!(admit_established(1, &mut n));
        assert!(!admit_established(1, &mut n));
        assert_eq!(n, 1);
        assert!(admit_established(0, &mut n), "0 = unlimited");
        // Through the create notification: the first is admitted, the second refused.
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, a));
        assert!(!on_conn_create(&mut i, core::ptr::null_mut(), None, b));
        assert_eq!((i.n_counted, i.n_provisional), (1, 1));
    }

    #[test]
    fn rejected_admission_keeps_provisional_until_refuse() {
        let mut i = inner(1);
        // Both pass server_accept (half-open, uncounted); `a` then takes the only unit.
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, a));
        assert_eq!(i.n_provisional, 1);
        assert!(!on_conn_create(&mut i, core::ptr::null_mut(), None, b));
        let slot = i.conns.get(b).expect("slot stays live");
        assert!(slot.provisional && !slot.counted);
        assert_eq!(
            slot.provisional_deadline,
            Some(Time(0) + PROVISIONAL_TIMEOUT)
        );
        assert_eq!((i.n_provisional, i.n_counted), (1, 1));
        assert!(i.events.pop(&mut i.streams, &mut i.conns).is_some()); // a's NewConn
        assert!(i.events.pop(&mut i.streams, &mut i.conns).is_none());
        on_server_refuse(&mut i, b);
        assert!(!i.conns.is_live(b));
        assert_eq!((i.n_provisional, i.n_counted), (0, 1));
        on_server_refuse(&mut i, b); // stale: nothing to release twice
        assert_eq!(i.n_provisional, 0);
    }

    #[test]
    fn accept_refuses_at_established_and_provisional_caps() {
        let mut i = inner(1);
        for _ in 0..64 {
            accept(&mut i);
        }
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        let mut i = inner(20); // cap 4 × 20 = 80
        for _ in 0..80 {
            accept(&mut i);
        }
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        let mut i = inner(1);
        i.n_counted = 1;
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        assert_eq!(i.n_provisional, 0);
    }

    #[test]
    fn close_releases_counted_once() {
        let mut i = inner(0);
        let a = accept(&mut i);
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, a));
        let r = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        on_conn_close(&mut i, a, r);
        on_conn_close(&mut i, a, r);
        assert_eq!(i.n_counted, 0);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(
            evs,
            vec![Event::NewConn(conn_id(a)), Event::ConnClosed(conn_id(a), r)]
        );
    }

    #[test]
    fn local_close_reports_unknown_even_after_a_peer_echo() {
        let mut i = inner(0);
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, a));
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, b));
        i.conns.get_mut(a).unwrap().closed_locally = true;
        let echoed = CloseReason {
            err_type: ErrType::Application,
            code: 0x1001,
        };
        on_conn_close(&mut i, a, echoed);
        on_conn_close(&mut i, b, echoed);
        let closes: Vec<_> = std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns))
            .filter_map(|e| match e {
                Event::ConnClosed(c, r) => Some((c, r)),
                _ => None,
            })
            .collect();
        let unknown = CloseReason {
            err_type: ErrType::Unknown,
            code: 0x1001,
        };
        assert_eq!(closes, vec![(conn_id(a), unknown), (conn_id(b), echoed)]);
    }

    #[test]
    fn ceiling_checked_per_callback_not_per_drive() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, c));
        i.conns.get_mut(c).unwrap().streams = STREAM_CEILING - 1;
        let _ = i.events.pop(&mut i.streams, &mut i.conns); // NewConn
        let first = on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 4, StreamKind::Bidi);
        let s = first.expect("the 8192nd stream is admitted");
        assert_eq!(i.streams.len_live(), 1);
        assert!(matches!(
            i.events.pop(&mut i.streams, &mut i.conns),
            Some(Event::NewStream(_, id, _)) if id == stream_id(s)
        ));
        assert_eq!(i.conns.get(c).unwrap().streams, STREAM_CEILING);
        assert_eq!(i.conns.get(c).unwrap().pending_close, None);
        for n in 1..17u64 {
            let r = on_peer_stream_create(
                &mut i,
                c,
                core::ptr::null_mut(),
                4 + 4 * n,
                StreamKind::Bidi,
            );
            assert!(r.is_none());
            let conn = i.conns.get(c).unwrap();
            assert_eq!(conn.streams, STREAM_CEILING);
            assert_eq!(conn.pending_close, Some(CEILING_CLOSE_CODE));
            assert_eq!(i.streams.len_live(), 1, "nothing allocated");
            assert!(
                i.events.pop(&mut i.streams, &mut i.conns).is_none(),
                "nothing queued"
            );
        }
    }

    #[test]
    fn stream_close_releases_and_reports() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(on_conn_create(&mut i, core::ptr::null_mut(), None, c));
        let s =
            on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 0, StreamKind::Uni).unwrap();
        on_stream_close(&mut i, s);
        on_stream_close(&mut i, s);
        assert_eq!(i.conns.get(c).unwrap().streams, 0);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(evs.last(), Some(&Event::StreamClosed(stream_id(s))));
        assert_eq!(evs.len(), 3); // NewConn, NewStream, StreamClosed
    }

    #[test]
    fn write_refuses_only_live_conns_and_drops_the_rest() {
        let mut i = inner(0);
        let c = accept(&mut i);
        let dst = Some("10.0.0.1:1".parse().unwrap());
        let big = vec![0u8; 1200];
        let mut n = 0;
        while on_write(&mut i, c, 0, true, dst, &big) == 1200 {
            n += 1;
        }
        assert_eq!(n * 1200, crate::txq::QUEUE_QUOTA / 1200 * 1200);
        assert_eq!(i.txq.blocked_conns(), vec![conn_id(c)]);
        // "none" user data, and non-strict callbacks: never refused.
        assert_eq!(on_write(&mut i, SlotId::NONE, 0, true, dst, &big), 1200);
        assert_eq!(on_write(&mut i, c, 0, false, dst, &big), 1200);
        assert_eq!(on_write(&mut i, c, 0, true, None, &big), 1200);
    }
}
