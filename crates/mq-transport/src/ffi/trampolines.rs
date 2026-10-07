// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
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
use crate::{Inner, clock, datagram, stream};
use core::ffi::{c_int, c_uchar, c_void};
use libc::{sockaddr, socklen_t};
use mq_transport_api::{
    CloseReason, ConnId, ConnProto, ErrType, Event, PathId, SlotId, StreamCloseStats, StreamId,
    StreamInfo, StreamKind, Time,
};
use std::time::Duration;
use xquic_sys::*;

/// spec §4.2: stream slots per connection.
pub(crate) const STREAM_CEILING: u32 = 8192;
/// spec §4.2: application error code for a connection over the stream ceiling.
pub(crate) const CEILING_CLOSE_CODE: u64 = 0x1001;
/// spec §4.7: application error code for an unauthenticated connection evicted at the cap.
pub(crate) const EVICT_CLOSE_CODE: u64 = 0x1002;
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

/// spec §4.7: floor of the provisional cap and of the evicting backlog.
const BACKLOG_MIN: u32 = 64;

/// spec §4.7: provisional conns, and separately conns being evicted, are each capped here.
fn backlog_cap(max_conns: u32) -> u32 {
    BACKLOG_MIN.max(max_conns.saturating_mul(4))
}

/// The `max_conns` cap (spec §4.7; 0 = unlimited). `Ok(None)`: room. `Ok(Some(v))`: full, but
/// admitting is allowed by evicting `v`, the oldest counted connection that is neither
/// authenticated nor already evicting. `Err(())`: full. Evicting connections stay counted
/// until their close notification but do not hold the cap.
fn cap_check(inner: &Inner) -> Result<Option<SlotId>, ()> {
    let max = inner.cfg.max_conns;
    if max == 0 || inner.n_counted < max {
        return Ok(None);
    }
    // ponytail: two O(conns) scans, only at the cap; conns ≈ max_conns there.
    let live = inner.conns.iter_live();
    let evicting = live.filter(|(_, c)| c.evicting).count() as u32;
    if inner.n_counted - evicting < max {
        return Ok(None);
    }
    // Victims linger ~3 PTO in xquic, and a conn is created at ALPN selection (before the
    // handshake completes): without this bound a ClientHello burst grows them unboundedly.
    if evicting >= backlog_cap(max) {
        return Err(());
    }
    let victim = inner
        .conns
        .iter_live()
        .filter(|(_, c)| c.counted && !c.authed && !c.evicting)
        .min_by_key(|(_, c)| c.admitted);
    victim.map(|(s, _)| Some(s)).ok_or(())
}

/// `server_accept`: both caps, then a provisional slot. `None` → refuse. The eviction itself
/// waits for the create notification (ALPN selected from the ClientHello).
pub(crate) fn on_server_accept(
    inner: &mut Inner,
    conn: *mut xqc_connection_t,
    cid: xqc_cid_t,
    now: Time,
) -> Option<SlotId> {
    let max = inner.cfg.max_conns;
    cap_check(inner).ok()?;
    if inner.n_provisional >= backlog_cap(max) {
        return None;
    }
    let mut slot = ConnSlot::new(true, conn, cid);
    slot.provisional = true;
    slot.provisional_deadline = Some(now + PROVISIONAL_TIMEOUT);
    inner.n_provisional += 1;
    Some(inner.conns.insert(slot))
}

/// `server_refuse`: release an accepted connection without an ALPN close notification. A
/// counted one is an H3 connection whose xquic-side create failed after ours admitted it
/// (spec §3.3): balance the count and report the close its `NewConn` promised.
pub(crate) fn on_server_refuse(inner: &mut Inner, s: SlotId) {
    let Some(slot) = inner.conns.remove(s) else {
        return;
    };
    inner.txq.drop_conn(conn_id(s));
    if slot.provisional {
        inner.n_provisional -= 1;
    }
    if slot.counted {
        inner.n_counted -= 1;
        let reason = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        inner.events.push(Event::ConnClosed(conn_id(s), reason));
    }
}

/// ALPN (raw or H3) create notification. `false` → return -1. Server: the second,
/// authoritative cap check, evicting a victim through the next `drive` (no xquic call here);
/// a refusal changes nothing. Client: records the connection pointer and cid.
pub(crate) fn on_conn_create(
    inner: &mut Inner,
    conn: *mut xqc_connection_t,
    cid: Option<xqc_cid_t>,
    s: SlotId,
    proto: ConnProto,
) -> bool {
    let Some(server) = inner.conns.get(s).map(|c| c.server) else {
        return false;
    };
    if server {
        match cap_check(inner) {
            Err(()) => return false,
            Ok(Some(v)) => {
                let v = inner.conns.get_mut(v).expect("a live victim");
                v.evicting = true;
                v.pending_close.get_or_insert(EVICT_CLOSE_CODE);
                log::info!("mq_transport: conn cap reached, evicting an unauthenticated conn");
            }
            Ok(None) => {}
        }
    }
    let Inner {
        conns,
        n_counted,
        n_provisional,
        n_admitted,
        events,
        ..
    } = inner;
    let slot = conns.get_mut(s).expect("checked live");
    if server {
        *n_counted += 1;
        *n_admitted += 1;
        slot.admitted = *n_admitted;
        if slot.provisional {
            *n_provisional -= 1;
        }
        slot.provisional = false;
        slot.provisional_deadline = None;
        slot.counted = true;
        events.push(Event::NewConn(conn_id(s), proto));
    } else {
        slot.xqc = conn;
        if let Some(cid) = cid {
            slot.cid = cid;
        }
    }
    slot.proto = proto;
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
    if slot.dgram_rx_dropped > 0 {
        let n = slot.dgram_rx_dropped;
        log::info!("mq_transport: conn {} dgram_rx_dropped={n}", id.index());
    }
    inner.events.push(Event::ConnClosed(id, reason));
    if slot.counted {
        inner.n_counted -= 1;
    }
    inner.txq.drop_conn(id);
}

/// A peer-opened stream or H3 request: the per-connection ceiling both share, checked before
/// allocating (spec §4.2, §3.3). Over it, the next `drive` closes the connection.
fn admit_peer(c: &mut ConnSlot) -> bool {
    if c.streams >= STREAM_CEILING {
        c.pending_close = Some(CEILING_CLOSE_CODE);
        return false;
    }
    c.streams += 1;
    true
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
    if !admit_peer(inner.conns.get_mut(conn)?) {
        return None;
    }
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
///
/// adoption spec §3: `stats` (read by the trampoline before this runs) are queued first when
/// the stream's connection is raw-H3.
pub(crate) fn on_stream_close(inner: &mut Inner, s: SlotId, stats: StreamCloseStats) {
    let Some(slot) = inner.streams.remove(s) else {
        return;
    };
    if let Some(c) = inner.conns.get_mut(slot.conn) {
        c.streams -= 1;
        if c.proto == ConnProto::H3 {
            inner
                .events
                .push(Event::StreamCloseStats(stream_id(s), Box::new(stats)));
        }
    }
    inner.events.push(Event::StreamClosed(stream_id(s)));
}

/// adoption spec §3: the peer's RESET_STREAM / STOP_SENDING code, queued while the stream's
/// slot is live (when the frame is processed, before any readable it causes). One-shot per
/// kind: xquic notifies again for a retransmitted frame.
pub(crate) fn on_peer_abort(
    inner: &mut Inner,
    s: SlotId,
    kind: xqc_stream_peer_abort_t,
    code: u64,
) {
    let Some(slot) = inner.streams.get_mut(s) else {
        return;
    };
    let (reported, e) = match kind {
        XQC_STREAM_PEER_STOP_SENDING => (
            &mut slot.stop_sending_reported,
            Event::StreamStopSending(stream_id(s), code),
        ),
        _ => (
            &mut slot.peer_reset_reported,
            Event::StreamPeerReset(stream_id(s), code),
        ),
    };
    if !std::mem::replace(reported, true) {
        inner.events.push(e);
    }
}

/// `msg` is null or a NUL-terminated string; at most 64 bytes are copied.
///
/// # Safety
/// `msg` is null or points to a NUL-terminated string (xquic's static messages).
unsafe fn close_msg(msg: *const core::ffi::c_char) -> Option<String> {
    let msg = msg.cast::<u8>();
    (!msg.is_null()).then(|| {
        // SAFETY: guaranteed by the caller; reading stops at the NUL (or after 64 bytes).
        let bytes: Vec<u8> = (0..64)
            .map(|k| unsafe { *msg.add(k) })
            .take_while(|&b| b != 0)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// SP2 spec §3.2: into the connection's receive ring; a stale slot drops it, a full ring
/// counts the drop.
pub(crate) fn on_datagram_read(inner: &mut Inner, s: SlotId, data: &[u8]) {
    let Some(c) = inner.conns.get_mut(s) else {
        return;
    };
    if datagram::ring_push(c, data) {
        inner
            .events
            .push_datagram_readable(&mut inner.conns, conn_id(s));
    }
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

pub(super) unsafe extern "C" fn path_removed_notify(
    _scid: *const xqc_cid_t,
    path_id: u64,
    ud: *mut c_void,
) {
    with_inner((), |i| {
        if i.conns.is_live(slot_of(ud)) {
            i.events
                .push(Event::PathRemoved(conn_id(slot_of(ud)), PathId(path_id)));
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
    // SAFETY: forwarded from xquic unchanged.
    unsafe { conn_create(conn, cid, ud, ConnProto::Raw) }
}

/// adoption spec §3: a raw conn on ALPN `h3`; `no_reset_echo` is set per conn.
pub(super) unsafe extern "C" fn h3raw_conn_create_notify(
    conn: *mut xqc_connection_t,
    cid: *const xqc_cid_t,
    ud: *mut c_void,
    _proto: *mut c_void,
) -> c_int {
    // SAFETY: forwarded from xquic unchanged; the setter is plain on the conn being created.
    unsafe {
        if conn_create(conn, cid, ud, ConnProto::H3) != 0 {
            return -1;
        }
        xqc_conn_set_no_reset_echo(conn, 1);
    }
    0
}

/// # Safety
/// The arguments of an xquic `conn_create_notify`.
unsafe fn conn_create(
    conn: *mut xqc_connection_t,
    cid: *const xqc_cid_t,
    ud: *mut c_void,
    proto: ConnProto,
) -> c_int {
    // SAFETY: `cid` is null or valid for this call; copied.
    let cid = (!cid.is_null()).then(|| unsafe { cid.read_unaligned() });
    let s = slot_of(ud);
    if !with_inner(false, |i| on_conn_create(i, conn, cid, s, proto)) {
        return -1;
    }
    // SAFETY: plain setters on the connection being created.
    unsafe {
        xqc_conn_set_alp_user_data(conn, ud_of(s));
        xqc_datagram_set_user_data(conn, ud_of(s));
    }
    0
}

/// `proto` is the ALPN user data, set only on admission.
pub(super) unsafe extern "C" fn conn_close_notify(
    conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
    proto: *mut c_void,
) -> c_int {
    // SAFETY: the connection being destroyed.
    let reason = unsafe { close_reason(conn) };
    with_inner((), |i| on_conn_close(i, slot_of(proto), reason));
    0
}

/// # Safety
/// `conn` is a live connection (plain getters).
unsafe fn close_reason(conn: *mut xqc_connection_t) -> CloseReason {
    // SAFETY: guaranteed by the caller.
    let (ty, errno) = unsafe { (xqc_conn_get_err_type(conn), xqc_conn_get_errno(conn)) };
    CloseReason {
        err_type: match ty {
            XQC_CONN_ERR_TYPE_TRANSPORT => ErrType::Transport,
            XQC_CONN_ERR_TYPE_APPLICATION => ErrType::Application,
            _ => ErrType::Unknown,
        },
        code: errno as u32 as u64,
    }
}

fn established(s: SlotId) {
    with_inner((), |i| {
        if i.conns.is_live(s) {
            i.events.push(Event::ConnEstablished(conn_id(s)));
        }
    })
}

pub(super) unsafe extern "C" fn conn_handshake_finished(
    _conn: *mut xqc_connection_t,
    _ud: *mut c_void,
    proto: *mut c_void,
) {
    established(slot_of(proto))
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

/// adoption spec §3: registered for raw-H3 conns only.
pub(super) unsafe extern "C" fn stream_peer_abort_notify(
    _xs: *mut xqc_stream_t,
    kind: xqc_stream_peer_abort_t,
    code: u64,
    ud: *mut c_void,
) {
    let s = slot_of(ud);
    if !s.is_none() {
        // A null user data is a stream we refused (DISCARDED): not ours.
        with_inner((), |i| on_peer_abort(i, s, kind, code));
    }
}

pub(super) unsafe extern "C" fn stream_close_notify(
    xs: *mut xqc_stream_t,
    ud: *mut c_void,
) -> xqc_int_t {
    let s = slot_of(ud);
    if !s.is_none() {
        // Only H3-proto conns queue the stats (`on_stream_close`): skip the read otherwise.
        let h3 = with_inner(false, |i| {
            i.streams
                .get(s)
                .and_then(|st| i.conns.get(st.conn))
                .is_some_and(|c| c.proto == ConnProto::H3)
        });
        let mut stats = StreamCloseStats {
            fin_send_us: 0,
            fin_ack_us: 0,
            mp_state: 0,
            stream_err: 0,
            close_msg: None,
        };
        if h3 {
            // adoption spec §3: a plain read, before `with_inner` (no re-entrancy).
            // SAFETY: `xs` is the stream being closed, valid inside its close callback; `st` is
            // a plain C struct, all-zero valid; `close_msg` is null or a static string.
            unsafe {
                let mut st: xqc_stream_close_stats_t = core::mem::zeroed();
                xqc_stream_get_close_stats(xs, &mut st);
                stats = StreamCloseStats {
                    fin_send_us: st.fin_send_time,
                    fin_ack_us: st.fin_ack_time,
                    mp_state: st.mp_state,
                    stream_err: st.err,
                    close_msg: close_msg(st.close_msg),
                };
            }
        }
        with_inner((), |i| on_stream_close(i, s, stats));
    }
    0
}

/// `ud` is the datagram user data: the connection's slot, set on creation (SP2 spec §3.2).
pub(super) unsafe extern "C" fn datagram_read_notify(
    _conn: *mut xqc_connection_t,
    ud: *mut c_void,
    data: *const c_void,
    len: usize,
    _recv_ts: u64,
) {
    let s = slot_of(ud);
    if s.is_none() {
        return; // spec §4.8: null user data is not ours
    }
    let data = if data.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: xquic passes `len` readable bytes for this call; copied before return.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), len) }
    };
    with_inner((), |i| on_datagram_read(i, s, data))
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
                h3: false,
                qlog: None,
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

    fn create(i: &mut Inner, s: SlotId, proto: ConnProto) -> bool {
        on_conn_create(i, core::ptr::null_mut(), None, s, proto)
    }

    #[test]
    fn second_cap_check_refuses_when_two_half_open_pass_the_first() {
        // Two connections pass server_accept while nothing is counted yet.
        let mut i = inner(1);
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert_eq!(i.n_provisional, 2);
        // Through the create notification: the first is admitted, the second refused.
        assert!(create(&mut i, a, ConnProto::Raw));
        i.conns.get_mut(a).unwrap().authed = true; // no eviction victim
        assert!(!create(&mut i, b, ConnProto::Raw));
        assert_eq!((i.n_counted, i.n_provisional), (1, 1));
    }

    #[test]
    fn rejected_admission_keeps_provisional_until_refuse() {
        let mut i = inner(1);
        // Both pass server_accept (half-open, uncounted); `a` then takes the only unit.
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert!(create(&mut i, a, ConnProto::Raw));
        i.conns.get_mut(a).unwrap().authed = true; // no eviction victim
        assert_eq!(i.n_provisional, 1);
        assert!(!create(&mut i, b, ConnProto::Raw));
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
        assert!(create(&mut i, a, ConnProto::Raw));
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
            vec![
                Event::NewConn(conn_id(a), ConnProto::Raw),
                Event::ConnClosed(conn_id(a), r)
            ]
        );
    }

    #[test]
    fn local_close_reports_unknown_even_after_a_peer_echo() {
        let mut i = inner(0);
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert!(create(&mut i, a, ConnProto::Raw));
        assert!(create(&mut i, b, ConnProto::Raw));
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

    fn admitted(i: &mut Inner, proto: ConnProto) -> SlotId {
        let s = accept(i);
        assert!(create(i, s, proto));
        s
    }

    fn evicting(i: &Inner, s: SlotId) -> bool {
        i.conns.get(s).unwrap().evicting
    }

    fn close(i: &mut Inner, s: SlotId) {
        let r = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        on_conn_close(i, s, r);
    }

    #[test]
    fn at_cap_admission_evicts_the_oldest_unauthed_conn() {
        let mut i = inner(3);
        let a = admitted(&mut i, ConnProto::Raw);
        let b = admitted(&mut i, ConnProto::H3);
        let c = admitted(&mut i, ConnProto::H3);
        i.conns.get_mut(a).unwrap().authed = true;
        // At cap: accept passes (a victim exists), create evicts b, the oldest unauthed.
        let d = admitted(&mut i, ConnProto::H3);
        assert!(!evicting(&i, a) && evicting(&i, b) && !evicting(&i, c) && !evicting(&i, d));
        assert_eq!(
            i.conns.get(b).unwrap().pending_close,
            Some(EVICT_CLOSE_CODE)
        );
        assert_eq!(i.conns.get(c).unwrap().pending_close, None);
        assert_eq!(i.n_counted, 4, "over cap until b's close notification");
        // b is not picked twice: the next one evicts c.
        let e = admitted(&mut i, ConnProto::Raw);
        assert!(evicting(&i, c) && !evicting(&i, d) && !evicting(&i, e));
        // b's close releases its unit; the effective count stays at the cap.
        close(&mut i, b);
        assert_eq!(i.n_counted, 4);
        assert!(!i.conns.is_live(b));
    }

    #[test]
    fn authed_conns_are_never_evicted() {
        let mut i = inner(2);
        let a = admitted(&mut i, ConnProto::H3);
        let b = admitted(&mut i, ConnProto::Raw);
        i.conns.get_mut(a).unwrap().authed = true;
        i.conns.get_mut(b).unwrap().authed = true;
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        // One that passed accept earlier is refused at create.
        let mut i = inner(1);
        let late = accept(&mut i);
        let a = admitted(&mut i, ConnProto::H3);
        i.conns.get_mut(a).unwrap().authed = true;
        assert!(!create(&mut i, late, ConnProto::H3));
        assert!(!evicting(&i, a));
        assert_eq!(i.n_counted, 1);
    }

    #[test]
    fn evicting_conns_neither_hold_the_cap_nor_are_victims_again() {
        let mut i = inner(1);
        let a = admitted(&mut i, ConnProto::H3);
        let b = admitted(&mut i, ConnProto::H3); // evicts a
        assert!(evicting(&i, a) && !evicting(&i, b));
        i.conns.get_mut(b).unwrap().authed = true;
        // a is leaving and b is authed: full, no victim.
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        close(&mut i, a);
        assert_eq!(i.n_counted, 1);
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        // A refused create of an evicting conn's slot still balances (server_refuse path).
        let mut i = inner(1);
        let a = admitted(&mut i, ConnProto::H3);
        admitted(&mut i, ConnProto::H3);
        on_server_refuse(&mut i, a);
        assert_eq!(i.n_counted, 1);
    }

    /// Victims linger ~3 PTO in xquic after the close: a burst of newcomers must not grow
    /// that backlog without bound (Codex SP3-1 P1).
    #[test]
    fn evicting_backlog_is_bounded() {
        let mut i = inner(1);
        let mut first = admitted(&mut i, ConnProto::H3);
        let late = accept(&mut i); // passed accept before the backlog filled
        for _ in 0..BACKLOG_MIN {
            admitted(&mut i, ConnProto::H3);
        }
        let n = i.conns.iter_live().filter(|(_, c)| c.evicting).count();
        assert_eq!(n, BACKLOG_MIN as usize);
        assert_eq!(i.n_counted, BACKLOG_MIN + 1);
        // Full backlog: refused at accept and at create, nothing more is evicted.
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
        assert!(!create(&mut i, late, ConnProto::H3));
        assert_eq!(i.n_counted, BACKLOG_MIN + 1);
        // A victim's close frees one backlog place.
        assert!(evicting(&i, first));
        close(&mut i, first);
        first = admitted(&mut i, ConnProto::H3);
        assert!(!evicting(&i, first));
        assert!(on_server_accept(&mut i, core::ptr::null_mut(), cid(), Time(0)).is_none());
    }

    #[test]
    fn unlimited_cap_never_evicts() {
        let mut i = inner(0);
        let a = admitted(&mut i, ConnProto::H3);
        admitted(&mut i, ConnProto::H3);
        assert!(!evicting(&i, a));
    }

    #[test]
    fn ceiling_checked_per_callback_not_per_drive() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(create(&mut i, c, ConnProto::Raw));
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

    fn no_stats() -> StreamCloseStats {
        StreamCloseStats {
            fin_send_us: 0,
            fin_ack_us: 0,
            mp_state: 0,
            stream_err: 0,
            close_msg: None,
        }
    }

    #[test]
    fn stream_close_releases_and_reports() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(create(&mut i, c, ConnProto::Raw));
        let s =
            on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 0, StreamKind::Uni).unwrap();
        on_stream_close(&mut i, s, no_stats());
        on_stream_close(&mut i, s, no_stats());
        assert_eq!(i.conns.get(c).unwrap().streams, 0);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(evs.last(), Some(&Event::StreamClosed(stream_id(s))));
        assert_eq!(evs.len(), 3); // NewConn, NewStream, StreamClosed
    }

    #[test]
    fn peer_abort_reported_once_per_kind() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(create(&mut i, c, ConnProto::H3));
        let s =
            on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 0, StreamKind::Bidi).unwrap();
        for code in [5, 6] {
            on_peer_abort(&mut i, s, XQC_STREAM_PEER_RESET_STREAM, code);
            on_peer_abort(&mut i, s, XQC_STREAM_PEER_STOP_SENDING, code);
        }
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(
            evs[2..],
            [
                Event::StreamPeerReset(stream_id(s), 5),
                Event::StreamStopSending(stream_id(s), 5),
            ]
        );
    }

    #[test]
    fn peer_abort_for_released_slot_is_dropped() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(create(&mut i, c, ConnProto::H3));
        let s =
            on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 0, StreamKind::Bidi).unwrap();
        on_peer_abort(&mut i, s, XQC_STREAM_PEER_STOP_SENDING, 7);
        on_stream_close(&mut i, s, no_stats());
        on_peer_abort(&mut i, s, XQC_STREAM_PEER_RESET_STREAM, 8);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(
            evs[2..],
            [
                Event::StreamStopSending(stream_id(s), 7),
                Event::StreamCloseStats(stream_id(s), Box::new(no_stats())),
                Event::StreamClosed(stream_id(s)),
            ]
        );
    }

    #[test]
    fn datagram_for_released_slot_is_dropped() {
        let mut i = inner(0);
        let c = accept(&mut i);
        on_server_refuse(&mut i, c);
        on_datagram_read(&mut i, c, b"x");
        assert!(i.events.pop(&mut i.streams, &mut i.conns).is_none());
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

    #[test]
    fn h3_create_admits_and_counts() {
        let mut i = inner(0);
        let a = accept(&mut i);
        assert!(create(&mut i, a, ConnProto::H3));
        assert_eq!((i.n_counted, i.n_provisional), (1, 0));
        let slot = i.conns.get(a).unwrap();
        assert!(slot.counted && slot.proto == ConnProto::H3);
        assert_eq!(
            i.events.pop(&mut i.streams, &mut i.conns),
            Some(Event::NewConn(conn_id(a), ConnProto::H3))
        );
    }

    #[test]
    fn h3_create_refused_at_cap() {
        let mut i = inner(1);
        let (a, b) = (accept(&mut i), accept(&mut i));
        assert!(create(&mut i, a, ConnProto::H3));
        i.conns.get_mut(a).unwrap().authed = true; // no eviction victim
        assert!(!create(&mut i, b, ConnProto::H3));
        assert_eq!((i.n_counted, i.n_provisional), (1, 1));
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        assert_eq!(evs, vec![Event::NewConn(conn_id(a), ConnProto::H3)]);
    }

    /// spec §3.3: xquic's H3 create can fail after ours counted the connection; xquic then
    /// calls `server_refuse`, which must balance the count and report the close.
    #[test]
    fn server_refuse_after_counted_balances() {
        let mut i = inner(0);
        let a = accept(&mut i);
        assert!(create(&mut i, a, ConnProto::H3));
        on_server_refuse(&mut i, a);
        assert!(!i.conns.is_live(a));
        assert_eq!((i.n_counted, i.n_provisional), (0, 0));
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns)).collect();
        let unknown = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        assert_eq!(
            evs,
            vec![
                Event::NewConn(conn_id(a), ConnProto::H3),
                Event::ConnClosed(conn_id(a), unknown)
            ]
        );
    }
}
