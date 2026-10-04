//! Transport and ALPN callbacks (spec §4.4, §4.7, §4.8; plan Task 4.6 table).
//!
//! Every trampoline runs inside `guard` (a panic aborts) and reaches `Inner` only through
//! `clock::current()`. The bookkeeping lives in plain `fn on_*(inner: &mut Inner, ..)`
//! functions that call no xquic function, so the `&mut Inner` they get never spans a call
//! that could re-enter a trampoline, and they are unit-testable without an engine. The
//! xquic getters/setters a trampoline needs run before or after that scope.

use super::{from_sockaddr, guard};
use crate::slots::{ConnSlot, H3ReqSlot, StreamSlot};
use crate::txq::Refusal;
use crate::{Inner, clock, datagram, stream};
use core::ffi::{c_int, c_uchar, c_void};
use libc::{sockaddr, socklen_t};
use mq_transport_api::{
    CloseReason, ConnId, ConnProto, ErrType, Event, H3Close, H3ReqId, H3ReqStats, PathId, Role,
    SlotId, StreamId, StreamInfo, StreamKind, Time, Unread,
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

pub(crate) fn req_id(s: SlotId) -> H3ReqId {
    H3ReqId::from_slot(s).expect("live slot ids have a non-zero generation")
}

/// spec §3.4: the `XQC_REQ_NOTIFY_READ_*` bits the transport acts on.
pub(crate) const READ_HEADER: u8 = XQC_REQ_NOTIFY_READ_HEADER as u8;
pub(crate) const READ_TRAILER: u8 = XQC_REQ_NOTIFY_READ_TRAILER as u8;

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
    let victim = inner
        .conns
        .iter_live()
        .filter(|(_, c)| c.counted && !c.authed && !c.evicting)
        .min_by_key(|(_, c)| c.admitted);
    victim.map(|(s, _)| Some(s)).ok_or(())
}

/// `server_accept`: both caps, then a provisional slot. `None` → refuse. The eviction itself
/// waits for the create notification (a completed handshake).
pub(crate) fn on_server_accept(
    inner: &mut Inner,
    conn: *mut xqc_connection_t,
    cid: xqc_cid_t,
    now: Time,
) -> Option<SlotId> {
    let max = inner.cfg.max_conns;
    cap_check(inner).ok()?;
    if inner.n_provisional >= 64.max(max.saturating_mul(4)) {
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
pub(crate) fn on_stream_close(inner: &mut Inner, s: SlotId) {
    let Some(slot) = inner.streams.remove(s) else {
        return;
    };
    if let Some(c) = inner.conns.get_mut(slot.conn) {
        c.streams -= 1;
    }
    inner.events.push(Event::StreamClosed(stream_id(s)));
}

/// Server: the peer opened a request (spec §3.3). `None` = refused: the request keeps NULL
/// user data, so every later notification for it is a no-op, and the connection closes at the
/// next `drive` (xquic ignores the create notification's return value).
pub(crate) fn on_h3_request_create(
    inner: &mut Inner,
    conn: SlotId,
    h3r: *mut xqc_h3_request_t,
    quic_id: u64,
) -> Option<SlotId> {
    if !admit_peer(inner.conns.get_mut(conn)?) {
        return None;
    }
    let s = inner.h3reqs.insert(H3ReqSlot::new(conn, h3r, quic_id));
    inner
        .events
        .push(Event::H3Request(conn_id(conn), req_id(s)));
    Some(s)
}

/// spec §3.3/§3.4: accumulate the read flags and queue `H3Readable`. `true` → the trampoline
/// drains (and discards) the trailer section now: the app already read the header section.
/// A trailer that arrives before that keeps its bit for `h3_recv_headers`.
pub(crate) fn on_h3_read(inner: &mut Inner, s: SlotId, flag: u8) -> bool {
    let Some(r) = inner.h3reqs.get_mut(s) else {
        return false;
    };
    r.read_flags |= flag;
    let drain = r.header_consumed && r.read_flags & READ_TRAILER != 0;
    if drain {
        r.read_flags &= !READ_TRAILER;
    }
    inner.events.push_h3_readable(&mut inner.h3reqs, req_id(s));
    drain
}

/// Request close notification: every request slot is released here (spec §3.3, §3.5). The
/// connection slot may already be gone (a QPACK-blocked request outlives its connection).
pub(crate) fn on_h3_request_close(
    inner: &mut Inner,
    s: SlotId,
    stats: H3ReqStats,
    unread: Option<Unread>,
) {
    let Some(r) = inner.h3reqs.remove(s) else {
        return;
    };
    if let Some(c) = inner.conns.get_mut(r.conn) {
        c.streams -= 1;
    }
    let close = Box::new(H3Close { stats, unread });
    inner.events.push(Event::H3Closed(req_id(s), close));
}

/// spec §3.3 close row: a client request whose fin the app has not consumed is drained before
/// the release; `Some(read_flags)` then.
fn rescue_flags(inner: &Inner, s: SlotId) -> Option<u8> {
    if inner.cfg.role != Role::Client {
        return None;
    }
    inner
        .h3reqs
        .get(s)
        .filter(|r| !r.fin_consumed)
        .map(|r| r.read_flags)
}

/// spec §3.7: drains the pending header section (when `header`) and the whole body; `Some` only
/// when the drain ends with xquic's fin — a partial body is never rescued.
///
/// # Safety
/// `h3r` is the request inside its close notification (intact until it returns).
unsafe fn drain_unread(h3r: *mut xqc_h3_request_t, header: bool) -> Option<Unread> {
    let headers = if header {
        let mut fin = 0u8; // xquic logs it before writing it
        // SAFETY: guaranteed by the caller.
        let hs = unsafe { xqc_h3_request_recv_headers(h3r, &mut fin) };
        if hs.is_null() {
            return None;
        }
        let mut v = Vec::new();
        // SAFETY: the section just returned, unchanged for this call.
        unsafe { crate::h3::for_each_header(hs, &mut |n, x| v.push((n.to_vec(), x.to_vec()))) };
        Some(v)
    } else {
        None
    };
    const CHUNK: usize = 64 * 1024;
    let mut body = Vec::new();
    loop {
        let len = body.len();
        body.resize(len + CHUNK, 0);
        let mut fin = 0u8;
        // SAFETY: guaranteed by the caller; `CHUNK` writable bytes at `len`.
        let n =
            unsafe { xqc_h3_request_recv_body(h3r, body.as_mut_ptr().add(len), CHUNK, &mut fin) };
        if n < 0 {
            return None; // EAGAIN: no fin behind the buffered body
        }
        body.truncate(len + n as usize);
        if fin != 0 {
            return Some(Unread { headers, body });
        }
    }
}

/// spec §3.1: the fields C's call site reads; `close_msg` copied up to 64 bytes.
///
/// # Safety
/// `st.stream_close_msg` is null or a NUL-terminated string (xquic's static messages).
pub(crate) unsafe fn h3_stats(st: &xqc_request_stats_t) -> H3ReqStats {
    let msg = st.stream_close_msg.cast::<u8>();
    let close_msg = (!msg.is_null()).then(|| {
        // SAFETY: guaranteed by the caller; reading stops at the NUL (or after 64 bytes).
        let bytes: Vec<u8> = (0..64)
            .map(|k| unsafe { *msg.add(k) })
            .take_while(|&b| b != 0)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    });
    H3ReqStats {
        send_body: st.send_body_size as u64,
        recv_body: st.recv_body_size as u64,
        begin_us: st.h3r_begin_time,
        header_send_us: st.h3r_header_send_time,
        fin_send_us: st.stream_fin_send_time,
        fin_ack_us: st.stream_fin_ack_time,
        mp_state: st.mp_state,
        stream_err: st.stream_err,
        close_msg,
    }
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
    // SAFETY: `cid` is null or valid for this call; copied.
    let cid = (!cid.is_null()).then(|| unsafe { cid.read_unaligned() });
    let s = slot_of(ud);
    if !with_inner(false, |i| on_conn_create(i, conn, cid, s, ConnProto::Raw)) {
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

// ── H3 connection callbacks (spec §3.3): `ud` is the transport user data = the conn slot.
// Never `xqc_h3_conn_set_user_data` (it overwrites that user data, spec §3.2).

pub(super) unsafe extern "C" fn h3_conn_create_notify(
    h3c: *mut xqc_h3_conn_t,
    cid: *const xqc_cid_t,
    ud: *mut c_void,
) -> c_int {
    // SAFETY: `cid` is null or valid for this call; copied. `h3c` is being created: a getter.
    let (cid, conn) = unsafe {
        (
            (!cid.is_null()).then(|| cid.read_unaligned()),
            xqc_h3_conn_get_xqc_conn(h3c),
        )
    };
    let s = slot_of(ud);
    let ok = with_inner(false, |i| {
        if !on_conn_create(i, conn, cid, s, ConnProto::H3) {
            return false;
        }
        if let Some(slot) = i.conns.get_mut(s) {
            slot.h3c = h3c;
        }
        true
    });
    if ok { 0 } else { -1 }
}

pub(super) unsafe extern "C" fn h3_conn_close_notify(
    h3c: *mut xqc_h3_conn_t,
    _cid: *const xqc_cid_t,
    ud: *mut c_void,
) -> c_int {
    // SAFETY: the H3 connection being destroyed and its live QUIC connection.
    let reason = unsafe { close_reason(xqc_h3_conn_get_xqc_conn(h3c)) };
    with_inner((), |i| on_conn_close(i, slot_of(ud), reason));
    0
}

pub(super) unsafe extern "C" fn h3_conn_handshake_finished(
    _h3c: *mut xqc_h3_conn_t,
    ud: *mut c_void,
) {
    established(slot_of(ud))
}

// Request callbacks (spec §3.3): `ud` is the request's user data = its slot, or NULL for a
// request we refused (every notification for it is then a no-op).

/// The role decides: a server's `ud` is NULL on both xquic creation paths and the peer opened
/// the request; a client's `ud` is the slot `open_h3_request` preallocated.
pub(super) unsafe extern "C" fn h3_request_create_notify(
    h3r: *mut xqc_h3_request_t,
    ud: *mut c_void,
) -> c_int {
    // SAFETY: plain getters on the request being created.
    let (conn, quic_id) = unsafe {
        (
            slot_of(xqc_h3_get_conn_user_data_by_request(h3r)),
            xqc_h3_stream_id(h3r),
        )
    };
    let admitted = with_inner(None, |i| {
        if matches!(i.cfg.role, Role::Server { .. }) {
            return on_h3_request_create(i, conn, h3r, quic_id);
        }
        if let Some(r) = i.h3reqs.get_mut(slot_of(ud)) {
            r.xqc = h3r;
            r.quic_id = quic_id;
        }
        None
    });
    if let Some(s) = admitted {
        // SAFETY: a plain setter on the request being created.
        unsafe { xqc_h3_request_set_user_data(h3r, ud_of(s)) };
    }
    0 // ignored by xquic
}

pub(super) unsafe extern "C" fn h3_request_close_notify(
    h3r: *mut xqc_h3_request_t,
    ud: *mut c_void,
) -> c_int {
    let s = slot_of(ud);
    if s.is_none() {
        return 0;
    }
    // SAFETY: the request is intact for the duration of its close notification (spec §3.7);
    // xquic's close messages are static strings.
    let stats = unsafe { h3_stats(&xqc_h3_request_get_stats(h3r)) };
    let unread = with_inner(None, |i| rescue_flags(i, s))
        // SAFETY: as above; the drain calls getters that fire no notification.
        .and_then(|flags| unsafe { drain_unread(h3r, flags & READ_HEADER != 0) });
    with_inner((), |i| on_h3_request_close(i, s, stats, unread));
    0
}

pub(super) unsafe extern "C" fn h3_request_read_notify(
    h3r: *mut xqc_h3_request_t,
    flag: xqc_request_notify_flag_t,
    ud: *mut c_void,
) -> c_int {
    let s = slot_of(ud);
    if s.is_none() {
        return 0;
    }
    if with_inner(false, |i| on_h3_read(i, s, flag as u8)) {
        let mut fin = 0u8; // xquic logs it before writing it
        // SAFETY: the request being notified; a getter that fires no notification. The trailer
        // section is discarded and its fin ignored (spec §3.3).
        unsafe { xqc_h3_request_recv_headers(h3r, &mut fin) };
    }
    0
}

pub(super) unsafe extern "C" fn h3_request_write_notify(
    _h3r: *mut xqc_h3_request_t,
    ud: *mut c_void,
) -> c_int {
    let s = slot_of(ud);
    if !s.is_none() {
        with_inner((), |i| i.events.push_h3_writable(&mut i.h3reqs, req_id(s)));
    }
    0
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
        assert!(
            i.events
                .pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)
                .is_some()
        ); // a's NewConn
        assert!(
            i.events
                .pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)
                .is_none()
        );
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
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
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
        let closes: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
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
        let _ = i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs); // NewConn
        let first = on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 4, StreamKind::Bidi);
        let s = first.expect("the 8192nd stream is admitted");
        assert_eq!(i.streams.len_live(), 1);
        assert!(matches!(
            i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs),
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
                i.events
                    .pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)
                    .is_none(),
                "nothing queued"
            );
        }
    }

    #[test]
    fn stream_close_releases_and_reports() {
        let mut i = inner(0);
        let c = accept(&mut i);
        assert!(create(&mut i, c, ConnProto::Raw));
        let s =
            on_peer_stream_create(&mut i, c, core::ptr::null_mut(), 0, StreamKind::Uni).unwrap();
        on_stream_close(&mut i, s);
        on_stream_close(&mut i, s);
        assert_eq!(i.conns.get(c).unwrap().streams, 0);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
        assert_eq!(evs.last(), Some(&Event::StreamClosed(stream_id(s))));
        assert_eq!(evs.len(), 3); // NewConn, NewStream, StreamClosed
    }

    #[test]
    fn datagram_for_released_slot_is_dropped() {
        let mut i = inner(0);
        let c = accept(&mut i);
        on_server_refuse(&mut i, c);
        on_datagram_read(&mut i, c, b"x");
        assert!(
            i.events
                .pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)
                .is_none()
        );
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
            i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs),
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
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
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
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
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

    fn h3_conn(i: &mut Inner) -> SlotId {
        let c = accept(i);
        assert!(create(i, c, ConnProto::H3));
        let _ = i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs); // NewConn
        c
    }

    fn stats() -> H3ReqStats {
        H3ReqStats {
            send_body: 1,
            recv_body: 2,
            begin_us: 3,
            header_send_us: 4,
            fin_send_us: 5,
            fin_ack_us: 6,
            mp_state: 0,
            stream_err: 0,
            close_msg: None,
        }
    }

    /// spec §3.3: the server's ceiling, shared with raw streams, is checked before allocating;
    /// a refusal allocates and queues nothing and closes the connection at the next `drive`.
    #[test]
    fn h3_request_create_refused_at_ceiling() {
        let mut i = inner(0);
        let c = h3_conn(&mut i);
        i.conns.get_mut(c).unwrap().streams = STREAM_CEILING - 1;
        let s = on_h3_request_create(&mut i, c, core::ptr::null_mut(), 0).expect("admitted");
        assert_eq!(
            i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs),
            Some(Event::H3Request(conn_id(c), req_id(s)))
        );
        assert_eq!(i.conns.get(c).unwrap().streams, STREAM_CEILING);
        assert_eq!(
            on_h3_request_create(&mut i, c, core::ptr::null_mut(), 4),
            None
        );
        let conn = i.conns.get(c).unwrap();
        assert_eq!(conn.streams, STREAM_CEILING);
        assert_eq!(conn.pending_close, Some(CEILING_CLOSE_CODE));
        assert_eq!(i.h3reqs.len_live(), 1, "nothing allocated");
        assert!(
            i.events
                .pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)
                .is_none()
        );
    }

    #[test]
    fn h3_request_close_decrements_streams() {
        let mut i = inner(0);
        let c = h3_conn(&mut i);
        let s = on_h3_request_create(&mut i, c, core::ptr::null_mut(), 0).unwrap();
        assert_eq!(i.conns.get(c).unwrap().streams, 1);
        on_h3_request_close(&mut i, s, stats(), None);
        on_h3_request_close(&mut i, s, stats(), None); // stale: released once
        assert_eq!(i.conns.get(c).unwrap().streams, 0);
        assert!(!i.h3reqs.is_live(s));
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
        let close = Box::new(H3Close {
            stats: stats(),
            unread: None,
        });
        assert_eq!(
            evs,
            vec![
                Event::H3Request(conn_id(c), req_id(s)),
                Event::H3Closed(req_id(s), close)
            ]
        );
    }

    /// spec §3.5: a QPACK-blocked request can be destroyed after its connection closed.
    #[test]
    fn h3_close_tolerates_gone_conn_slot() {
        let mut i = inner(0);
        let c = h3_conn(&mut i);
        let s = on_h3_request_create(&mut i, c, core::ptr::null_mut(), 0).unwrap();
        let r = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        on_conn_close(&mut i, c, r);
        on_h3_request_close(&mut i, s, stats(), None);
        assert!(!i.h3reqs.is_live(s));
        let last =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs)).last();
        assert!(matches!(last, Some(Event::H3Closed(id, _)) if id == req_id(s)));
    }

    /// spec §3.3/§3.4: a trailer is drained in the notification only once the header section
    /// was consumed; `H3Readable` coalesces.
    #[test]
    fn h3_trailer_drain_waits_for_header_section() {
        let mut i = inner(0);
        let c = h3_conn(&mut i);
        let s = on_h3_request_create(&mut i, c, core::ptr::null_mut(), 0).unwrap();
        let _ = i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs); // H3Request
        assert!(!on_h3_read(&mut i, s, READ_HEADER | READ_TRAILER));
        assert_eq!(
            i.h3reqs.get(s).unwrap().read_flags,
            READ_HEADER | READ_TRAILER
        );
        let r = i.h3reqs.get_mut(s).unwrap();
        r.read_flags = 0;
        r.header_consumed = true;
        assert!(on_h3_read(&mut i, s, READ_TRAILER));
        assert_eq!(i.h3reqs.get(s).unwrap().read_flags, 0);
        let evs: Vec<_> =
            std::iter::from_fn(|| i.events.pop(&mut i.streams, &mut i.conns, &mut i.h3reqs))
                .collect();
        assert_eq!(evs, vec![Event::H3Readable(req_id(s))]);
        assert!(
            !on_h3_read(&mut i, SlotId::NONE, READ_TRAILER),
            "stale: no-op"
        );
    }

    #[test]
    fn h3_stats_maps_fields_and_caps_close_msg() {
        // SAFETY: a plain C struct; all-zero is valid (null close message).
        let mut st: xqc_request_stats_t = unsafe { core::mem::zeroed() };
        st.send_body_size = 5;
        st.recv_body_size = 7;
        st.h3r_begin_time = 1;
        st.h3r_header_send_time = 2;
        st.stream_fin_send_time = 3;
        st.stream_fin_ack_time = 4;
        st.mp_state = 3;
        st.stream_err = 0x10c;
        // SAFETY: null close message.
        let got = unsafe { h3_stats(&st) };
        let want = H3ReqStats {
            send_body: 5,
            recv_body: 7,
            begin_us: 1,
            header_send_us: 2,
            fin_send_us: 3,
            fin_ack_us: 4,
            mp_state: 3,
            stream_err: 0x10c,
            close_msg: None,
        };
        assert_eq!(got, want);
        let long = std::ffi::CString::new("m".repeat(100)).unwrap();
        st.stream_close_msg = long.as_ptr();
        // SAFETY: a NUL-terminated string that outlives the call.
        assert_eq!(unsafe { h3_stats(&st) }.close_msg, Some("m".repeat(64)));
        st.stream_close_msg = c"remote reset".as_ptr();
        // SAFETY: as above.
        assert_eq!(
            unsafe { h3_stats(&st) }.close_msg.as_deref(),
            Some("remote reset")
        );
    }
}
