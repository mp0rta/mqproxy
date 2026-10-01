//! Callback tables (spec §4.8, §4.9). Every xquic user-data slot holds a `SlotId` or 0 ("none").
//! Conn/stream bodies marked `TODO(task 4.6)` are stubs that Task 4.6 replaces with trampolines.

use crate::clock;
use core::ffi::{c_char, c_int, c_uchar, c_void};
use libc::{sockaddr, socklen_t};
use mq_transport_api::SlotId;
use std::panic::{AssertUnwindSafe, catch_unwind};
use xquic_sys::*;

/// spec §4.8: a panic never unwinds into C — log and abort.
pub(crate) fn guard<R>(f: impl FnOnce() -> R) -> R {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => {
            log::error!("panic inside an xquic callback; aborting");
            std::process::abort()
        }
    }
}

/// spec §4.9: the four callbacks xquic invokes without a null check are always registered.
pub(crate) fn transport_callbacks() -> xqc_transport_callbacks_t {
    xqc_transport_callbacks_t {
        server_accept: Some(server_accept),
        server_refuse: Some(server_refuse),
        stateless_reset: Some(stateless_reset),
        write_socket: Some(write_socket),
        write_mmsg: None,
        write_socket_ex: Some(write_socket_ex),
        write_mmsg_ex: None,
        conn_update_cid_notify: Some(conn_update_cid_notify),
        save_token: Some(save_token),
        save_session_cb: Some(save_string),
        save_tp_cb: Some(save_string),
        cert_verify_cb: Some(cert_verify),
        ready_to_create_path_notify: Some(ready_to_create_path_notify),
        path_created_notify: None,
        path_removed_notify: None,
        conn_closing: None,
        conn_peer_addr_changed_notify: None,
        path_peer_addr_changed_notify: None,
        conn_cert_cb: None,
        conn_ssl_msg_cb: None,
        conn_retry_packet_condition_check: None,
        conn_send_packet_before_accept: Some(conn_send_packet_before_accept),
    }
}

/// ALPN callbacks (`"mqproxy-tcp/1"`). Datagram callbacks come with SP2.
pub(crate) fn app_proto_callbacks() -> xqc_app_proto_callbacks_t {
    xqc_app_proto_callbacks_t {
        conn_cbs: xqc_conn_callbacks_t {
            conn_create_notify: Some(conn_create_notify),
            conn_close_notify: Some(conn_close_notify),
            conn_handshake_finished: Some(conn_handshake_finished),
            conn_ping_acked: None,
        },
        stream_cbs: xqc_stream_callbacks_t {
            stream_read_notify: Some(stream_read_notify),
            stream_write_notify: Some(stream_write_notify),
            stream_create_notify: Some(stream_create_notify),
            stream_close_notify: Some(stream_close_notify),
            stream_closing_notify: None,
        },
        // SAFETY: all-None is a valid value of a struct of Option<fn> fields.
        dgram_cbs: unsafe { core::mem::zeroed() },
    }
}

// ── transport callbacks ─────────────────────────────────────────────────

// TODO(task 4.6): cap checks, provisional slot, transport user data.
unsafe extern "C" fn server_accept(
    _engine: *mut xqc_engine_t,
    _conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
) -> c_int {
    0
}

// TODO(task 4.6): release the provisional slot.
unsafe extern "C" fn server_refuse(
    _engine: *mut xqc_engine_t,
    _conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
) {
}

// TODO(task 4.6): push_or_drop((None, PathId(0))).
unsafe extern "C" fn stateless_reset(
    _buf: *const c_uchar,
    size: usize,
    _peer: *const sockaddr,
    _peerlen: socklen_t,
    _local: *const sockaddr,
    _locallen: socklen_t,
    _ud: *mut c_void,
) -> isize {
    size as isize
}

// TODO(task 4.6): queue on (conn, PathId(0)).
unsafe extern "C" fn write_socket(
    _buf: *const c_uchar,
    size: usize,
    _peer: *const sockaddr,
    _peerlen: socklen_t,
    _ud: *mut c_void,
) -> isize {
    size as isize
}

// TODO(task 4.6): queue on (conn, path).
unsafe extern "C" fn write_socket_ex(
    _path_id: u64,
    _buf: *const c_uchar,
    size: usize,
    _peer: *const sockaddr,
    _peerlen: socklen_t,
    _ud: *mut c_void,
) -> isize {
    size as isize
}

// TODO(task 4.6): push_or_drop((None, PathId(0))).
unsafe extern "C" fn conn_send_packet_before_accept(
    _buf: *const c_uchar,
    size: usize,
    _peer: *const sockaddr,
    _peerlen: socklen_t,
    _ud: *mut c_void,
) -> isize {
    size as isize
}

/// spec §4.9: the peer can retire the user SCID; keep the slot's cid current.
unsafe extern "C" fn conn_update_cid_notify(
    _conn: *mut xqc_connection_t,
    _retire: *const xqc_cid_t,
    new_cid: *const xqc_cid_t,
    ud: *mut c_void,
) {
    guard(|| {
        let inner = clock::current();
        if inner.is_null() || new_cid.is_null() {
            return;
        }
        // SAFETY: `new_cid` is valid for this call (copied before return, spec §4.8 "Borrowed
        // data"; xquic may hand an unaligned pointer, hence read_unaligned). `inner` is the live
        // Box<Inner> set by `clock::enter`; no other reference into it exists during a callback.
        unsafe {
            let cid = new_cid.read_unaligned();
            if let Some(slot) = (*inner).conns.get_mut(SlotId::from_raw(ud as u64)) {
                slot.cid = cid;
            }
        }
    })
}

/// spec §4.7: accept any certificate (as the C client does).
unsafe extern "C" fn cert_verify(
    _certs: *mut *const c_uchar,
    _cert_len: *const usize,
    _certs_len: usize,
    _ud: *mut c_void,
) -> c_int {
    0
}

// TODO(task 4.6): push_mp_ready(conn).
unsafe extern "C" fn ready_to_create_path_notify(_scid: *const xqc_cid_t, _ud: *mut c_void) {}

/// No resumption store, as in C.
unsafe extern "C" fn save_token(_token: *const c_uchar, _len: u32, _ud: *mut c_void) {}

/// `save_session_cb` and `save_tp_cb`: no-ops, as in C.
unsafe extern "C" fn save_string(_data: *const c_char, _len: usize, _ud: *mut c_void) {}

// ── ALPN callbacks ──────────────────────────────────────────────────────

// TODO(task 4.6): second cap check / bind ALPN user data.
unsafe extern "C" fn conn_create_notify(
    _conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
    _proto: *mut c_void,
) -> c_int {
    0
}

// TODO(task 4.6): ConnClosed + release.
unsafe extern "C" fn conn_close_notify(
    _conn: *mut xqc_connection_t,
    _cid: *const xqc_cid_t,
    _ud: *mut c_void,
    _proto: *mut c_void,
) -> c_int {
    0
}

// TODO(task 4.6): ConnEstablished.
unsafe extern "C" fn conn_handshake_finished(
    _conn: *mut xqc_connection_t,
    _ud: *mut c_void,
    _proto: *mut c_void,
) {
}

// TODO(task 4.6): readable / abandoned drain.
unsafe extern "C" fn stream_read_notify(_s: *mut xqc_stream_t, _ud: *mut c_void) -> xqc_int_t {
    0
}

// TODO(task 4.6): writable.
unsafe extern "C" fn stream_write_notify(_s: *mut xqc_stream_t, _ud: *mut c_void) -> xqc_int_t {
    0
}

// TODO(task 4.6): admission / bind.
unsafe extern "C" fn stream_create_notify(_s: *mut xqc_stream_t, _ud: *mut c_void) -> xqc_int_t {
    0
}

// TODO(task 4.6): release + StreamClosed.
unsafe extern "C" fn stream_close_notify(_s: *mut xqc_stream_t, _ud: *mut c_void) -> xqc_int_t {
    0
}
