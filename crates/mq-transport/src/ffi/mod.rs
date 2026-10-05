//! Callback tables (spec §4.8, §4.9). Every xquic user-data slot holds a `SlotId` or 0 ("none").
//! The bodies that touch transport state live in `trampolines`.

pub(crate) mod trampolines;

use core::ffi::{c_char, c_int, c_uchar, c_void};
use libc::{sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t};
use mq_transport_api::ConnProto;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::panic::{AssertUnwindSafe, catch_unwind};
use trampolines::*;
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
        path_removed_notify: Some(path_removed_notify),
        conn_closing: None,
        conn_peer_addr_changed_notify: None,
        path_peer_addr_changed_notify: None,
        conn_cert_cb: None,
        conn_ssl_msg_cb: None,
        conn_retry_packet_condition_check: None,
        conn_send_packet_before_accept: Some(conn_send_packet_before_accept),
    }
}

/// ALPN callbacks (`"mqproxy-tcp/1"`, or `"h3"` on the raw-H3 backend; adoption spec §3). Of
/// the datagram callbacks only read and write are registered (SP2 spec §3.3).
pub(crate) fn app_proto_callbacks(proto: ConnProto) -> xqc_app_proto_callbacks_t {
    xqc_app_proto_callbacks_t {
        conn_cbs: xqc_conn_callbacks_t {
            conn_create_notify: Some(match proto {
                ConnProto::Raw => conn_create_notify,
                ConnProto::H3 => h3raw_conn_create_notify,
            }),
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
            // adoption spec §3: raw-H3 conns only; raw conns never report peer aborts.
            stream_peer_abort_notify: match proto {
                ConnProto::Raw => None,
                ConnProto::H3 => Some(stream_peer_abort_notify),
            },
        },
        dgram_cbs: xqc_datagram_callbacks_t {
            datagram_read_notify: Some(datagram_read_notify),
            datagram_write_notify: Some(datagram_write_notify),
            datagram_acked_notify: None,
            datagram_lost_notify: None,
            datagram_mss_updated_notify: None,
        },
    }
}

/// H3 callbacks (spec §3.3): connection and request notifications only; the h3-ext datagram
/// and bytestream tables stay empty (xquic null-checks them).
pub(crate) fn h3_callbacks() -> xqc_h3_callbacks_t {
    // SAFETY: a C struct of `Option<fn>` fields; all-zero is all `None`.
    let mut cbs: xqc_h3_callbacks_t = unsafe { core::mem::zeroed() };
    cbs.h3c_cbs.h3_conn_create_notify = Some(h3_conn_create_notify);
    cbs.h3c_cbs.h3_conn_close_notify = Some(h3_conn_close_notify);
    cbs.h3c_cbs.h3_conn_handshake_finished = Some(h3_conn_handshake_finished);
    cbs.h3r_cbs.h3_request_create_notify = Some(h3_request_create_notify);
    cbs.h3r_cbs.h3_request_close_notify = Some(h3_request_close_notify);
    cbs.h3r_cbs.h3_request_read_notify = Some(h3_request_read_notify);
    cbs.h3r_cbs.h3_request_write_notify = Some(h3_request_write_notify);
    cbs
}

// ── callbacks with no state ─────────────────────────────────────────────

/// spec §4.7: accept any certificate (as the C client does).
unsafe extern "C" fn cert_verify(
    _certs: *mut *const c_uchar,
    _cert_len: *const usize,
    _certs_len: usize,
    _ud: *mut c_void,
) -> c_int {
    0
}

/// SP2 spec §3.3: nothing waits for writability (failed sends are dropped); registered so
/// the facade does not rely on the fork's null check.
unsafe extern "C" fn datagram_write_notify(_conn: *mut xqc_connection_t, _ud: *mut c_void) {}

/// No resumption store, as in C.
unsafe extern "C" fn save_token(_token: *const c_uchar, _len: u32, _ud: *mut c_void) {}

/// `save_session_cb` and `save_tp_cb`: no-ops, as in C.
unsafe extern "C" fn save_string(_data: *const c_char, _len: usize, _ud: *mut c_void) {}

// ── socket addresses ────────────────────────────────────────────────────

/// `SocketAddr` → C socket address for xquic (which copies it).
pub(crate) fn to_sockaddr(a: SocketAddr) -> (sockaddr_storage, socklen_t) {
    // SAFETY: sockaddr_storage is plain data; all-zero is a valid (AF_UNSPEC) value.
    let mut ss: sockaddr_storage = unsafe { core::mem::zeroed() };
    let p = (&mut ss as *mut sockaddr_storage).cast::<u8>();
    let len = match a {
        SocketAddr::V4(v4) => {
            let sin = sockaddr_in {
                sin_family: libc::AF_INET as sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is large and aligned enough for any sockaddr_*.
            unsafe { p.cast::<sockaddr_in>().write(sin) };
            size_of::<sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6 = sockaddr_in6 {
                sin6_family: libc::AF_INET6 as sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: as above.
            unsafe { p.cast::<sockaddr_in6>().write(sin6) };
            size_of::<sockaddr_in6>()
        }
    };
    (ss, len as socklen_t)
}

/// C socket address from xquic → `SocketAddr`; `None` for null, short or non-IP addresses.
///
/// # Safety
/// `sa` is null or points to `len` readable bytes (valid for this call, spec §4.8).
pub(crate) unsafe fn from_sockaddr(sa: *const sockaddr, len: socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    if sa.is_null() || len < size_of::<sa_family_t>() {
        return None;
    }
    // SAFETY: at least the family is readable; xquic may hand unaligned pointers.
    let family = unsafe { sa.cast::<sa_family_t>().read_unaligned() };
    match i32::from(family) {
        libc::AF_INET if len >= size_of::<sockaddr_in>() => {
            // SAFETY: `len` covers a sockaddr_in.
            let sin = unsafe { sa.cast::<sockaddr_in>().read_unaligned() };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddrV4::new(ip, u16::from_be(sin.sin_port)).into())
        }
        libc::AF_INET6 if len >= size_of::<sockaddr_in6>() => {
            // SAFETY: `len` covers a sockaddr_in6.
            let s = unsafe { sa.cast::<sockaddr_in6>().read_unaligned() };
            let ip = Ipv6Addr::from(s.sin6_addr.s6_addr);
            let port = u16::from_be(s.sin6_port);
            let flow = u32::from_be(s.sin6_flowinfo);
            Some(SocketAddrV6::new(ip, port, flow, s.sin6_scope_id).into())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_round_trip() {
        for a in ["10.1.2.3:4433", "[2001:db8::1]:443", "[fe80::1%3]:9"] {
            let a: SocketAddr = a.parse().unwrap();
            let (ss, len) = to_sockaddr(a);
            // SAFETY: `ss` holds `len` initialised bytes.
            let back = unsafe { from_sockaddr((&ss as *const sockaddr_storage).cast(), len) };
            assert_eq!(back, Some(a));
        }
        // SAFETY: null is allowed.
        assert_eq!(unsafe { from_sockaddr(core::ptr::null(), 16) }, None);
    }
}
