//! spec §8.2: FFI to the C wire codec (`src/wire/mq_wire.c`, `mq_varint.c`,
//! `mq_udp_msg.c`) for the differential test. Structs mirror
//! `src/wire/mq_wire.h` / `mq_udp_msg.h` exactly; C enums are `c_int`. Every
//! frame codec function returns bytes written/consumed, or -1 on error (the
//! `codec!` wrappers map that to `Option`); the datagram header functions
//! return 0 / -1 and have hand-written wrappers.
use std::ffi::c_int;
use std::mem::{offset_of, size_of};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthReqC {
    pub version: u64,
    pub client_id: [u8; 64],
    pub auth_token: [u8; 256],
    pub features: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthRespC {
    pub status: c_int,
    pub error_code: c_int,
    pub server_id: [u8; 64],
    pub features: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectTcpReqC {
    pub flags: u64,
    pub address_type: c_int,
    pub host: [u8; 255],
    pub host_len: usize,
    pub port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectTcpRespC {
    pub status: c_int,
    pub error_code: c_int,
    pub message: [u8; 256],
    pub message_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpSessionOpenC {
    pub session_id: u32,
    pub flags: u64,
    pub address_type: c_int,
    pub host: [u8; 255],
    pub host_len: usize,
    pub port: u16,
    pub idle_timeout_ms: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpSessionRespC {
    pub status: c_int,
    pub error_code: c_int,
    pub message: [u8; 256],
    pub message_len: usize,
    pub idle_timeout_ms: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpMsgHdrC {
    pub session_id: u32,
    pub packet_id: u16,
    pub flags: u8,
    pub frag_id: u8,
    pub frag_count: u8,
}

unsafe extern "C" {
    fn mq_encode_auth_req(buf: *mut u8, cap: usize, f: *const AuthReqC) -> c_int;
    fn mq_decode_auth_req(buf: *const u8, len: usize, out: *mut AuthReqC) -> c_int;
    fn mq_encode_auth_resp(buf: *mut u8, cap: usize, f: *const AuthRespC) -> c_int;
    fn mq_decode_auth_resp(buf: *const u8, len: usize, out: *mut AuthRespC) -> c_int;
    fn mq_encode_connect_tcp_req(buf: *mut u8, cap: usize, f: *const ConnectTcpReqC) -> c_int;
    fn mq_decode_connect_tcp_req(buf: *const u8, len: usize, out: *mut ConnectTcpReqC) -> c_int;
    fn mq_encode_connect_tcp_resp(buf: *mut u8, cap: usize, f: *const ConnectTcpRespC) -> c_int;
    fn mq_decode_connect_tcp_resp(buf: *const u8, len: usize, out: *mut ConnectTcpRespC) -> c_int;
    fn mq_encode_udp_session_open(buf: *mut u8, cap: usize, f: *const UdpSessionOpenC) -> c_int;
    fn mq_decode_udp_session_open(buf: *const u8, len: usize, out: *mut UdpSessionOpenC) -> c_int;
    fn mq_encode_udp_session_resp(buf: *mut u8, cap: usize, f: *const UdpSessionRespC) -> c_int;
    fn mq_decode_udp_session_resp(buf: *const u8, len: usize, out: *mut UdpSessionRespC) -> c_int;
    fn mq_udp_msg_encode_hdr(buf: *mut u8, h: *const UdpMsgHdrC) -> c_int;
    fn mq_udp_msg_decode_hdr(buf: *const u8, len: usize, out: *mut UdpMsgHdrC) -> c_int;
    fn mq_varint_encode(buf: *mut u8, cap: usize, v: u64) -> c_int;
    fn mq_varint_decode(buf: *const u8, len: usize, out: *mut u64) -> c_int;
    fn mq_difftest_layout(n: *mut usize) -> *const usize;
}

/// Ample for any of these frames (largest AUTH_REQUEST is < 350 bytes).
const ENC_CAP: usize = 1024;

macro_rules! codec {
    ($dec:ident, $enc:ident, $ty:ty, $c_dec:ident, $c_enc:ident, [$($cstr:ident),*]) => {
        /// C decode: `(frame, consumed)`, or `None` when C returns -1.
        pub fn $dec(buf: &[u8]) -> Option<($ty, usize)> {
            // SAFETY: all-zero is a valid value of these plain-data structs; C
            // reads at most `buf.len()` bytes and writes only into `out`.
            let mut out: $ty = unsafe { std::mem::zeroed() };
            let n = unsafe { $c_dec(buf.as_ptr(), buf.len(), &mut out) };
            usize::try_from(n).ok().map(|n| (out, n))
        }
        /// C encode, or `None` when C returns -1.
        ///
        /// # Panics
        /// If a field C reads with `strlen` holds no NUL (C would read past it).
        pub fn $enc(f: &$ty) -> Option<Vec<u8>> {
            $(assert!(
                f.$cstr.contains(&0),
                concat!(stringify!($cstr), " is not NUL-terminated")
            );)*
            let mut buf = vec![0u8; ENC_CAP];
            // SAFETY: every strlen'd field is NUL-terminated (asserted above);
            // C writes at most `ENC_CAP` bytes and only reads `f`.
            let n = unsafe { $c_enc(buf.as_mut_ptr(), buf.len(), f) };
            buf.truncate(usize::try_from(n).ok()?);
            Some(buf)
        }
    };
}

codec!(
    decode_auth_req,
    encode_auth_req,
    AuthReqC,
    mq_decode_auth_req,
    mq_encode_auth_req,
    [client_id, auth_token]
);
codec!(
    decode_auth_resp,
    encode_auth_resp,
    AuthRespC,
    mq_decode_auth_resp,
    mq_encode_auth_resp,
    [server_id]
);
codec!(
    decode_connect_tcp_req,
    encode_connect_tcp_req,
    ConnectTcpReqC,
    mq_decode_connect_tcp_req,
    mq_encode_connect_tcp_req,
    []
);
codec!(
    decode_connect_tcp_resp,
    encode_connect_tcp_resp,
    ConnectTcpRespC,
    mq_decode_connect_tcp_resp,
    mq_encode_connect_tcp_resp,
    [message]
);

codec!(
    decode_udp_session_open,
    encode_udp_session_open,
    UdpSessionOpenC,
    mq_decode_udp_session_open,
    mq_encode_udp_session_open,
    []
);
// C re-encodes `message` by `message_len`, not strlen: no NUL requirement.
codec!(
    decode_udp_session_resp,
    encode_udp_session_resp,
    UdpSessionRespC,
    mq_decode_udp_session_resp,
    mq_encode_udp_session_resp,
    []
);

/// C datagram header encode (writes exactly 9 bytes, returns 0), or `None` on -1.
pub fn c_udp_hdr_encode(h: &UdpMsgHdrC) -> Option<[u8; 9]> {
    let mut buf = [0u8; 9];
    // SAFETY: C writes exactly 9 bytes into `buf` and only reads `h`.
    let r = unsafe { mq_udp_msg_encode_hdr(buf.as_mut_ptr(), h) };
    (r == 0).then_some(buf)
}

/// C datagram header decode of the first 9 bytes, or `None` on -1 (`buf` < 9 bytes).
pub fn c_udp_hdr_decode(buf: &[u8]) -> Option<UdpMsgHdrC> {
    // SAFETY: all-zero is a valid value of this plain-data struct; C reads at
    // most `buf.len()` bytes and writes only into `out`.
    let mut out: UdpMsgHdrC = unsafe { std::mem::zeroed() };
    let r = unsafe { mq_udp_msg_decode_hdr(buf.as_ptr(), buf.len(), &mut out) };
    (r == 0).then_some(out)
}

/// C varint encode into a `cap`-byte buffer: the written bytes, or `None` on -1.
pub fn varint_encode(cap: usize, v: u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; cap];
    // SAFETY: C writes at most `cap` bytes.
    let n = unsafe { mq_varint_encode(buf.as_mut_ptr(), cap, v) };
    buf.truncate(usize::try_from(n).ok()?);
    Some(buf)
}

/// C varint decode: `(value, consumed)`, or `None` on -1.
pub fn varint_decode(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0;
    // SAFETY: C reads at most `buf.len()` bytes and writes only `v`.
    let n = unsafe { mq_varint_decode(buf.as_ptr(), buf.len(), &mut v) };
    usize::try_from(n).ok().map(|n| (v, n))
}

/// sizeof/offsetof table as the C compiler sees `mq_wire.h` / `mq_udp_msg.h` (layout.c).
pub fn c_layout() -> Vec<usize> {
    let mut n = 0;
    // SAFETY: returns a pointer to a static array of `n` elements.
    unsafe { std::slice::from_raw_parts(mq_difftest_layout(&mut n), n) }.to_vec()
}

/// The same table for the Rust mirrors, in layout.c order.
pub fn rust_layout() -> Vec<usize> {
    vec![
        size_of::<AuthReqC>(),
        offset_of!(AuthReqC, version),
        offset_of!(AuthReqC, client_id),
        offset_of!(AuthReqC, auth_token),
        offset_of!(AuthReqC, features),
        size_of::<AuthRespC>(),
        offset_of!(AuthRespC, status),
        offset_of!(AuthRespC, error_code),
        offset_of!(AuthRespC, server_id),
        offset_of!(AuthRespC, features),
        size_of::<ConnectTcpReqC>(),
        offset_of!(ConnectTcpReqC, flags),
        offset_of!(ConnectTcpReqC, address_type),
        offset_of!(ConnectTcpReqC, host),
        offset_of!(ConnectTcpReqC, host_len),
        offset_of!(ConnectTcpReqC, port),
        size_of::<ConnectTcpRespC>(),
        offset_of!(ConnectTcpRespC, status),
        offset_of!(ConnectTcpRespC, error_code),
        offset_of!(ConnectTcpRespC, message),
        offset_of!(ConnectTcpRespC, message_len),
        size_of::<c_int>(), // mq_status_t
        size_of::<c_int>(), // mq_addr_type_t
        size_of::<UdpSessionOpenC>(),
        offset_of!(UdpSessionOpenC, session_id),
        offset_of!(UdpSessionOpenC, flags),
        offset_of!(UdpSessionOpenC, address_type),
        offset_of!(UdpSessionOpenC, host),
        offset_of!(UdpSessionOpenC, host_len),
        offset_of!(UdpSessionOpenC, port),
        offset_of!(UdpSessionOpenC, idle_timeout_ms),
        size_of::<UdpSessionRespC>(),
        offset_of!(UdpSessionRespC, status),
        offset_of!(UdpSessionRespC, error_code),
        offset_of!(UdpSessionRespC, message),
        offset_of!(UdpSessionRespC, message_len),
        offset_of!(UdpSessionRespC, idle_timeout_ms),
        size_of::<UdpMsgHdrC>(),
        offset_of!(UdpMsgHdrC, session_id),
        offset_of!(UdpMsgHdrC, packet_id),
        offset_of!(UdpMsgHdrC, flags),
        offset_of!(UdpMsgHdrC, frag_id),
        offset_of!(UdpMsgHdrC, frag_count),
        size_of::<c_int>(), // mq_udp_err_t
    ]
}
