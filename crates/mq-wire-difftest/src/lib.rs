//! spec §8.2: FFI to the C wire codec (`src/wire/mq_wire.c`, `mq_varint.c`)
//! for the differential test. Structs mirror `src/wire/mq_wire.h` exactly;
//! C enums are `c_int`. Every C function returns bytes written/consumed, or
//! -1 on error; the safe wrappers map that to `Option`.
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

unsafe extern "C" {
    fn mq_encode_auth_req(buf: *mut u8, cap: usize, f: *const AuthReqC) -> c_int;
    fn mq_decode_auth_req(buf: *const u8, len: usize, out: *mut AuthReqC) -> c_int;
    fn mq_encode_auth_resp(buf: *mut u8, cap: usize, f: *const AuthRespC) -> c_int;
    fn mq_decode_auth_resp(buf: *const u8, len: usize, out: *mut AuthRespC) -> c_int;
    fn mq_encode_connect_tcp_req(buf: *mut u8, cap: usize, f: *const ConnectTcpReqC) -> c_int;
    fn mq_decode_connect_tcp_req(buf: *const u8, len: usize, out: *mut ConnectTcpReqC) -> c_int;
    fn mq_encode_connect_tcp_resp(buf: *mut u8, cap: usize, f: *const ConnectTcpRespC) -> c_int;
    fn mq_decode_connect_tcp_resp(buf: *const u8, len: usize, out: *mut ConnectTcpRespC) -> c_int;
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

/// sizeof/offsetof table as the C compiler sees `mq_wire.h` (layout.c).
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
    ]
}
