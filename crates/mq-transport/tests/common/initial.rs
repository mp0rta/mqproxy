// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Hand-built QUIC v1 client Initial packets (RFC 9001 §5) carrying a ClientHello that never
//! completes: no real client sends one, so the provisional-connection test builds them.
//! Crypto comes from the BoringSSL that xquic-sys links statically.

use core::ffi::{c_int, c_uint, c_void};

unsafe extern "C" {
    fn EVP_sha256() -> *const c_void;
    fn HKDF_extract(
        out_key: *mut u8,
        out_len: *mut usize,
        digest: *const c_void,
        secret: *const u8,
        secret_len: usize,
        salt: *const u8,
        salt_len: usize,
    ) -> c_int;
    fn HKDF_expand(
        out_key: *mut u8,
        out_len: usize,
        digest: *const c_void,
        prk: *const u8,
        prk_len: usize,
        info: *const u8,
        info_len: usize,
    ) -> c_int;
    fn EVP_aead_aes_128_gcm() -> *const c_void;
    fn EVP_AEAD_CTX_new(
        aead: *const c_void,
        key: *const u8,
        key_len: usize,
        tag_len: usize,
    ) -> *mut c_void;
    fn EVP_AEAD_CTX_free(ctx: *mut c_void);
    #[allow(clippy::too_many_arguments)]
    fn EVP_AEAD_CTX_seal(
        ctx: *const c_void,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        input: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
    ) -> c_int;
    fn AES_set_encrypt_key(key: *const u8, bits: c_uint, aeskey: *mut AesKey) -> c_int;
    fn AES_ecb_encrypt(input: *const u8, out: *mut u8, key: *const AesKey, enc: c_int);
}

/// BoringSSL's `AES_KEY` (61 words), with room to spare.
#[repr(C, align(16))]
struct AesKey([u32; 64]);

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = vec![(len >> 8) as u8, len as u8, full.len() as u8];
    info.extend_from_slice(full.as_bytes());
    info.push(0); // empty context
    let mut out = vec![0u8; len];
    // SAFETY: every pointer covers its stated length.
    let ok = unsafe {
        HKDF_expand(
            out.as_mut_ptr(),
            len,
            EVP_sha256(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    assert_eq!(ok, 1);
    out
}

/// Client Initial keys for `dcid`: (key, iv, hp).
fn client_keys(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut prk = [0u8; 32];
    let mut prk_len = 0usize;
    // SAFETY: as above.
    let ok = unsafe {
        HKDF_extract(
            prk.as_mut_ptr(),
            &mut prk_len,
            EVP_sha256(),
            dcid.as_ptr(),
            dcid.len(),
            INITIAL_SALT_V1.as_ptr(),
            INITIAL_SALT_V1.len(),
        )
    };
    assert_eq!((ok, prk_len), (1, 32));
    let client = expand_label(&prk, "client in", 32);
    (
        expand_label(&client, "quic key", 16),
        expand_label(&client, "quic iv", 12),
        expand_label(&client, "quic hp", 16),
    )
}

fn varint(v: u64, out: &mut Vec<u8>) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16383 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        _ => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
    }
}

/// The start of a ClientHello that claims 4000 bytes: it can never complete from the
/// fragments these tests send.
pub fn client_hello_fragment(offset: usize, len: usize) -> Vec<u8> {
    let mut m = vec![0x01, 0x00, 0x0f, 0xa0, 0x03, 0x03]; // ClientHello, u24 len 4000, TLS 1.2
    m.resize(offset + len, 0x5a);
    m[offset..].to_vec()
}

/// One protected 1200-byte client Initial with packet number `pn` and one CRYPTO frame.
pub fn initial(dcid: &[u8], scid: &[u8], pn: u32, crypto_offset: u64, crypto: &[u8]) -> Vec<u8> {
    const DATAGRAM: usize = 1200;
    const TAG: usize = 16;
    let mut hdr = vec![0xc3, 0, 0, 0, 1, dcid.len() as u8];
    hdr.extend_from_slice(dcid);
    hdr.push(scid.len() as u8);
    hdr.extend_from_slice(scid);
    hdr.push(0); // token length
    let len_at = hdr.len();
    hdr.extend_from_slice(&[0, 0]); // 2-byte Length, filled below
    let pn_at = hdr.len();
    hdr.extend_from_slice(&pn.to_be_bytes());

    let mut payload = vec![0x06];
    varint(crypto_offset, &mut payload);
    varint(crypto.len() as u64, &mut payload);
    payload.extend_from_slice(crypto);
    let room = DATAGRAM - TAG - hdr.len();
    assert!(payload.len() <= room, "CRYPTO data does not fit");
    payload.resize(room, 0); // PADDING
    let length = (4 + payload.len() + TAG) as u16;
    hdr[len_at..len_at + 2].copy_from_slice(&(0x4000 | length).to_be_bytes());

    let (key, iv, hp) = client_keys(dcid);
    let mut nonce = iv.clone();
    for (n, p) in nonce[4..].iter_mut().zip(u64::from(pn).to_be_bytes()) {
        *n ^= p;
    }
    let mut sealed = vec![0u8; payload.len() + TAG];
    let mut sealed_len = 0usize;
    // SAFETY: every pointer covers its stated length; the context is freed below.
    unsafe {
        let ctx = EVP_AEAD_CTX_new(EVP_aead_aes_128_gcm(), key.as_ptr(), key.len(), TAG);
        assert!(!ctx.is_null());
        let ok = EVP_AEAD_CTX_seal(
            ctx,
            sealed.as_mut_ptr(),
            &mut sealed_len,
            sealed.len(),
            nonce.as_ptr(),
            nonce.len(),
            payload.as_ptr(),
            payload.len(),
            hdr.as_ptr(),
            hdr.len(),
        );
        EVP_AEAD_CTX_free(ctx);
        assert_eq!((ok, sealed_len), (1, sealed.len()));
    }
    let mut pkt = hdr;
    pkt.extend_from_slice(&sealed);

    // Header protection: the sample starts 4 bytes after the packet number's start.
    let mut mask = [0u8; 16];
    let mut aes = AesKey([0; 64]);
    // SAFETY: a 128-bit key; `sample` and `mask` are 16 bytes.
    unsafe {
        assert_eq!(AES_set_encrypt_key(hp.as_ptr(), 128, &mut aes), 0);
        AES_ecb_encrypt(pkt[pn_at + 4..].as_ptr(), mask.as_mut_ptr(), &aes, 1);
    }
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        pkt[pn_at + i] ^= mask[1 + i];
    }
    assert_eq!(pkt.len(), DATAGRAM);
    pkt
}
