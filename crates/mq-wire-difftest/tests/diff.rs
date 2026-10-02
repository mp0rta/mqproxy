// spec §8.2: differential test of mq-wire against the C codec (src/wire/).
// The C codec is normative inside the domain it can represent: no NUL in the
// fields C reads back with strlen (client_id, auth_token, server_id, message)
// and error_code < 2^31 (C narrows it to an `int` enum). Outside that domain
// only the decode outcome (Ok vs Err) is compared. The UDP frames and the
// datagram header have no such limits: every decoded value is compared in full.
use mq_wire::frames::{
    AddrType, AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp, EncodeError, MAX_FRAME,
    UdpSessionOpen, UdpSessionResp,
};
use mq_wire::udp_msg::{UDP_MSG_HDR, UdpMsgHdr};
use mq_wire::varint;
use mq_wire_difftest as c;
use std::ffi::CStr;

const N: usize = 10_000;

/// xorshift64*: fixed seed so every run sees the same inputs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    /// Value of a random bit width 0..=bits, so every varint prefix length is hit.
    fn width(&mut self, bits: u32) -> u64 {
        let w = self.below(u64::from(bits) + 1) as u32;
        if w == 0 { 0 } else { self.next() >> (64 - w) }
    }
}

// ---- domain + comparison, one per frame; used by every test group ----

const ERR_DOMAIN: u64 = 1 << 31;

fn cstr(b: &[u8]) -> &[u8] {
    CStr::from_bytes_until_nul(b)
        .expect("C wrote a NUL")
        .to_bytes()
}

fn rust_reencode(f: impl FnOnce(&mut [u8]) -> usize) -> Vec<u8> {
    let mut out = [0u8; MAX_FRAME];
    let n = f(&mut out);
    out[..n].to_vec()
}

/// Some(in_domain) when both decoded, None when both rejected; panics on divergence.
fn cmp_auth_req(input: &[u8]) -> Option<bool> {
    let r = AuthReq::decode(input);
    let cd = c::decode_auth_req(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "auth_req outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // Consumed length and scalars do not depend on the domain limits.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(r.version, cf.version);
    assert_eq!(r.features, cf.features);
    if r.client_id.contains(&0) || r.auth_token.contains(&0) {
        return Some(false);
    }
    assert_eq!(r.client_id, cstr(&cf.client_id));
    assert_eq!(r.auth_token, cstr(&cf.auth_token));
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_auth_req(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

fn cmp_auth_resp(input: &[u8]) -> Option<bool> {
    let r = AuthResp::decode(input);
    let cd = c::decode_auth_resp(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "auth_resp outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // Consumed length and scalars do not depend on the domain limits.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(u32::from(r.status), cf.status as u32);
    assert_eq!(r.features, cf.features);
    if r.server_id.contains(&0) || r.error_code >= ERR_DOMAIN {
        return Some(false);
    }
    assert_eq!(r.error_code, u64::from(cf.error_code as u32));
    assert_eq!(r.server_id, cstr(&cf.server_id));
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_auth_resp(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

fn cmp_connect_tcp_req(input: &[u8]) -> Option<bool> {
    let r = ConnectTcpReq::decode(input);
    let cd = c::decode_connect_tcp_req(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "connect_tcp_req outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // host carries an explicit length on both sides: always fully comparable.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(r.flags, cf.flags);
    assert_eq!(r.address_type as i32, cf.address_type);
    assert_eq!(r.host, &cf.host[..cf.host_len]);
    assert_eq!(r.port, cf.port);
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_connect_tcp_req(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

fn cmp_connect_tcp_resp(input: &[u8]) -> Option<bool> {
    let r = ConnectTcpResp::decode(input);
    let cd = c::decode_connect_tcp_resp(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "connect_tcp_resp outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // Consumed length, status and the length-carrying message do not depend
    // on the domain limits.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(u32::from(r.status), cf.status as u32);
    assert_eq!(r.message, &cf.message[..cf.message_len]);
    // C decodes message with an explicit length but re-encodes it with strlen.
    if r.message.contains(&0) || r.error_code >= ERR_DOMAIN {
        return Some(false);
    }
    assert_eq!(r.error_code, u64::from(cf.error_code as u32));
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_connect_tcp_resp(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

fn cmp_udp_open(input: &[u8]) -> Option<bool> {
    let r = UdpSessionOpen::decode(input);
    let cd = c::decode_udp_session_open(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "udp_open outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // host carries an explicit length on both sides: always fully comparable.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(r.session_id, cf.session_id);
    assert_eq!(r.flags, cf.flags);
    assert_eq!(r.address_type as i32, cf.address_type);
    assert_eq!(r.host, &cf.host[..cf.host_len]);
    assert_eq!(r.port, cf.port);
    assert_eq!(r.idle_timeout_ms, cf.idle_timeout_ms);
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_udp_session_open(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

fn cmp_udp_resp(input: &[u8]) -> Option<bool> {
    let r = UdpSessionResp::decode(input);
    let cd = c::decode_udp_session_resp(input);
    assert_eq!(
        r.is_ok(),
        cd.is_some(),
        "udp_resp outcome differs on {input:02x?}"
    );
    let ((r, rn), (cf, cn)) = (r.ok()?, cd?);
    // Both sides carry the message length explicitly and C re-encodes it with
    // `message_len` (no strlen); error_code is <= 4 on every accepted frame.
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(u32::from(r.status), cf.status as u32);
    assert_eq!(r.error_code, u64::from(cf.error_code as u32));
    assert_eq!(r.message, &cf.message[..cf.message_len]);
    assert_eq!(r.idle_timeout_ms, cf.idle_timeout_ms);
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_udp_session_resp(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
    Some(true)
}

/// The header has no padding or length: it decodes iff `input` holds 9 bytes.
fn cmp_udp_hdr(input: &[u8]) -> Option<bool> {
    let r = UdpMsgHdr::decode(input);
    let cd = c::c_udp_hdr_decode(input);
    assert_eq!(
        r.is_some(),
        cd.is_some(),
        "udp_hdr outcome differs on {input:02x?}"
    );
    let (r, cf) = (r?, cd?);
    assert_eq!(r.session_id, cf.session_id);
    assert_eq!(r.packet_id, cf.packet_id);
    assert_eq!(r.flags, cf.flags);
    assert_eq!(r.frag_id, cf.frag_id);
    assert_eq!(r.frag_count, cf.frag_count);
    let mut re = [0u8; UDP_MSG_HDR];
    r.encode(&mut re);
    assert_eq!(re[..], input[..UDP_MSG_HDR], "re-encode on {input:02x?}");
    assert_eq!(Some(re), c::c_udp_hdr_encode(&cf));
    Some(true)
}

fn cmp_varint_decode(input: &[u8]) -> Option<bool> {
    let r = varint::decode(input).ok();
    assert_eq!(r, c::varint_decode(input), "varint decode on {input:02x?}");
    r.map(|_| true)
}

// ---- 1. corpus replay ----

fn replay(dir: &str, cmp: Cmp) {
    let path = format!("{}/../../fuzz/corpus/{dir}", env!("CARGO_MANIFEST_DIR"));
    let mut n = 0;
    for e in std::fs::read_dir(&path).unwrap_or_else(|e| panic!("{path}: {e}")) {
        cmp(&std::fs::read(e.unwrap().path()).unwrap());
        n += 1;
    }
    assert!(n > 0, "empty corpus {path}");
}

#[test]
fn corpus_replay() {
    replay("wire_auth_req", cmp_auth_req);
    replay("wire_auth_resp", cmp_auth_resp);
    replay("wire_connect_tcp_req", cmp_connect_tcp_req);
    replay("wire_connect_tcp_resp", cmp_connect_tcp_resp);
    replay("wire_udp_session_open", cmp_udp_open);
    replay("wire_udp_session_resp", cmp_udp_resp);
    replay("udp_msg_hdr", cmp_udp_hdr);
    replay("varint", cmp_varint_decode);
}

// ---- generators: raw wire bytes built field by field ----
// `wild` leaves the domain (over-cap strings, NULs, error codes >= 2^31, bad
// address types). In-domain frames still get non-minimal varints, padding and
// trailing bytes, so the consumed length is exercised.

fn put_varint(out: &mut Vec<u8>, rng: &mut Rng, v: u64) {
    // Sometimes a wider prefix than needed; both decoders must accept it.
    let n = [1, 2, 4, 8][rng.below(4) as usize].max(varint::len(v));
    let mut b = v.to_be_bytes()[8 - n..].to_vec();
    b[0] |= match n {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xC0,
    };
    out.extend(b);
}

fn put_string(out: &mut Vec<u8>, rng: &mut Rng, cap: u64, wild: bool, nul_ok: bool) {
    let len = if wild && rng.chance(20) {
        cap + 1 + rng.below(4)
    } else {
        rng.below(cap + 1)
    };
    put_varint(out, rng, len);
    for _ in 0..len {
        let b = rng.next() as u8;
        out.push(if b == 0 && !(nul_ok || wild) { 1 } else { b });
    }
}

fn error_code(rng: &mut Rng, wild: bool) -> u64 {
    if wild && rng.chance(20) {
        ERR_DOMAIN + rng.below(varint::MAX - ERR_DOMAIN + 1)
    } else {
        rng.width(31)
    }
}

fn finish(out: &mut Vec<u8>, rng: &mut Rng) {
    let pad = if rng.chance(30) { rng.below(16) } else { 0 };
    put_varint(out, rng, pad);
    let trailing = if rng.chance(20) { rng.below(8) } else { 0 };
    out.extend((0..pad + trailing).map(|_| rng.next() as u8));
}

fn gen_auth_req(rng: &mut Rng, wild: bool) -> Vec<u8> {
    let mut o = Vec::new();
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    put_string(&mut o, rng, 63, wild, false);
    put_string(&mut o, rng, 255, wild, false);
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    finish(&mut o, rng);
    o
}

fn gen_auth_resp(rng: &mut Rng, wild: bool) -> Vec<u8> {
    let mut o = vec![rng.next() as u8];
    let e = error_code(rng, wild);
    put_varint(&mut o, rng, e);
    put_string(&mut o, rng, 63, wild, false);
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    finish(&mut o, rng);
    o
}

fn gen_connect_tcp_req(rng: &mut Rng, wild: bool) -> Vec<u8> {
    let mut o = Vec::new();
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    let at = [AddrType::Ipv4, AddrType::Domain, AddrType::Ipv6][rng.below(3) as usize] as u8;
    o.push(if wild && rng.chance(20) {
        rng.next() as u8
    } else {
        at
    });
    put_string(&mut o, rng, 255, wild, true);
    o.extend((rng.next() as u16).to_be_bytes());
    finish(&mut o, rng);
    o
}

fn gen_connect_tcp_resp(rng: &mut Rng, wild: bool) -> Vec<u8> {
    let mut o = vec![rng.next() as u8];
    let e = error_code(rng, wild);
    put_varint(&mut o, rng, e);
    put_string(&mut o, rng, 255, wild, false);
    finish(&mut o, rng);
    o
}

fn gen_udp_open(rng: &mut Rng, wild: bool) -> Vec<u8> {
    let mut o = Vec::new();
    let sid = if wild && rng.chance(20) {
        (1 << 32) | rng.width(30)
    } else {
        rng.width(32)
    };
    put_varint(&mut o, rng, sid);
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    let at = [AddrType::Ipv4, AddrType::Domain, AddrType::Ipv6][rng.below(3) as usize] as u8;
    o.push(if wild && rng.chance(20) {
        rng.next() as u8
    } else {
        at
    });
    put_string(&mut o, rng, 255, wild, true);
    o.extend((rng.next() as u16).to_be_bytes());
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    finish(&mut o, rng);
    o
}

fn gen_udp_resp(rng: &mut Rng, wild: bool) -> Vec<u8> {
    // In domain: OK with code 0, or ERROR with code 1..=4. Wild: any status
    // 0..=3 with any code, so inconsistent pairs and code >= 5 are both hit.
    let (status, code) = if wild && rng.chance(30) {
        let code = if rng.chance(30) {
            error_code(rng, true)
        } else {
            rng.below(8)
        };
        (rng.below(4) as u8, code)
    } else if rng.chance(50) {
        (0, 0)
    } else {
        (1, 1 + rng.below(4))
    };
    let mut o = vec![status];
    put_varint(&mut o, rng, code);
    put_string(&mut o, rng, 255, wild, true);
    let v = rng.width(62);
    put_varint(&mut o, rng, v);
    finish(&mut o, rng);
    o
}

/// 9 random bytes, then a random payload (ignored by both decoders).
fn gen_udp_hdr(rng: &mut Rng, _wild: bool) -> Vec<u8> {
    (0..UDP_MSG_HDR as u64 + rng.below(8))
        .map(|_| rng.next() as u8)
        .collect()
}

type Gen = fn(&mut Rng, bool) -> Vec<u8>;
type Cmp = fn(&[u8]) -> Option<bool>;
const FRAMES: [(&str, Gen, Cmp); 4] = [
    ("auth_req", gen_auth_req, cmp_auth_req),
    ("auth_resp", gen_auth_resp, cmp_auth_resp),
    ("connect_tcp_req", gen_connect_tcp_req, cmp_connect_tcp_req),
    (
        "connect_tcp_resp",
        gen_connect_tcp_resp,
        cmp_connect_tcp_resp,
    ),
];

// ---- 2. in-domain generated frames ----

fn check_in_domain(name: &str, rng: &mut Rng, generate: Gen, cmp: Cmp) {
    for _ in 0..N {
        let input = generate(rng, false);
        assert_eq!(
            cmp(&input),
            Some(true),
            "{name}: not decoded in-domain: {input:02x?}"
        );
    }
}

#[test]
fn generated_in_domain() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for (name, generate, cmp) in FRAMES {
        check_in_domain(name, &mut rng, generate, cmp);
    }
}

// ---- 3. out-of-domain / mutated frames: outcome parity ----

fn check_mutated(name: &str, rng: &mut Rng, generate: Gen, cmp: Cmp) {
    let (mut ok, mut err) = (0, 0);
    for i in 0..N {
        let mut input = generate(rng, true);
        match i % 4 {
            0 => input.truncate(rng.below(input.len() as u64) as usize),
            1 => {
                let at = rng.below(input.len() as u64) as usize;
                input[at] = rng.next() as u8;
            }
            2 => input = (0..rng.below(40)).map(|_| rng.next() as u8).collect(),
            _ => {} // wild fields only
        }
        match cmp(&input) {
            Some(_) => ok += 1,
            None => err += 1,
        }
    }
    // Both outcomes must actually be exercised.
    assert!(ok > N / 10 && err > N / 10, "{name}: ok={ok} err={err}");
}

#[test]
fn generated_out_of_domain_and_mutated() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for (name, generate, cmp) in FRAMES {
        check_mutated(name, &mut rng, generate, cmp);
    }
}

// ---- 4. varint ----

#[test]
fn varint_encode_parity() {
    let mut rng = Rng(0xA076_1D64_78BD_642F);
    for _ in 0..N {
        let v = rng.width(64); // widths 63/64 exceed MAX: rejection parity
        let cap = if rng.chance(10) {
            rng.below(8) as usize
        } else {
            8
        };
        let mut buf = [0u8; 8];
        let r = varint::encode(&mut buf[..cap], v)
            .ok()
            .map(|n| buf[..n].to_vec());
        assert_eq!(
            r,
            c::varint_encode(cap, v),
            "varint encode {v:#x} cap {cap}"
        );
    }
}

#[test]
fn varint_decode_parity() {
    let mut rng = Rng(0xE703_7ED1_A0B4_28DB);
    for _ in 0..N {
        let input: Vec<u8> = (0..rng.below(10)).map(|_| rng.next() as u8).collect();
        cmp_varint_decode(&input);
    }
}

// ---- 5. UDP frames and the datagram header (spec §2.1, §2.2) ----

fn assert_rejected(cmp: Cmp, input: &[u8]) {
    assert_eq!(cmp(input), None, "both must reject {input:02x?}");
}

/// Both decoders accept `valid` and reject every strict prefix of it (the
/// trailing padding length is mandatory, so no prefix is a frame).
fn assert_prefixes_rejected(cmp: Cmp, valid: &[u8]) {
    assert_eq!(cmp(valid), Some(true), "control {valid:02x?}");
    for n in 0..valid.len() {
        assert_rejected(cmp, &valid[..n]);
    }
}

fn open_c(f: &UdpSessionOpen) -> c::UdpSessionOpenC {
    // SAFETY: all-zero is a valid value of this plain-data struct.
    let mut cf: c::UdpSessionOpenC = unsafe { std::mem::zeroed() };
    cf.session_id = f.session_id;
    cf.flags = f.flags;
    cf.address_type = f.address_type as i32;
    cf.host[..f.host.len()].copy_from_slice(f.host);
    cf.host_len = f.host.len();
    cf.port = f.port;
    cf.idle_timeout_ms = f.idle_timeout_ms;
    cf
}

fn resp_c(f: &UdpSessionResp) -> c::UdpSessionRespC {
    // SAFETY: all-zero is a valid value of this plain-data struct.
    let mut cf: c::UdpSessionRespC = unsafe { std::mem::zeroed() };
    cf.status = i32::from(f.status);
    cf.error_code = f.error_code as i32;
    cf.message[..f.message.len()].copy_from_slice(f.message);
    cf.message_len = f.message.len();
    cf.idle_timeout_ms = f.idle_timeout_ms;
    cf
}

fn rust_encode(f: impl FnOnce(&mut [u8]) -> Result<usize, EncodeError>) -> Option<Vec<u8>> {
    let mut out = [0u8; MAX_FRAME];
    f(&mut out).ok().map(|n| out[..n].to_vec())
}

fn random_bytes(rng: &mut Rng, max: u64) -> Vec<u8> {
    (0..rng.below(max + 1)).map(|_| rng.next() as u8).collect()
}

#[test]
fn udp_open_equal() {
    let mut rng = Rng(0x1F83_D9AB_FB41_BD6B);
    check_in_domain("udp_open", &mut rng, gen_udp_open, cmp_udp_open);
    check_mutated("udp_open", &mut rng, gen_udp_open, cmp_udp_open);

    // Encode side: random structs, including varints above 2^62-1 (both reject).
    let mut encoded = 0;
    for _ in 0..N {
        let host = random_bytes(&mut rng, 255);
        let f = UdpSessionOpen {
            session_id: rng.width(32) as u32,
            flags: rng.width(64),
            address_type: [AddrType::Ipv4, AddrType::Domain, AddrType::Ipv6][rng.below(3) as usize],
            host: &host,
            port: rng.next() as u16,
            idle_timeout_ms: rng.width(64),
        };
        let r = rust_encode(|o| f.encode(o));
        assert_eq!(r, c::encode_udp_session_open(&open_c(&f)), "encode {f:?}");
        encoded += usize::from(r.is_some());
    }
    assert!(encoded > N / 10 && encoded < N, "encoded {encoded}/{N}");

    // sid 0 | flags 0 | atype 1 | host "" | port 0 | idle 0 | pad 0
    let valid = [0, 0, 1, 0, 0, 0, 0, 0];
    assert_prefixes_rejected(cmp_udp_open, &valid);
    let sid_2_32 = [0xC0, 0, 0, 1, 0, 0, 0, 0];
    assert_rejected(cmp_udp_open, &[&sid_2_32[..], &valid[1..]].concat());
    assert_rejected(cmp_udp_open, &sid_2_32); // invalid AND truncated
    for at in [0x00, 0x02, 0x05, 0xFF] {
        assert_rejected(cmp_udp_open, &[0, 0, at, 0, 0, 0, 0, 0]);
    }
    // C refuses to encode an address type outside {1, 3, 4}.
    let mut cf = open_c(&UdpSessionOpen {
        session_id: 0,
        flags: 0,
        address_type: AddrType::Ipv4,
        host: b"",
        port: 0,
        idle_timeout_ms: 0,
    });
    cf.address_type = 5;
    assert_eq!(c::encode_udp_session_open(&cf), None);
}

#[test]
fn udp_resp_equal() {
    let mut rng = Rng(0x5BE0_CD19_137E_2179);
    check_in_domain("udp_resp", &mut rng, gen_udp_resp, cmp_udp_resp);
    check_mutated("udp_resp", &mut rng, gen_udp_resp, cmp_udp_resp);

    // Encode side: status 0..=2 with code 0..=6 (5 is C's boundary-only CLOSED).
    let mut encoded = 0;
    for _ in 0..N {
        let message = random_bytes(&mut rng, 255);
        let f = UdpSessionResp {
            status: rng.below(3) as u8,
            error_code: rng.below(7),
            message: &message,
            idle_timeout_ms: rng.width(64),
        };
        let r = rust_encode(|o| f.encode(o));
        assert_eq!(r, c::encode_udp_session_resp(&resp_c(&f)), "encode {f:?}");
        encoded += usize::from(r.is_some());
    }
    assert!(encoded > N / 10 && encoded < N, "encoded {encoded}/{N}");

    // status | code | message "" | idle 0 | pad 0
    assert_prefixes_rejected(cmp_udp_resp, &[0, 0, 0, 0, 0]);
    assert_prefixes_rejected(cmp_udp_resp, &[1, 4, 0, 0, 0]);
    for bad in [
        [1, 5, 0, 0, 0], // error_code 5 (CLOSED) is boundary-only
        [1, 6, 0, 0, 0],
        [0, 1, 0, 0, 0], // OK with a non-zero code
        [1, 0, 0, 0, 0], // ERROR with code 0
        [2, 0, 0, 0, 0], // status is neither OK nor ERROR
        [2, 1, 0, 0, 0],
    ] {
        assert_rejected(cmp_udp_resp, &bad);
        assert_rejected(cmp_udp_resp, &bad[..2]); // invalid AND truncated
    }
}

#[test]
fn udp_hdr_equal() {
    let mut rng = Rng(0x6C44_198C_4A47_5817);
    check_in_domain("udp_hdr", &mut rng, gen_udp_hdr, cmp_udp_hdr);
    check_mutated("udp_hdr", &mut rng, gen_udp_hdr, cmp_udp_hdr);

    // Encode side: C and Rust emit the same 9 bytes, field extremes included.
    for i in 0..N {
        let pick = |rng: &mut Rng, max: u64| match i % 3 {
            0 => 0,
            1 => max,
            _ => rng.below(max + 1),
        };
        let h = UdpMsgHdr {
            session_id: pick(&mut rng, u64::from(u32::MAX)) as u32,
            packet_id: pick(&mut rng, u64::from(u16::MAX)) as u16,
            flags: pick(&mut rng, 255) as u8,
            frag_id: pick(&mut rng, 255) as u8,
            frag_count: pick(&mut rng, 255) as u8,
        };
        let mut re = [0u8; UDP_MSG_HDR];
        h.encode(&mut re);
        let cf = c::UdpMsgHdrC {
            session_id: h.session_id,
            packet_id: h.packet_id,
            flags: h.flags,
            frag_id: h.frag_id,
            frag_count: h.frag_count,
        };
        assert_eq!(c::c_udp_hdr_encode(&cf), Some(re), "encode {h:?}");
    }

    // Strictly shorter than 9 bytes: rejected; 9 bytes or more: accepted.
    let valid = [0u8; UDP_MSG_HDR];
    for n in 0..UDP_MSG_HDR {
        assert_rejected(cmp_udp_hdr, &valid[..n]);
    }
    assert_eq!(cmp_udp_hdr(&valid), Some(true));
    assert_eq!(cmp_udp_hdr(&[0xFF; UDP_MSG_HDR + 5]), Some(true));
}

#[test]
fn struct_layout_matches_header() {
    assert_eq!(c::rust_layout(), c::c_layout());
}

#[test]
#[should_panic(expected = "server_id is not NUL-terminated")]
fn c_encode_refuses_unterminated_string() {
    let (mut f, _) = c::decode_auth_resp(&[0, 0, 0, 0, 0]).unwrap();
    f.server_id = [b'x'; 64];
    c::encode_auth_resp(&f);
}
