// spec §8.2: differential test of mq-wire against the C codec (src/wire/).
// The C codec is normative inside the domain it can represent: no NUL in the
// fields C reads back with strlen (client_id, auth_token, server_id, message)
// and error_code < 2^31 (C narrows it to an `int` enum). Outside that domain
// only the decode outcome (Ok vs Err) is compared.
use mq_wire::frames::{AddrType, AuthReq, AuthResp, ConnectTcpReq, ConnectTcpResp, MAX_FRAME};
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
    if r.client_id.contains(&0) || r.auth_token.contains(&0) {
        return Some(false);
    }
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(r.version, cf.version);
    assert_eq!(r.client_id, cstr(&cf.client_id));
    assert_eq!(r.auth_token, cstr(&cf.auth_token));
    assert_eq!(r.features, cf.features);
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
    if r.server_id.contains(&0) || r.error_code >= ERR_DOMAIN {
        return Some(false);
    }
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(u32::from(r.status), cf.status as u32);
    assert_eq!(r.error_code, u64::from(cf.error_code as u32));
    assert_eq!(r.server_id, cstr(&cf.server_id));
    assert_eq!(r.features, cf.features);
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
    // C decodes message with an explicit length but re-encodes it with strlen.
    if r.message.contains(&0) || r.error_code >= ERR_DOMAIN {
        return Some(false);
    }
    assert_eq!(rn, cn, "consumed on {input:02x?}");
    assert_eq!(u32::from(r.status), cf.status as u32);
    assert_eq!(r.error_code, u64::from(cf.error_code as u32));
    assert_eq!(r.message, &cf.message[..cf.message_len]);
    let re = rust_reencode(|o| r.encode(o).unwrap());
    assert_eq!(
        re,
        c::encode_connect_tcp_resp(&cf).unwrap(),
        "re-encode on {input:02x?}"
    );
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

#[test]
fn generated_in_domain() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for (name, generate, cmp) in FRAMES {
        for _ in 0..N {
            let input = generate(&mut rng, false);
            assert_eq!(
                cmp(&input),
                Some(true),
                "{name}: not decoded in-domain: {input:02x?}"
            );
        }
    }
}

// ---- 3. out-of-domain / mutated frames: outcome parity ----

#[test]
fn generated_out_of_domain_and_mutated() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for (name, generate, cmp) in FRAMES {
        let (mut ok, mut err) = (0, 0);
        for i in 0..N {
            let mut input = generate(&mut rng, true);
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

#[test]
fn struct_layout_matches_header() {
    assert_eq!(c::rust_layout(), c::c_layout());
}
