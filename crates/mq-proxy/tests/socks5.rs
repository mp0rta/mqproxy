// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.1: SOCKS5 ingress parser.

use mq_proxy::ingress::{Progress, Socks5Parser, socks5_error_reply, socks5_success_reply};
use mq_runtime::{Host, Target};
use mq_wire::frames::TcpErr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const GREETING_OK: &[u8] = &[0x05, 0x01, 0x00];
const GREETING_MULTI_OK: &[u8] = &[0x05, 0x02, 0x02, 0x00];
const GREETING_NO_NOAUTH: &[u8] = &[0x05, 0x01, 0x02];
const GREETING_BADVER: &[u8] = &[0x04, 0x01, 0x00];

const REQ_IPV4: &[u8] = &[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
const REQ_DOMAIN: &[u8] = &[
    0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
    0x01, 0xBB,
];
const REQ_IPV6: &[u8] = &[
    0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1F, 0x90,
];
const REQ_CMD_BIND: &[u8] = &[0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];
const REQ_BAD_ATYP: &[u8] = &[0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0x00, 0x50];
const REQ_BADVER: &[u8] = &[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50];

const REQ_ASSOCIATE_V4_ZERO: &[u8] = &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const REQ_ASSOCIATE_V4: &[u8] = &[0x05, 0x03, 0x00, 0x01, 192, 168, 1, 1, 0x04, 0xD2];
const REQ_ASSOCIATE_DOMAIN: &[u8] = &[
    0x05, 0x03, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
    0x01, 0xBB,
];
const REQ_ASSOCIATE_V6: &[u8] = &[
    0x05, 0x03, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x1F,
    0x90,
];

const METHOD_OK: &[u8] = &[0x05, 0x00];
const METHOD_NONE: &[u8] = &[0x05, 0xFF];

fn rep(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

fn greeted() -> Socks5Parser {
    let mut p = Socks5Parser::default();
    assert_eq!(
        p.feed(GREETING_OK),
        Progress::Reply {
            consumed: 3,
            bytes: METHOD_OK,
            close: false
        }
    );
    p
}

fn done(consumed: usize, host: Host, port: u16) -> Progress<'static> {
    Progress::Done {
        consumed,
        target: Target { host, port },
    }
}

// ---- greeting ----

#[test]
fn greeting_ok() {
    greeted();
}

#[test]
fn greeting_multi_method_ok() {
    let mut p = Socks5Parser::default();
    assert_eq!(
        p.feed(GREETING_MULTI_OK),
        Progress::Reply {
            consumed: 4,
            bytes: METHOD_OK,
            close: false
        }
    );
}

#[test]
fn greeting_no_noauth() {
    let mut p = Socks5Parser::default();
    assert_eq!(
        p.feed(GREETING_NO_NOAUTH),
        Progress::Reply {
            consumed: 0,
            bytes: METHOD_NONE,
            close: true
        }
    );
}

#[test]
fn greeting_bad_version() {
    let mut p = Socks5Parser::default();
    assert_eq!(p.feed(GREETING_BADVER), Progress::Close);
}

#[test]
fn greeting_need_more() {
    let mut p = Socks5Parser::default();
    assert_eq!(p.feed(&GREETING_OK[..2]), Progress::Need);
}

#[test]
fn greeting_one_byte() {
    let mut p = Socks5Parser::default();
    assert_eq!(p.feed(&GREETING_OK[..1]), Progress::Need);
    assert_eq!(p.feed(&[]), Progress::Need);
}

// ---- requests ----

#[test]
fn request_ipv4() {
    assert_eq!(
        greeted().feed(REQ_IPV4),
        done(10, Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), 80)
    );
}

#[test]
fn request_domain() {
    assert_eq!(
        greeted().feed(REQ_DOMAIN),
        done(REQ_DOMAIN.len(), Host::Domain("example.com".into()), 443)
    );
}

#[test]
fn request_ipv6() {
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        greeted().feed(REQ_IPV6),
        done(22, Host::Ip(IpAddr::V6(ip)), 0x1F90)
    );
}

#[test]
fn request_fragmented() {
    let mut p = greeted();
    assert_eq!(p.feed(&REQ_IPV4[..5]), Progress::Need);
    assert_eq!(
        p.feed(REQ_IPV4),
        done(10, Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), 80)
    );
}

#[test]
fn request_need_more_every_prefix() {
    for req in [REQ_IPV4, REQ_DOMAIN, REQ_IPV6, REQ_ASSOCIATE_DOMAIN] {
        for n in 0..req.len() {
            assert_eq!(
                greeted().feed(&req[..n]),
                Progress::Need,
                "prefix {n} of {req:?}"
            );
        }
    }
}

#[test]
fn request_cmd_unsupported() {
    // An unsupported command: REP 0x07, then close.
    assert_eq!(
        greeted().feed(REQ_CMD_BIND),
        Progress::Reply {
            consumed: 0,
            bytes: &rep(0x07),
            close: true
        }
    );
}

#[test]
fn request_bind_still_unsupported() {
    // BIND is refused as soon as the CMD byte is visible.
    assert_eq!(
        greeted().feed(&REQ_CMD_BIND[..4]),
        Progress::Reply {
            consumed: 0,
            bytes: &rep(0x07),
            close: true
        }
    );
}

#[test]
fn request_bad_atyp() {
    assert_eq!(
        greeted().feed(REQ_BAD_ATYP),
        Progress::Reply {
            consumed: 0,
            bytes: &rep(0x08),
            close: true
        }
    );
}

#[test]
fn request_bad_version() {
    assert_eq!(greeted().feed(REQ_BADVER), Progress::Close);
}

#[test]
fn request_domain_not_utf8_refused() {
    let req = [0x05, 0x01, 0x00, 0x03, 2, 0xFF, 0xFE, 0x00, 0x50];
    assert_eq!(
        greeted().feed(&req),
        Progress::Reply {
            consumed: 0,
            bytes: &rep(0x08),
            close: true
        }
    );
}

// ---- ASSOCIATE: parsed as a request, the DST ignored (spec §6.1) ----

#[test]
fn associate_ipv4_zero_dst() {
    let r = REQ_ASSOCIATE_V4_ZERO;
    assert_eq!(greeted().feed(r), Progress::Associate { consumed: r.len() });
}

#[test]
fn associate_ipv4_dst() {
    let r = REQ_ASSOCIATE_V4;
    assert_eq!(greeted().feed(r), Progress::Associate { consumed: r.len() });
}

#[test]
fn associate_domain_dst() {
    let r = REQ_ASSOCIATE_DOMAIN;
    assert_eq!(greeted().feed(r), Progress::Associate { consumed: r.len() });
}

#[test]
fn associate_ipv6_dst() {
    let r = REQ_ASSOCIATE_V6;
    assert_eq!(greeted().feed(r), Progress::Associate { consumed: r.len() });
}

#[test]
fn associate_truncated_needs_more() {
    // Every prefix of an ASSOCIATE request, DST included, is incomplete.
    for req in [
        REQ_ASSOCIATE_V4_ZERO,
        REQ_ASSOCIATE_V4,
        REQ_ASSOCIATE_DOMAIN,
        REQ_ASSOCIATE_V6,
    ] {
        for n in 0..req.len() {
            assert_eq!(
                greeted().feed(&req[..n]),
                Progress::Need,
                "prefix {n} of {req:?}"
            );
        }
    }
}

// ---- reply builders ----

#[test]
fn method_reply() {
    // Method replies are the greeting Reply bytes (05 00 accepted / 05 FF refused).
    greeted();
    greeting_no_noauth();
}

#[test]
fn connect_reply() {
    assert_eq!(
        socks5_success_reply(),
        [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    );
    let r = socks5_error_reply(TcpErr::ConnRefused);
    assert_eq!(r[1], 0x05);
    assert_eq!(r[3], 0x01);
}

#[test]
fn connect_reply_unchanged() {
    assert_eq!(socks5_success_reply(), rep(0x00));
}

#[test]
fn reply_code() {
    assert_eq!(socks5_success_reply()[1], 0x00);
    assert_eq!(socks5_error_reply(TcpErr::ConnRefused), rep(0x05));
    assert_eq!(socks5_error_reply(TcpErr::DnsFailed), rep(0x04));
    assert_eq!(socks5_error_reply(TcpErr::Timeout), rep(0x06));
    assert_eq!(socks5_error_reply(TcpErr::PolicyDenied), rep(0x02));
    // An error reply never reports success: Ok falls through to general failure.
    assert_eq!(socks5_error_reply(TcpErr::Ok), rep(0x01));
}

// ---- Rust-side additions ----

#[test]
fn greeting_consumed_then_request_parsed_from_same_buffer() {
    let mut buf = GREETING_OK.to_vec();
    buf.extend_from_slice(REQ_IPV4);
    let mut p = Socks5Parser::default();
    assert_eq!(
        p.feed(&buf),
        Progress::Reply {
            consumed: 3,
            bytes: METHOD_OK,
            close: false
        }
    );
    assert_eq!(
        p.feed(&buf[3..]),
        done(10, Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), 80)
    );
}

#[test]
fn pipelined_bytes_left_unconsumed() {
    let mut buf = REQ_DOMAIN.to_vec();
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(
        greeted().feed(&buf),
        done(REQ_DOMAIN.len(), Host::Domain("example.com".into()), 443)
    );
}

#[test]
fn bad_version_closes_without_reply() {
    // Bad VER in the greeting or in the request: Close, no reply bytes.
    let mut buf = GREETING_BADVER.to_vec();
    buf.extend_from_slice(REQ_IPV4);
    assert_eq!(Socks5Parser::default().feed(&buf), Progress::Close);
    assert_eq!(Socks5Parser::default().feed(&[0x04]), Progress::Need); // VER unseen until 2 bytes
    assert_eq!(greeted().feed(&REQ_BADVER[..4]), Progress::Close);
}
