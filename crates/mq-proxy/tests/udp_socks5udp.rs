//! spec §5: SOCKS5 UDP encapsulation header (RFC 1928 §7).

use mq_proxy::udp::socks5udp::{Dst, build, parse, target_of};
use mq_runtime::{Host, Target};
use mq_wire::frames::AddrType;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const V4: &[u8] = &[0, 0, 0, 0x01, 192, 168, 1, 1, 0x04, 0xD2];
const V6: &[u8] = &[
    0, 0, 0, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1F, 0x90,
];
const DOMAIN: &[u8] = &[
    0, 0, 0, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xBB,
];

fn with_payload(hdr: &[u8]) -> Vec<u8> {
    [hdr, b"payload"].concat()
}

#[test]
fn parse_v4() {
    let buf = with_payload(V4);
    let (dst, off) = parse(&buf).unwrap();
    assert_eq!(dst.atype, AddrType::Ipv4);
    assert_eq!(dst.addr, [192, 168, 1, 1]);
    assert_eq!(dst.port, 1234);
    assert_eq!(&buf[off..], b"payload");
}

#[test]
fn parse_v6() {
    let buf = with_payload(V6);
    let (dst, off) = parse(&buf).unwrap();
    assert_eq!(dst.atype, AddrType::Ipv6);
    assert_eq!(dst.addr, &V6[4..20]);
    assert_eq!(dst.port, 8080);
    assert_eq!(&buf[off..], b"payload");
}

#[test]
fn parse_domain() {
    let buf = with_payload(DOMAIN);
    let (dst, off) = parse(&buf).unwrap();
    assert_eq!(dst.atype, AddrType::Domain);
    assert_eq!(dst.addr, b"example.com");
    assert_eq!(dst.port, 443);
    assert_eq!(&buf[off..], b"payload");
}

#[test]
fn parse_rejects_rsv() {
    for pos in [0, 1] {
        let mut buf = with_payload(V4);
        buf[pos] = 1;
        assert!(parse(&buf).is_none(), "RSV byte {pos}");
    }
}

#[test]
fn parse_rejects_frag() {
    let mut buf = with_payload(V4);
    buf[2] = 1;
    assert!(parse(&buf).is_none());
}

#[test]
fn parse_rejects_atype() {
    for atype in [0x00, 0x02, 0x05, 0xFF] {
        let mut buf = with_payload(V4);
        buf[3] = atype;
        assert!(parse(&buf).is_none(), "ATYP {atype:#x}");
    }
}

#[test]
fn parse_short_is_none() {
    // Every strict prefix of a header (no payload behind it) is short, the domain
    // length byte included.
    for hdr in [V4, V6, DOMAIN] {
        for n in 0..hdr.len() {
            assert!(parse(&hdr[..n]).is_none(), "{n} of {} bytes", hdr.len());
        }
        assert!(parse(hdr).is_some());
    }
}

#[test]
fn build_echoes_domain_verbatim() {
    let (dst, off) = parse(DOMAIN).unwrap();
    let mut out = Vec::new();
    let n = build(&mut out, &dst);
    assert_eq!(out, DOMAIN);
    assert_eq!(n, 4 + 1 + b"example.com".len() + 2);
    assert_eq!(n, off);
}

#[test]
fn build_roundtrips_v4_v6_and_appends() {
    for hdr in [V4, V6] {
        let (dst, _) = parse(hdr).unwrap();
        let mut out = vec![0xAA];
        let n = build(&mut out, &dst);
        assert_eq!(n, hdr.len());
        assert_eq!(&out[1..], hdr);
    }
}

#[test]
fn target_of_maps_each_atype() {
    let t = |hdr| target_of(&parse(hdr).unwrap().0);
    assert_eq!(
        t(V4),
        Some(Target {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            port: 1234,
        })
    );
    assert_eq!(
        t(V6),
        Some(Target {
            host: Host::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            port: 8080,
        })
    );
    assert_eq!(
        t(DOMAIN),
        Some(Target {
            host: Host::Domain("example.com".into()),
            port: 443,
        })
    );
}

#[test]
fn target_of_empty_domain_is_none() {
    // parse accepts a zero-length domain (as C); only the Target conversion refuses it.
    let (dst, off) = parse(&[0, 0, 0, 0x03, 0, 0x00, 0x50]).unwrap();
    assert_eq!((dst.addr.len(), off), (0, 7));
    assert_eq!(target_of(&dst), None);
}

#[test]
fn target_of_non_utf8_is_none() {
    let dst = Dst {
        atype: AddrType::Domain,
        addr: &[0xFF, 0xFE],
        port: 53,
    };
    assert_eq!(target_of(&dst), None);
}
