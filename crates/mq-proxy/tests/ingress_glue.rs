//! spec §6.1: the client's ingress glue — parsers fed from `tcp_rx`, replies via
//! `tcp_write`, read interest off once complete, the 8 KiB cap and the 10 s deadline.

mod common;

use common::*;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

#[test]
fn socks5_method_reply_via_tcp_write() {
    let mut h = H::new(cfg());
    let tcp = h.accept(h.socks, meta(None));
    h.rx(tcp, SOCKS_GREETING);
    assert_eq!(h.tx_all(tcp), [5, 0]);
    // The greeting was consumed: nothing is left in the receive buffer.
    assert!(h.sh.with_app(h.now, |_, cx| cx.tcp_rx(tcp).is_empty()));
    assert!(!H::closed(&h.reqs(), tcp));
}

#[test]
fn read_interest_off_after_request_complete() {
    let mut h = H::new(cfg());
    let tcp = h.accept(h.socks, meta(None));
    h.rx(tcp, SOCKS_GREETING);
    assert!(h.sh.tcp_interest(tcp).read, "still reading the request");
    h.rx(tcp, &SOCKS_CONNECT[..5]);
    assert!(h.sh.tcp_interest(tcp).read, "request incomplete");
    let mut rest = SOCKS_CONNECT[5..].to_vec();
    rest.extend_from_slice(b"behind");
    h.rx(tcp, &rest);
    assert!(!h.sh.tcp_interest(tcp).read, "request complete: read off");
    // Bytes behind the request stay in the receive buffer (the prebuffer).
    assert!(h.sh.with_app(h.now, |_, cx| cx.tcp_rx(tcp) == b"behind"));
}

#[test]
fn cap_8k_closes_socket() {
    let mut h = H::new(cfg());
    let tcp = h.accept(h.http, meta(None));
    let mut b = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
    b.resize(8192, b'a');
    h.rx(tcp, &b);
    assert!(
        H::closed(&h.reqs(), tcp),
        "8 KiB without a complete request"
    );
    assert!(h.tx_all(tcp).is_empty(), "closed without a reply");
}

#[test]
fn ingress_deadline_10s_closes() {
    let mut h = H::new(cfg());
    let tcp = h.accept(h.socks, meta(None));
    h.rx(tcp, SOCKS_GREETING);
    assert_eq!(h.tx_all(tcp), [5, 0]);
    h.advance(Duration::from_millis(9_999));
    assert!(!H::closed(&h.reqs(), tcp));
    h.advance(Duration::from_millis(1));
    assert!(H::closed(&h.reqs(), tcp), "no complete request within 10 s");
}

#[test]
fn transparent_target_from_original_dst_ipv4_only() {
    let mut h = H::new(cfg());
    h.serving();
    // IPv4 original destination: opened toward it.
    let s = h.next_stream(h.conn);
    let v4 = h.accept(h.tproxy, meta(Some("10.0.0.1:80".parse().unwrap())));
    assert!(!h.sh.tcp_interest(v4).read, "request complete at accept");
    assert_eq!(
        h.t.sent_bytes(s),
        [0x01, 0x00, 0x01, 4, 10, 0, 0, 1, 0, 80, 0x00],
        "type, flags, IPv4, host, port, padding"
    );
    // IPv6 original destination: closed, nothing opened.
    let opens = h.opens();
    let v6 = h.accept(
        h.tproxy,
        meta(Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 80)))),
    );
    assert!(H::closed(&h.reqs(), v6));
    assert_eq!(h.opens(), opens);
}

#[test]
fn transparent_missing_original_dst_closes() {
    let mut h = H::new(cfg());
    h.serving();
    let opens = h.opens();
    let tcp = h.accept(h.tproxy, meta(None));
    assert!(H::closed(&h.reqs(), tcp));
    assert!(h.tx_all(tcp).is_empty(), "transparent capture has no reply");
    assert_eq!(h.opens(), opens, "nothing opened");
}
