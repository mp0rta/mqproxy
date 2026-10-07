// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §7.3 / §7.4 / §7.8: the MITM conn — peek and routing, the TLS
//! and h2 handshakes, idle, and the `Closing` drain. Streams are the Task
//! 7.2 stub: every request is answered 502 `tunnel-unavailable`.

mod common;
mod mitm_harness;

use mitm_harness::*;
use mq_proxy::client::mitm::Handoff;
use mq_proxy::client::mitm::policy::IgnoreHosts;
use mq_proxy::ingress::INGRESS_CAP;
use mq_runtime::{Host, IoRequest, KeepAlive, Target, TcpId};
use rustls::SignatureScheme;
use std::net::Ipv4Addr;
use std::time::Duration;

const US: Duration = Duration::from_micros(1);

fn target() -> Target {
    Target {
        host: Host::Ip(Ipv4Addr::LOCALHOST.into()),
        port: 443,
    }
}

fn has(mh: &MH, kv: &str) -> bool {
    mh.metrics().split(' ').any(|f| f == kv)
}

/// `tcp` went to the relay for `why`, untouched: its bytes still in `rx`,
/// read interest off, nothing sent, the conn gone from `Mitm`.
fn assert_opaque(mh: &mut MH, tcp: TcpId, sent: &[u8], why: &str) {
    assert_handoff(mh, tcp, sent, why);
    assert_eq!(mh.conn_count(), 0);
}

fn assert_handoff(mh: &mut MH, tcp: TcpId, sent: &[u8], why: &str) {
    assert_eq!(
        mh.handoffs(),
        vec![Handoff {
            tcp,
            target: target()
        }]
    );
    assert!(mh.rx(tcp) == sent, "the peeked bytes stay in rx");
    assert!(!mh.sh.tcp_interest(tcp).read, "read off for the relay");
    assert_eq!(mh.tcp_queued(tcp), 0, "nothing sent");
    assert!(has(mh, &format!("opaque_{why}=1")), "{}", mh.metrics());
    assert!(has(mh, "mitm=0"), "{}", mh.metrics());
}

/// The browser's ClientHello, fed into a fresh socket; returns both.
fn hello_in(mh: &mut MH, b: &mut Browser) -> (TcpId, Vec<u8>) {
    let tcp = mh.accept();
    let hello = b.exchange(&[]);
    mh.tcp_in(tcp, &hello);
    (tcp, hello)
}

/// A GET through the stub: 502 `tunnel-unavailable`, empty body.
fn assert_stub_502(mh: &mut MH, b: &mut Browser, tcp: TcpId) {
    let s = b.request("GET", "/x", &[], b"");
    mh.relay(b, tcp);
    let (head, body) = b.response(&s).expect("a response");
    assert_eq!(head.status, 502);
    assert_eq!(head.headers["x-mq-error"], "tunnel-unavailable");
    assert!(body.is_empty());
}

#[test]
fn peek_decides_mitm_and_handshakes() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    assert!(!b.tls.is_handshaking());
    assert_eq!(b.tls.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(b.tls.peer_certificates().unwrap().len(), 2, "leaf + CA");
    assert_stub_502(&mut mh, &mut b, tcp);
    assert!(mh.handoffs().is_empty());
    assert_eq!(mh.conn_count(), 1);
    for kv in ["conns=1", "mitm=1", "leaf_miss=1", "reqs=1", "rejects=1"] {
        assert!(has(&mh, kv), "{kv}: {}", mh.metrics());
    }
}

#[test]
fn peek_one_byte_segments_decides_mitm() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.accept();
    let hello = b.exchange(&[]);
    for (i, byte) in hello.iter().enumerate() {
        assert!(has(&mh, "mitm=0") || mh.metrics().is_empty(), "at byte {i}");
        mh.tcp_in(tcp, &[*byte]);
    }
    assert!(has(&mh, "mitm=1"), "{}", mh.metrics());
    mh.relay(&mut b, tcp);
    assert!(!b.tls.is_handshaking());
    assert_stub_502(&mut mh, &mut b, tcp);
}

#[test]
fn peek_6k_client_hello_in_one_rx_no_new_input() {
    let mut mh = MH::p256();
    let long: Vec<Vec<u8>> = (0..24).map(|i| vec![b'a' + i; 250]).collect();
    let mut protos: Vec<&[u8]> = long.iter().map(Vec::as_slice).collect();
    protos.push(b"h2");
    let mut b = Browser::new("example.com").alpn(&protos);
    let tcp = mh.accept();
    let hello = b.exchange(&[]);
    assert!(
        (6000..INGRESS_CAP).contains(&hello.len()),
        "{}",
        hello.len()
    );
    mh.tcp_in(tcp, &hello); // one read: rustls takes ≤ 4 KiB per `read_tls`
    assert!(has(&mh, "mitm=1"), "{}", mh.metrics());
    assert!(mh.rx(tcp).is_empty(), "consumed at the commit");
    assert!(mh.tcp_queued(tcp) > 0, "the ServerHello is out");
    mh.relay(&mut b, tcp);
    assert_stub_502(&mut mh, &mut b, tcp);
}

#[test]
fn peek_non_tls_opaque_bytes_preserved() {
    let mut mh = MH::p256();
    let tcp = mh.accept();
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    mh.tcp_in(tcp, req);
    assert_opaque(&mut mh, tcp, req, "not_tls");
}

#[test]
fn peek_no_sni_opaque() {
    let mut mh = MH::p256();
    let mut b = Browser::new("127.0.0.1"); // rustls sends no SNI for an IP
    let (tcp, hello) = hello_in(&mut mh, &mut b);
    assert_opaque(&mut mh, tcp, &hello, "no_sni");
}

#[test]
fn peek_no_h2_opaque() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com").alpn(&[b"http/1.1"]);
    let (tcp, hello) = hello_in(&mut mh, &mut b);
    assert_opaque(&mut mh, tcp, &hello, "no_h2");
}

#[test]
fn peek_ignored_opaque() {
    let mut c = cfg("ca-p256");
    c.ignore = IgnoreHosts::parse(["example.com"]).unwrap();
    let mut mh = MH::new(c);
    let mut b = Browser::new("example.com");
    let (tcp, hello) = hello_in(&mut mh, &mut b);
    assert_opaque(&mut mh, tcp, &hello, "ignored");
}

#[test]
fn peek_out_of_scope_opaque() {
    // Permits `.example.com` only.
    let mut mh = MH::new(cfg("ca-dns-constraint"));
    let mut b = Browser::new("other.test");
    let (tcp, hello) = hello_in(&mut mh, &mut b);
    assert_opaque(&mut mh, tcp, &hello, "ca_scope");
}

#[test]
fn peek_eof_with_bytes_opaque() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.accept();
    let part = b.exchange(&[])[..100].to_vec();
    mh.tcp_in(tcp, &part);
    assert!(mh.handoffs().is_empty(), "undecided");
    mh.tcp_eof(tcp);
    assert_opaque(&mut mh, tcp, &part, "eof");
}

#[test]
fn peek_eof_empty_closes() {
    let mut mh = MH::p256();
    let tcp = mh.accept();
    mh.tcp_eof(tcp);
    assert_eq!(mh.close_of(tcp), Some(false));
    assert!(mh.handoffs().is_empty());
    assert_eq!(mh.conn_count(), 0);
}

#[test]
fn peek_timeout_opaque() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.accept();
    let part = b.exchange(&[])[..100].to_vec();
    mh.tcp_in(tcp, &part);
    mh.advance(Duration::from_secs(5) - US);
    assert!(mh.handoffs().is_empty());
    mh.advance(US);
    assert_opaque(&mut mh, tcp, &part, "timeout");
}

#[test]
fn peek_too_large_opaque() {
    let mut mh = MH::p256();
    let tcp = mh.accept();
    // A handshake record announcing a 16 KiB ClientHello that never completes.
    let mut junk = vec![0x16, 0x03, 0x01, 0x3f, 0xff, 0x01, 0x00, 0x3f, 0xfb];
    junk.resize(INGRESS_CAP, 0);
    mh.tcp_in(tcp, &junk);
    assert_opaque(&mut mh, tcp, &junk, "too_large");
}

#[test]
fn into_connection_failure_opaque() {
    let mut mh = MH::p256();
    // No scheme the P-256 leaf can sign with.
    let mut b = Browser::new("example.com").sigschemes(&[SignatureScheme::RSA_PSS_SHA256]);
    let (tcp, hello) = hello_in(&mut mh, &mut b);
    assert_opaque(&mut mh, tcp, &hello, "tls_incompat");
    assert!(has(&mh, "leaf_miss=1"), "the leaf was forged first");
}

#[test]
fn at_capacity_opaque() {
    let mut c = cfg("ca-p256");
    c.tuning.max_conns = 1;
    let mut mh = MH::new(c);
    let first = mh.accept();
    let tcp = mh.accept();
    assert_handoff(&mut mh, tcp, b"", "capacity");
    assert_eq!(mh.conn_count(), 1);
    assert!(mh.sh.tcp_interest(first).read, "the first keeps peeking");
}

#[test]
fn keepalive_set_at_live() {
    let ka = KeepAlive {
        idle: Duration::from_secs(7),
        interval: Duration::from_secs(3),
        count: 2,
        user_timeout: Duration::from_secs(20),
    };
    let mut c = cfg("ca-p256");
    c.tuning.keepalive = ka;
    let mut mh = MH::new(c);
    let mut b = Browser::new("example.com");
    let tcp = mh.accept();
    let hello = b.exchange(&[]);
    mh.tcp_in(tcp, &hello[..100]);
    let want = IoRequest::TcpSetKeepalive { tcp, ka };
    assert!(!mh.io().contains(&want), "not while peeking");
    mh.tcp_in(tcp, &hello[100..]);
    assert!(mh.io().contains(&want));
}

#[test]
fn handshake_deadline_closes() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    b.stop_polling_h2(); // TLS completes, the h2 preface never comes
    let tcp = mh.connect(&mut b);
    assert!(!b.tls.is_handshaking());
    mh.advance(Duration::from_secs(5) - US);
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), None);
    mh.advance(US);
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), Some(false));
    assert!(b.close_notify);
    assert!(!b.frame_types().contains(&GOAWAY));
}

#[test]
fn idle_closes_with_zero_streams() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    mh.advance(Duration::from_secs(30));
    b.raw_plain(&ping_frame(1)); // inbound bytes at 30 s
    mh.relay(&mut b, tcp);
    // 60 s after the handshake the timer re-arms for the remainder.
    mh.advance(Duration::from_secs(30));
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), None, "30 s since the last inbound bytes");
    mh.advance(Duration::from_secs(30) - US);
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), None);
    mh.advance(US);
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), Some(false));
    assert_eq!(b.frame_types().last(), Some(&GOAWAY));
    assert!(b.close_notify);
}

#[test]
fn closing_goaway_before_close_notify() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    mh.shutdown();
    mh.relay(&mut b, tcp);
    // rustls hands out no plaintext after a close_notify, so the GOAWAY in
    // the plaintext preceded it.
    assert_eq!(b.frame_types().last(), Some(&GOAWAY));
    assert!(b.close_notify);
    assert!(b.tls_error.is_none());
    assert_eq!(mh.close_of(tcp), Some(false));
    mh.advance(Duration::from_secs(1));
    assert_eq!(
        mh.close_of(tcp),
        Some(false),
        "a gone socket is not aborted"
    );
    assert_eq!(mh.conn_count(), 0);
}

#[test]
fn closing_backpressured_tcp_flushes_then_closes() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    // 6000 PINGs: ~100 KiB of PING ACKs, more than TCP's 64 KiB, and the
    // browser does not read.
    let pings: Vec<u8> = (0..6000).flat_map(ping_frame).collect();
    let mut wire = Vec::new();
    for chunk in pings.chunks(16 * 1024) {
        b.raw_plain(chunk);
        wire.extend(b.exchange(&[]));
    }
    assert_eq!(mh.tcp_in_some(tcp, &wire), wire.len());
    assert!(mh.tcp_queued(tcp) > 48 * 1024, "{}", mh.tcp_queued(tcp));
    mh.shutdown();
    assert_eq!(mh.close_of(tcp), None, "the output waits for TCP");
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), Some(false), "flushed, then closed");
    let types = b.frame_types();
    assert_eq!(
        types.iter().filter(|&&t| t == 6).count(),
        6000,
        "no ACK lost"
    );
    assert_eq!(types.last(), Some(&GOAWAY));
    assert!(b.close_notify);
}

#[test]
fn closing_deadline_aborts() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    // GOAWAY and close_notify are queued, but the browser stops reading:
    // `tcp_close` waits on the send buffer.
    mh.shutdown();
    assert_eq!(mh.close_of(tcp), None);
    mh.advance(Duration::from_secs(1) - US);
    assert_eq!(mh.close_of(tcp), None);
    mh.advance(US);
    assert_eq!(mh.close_of(tcp), Some(true));
    assert_eq!(mh.conn_count(), 0);
}

#[test]
fn unfinished_handshake_closes_without_goaway() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    b.stop_polling_h2();
    let tcp = mh.connect(&mut b);
    b.raw_plain(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); // not the preface
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), Some(false));
    assert!(b.close_notify);
    assert_eq!(
        b.frame_types(),
        vec![SETTINGS],
        "the server preface, no GOAWAY"
    );
    assert!(has(&mh, "h2_fail=1"), "{}", mh.metrics());
}

#[test]
fn tls_fatal_sends_only_the_alert() {
    let mut mh = MH::p256();
    let mut b = Browser::new("example.com");
    let tcp = mh.connect(&mut b);
    let mut bad = vec![0x17, 0x03, 0x03, 0x00, 0x20]; // an undecryptable record
    bad.resize(5 + 0x20, 0xaa);
    mh.tcp_in(tcp, &bad);
    mh.relay(&mut b, tcp);
    assert_eq!(mh.close_of(tcp), Some(false));
    assert!(
        matches!(b.tls_error, Some(rustls::Error::AlertReceived(_))),
        "{:?}",
        b.tls_error
    );
    assert!(!b.frame_types().contains(&GOAWAY));
    assert!(has(&mh, "tls_fail=1"), "{}", mh.metrics());
}
