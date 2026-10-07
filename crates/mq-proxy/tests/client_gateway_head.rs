// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §5.2: the fetch request head — listener replies, the head deadline,
//! the reject sequence, steps 9–10 (tunnel, open, send headers) and the hand-off
//! to the upload.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::Call;
use mq_runtime::{IoRequest, IoResult, TcpId};
use mq_transport_api::{ConnId, Error, Event, H3ReqId, StreamError};
use std::time::Duration;

/// A gateway-only client whose tunnel is established.
fn up() -> (H, ConnId) {
    let mut h = H::new(ClientConfig {
        gateway: Some(addr(8080)),
        has_tcp_ingress: false,
        ..cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    (h, gw)
}

fn listener(code: u16, phrase: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

/// Accept a fetch socket and deliver `bytes` in one read.
fn send(h: &mut H, bytes: &[u8]) -> TcpId {
    let tcp = h.accept(h.fetch, meta(None));
    h.rx(tcp, bytes);
    tcp
}

/// What was written, then whether the socket was closed gracefully.
fn reply_and_close(h: &mut H, tcp: TcpId) -> Vec<u8> {
    let out = h.tx_all(tcp);
    let reqs = h.reqs();
    assert!(
        reqs.iter()
            .any(|r| matches!(r, IoRequest::TcpClose { tcp: t, abort: false } if *t == tcp)),
        "{reqs:?}"
    );
    out
}

/// The next `open_h3_request` on `gw` returns this id.
fn next_req(h: &H, gw: ConnId) -> H3ReqId {
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(gw, Ok(r));
    r
}

fn opened(h: &H) -> usize {
    h.count(|c| matches!(c, Call::OpenH3Request(_)))
}

#[test]
fn listener_404_for_other_path() {
    for head in [
        "GET /_mqproxy/fetch HTTP/1.1\r\n\r\n",
        "POST /other HTTP/1.1\r\n\r\n",
        "POST /_mqproxy/fetch?x HTTP/1.1\r\n\r\n",
    ] {
        let (mut h, _) = up();
        let tcp = send(&mut h, head.as_bytes());
        assert_eq!(
            reply_and_close(&mut h, tcp),
            listener(404, "Not Found"),
            "{head}"
        );
        assert_eq!(opened(&h), 0);
    }
}

#[test]
fn listener_411_for_chunked() {
    let (mut h, _) = up();
    let tcp = send(&mut h, &fetch_req("Transfer-Encoding: chunked\r\n", b""));
    assert_eq!(
        reply_and_close(&mut h, tcp),
        listener(411, "Length Required")
    );
    assert_eq!(opened(&h), 0);
}

#[test]
fn listener_400_for_bad_head() {
    let (mut h, _) = up();
    let tcp = send(
        &mut h,
        b"POST /_mqproxy/fetch HTTP/1.1\r\nBad Name: x\r\n\r\n",
    );
    assert_eq!(reply_and_close(&mut h, tcp), listener(400, "Bad Request"));
    assert_eq!(opened(&h), 0);
}

#[test]
fn head_16k_without_terminator_400() {
    let (mut h, _) = up();
    let mut b = b"POST /_mqproxy/fetch HTTP/1.1\r\nX-Pad: ".to_vec();
    b.resize(16_384, b'a');
    let tcp = send(&mut h, &b);
    assert_eq!(reply_and_close(&mut h, tcp), listener(400, "Bad Request"));
}

#[test]
fn head_split_across_two_reads_accumulates() {
    let (mut h, gw) = up();
    let r = next_req(&h, gw);
    let req = fetch_req("", b"");
    let tcp = send(&mut h, &req[..20]);
    assert!(h.tx_all(tcp).is_empty());
    assert!(h.reqs().is_empty(), "still open");
    h.rx(tcp, &req[20..]);
    assert_eq!(opened(&h), 1);
    assert_eq!(h.t.h3_headers_sent(r).len(), 1);
}

#[test]
fn head_deadline_400() {
    let (mut h, _) = up();
    let tcp = send(&mut h, b"POST /_mqproxy/fetch HTTP/1.1\r\n");
    h.advance(Duration::from_millis(9_999));
    assert!(h.tx_all(tcp).is_empty());
    h.advance(Duration::from_millis(1));
    assert_eq!(reply_and_close(&mut h, tcp), listener(400, "Bad Request"));
}

#[test]
fn readeof_during_head_closes_silently() {
    let (mut h, _) = up();
    let tcp = send(&mut h, b"POST /_mqproxy/fetch HTTP/1.1\r\n");
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert!(reply_and_close(&mut h, tcp).is_empty());
    assert_eq!(h.sh.next_timeout(), None, "head timer cancelled");
}

#[test]
fn reject_replies_byte_exact() {
    let req = |hs: &str| format!("POST /_mqproxy/fetch HTTP/1.1\r\n{hs}\r\n").into_bytes();
    let auth = "X-Mq-Auth: Bearer t\r\n";
    let target = "X-Mq-Target: https://example.com/\r\n";
    let long = "v".repeat(mq_http::limits::FIELD_MAX);
    let cases = [
        (
            format!("{auth}x-mq-auth: Bearer u\r\n{target}"),
            "duplicate-control-header",
        ),
        (target.to_string(), "missing-auth"),
        (format!("X-Mq-Auth: Basic t\r\n{target}"), "bad-auth-format"),
        (auth.to_string(), "bad-target"),
        (
            format!("{auth}{target}X-Mq-Method: CONNECT\r\n"),
            "bad-method",
        ),
        (
            format!("{auth}{target}X-Mq-Origin-Protocol: h9\r\n"),
            "bad-origin-protocol",
        ),
        (
            format!("{auth}{target}X-Mq-Cache: soon\r\n"),
            "bad-cache-ttl",
        ),
        (
            format!("{auth}{target}X-Long: {long}\r\n"),
            "header-too-long",
        ),
    ];
    for (hs, xmq) in cases {
        let (mut h, _) = up();
        let tcp = send(&mut h, &req(&hs));
        assert_eq!(reply_and_close(&mut h, tcp), gw_reject(400, xmq), "{xmq}");
        assert_eq!(opened(&h), 0);
    }
    assert_eq!(
        gw_reject(400, "missing-auth"),
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Mq-Error: missing-auth\r\n\r\n"
    );
}

#[test]
fn tunnel_down_502() {
    let mut h = H::new(ClientConfig {
        gateway: Some(addr(8080)),
        has_tcp_ingress: false,
        ..cfg()
    });
    // Not established yet.
    let tcp = send(&mut h, &fetch_req("", b""));
    assert_eq!(
        reply_and_close(&mut h, tcp),
        gw_reject(502, "tunnel-unavailable")
    );
    assert_eq!(opened(&h), 0);
}

#[test]
fn open_h3_request_failure_502() {
    let (mut h, gw) = up();
    h.t.expect_open_h3_request(gw, Err(Error::Ceiling));
    let tcp = send(&mut h, &fetch_req("", b""));
    assert_eq!(
        reply_and_close(&mut h, tcp),
        gw_reject(502, "tunnel-unavailable")
    );
    assert_eq!(opened(&h), 1);
}

#[test]
fn send_headers_error_resets_and_502() {
    for e in [StreamError::Conn, StreamError::Blocked] {
        let (mut h, gw) = up();
        let r = next_req(&h, gw);
        h.t.expect_h3_send_headers(r, Err(e));
        let tcp = send(&mut h, &fetch_req("", b""));
        assert_eq!(
            reply_and_close(&mut h, tcp),
            gw_reject(502, "tunnel-unavailable"),
            "{e:?}"
        );
        assert_eq!(h.count(|c| *c == Call::H3Reset(r)), 1, "{e:?}");
    }
}

#[test]
fn accept_sends_headers_fin_iff_cl_zero() {
    for (extra, fin) in [
        ("", true),
        ("Content-Length: 0\r\n", true),
        ("Content-Length: 5\r\n", false),
    ] {
        let (mut h, gw) = up();
        let r = next_req(&h, gw);
        let tcp = send(&mut h, &fetch_req(extra, b""));
        let sent = h.t.h3_headers_sent(r);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, fin, "{extra:?}");
        let has_cl = sent[0]
            .0
            .iter()
            .any(|(n, _)| n.as_slice() == b"content-length");
        assert_eq!(has_cl, !fin);
        assert!(h.tx_all(tcp).is_empty(), "no reply yet");
        assert!(h.reqs().is_empty(), "still open");
        assert_eq!(h.sh.next_timeout(), None, "head timer cancelled");
        assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 64 * 1024, "rx limit raised");
    }
}

#[test]
fn head_and_body_in_one_read_starts_upload() {
    let (mut h, gw) = up();
    let r = next_req(&h, gw);
    let tcp = send(&mut h, &fetch_req("Content-Length: 5\r\n", b"hello"));
    assert_eq!(h.t.h3_sends(r), [b"hello".to_vec()]);
    let last = h.log().into_iter().rev().find_map(|c| match c {
        Call::H3SendBody { fin, .. } => Some(fin),
        _ => None,
    });
    assert_eq!(last, Some(true), "FIN rides the last byte");
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 64 * 1024, "body consumed");
}
