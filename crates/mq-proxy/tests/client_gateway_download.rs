//! SP3 spec §5.4: the fetch download (H3 → local TCP) — the rendered head,
//! 16 KiB reads written raw or chunk-framed, `SendBufFull` backpressure, the
//! malformed-head 502, and the abort paths (§5.5). The body check is the
//! core's, tested in `client_exchange.rs` (SP4 spec §4.3).

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::Call;
use mq_runtime::{IoRequest, TcpId};
use mq_transport_api::{Event, H3ReqId, StreamError};

/// A gateway-only client with an open, bodiless fetch request.
fn open() -> (H, TcpId, H3ReqId) {
    let mut h = H::new(ClientConfig {
        gateway: Some(addr(8080)),
        has_tcp_ingress: false,
        ..cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(gw, Ok(r));
    let tcp = h.accept(h.fetch, meta(None));
    h.rx(tcp, &fetch_req("", b""));
    (h, tcp, r)
}

fn hs(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// Inject a response head (and optionally body) and let the client run.
fn respond(h: &mut H, r: H3ReqId, head: &[(&str, &str)], head_fin: bool) {
    h.t.inject_h3_headers(r, hs(head), head_fin);
    h.drive();
}

fn body(h: &mut H, r: H3ReqId, bytes: &[u8], fin: bool) {
    h.t.inject_h3_body(r, bytes.to_vec(), fin);
    h.drive();
}

fn resets(h: &H, r: H3ReqId) -> usize {
    h.count(|c| *c == Call::H3Reset(r))
}

/// `Some(abort)` when the socket was closed.
fn close_of(h: &mut H, tcp: TcpId) -> Option<bool> {
    h.reqs().into_iter().find_map(|q| match q {
        IoRequest::TcpClose { tcp: t, abort } if t == tcp => Some(abort),
        _ => None,
    })
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

const HEAD_CL: &[u8] = b"HTTP/1.1 200 \r\ncontent-length: 40000\r\nConnection: close\r\n\r\n";
const HEAD_CHUNKED: &[u8] =
    b"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

#[test]
fn download_cl_passthrough_body() {
    let (mut h, tcp, r) = open();
    let b = pattern(40_000);
    respond(
        &mut h,
        r,
        &[(":status", "200"), ("content-length", "40000")],
        false,
    );
    body(&mut h, r, &b, true);
    let caps: Vec<usize> = h
        .log()
        .into_iter()
        .filter_map(|c| match c {
            Call::H3RecvBody { r: x, cap } if x == r => Some(cap),
            _ => None,
        })
        .collect();
    assert!(caps.iter().all(|&c| c == 16_384), "16 KiB reads: {caps:?}");
    let mut want = HEAD_CL.to_vec();
    want.extend_from_slice(&b);
    assert_eq!(h.tx_all(tcp), want, "body written raw");
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn download_chunked_framing_and_terminator() {
    let (mut h, tcp, r) = open();
    let b = pattern(40_000);
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, &b, true);
    let mut want = HEAD_CHUNKED.to_vec();
    for c in b.chunks(16_384) {
        want.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        want.extend_from_slice(c);
        want.extend_from_slice(b"\r\n");
    }
    want.extend_from_slice(b"0\r\n\r\n");
    assert!(want[HEAD_CHUNKED.len()..].starts_with(b"4000\r\n"));
    assert!(
        want.windows(8).any(|w| w == b"\r\n1c40\r\n"),
        "40000 - 2 * 16384"
    );
    assert_eq!(h.tx_all(tcp), want);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn download_zero_length_read_not_framed() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, b"abc", false);
    body(&mut h, r, b"", true); // `(0, true)`: an empty FIN
    let mut want = HEAD_CHUNKED.to_vec();
    want.extend_from_slice(b"3\r\nabc\r\n0\r\n\r\n");
    assert_eq!(h.tx_all(tcp), want);
    assert_eq!(close_of(&mut h, tcp), Some(false));
}

#[test]
fn download_sendbuffull_holds_pending_until_writable() {
    let (mut h, tcp, r) = open();
    let b = pattern(100 * 1024);
    respond(
        &mut h,
        r,
        &[(":status", "200"), ("content-length", "102400")],
        false,
    );
    let reads = |h: &H| h.count(|c| matches!(c, Call::H3RecvBody { r: x, .. } if *x == r));
    let before = reads(&h);
    body(&mut h, r, &b, true);
    let head = b"HTTP/1.1 200 \r\ncontent-length: 102400\r\nConnection: close\r\n\r\n";
    // Head + three 16 KiB reads fit the 64 KiB send buffer; the fourth waits.
    assert_eq!(h.sh.tcp_tx_buf(tcp).len(), head.len() + 3 * 16_384);
    assert_eq!(reads(&h) - before, 4, "no read while a frame is pending");
    h.event(Event::H3Readable(r));
    assert_eq!(reads(&h) - before, 4);
    assert_eq!(close_of(&mut h, tcp), None);
    let mut out = h.tx_all(tcp); // drains → `on_tcp_writable`
    assert_eq!(close_of(&mut h, tcp), None, "closes only after the drain");
    out.extend(h.tx_all(tcp));
    let mut want = head.to_vec();
    want.extend_from_slice(&b);
    assert_eq!(out, want);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn download_sendbuffull_on_last_frame_keeps_terminator() {
    let (mut h, tcp, r) = open();
    let b = pattern(4 * 16_384);
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, &b, true);
    assert_eq!(close_of(&mut h, tcp), None);
    let mut out = h.tx_all(tcp);
    out.extend(h.tx_all(tcp));
    assert!(out.ends_with(b"\r\n0\r\n\r\n"));
    assert_eq!(out.len(), HEAD_CHUNKED.len() + 4 * (6 + 16_384 + 2) + 5);
    assert_eq!(close_of(&mut h, tcp), Some(false));
}

#[test]
fn malformed_head_502_upstream_protocol_and_reset() {
    for head in [
        &[("content-type", "text/plain")][..], // no :status
        &[(":status", "2x0")],
        &[(":status", "200"), ("x", "a\rb")],
    ] {
        let (mut h, tcp, r) = open();
        respond(&mut h, r, head, false);
        assert_eq!(
            h.tx_all(tcp),
            b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-protocol\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(close_of(&mut h, tcp), Some(false));
        assert_eq!(resets(&h, r), 1);
        // Removed: a later body is not read.
        body(&mut h, r, b"x", true);
        assert_eq!(h.count(|c| matches!(c, Call::H3RecvBody { .. })), 0);
    }
}

#[test]
fn fin_on_headers_finishes() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "204")], true);
    assert_eq!(
        h.tx_all(tcp),
        b"HTTP/1.1 204 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    );
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
    assert_eq!(h.count(|c| matches!(c, Call::H3RecvBody { .. })), 0);
}

#[test]
fn recv_error_before_head_aborts() {
    let (mut h, tcp, r) = open();
    h.t.inject_h3_error(r, StreamError::Reset);
    h.drive();
    assert_eq!(h.sh.tcp_tx_buf(tcp).len(), 0, "no 502 on this path");
    assert_eq!(close_of(&mut h, tcp), Some(true));
    assert_eq!(resets(&h, r), 1);
}

#[test]
fn recv_error_after_head_aborts() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, b"abc", false);
    h.t.inject_h3_error(r, StreamError::Reset);
    h.drive();
    assert_eq!(close_of(&mut h, tcp), Some(true));
    assert_eq!(resets(&h, r), 1);
}
