//! SP3 spec §6.2, §6.3 (drain), §6.5: H3 intake on the composed server.

mod server_harness;

use mq_proxy::config::{GatewayConfig, ServerConfig};
use mq_runtime::DialError;
use mq_runtime::testing::Call;
use mq_transport_api::{H3ReqId, StreamError};
use server_harness::*;

type Hs = Vec<(Vec<u8>, Vec<u8>)>;

fn hs(pairs: &[(&str, &str)]) -> Hs {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// A GET for `http://o.test/` with `auth`, `edit` appended (pseudo-headers
/// named in `edit` replace the default).
fn request(auth: &str, edit: &[(&str, &str)]) -> Hs {
    let mut h = hs(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "o.test"),
        (":path", "/"),
        ("x-mq-auth", auth),
    ]);
    for (n, v) in edit {
        h.retain(|(x, _)| !(n.starts_with(':') && x == n.as_bytes()));
        h.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
    }
    h
}

const OK: &str = "Bearer secret";

fn masquerade() -> ServerConfig {
    ServerConfig {
        gateway: Some(GatewayConfig {
            masquerade: true,
            ..GatewayConfig::default()
        }),
        ..cfg()
    }
}

/// A peer request on a fresh H3 conn whose header section is `headers`.
fn open(h: &mut H, headers: Hs, fin: bool) -> H3ReqId {
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_headers(r, headers, fin);
    h.drive();
    r
}

fn error_reply(status: &str, xmq: &str) -> Vec<(Hs, bool)> {
    vec![(
        hs(&[
            (":status", status),
            ("x-mq-error", xmq),
            ("content-length", "0"),
        ]),
        true,
    )]
}

fn bare_404() -> Vec<(Hs, bool)> {
    vec![(hs(&[(":status", "404"), ("content-length", "0")]), true)]
}

#[test]
fn recv_headers_error_is_400_bad_request() {
    let mut h = H::with_gateway(cfg());
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_error(r, StreamError::Conn);
    h.drive();
    assert_eq!(h.t.h3_headers_sent(r), error_reply("400", "bad-request"));
}

#[test]
fn send_error_golden_headers() {
    let mut h = H::with_gateway(cfg());
    let r = open(&mut h, request("Bearer nope", &[]), true);
    assert_eq!(h.t.h3_headers_sent(r), error_reply("403", "auth-failed"));
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
    // A failed send is reset; nothing else is sent.
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.expect_h3_send_headers(r, Err(StreamError::Conn));
    h.t.inject_h3_headers(r, request("Bearer nope", &[]), true);
    h.drive();
    assert!(h.log().contains(&Call::H3Reset(r)));
    // `Blocked` on the tiny block counts as sent.
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.expect_h3_send_headers(r, Err(StreamError::Blocked));
    h.t.inject_h3_headers(r, request("Bearer nope", &[]), true);
    h.drive();
    assert!(!h.log().contains(&Call::H3Reset(r)));
}

#[test]
fn masquerade_unauthed_bare_404() {
    let mut h = H::with_gateway(masquerade());
    let r = open(&mut h, request("Bearer nope", &[]), true);
    assert_eq!(h.t.h3_headers_sent(r), bare_404(), "403 path");
    let r = open(&mut h, request(OK, &[("x(y", "v")]), true);
    assert_eq!(
        h.t.h3_headers_sent(r),
        bare_404(),
        "bad-header, before auth"
    );
    let r = open(&mut h, request(OK, &[("content-length", "x")]), true);
    assert_eq!(
        h.t.h3_headers_sent(r),
        bare_404(),
        "bad-request, before auth"
    );
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_error(r, StreamError::Reset);
    h.drive();
    assert_eq!(h.t.h3_headers_sent(r), bare_404(), "step 1");
}

#[test]
fn masquerade_authed_keeps_diagnostics() {
    let mut h = H::with_gateway(masquerade());
    let r = open(&mut h, request(OK, &[(":path", "/a#b")]), true);
    assert_eq!(h.t.h3_headers_sent(r), error_reply("400", "bad-target"));
    let r = open(&mut h, request(OK, &[(":method", "CONNECT")]), true);
    assert_eq!(h.t.h3_headers_sent(r), error_reply("400", "bad-request"));
    let r = open(&mut h, request(OK, &[(":authority", "a{b")]), true);
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "origin-start-failed")
    );
}

#[test]
fn finished_request_keeps_draining() {
    const PIECE: usize = 64 * 1024;
    let mut h = H::with_gateway(cfg());
    let r = open(&mut h, request("Bearer nope", &[]), false);
    assert_eq!(h.t.h3_headers_sent(r), error_reply("403", "auth-failed"));
    // 1 MiB arriving after the 403: every piece is read and discarded.
    for i in 0..16 {
        h.t.inject_h3_body(r, vec![b'x'; PIECE], i == 15);
        h.drive();
        assert_eq!(h.t.h3_body_unread(r), 0, "piece {i}");
    }
    assert!(h.count(|c| matches!(c, Call::H3RecvBody { r: x, .. } if *x == r)) >= 64);
    // Headers + body + FIN in one notification: drained in the same callback.
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_headers(r, request("Bearer nope", &[]), false);
    h.t.inject_h3_body(r, vec![b'x'; 16 * PIECE], true);
    h.drive();
    assert_eq!(h.t.h3_headers_sent(r), error_reply("403", "auth-failed"));
    assert_eq!(h.t.h3_body_unread(r), 0);
}

#[test]
fn origin_start_failed_502() {
    let mut h = H::with_gateway(cfg());
    for a in ["user@o.test", "o.test:99999", "o.test:", "[::1"] {
        let r = open(&mut h, request(OK, &[(":authority", a)]), true);
        let reply = error_reply("502", "origin-start-failed");
        assert_eq!(h.t.h3_headers_sent(r), reply, "{a}");
    }
    assert_eq!(h.dial(), None, "nothing dialled");
}

#[test]
fn authority_http_refuses_502_origin_start_failed() {
    let mut h = H::with_gateway(cfg());
    // `{` passes intake's `uri_field_ok`; `http::uri::Authority` refuses it.
    let r = open(&mut h, request(OK, &[(":authority", "a{b")]), false);
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "origin-start-failed")
    );
    assert_eq!(h.dial(), None);
    h.t.inject_h3_body(r, vec![b'x'; 1000], true);
    h.drive();
    assert_eq!(h.t.h3_body_unread(r), 0, "drained");
}

#[test]
fn limit_dial_result_origin_start_failed() {
    let mut h = H::with_gateway(cfg());
    let r = open(&mut h, request(OK, &[]), false);
    assert!(h.t.h3_headers_sent(r).is_empty(), "the origin is dialled");
    let (op, _, _) = h.dial().expect("a dial");
    h.dial_err(op, DialError::Limit);
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "origin-start-failed")
    );
    h.t.inject_h3_body(r, vec![b'x'; 100_000], true);
    h.drive();
    assert_eq!(h.t.h3_body_unread(r), 0, "drained after the reply");
}

#[test]
fn no_header_section_yet_waits_in_intake() {
    let mut h = H::with_gateway(cfg());
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.event(mq_transport_api::Event::H3Readable(r));
    assert!(h.log().contains(&Call::H3RecvHeaders(r)), "asked");
    assert!(h.t.h3_headers_sent(r).is_empty());
    assert!(!h.log().contains(&Call::H3Reset(r)));
    // The section arrives later and is admitted.
    h.t.inject_h3_headers(r, request(OK, &[]), true);
    h.drive();
    assert!(h.t.h3_headers_sent(r).is_empty());
    assert!(h.dial().is_some(), "admitted: the origin is dialled");
}
