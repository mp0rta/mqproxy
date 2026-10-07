// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.3 Auth: the control stream, the token compare, refusal, the auth
//! deadline, and the streams that are reset before or without auth.

mod server_harness;

use mq_proxy::config::ServerConfig;
use mq_runtime::testing::{Call, log_capture};
use mq_transport_api::{Event, StreamError, StreamKind};
use mq_wire::frames::{AuthResp, FEAT_UDP_RELAY};
use server_harness::*;
use std::time::Duration;

#[test]
fn auth_ok_advertises_udp_relay() {
    let mut h = H::new(cfg());
    let c = h.conn();
    let ctrl = h.ctrl(c, &auth_req(b"secret"), false);
    let sent = h.t.sent_bytes(ctrl);
    assert_eq!(sent, AUTH_OK_C, "C bytes");
    let (r, _) = AuthResp::decode(&sent).unwrap();
    assert!(r.is_ok());
    assert_eq!(r.error_code, 0);
    assert_eq!(r.server_id, b"mqproxy-server");
    assert_eq!(
        r.features, FEAT_UDP_RELAY,
        "spec §7.3: advertised by default"
    );
    assert_eq!(h.send_fins(ctrl), [false], "control stream stays open");
    assert_eq!(h.sh.app().auth_attempts(), 1);
    // spec §4.7: exempt from eviction at the conn cap.
    assert_eq!(h.count(|x| *x == Call::MarkConnAuthed(c)), 1);
    // Authenticated: no close, not even after the auth deadline.
    h.advance(Duration::from_secs(20));
    assert_eq!(h.close_conn_count(c), 0);
    assert!(!h.reset(ctrl));
}

#[test]
fn no_udp_clears_feature_bit() {
    let mut h = H::new(ServerConfig {
        udp_enabled: false,
        ..cfg()
    });
    let c = h.conn();
    let ctrl = h.ctrl(c, &auth_req(b"secret"), false);
    let sent = h.t.sent_bytes(ctrl);
    assert_eq!(sent, AUTH_OK_NO_UDP_C, "C bytes");
    let (r, _) = AuthResp::decode(&sent).unwrap();
    assert!(r.is_ok());
    assert_eq!(r.features, 0, "spec §7.3: --no-udp is not advertised");
}

#[test]
fn auth_long_token_truncated_to_255_matches_client() {
    log_capture::install();
    log_capture::take();
    let token = "k".repeat(300);
    let mut h = H::new(ServerConfig {
        token: token.clone(),
        ..cfg()
    });
    // The client truncates to 255 bytes: that authenticates.
    let a = h.conn();
    let ca = h.ctrl(a, &auth_req(&token.as_bytes()[..255]), false);
    assert_eq!(h.t.sent_bytes(ca), AUTH_OK_C);
    // 254 bytes does not.
    let b = h.conn();
    let cb = h.ctrl(b, &auth_req(&token.as_bytes()[..254]), false);
    assert_eq!(h.t.sent_bytes(cb), AUTH_FAILED_C);
    let warns = log_capture::take()
        .into_iter()
        .filter(|l| l.starts_with("WARN") && l.contains("token"))
        .count();
    assert_eq!(warns, 1, "warned once, at construction");
}

#[test]
fn auth_wrong_token_error_fin_then_close_after_1s() {
    let mut h = H::new(cfg());
    let c = h.conn();
    let ctrl = h.ctrl(c, &auth_req(b"wrong"), false);
    assert_eq!(h.t.sent_bytes(ctrl), AUTH_FAILED_C);
    assert_eq!(h.send_fins(ctrl), [true], "error response carries FIN");
    assert!(
        !h.reset(ctrl),
        "never reset: that would discard the response"
    );
    assert_eq!(h.sh.app().auth_attempts(), 1);
    assert_eq!(h.count(|x| matches!(x, Call::MarkConnAuthed(_))), 0);
    h.advance(Duration::from_millis(999));
    assert_eq!(h.close_conn_count(c), 0, "time to deliver the response");
    h.advance(Duration::from_millis(1));
    assert_eq!(h.close_conn_count(c), 1, "closed 1 s later");
    // ConnClosed follows; nothing more happens.
    h.advance(Duration::from_secs(20));
    assert_eq!(h.close_conn_count(c), 1);
}

#[test]
fn auth_malformed_same() {
    let mut h = H::new(cfg());
    // client_id declared 64 bytes long (cap 63): BadValue.
    let a = h.conn();
    let ca = h.ctrl(a, &[0x01, 0x40, 0x40], false);
    // A truncated AUTH_REQUEST ended by FIN.
    let b = h.conn();
    let cb = h.ctrl(b, &auth_req(b"secret")[..5], true);
    // An AUTH_REQUEST that does not complete within 1 KiB (huge padding).
    let c = h.conn();
    let mut big = auth_req(b"secret");
    big.pop(); // padding_length 0
    big.extend_from_slice(&[0x48, 0x00]); // padding_length 2048
    big.resize(1500, 0);
    let cc = h.ctrl(c, &big, false);
    assert_eq!(h.recv_caps(cc)[0], 1024, "rejected on a full 1 KiB buffer");
    // spec §6.2: a complete AUTH_REQUEST of 513 bytes (over the frame limit).
    let d = h.conn();
    let cd = h.ctrl(d, &pad_to(&auth_req(b"secret"), 513), false);
    for (conn, ctrl) in [(a, ca), (b, cb), (c, cc), (d, cd)] {
        assert_eq!(h.t.sent_bytes(ctrl), AUTH_FAILED_C);
        assert_eq!(h.send_fins(ctrl), [true]);
        assert!(!h.reset(ctrl));
        assert_eq!(h.close_conn_count(conn), 0);
    }
    assert_eq!(h.sh.app().auth_attempts(), 4, "each counts as an attempt");
    h.advance(Duration::from_secs(1));
    for conn in [a, b, c, d] {
        assert_eq!(h.close_conn_count(conn), 1);
    }
}

#[test]
fn auth_request_of_512_bytes_accepted() {
    let mut h = H::new(cfg());
    let c = h.conn();
    let ctrl = h.ctrl(c, &pad_to(&auth_req(b"secret"), 512), false);
    assert_eq!(h.t.sent_bytes(ctrl), AUTH_OK_C);
}

#[test]
fn auth_deadline_10s_from_new_conn() {
    let mut h = H::new(cfg());
    let c = h.conn();
    h.advance(Duration::from_secs(5));
    // The control stream opens late and sends half a request: no extension.
    let ctrl = h.ctrl(c, &auth_req(b"secret")[..4], false);
    h.advance(Duration::from_millis(4_999));
    assert_eq!(h.close_conn_count(c), 0);
    h.advance(Duration::from_millis(1));
    assert_eq!(h.close_conn_count(c), 1, "10 s after NewConn");
    assert!(h.t.sent_bytes(ctrl).is_empty(), "no response");
}

#[test]
fn data_stream_before_auth_reset() {
    let mut h = H::new(cfg());
    let c = h.conn();
    // No control stream yet.
    let s1 = h.data(c);
    assert!(h.reset(s1));
    // Control stream open but not authenticated.
    h.ctrl(c, &auth_req(b"secret")[..4], false);
    let s2 = h.data(c);
    assert!(h.reset(s2));
    assert!(h.dial().is_none());
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn uni_stream_reset() {
    let mut h = H::new(cfg());
    let c = h.conn();
    let pre = h.stream(c, 2, StreamKind::Uni);
    assert!(h.reset(pre), "before auth");
    h.ctrl(c, &auth_req(b"secret"), false);
    let post = h.stream(c, 6, StreamKind::Uni);
    assert!(h.reset(post), "after auth");
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn settled_control_stream_reset_closes_conn() {
    let mut h = H::new(cfg());
    let (c, ctrl) = h.authed();
    let before = h.recv_caps(ctrl).len();
    h.feed(ctrl, b"unexpected", false);
    assert_eq!(
        h.recv_caps(ctrl).len(),
        before + 2,
        "drained: data then Blocked"
    );
    assert_eq!(h.close_conn_count(c), 0, "discarded, not fatal");
    h.t.expect_stream_recv(ctrl, Err(StreamError::Reset));
    h.event(Event::StreamReadable(ctrl));
    assert!(h.reset(ctrl));
    assert_eq!(h.close_conn_count(c), 1);
    // StreamClosed on a settled control stream does the same.
    let (c2, ctrl2) = h.authed();
    h.event(Event::StreamClosed(ctrl2));
    assert_eq!(h.close_conn_count(c2), 1);
    // And after a refusal the stream is still read.
    let c3 = h.conn();
    let ctrl3 = h.ctrl(c3, &auth_req(b"wrong"), false);
    let n = h.recv_caps(ctrl3).len();
    h.t.expect_stream_recv(ctrl3, Err(StreamError::Reset));
    h.event(Event::StreamReadable(ctrl3));
    assert_eq!(h.recv_caps(ctrl3).len(), n + 1);
    assert_eq!(h.close_conn_count(c3), 1, "peer gave up: closed at once");
}
