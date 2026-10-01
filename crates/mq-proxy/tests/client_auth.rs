//! spec §6.2 Connecting → Authing → Serving: the control stream, the auth
//! deadline, auth refusal, control-stream loss and handshake write retries.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::{Call, log_capture};
use mq_transport_api::{Event, StreamError};
use std::time::Duration;

#[test]
fn connects_and_authenticates_with_c_bytes() {
    let mut h = H::new(cfg());
    assert_eq!(h.connects(), 1, "connect at start");
    let ctrl = h.establish();
    assert!(h.log().contains(&Call::OpenStream(h.conn)));
    assert!(h.log().contains(&Call::StreamSend {
        s: ctrl,
        bytes: AUTH_REQ_C.to_vec(),
        fin: false,
    }));
    // AUTH_RESPONSE ok → Serving: a request is opened at once.
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(0, 0), false)));
    h.event(Event::StreamReadable(ctrl));
    let s = h.next_stream(h.conn);
    h.socks_request(b"");
    assert_eq!(h.t.sent_bytes(s), CONNECT_REQ_C);
    assert_eq!(h.close_conn_count(h.conn), 0);
}

#[test]
fn auth_timeout_10s_closes_and_backs_off() {
    let mut h = H::new(cfg());
    h.establish();
    h.advance(Duration::from_millis(9_999));
    assert_eq!(h.close_conn_count(h.conn), 0);
    h.advance(Duration::from_millis(1));
    assert_eq!(
        h.close_conn_count(h.conn),
        1,
        "no AUTH_RESPONSE within 10 s"
    );
    // ConnClosed (queued by close_conn) arms the reconnect: first retry 250–500 ms.
    let wait = h.sh.next_timeout().expect("reconnect timer") - h.now;
    assert!(
        (Duration::from_millis(250)..=Duration::from_millis(500)).contains(&wait),
        "{wait:?}"
    );
    h.advance(wait);
    assert_eq!(h.connects(), 2, "reconnected after the backoff");
}

#[test]
fn auth_refused_fails_pending_and_closes() {
    let mut h = H::new(cfg());
    let ctrl = h.establish();
    let tcp = h.socks_request(b"");
    assert_eq!(
        h.opens(),
        1,
        "only the control stream: the request is pending"
    );
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(1, 1), false)));
    h.event(Event::StreamReadable(ctrl));
    assert_eq!(h.reply(tcp), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp));
    assert_eq!(h.close_conn_count(h.conn), 1);
    assert_eq!(h.opens(), 1);
}

#[test]
fn auth_response_over_512_bytes_is_malformed() {
    let mut h = H::new(cfg());
    let ctrl = h.establish();
    let tcp = h.socks_request(b"");
    h.t.expect_stream_recv(ctrl, Ok((pad_to(&auth_resp(0, 0), 513), false)));
    h.event(Event::StreamReadable(ctrl));
    assert_eq!(h.reply(tcp), SOCKS_REFUSED, "treated as a refusal");
    assert_eq!(h.close_conn_count(h.conn), 1);
}

#[test]
fn control_stream_closed_closes_conn() {
    let mut h = H::new(cfg());
    let ctrl = h.serving();
    h.event(Event::StreamClosed(ctrl));
    assert_eq!(h.close_conn_count(h.conn), 1);
}

#[test]
fn settled_control_stream_readable_is_drained_and_reset_closes_conn() {
    let mut h = H::new(cfg());
    let ctrl = h.serving();
    let recvs = |h: &H| h.count(|c| matches!(c, Call::StreamRecv { s, .. } if *s == ctrl));
    let before = recvs(&h);
    h.t.expect_stream_recv(ctrl, Ok((b"unexpected".to_vec(), false)));
    h.event(Event::StreamReadable(ctrl));
    // Read until Blocked: the data, then the empty queue.
    assert_eq!(recvs(&h), before + 2, "drained with stream_recv");
    assert_eq!(
        h.close_conn_count(h.conn),
        0,
        "data is discarded, not fatal"
    );
    // A reset is consumed by stream_recv and closes the connection.
    h.t.expect_stream_recv(ctrl, Err(StreamError::Reset));
    h.event(Event::StreamReadable(ctrl));
    assert_eq!(recvs(&h), before + 3);
    assert!(h.reset(ctrl));
    assert_eq!(h.close_conn_count(h.conn), 1);
}

#[test]
fn token_and_client_id_truncated_with_warning() {
    log_capture::install();
    log_capture::take();
    let token = "t".repeat(300);
    let id = "i".repeat(70);
    let mut h = H::new(ClientConfig {
        token: token.clone(),
        client_id: id.clone(),
        ..cfg()
    });
    let lines = log_capture::take();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("WARN") && l.contains("token")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("WARN") && l.contains("client-id")),
        "{lines:?}"
    );
    let ctrl = h.establish();
    let mut want = vec![0x01, 63];
    want.extend_from_slice(&id.as_bytes()[..63]);
    want.extend_from_slice(&[0x40, 0xFF]); // varint 255
    want.extend_from_slice(&token.as_bytes()[..255]);
    want.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(h.t.sent_bytes(ctrl), want);
}

#[test]
fn handshake_partial_write_retried_on_writable() {
    let mut h = H::new(cfg());
    let ctrl = h.t.new_stream_id();
    h.t.expect_open_stream(Ok(ctrl));
    h.t.expect_stream_send(ctrl, Ok(3));
    h.event(Event::ConnEstablished(h.conn));
    assert_eq!(h.t.sent_bytes(ctrl), AUTH_REQ_C[..3]);
    h.t.expect_stream_send(ctrl, Err(StreamError::Blocked));
    h.event(Event::StreamWritable(ctrl));
    assert_eq!(h.t.sent_bytes(ctrl), AUTH_REQ_C[..3], "blocked: kept");
    h.event(Event::StreamWritable(ctrl));
    assert_eq!(h.t.sent_bytes(ctrl), AUTH_REQ_C, "remainder sent");
    assert_eq!(h.close_conn_count(h.conn), 0);
    // The same for a data stream's CONNECT_TCP_REQUEST.
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(0, 0), false)));
    h.event(Event::StreamReadable(ctrl));
    let s = h.next_stream(h.conn);
    h.t.expect_stream_send(s, Ok(5));
    h.socks_request(b"");
    assert_eq!(h.t.sent_bytes(s), CONNECT_REQ_C[..5]);
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), CONNECT_REQ_C);
}

#[test]
fn ignores_events_for_stale_conn() {
    let mut h = H::new(ClientConfig {
        paths: vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()],
        ..cfg()
    });
    h.serving();
    let stale = h.t.new_conn_id();
    let opens = h.opens();
    h.event(Event::ConnEstablished(stale));
    h.event(Event::MpReady(stale));
    h.t.push_event(Event::ConnClosed(
        stale,
        mq_transport_api::CloseReason {
            err_type: mq_transport_api::ErrType::Unknown,
            code: 0,
        },
    ));
    h.drive();
    assert_eq!(h.opens(), opens, "no control stream for a stale conn");
    assert_eq!(h.connects(), 1);
    assert_eq!(h.sh.next_timeout(), None, "no reconnect armed");
    assert!(h.reqs().is_empty(), "no path sockets opened");
    // Still serving on the current conn.
    let s = h.next_stream(h.conn);
    h.socks_request(b"");
    assert_eq!(h.t.sent_bytes(s), CONNECT_REQ_C);
}
