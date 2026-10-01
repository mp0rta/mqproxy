//! spec §6.2 "Open" and §5.4 app-owned streams: CONNECT_TCP on a data stream,
//! the response phase, its failure paths and server-initiated streams.

mod common;

use common::*;
use mq_runtime::testing::Call;
use mq_transport_api::{Error, Event, StreamError, StreamInfo, StreamKind};
use std::io::ErrorKind;

#[test]
fn open_sends_type_and_request_then_relays_after_ok() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    assert!(h.log().contains(&Call::StreamSend {
        s,
        bytes: CONNECT_REQ_C.to_vec(),
        fin: false,
    }));
    assert_eq!(
        h.tx_all(tcp),
        [5, 0],
        "no success reply before the response"
    );
    // The response arrives with payload behind it, read 1 KiB at a time.
    let mut resp = connect_resp(0, 0);
    resp.extend_from_slice(b"hello");
    h.t.expect_stream_recv(s, Ok((resp, false)));
    h.event(Event::StreamReadable(s));
    assert!(h.log().contains(&Call::StreamRecv { s, cap: 1024 }));
    let mut want = SOCKS_OK.to_vec();
    want.extend_from_slice(b"hello");
    assert_eq!(h.tx_all(tcp), want, "success reply, then the preread");
    // The relay owns the stream now: its events no longer reach the app.
    let recvs = h.count(|c| matches!(c, Call::StreamRecv { .. }));
    h.t.expect_stream_recv(s, Ok((b" world".to_vec(), false)));
    h.event(Event::StreamReadable(s));
    assert!(h.count(|c| matches!(c, Call::StreamRecv { .. })) > recvs);
    assert_eq!(h.tx_all(tcp), b" world");
    assert!(!h.reset(s));
}

#[test]
fn preread_forwarded_only_after_ok() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"early");
    h.drive();
    assert_eq!(
        h.t.sent_bytes(s),
        CONNECT_REQ_C,
        "nothing but the request yet"
    );
    h.t.expect_stream_recv(s, Ok((connect_resp(0, 0), false)));
    h.event(Event::StreamReadable(s));
    h.drive();
    let mut want = CONNECT_REQ_C.to_vec();
    want.extend_from_slice(b"early");
    assert_eq!(h.t.sent_bytes(s), want, "prebuffer forwarded after OK");
    assert_eq!(h.reply(tcp), SOCKS_OK);
}

#[test]
fn error_response_replies_closes_and_resets_stream() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    h.t.expect_stream_recv(s, Ok((connect_resp(1, 3), false))); // TIMEOUT
    h.event(Event::StreamReadable(s));
    assert_eq!(h.reply(tcp), SOCKS_TIMEOUT);
    assert!(H::closed(&h.reqs(), tcp));
    assert!(h.reset(s));
}

#[test]
fn malformed_response_conn_refused_and_reset() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    // FIN before a whole frame.
    h.t.expect_stream_recv(s, Ok((vec![0x00, 0x00], true)));
    h.event(Event::StreamReadable(s));
    assert_eq!(h.reply(tcp), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp));
    assert!(h.reset(s));
    // An undecodable frame (message length over the cap).
    let s2 = h.next_stream(h.conn);
    let tcp2 = h.socks_request(b"");
    h.t.expect_stream_recv(s2, Ok((vec![0x00, 0x00, 0x41, 0x00], false)));
    h.event(Event::StreamReadable(s2));
    assert_eq!(h.reply(tcp2), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp2));
    assert!(h.reset(s2));
}

#[test]
fn stream_closed_before_response_conn_refused() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    h.event(Event::StreamClosed(s));
    assert_eq!(h.reply(tcp), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp));
}

#[test]
fn peer_reset_while_awaiting_response_is_consumed_and_refused() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    h.t.expect_stream_recv(s, Err(StreamError::Reset));
    h.event(Event::StreamReadable(s));
    assert!(
        h.log().contains(&Call::StreamRecv { s, cap: 1024 }),
        "the reset is consumed by stream_recv"
    );
    assert_eq!(h.reply(tcp), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp));
    assert!(h.reset(s));
}

#[test]
fn stream_open_failure_replies_conn_refused() {
    let mut h = H::new(cfg());
    h.serving();
    h.t.expect_open_stream(Err(Error::Ceiling));
    let tcp = h.socks_request(b"");
    assert_eq!(h.reply(tcp), SOCKS_REFUSED);
    assert!(H::closed(&h.reqs(), tcp));
}

#[test]
fn tcp_error_during_open_resets_stream() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.next_stream(h.conn);
    let tcp = h.socks_request(b"");
    h.sh.on_tcp_error(h.now, tcp, ErrorKind::ConnectionReset);
    assert!(h.reset(s));
    // A late response finds nothing to answer.
    h.t.expect_stream_recv(s, Ok((connect_resp(0, 0), false)));
    h.event(Event::StreamReadable(s));
    assert!(h.tx_all(tcp).is_empty());
}

#[test]
fn server_initiated_stream_is_reset() {
    let mut h = H::new(cfg());
    h.serving();
    let s = h.t.new_stream_id();
    h.event(Event::NewStream(
        h.conn,
        s,
        StreamInfo {
            conn: h.conn,
            quic_id: 1,
            kind: StreamKind::Bidi,
        },
    ));
    assert!(h.reset(s));
    assert_eq!(h.close_conn_count(h.conn), 0);
}
