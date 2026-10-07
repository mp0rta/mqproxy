// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.3 "Data streams": the dial, its result, the response, the relay
//! hand-off, and the app-owned stream rule (§5.4) while dialling and retiring.

mod server_harness;

use mq_runtime::{DialError, Host, IoRequest, SOCKET_CAP, Target};
use mq_transport_api::{Event, StreamError};
use server_harness::*;
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn dial_error_mapping_table() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    for (e, code) in [
        (DialError::Dns, 1),     // DNS_FAILED
        (DialError::Refused, 2), // CONN_REFUSED
        (DialError::Timeout, 3), // TIMEOUT
        (DialError::Limit, 4),   // POLICY_DENIED
        (DialError::Other, 2),   // CONN_REFUSED: unclassified errors
    ] {
        let (s, op) = h.request(c, b"");
        h.dial_err(op, e);
        assert_eq!(h.t.sent_bytes(s), connect_resp(1, code), "{e:?}");
    }
    // An IPv4 address that is not 4 bytes is DNS_FAILED without a dial
    // (answered, not reset).
    let s = h.data(c);
    h.feed(
        s,
        &[0x01, 0x00, 0x01, 0x03, 10, 0, 0, 0x00, 0x50, 0x00],
        false,
    );
    assert!(h.dial().is_none());
    assert_eq!(h.t.sent_bytes(s), connect_resp(1, 1));
    assert!(!h.reset(s));
}

#[test]
fn dial_requests_configured_deadline() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, CONNECT_REQ_C, false);
    let (_, target, deadline) = h.dial().unwrap();
    assert_eq!(
        target,
        Target {
            host: Host::Domain("example.com".into()),
            port: 443
        }
    );
    assert_eq!(deadline, Duration::from_secs(15), "default 15 s");
    // A configured deadline; an IPv4 target is dialled directly.
    let mut h = H::new(mq_proxy::config::ServerConfig {
        dial_deadline: Duration::from_secs(7),
        ..cfg()
    });
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(
        s,
        &[0x01, 0x00, 0x01, 0x04, 10, 0, 0, 1, 0x00, 0x50, 0x00],
        false,
    );
    let (_, target, deadline) = h.dial().unwrap();
    assert_eq!(
        target,
        Target {
            host: Host::Ip(Ipv4Addr::new(10, 0, 0, 1).into()),
            port: 80
        }
    );
    assert_eq!(deadline, Duration::from_secs(7));
}

#[test]
fn slow_resolution_policy() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (ok, op_ok) = h.request(c, b"early");
    let (late, op_late) = h.request(c, b"");
    // Resolution + connect take 14 s, inside the 15 s deadline.
    h.advance(Duration::from_secs(14));
    assert!(!h.reset(ok), "no app-side timeout while dialling");
    let tcp = h.dial_ok(op_ok);
    assert_eq!(h.t.sent_bytes(ok), connect_resp(0, 0));
    assert_eq!(h.tcp_out(tcp), b"early", "relaying");
    // The driver's deadline expires.
    h.advance(Duration::from_secs(1));
    h.dial_err(op_late, DialError::Timeout);
    assert_eq!(h.t.sent_bytes(late), connect_resp(1, 3));
}

#[test]
fn ok_response_fully_accepted_before_relay() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"early");
    let resp = connect_resp(0, 0);
    h.t.expect_stream_send(s, Ok(2));
    h.t.expect_stream_send(s, Err(StreamError::Blocked));
    let tcp = h.sh.on_dial_result(h.now, op, Ok(origin())).unwrap();
    h.drive();
    assert_eq!(h.t.sent_bytes(s), resp[..2]);
    assert!(h.tcp_out(tcp).is_empty(), "no relay on a partial response");
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), resp[..2], "blocked: kept");
    assert!(h.tcp_out(tcp).is_empty());
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), resp, "the rest");
    assert_eq!(h.tcp_out(tcp), b"early", "relay started");
    assert!(h.send_fins(s).iter().all(|f| !f));
    assert!(!h.reset(s));
}

#[test]
fn error_response_fin_no_reset() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"");
    h.dial_err(op, DialError::Refused);
    assert_eq!(h.t.sent_bytes(s), connect_resp(1, 2));
    assert_eq!(h.send_fins(s), [true]);
    assert!(!h.reset(s), "a reset would discard the response");
    // A partially accepted error response is finished, still with FIN.
    let (s2, op2) = h.request(c, b"");
    h.t.expect_stream_send(s2, Ok(1));
    h.dial_err(op2, DialError::Dns);
    assert_eq!(h.t.sent_bytes(s2), connect_resp(1, 1)[..1]);
    h.event(Event::StreamWritable(s2));
    assert_eq!(h.t.sent_bytes(s2), connect_resp(1, 1));
    assert_eq!(h.send_fins(s2), [true, true]);
    assert!(!h.reset(s2));
    // The stream finishes normally.
    h.event(Event::StreamClosed(s));
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn stream_closed_cancels_dial() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"");
    h.event(Event::StreamClosed(s));
    assert!(h.reqs().contains(&IoRequest::CancelDial { op }));
    assert!(h.reset(s));
    // The late result is dropped by the shard (cancelled), its socket closed.
    assert!(h.sh.on_dial_result(h.now, op, Ok(origin())).is_none());
    assert_eq!(h.t.sent_bytes(s), b"", "no response");
}

#[test]
fn readable_while_dialling_is_read_and_reset_cancels_dial() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // Early payload while dialling is read and kept as preread.
    let (kept, op_kept) = h.request(c, b"ab");
    let n = h.recv_caps(kept).len();
    h.feed(kept, b"cd", false);
    assert!(h.recv_caps(kept).len() > n, "stream_recv on StreamReadable");
    h.feed(kept, b"ef", true);
    let tcp = h.dial_ok(op_kept);
    assert_eq!(h.tcp_out(tcp), b"abcdef");
    // A reset while dialling cancels the dial and resets the stream.
    let (gone, op_gone) = h.request(c, b"");
    h.t.expect_stream_recv(gone, Err(StreamError::Reset));
    h.event(Event::StreamReadable(gone));
    assert!(h.reqs().contains(&IoRequest::CancelDial { op: op_gone }));
    assert!(h.reset(gone));
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn early_payload_capped_at_64k_then_probes_only() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"");
    let base = h.recv_caps(s).len();
    let payload: Vec<u8> = (0..70 * 1024).map(|i| i as u8).collect();
    h.feed(s, &payload, false);
    let caps = h.recv_caps(s)[base..].to_vec();
    let first_probe = caps.iter().position(|&c| c == 0).expect("a probe");
    assert_eq!(caps[..first_probe].iter().sum::<usize>(), 64 * 1024);
    assert!(caps[first_probe..].iter().all(|&c| c == 0), "{caps:?}");
    // Full: later readables only probe.
    let before = h.recv_caps(s).len();
    h.event(Event::StreamReadable(s));
    let after = h.recv_caps(s);
    assert!(after.len() > before);
    assert!(after[before..].iter().all(|&c| c == 0));
    let tcp = h.dial_ok(op);
    assert_eq!(h.tcp_out(tcp), payload[..64 * 1024], "64 KiB preread");
}

#[test]
fn retiring_stream_readable_is_read_and_reset_releases_budget() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"");
    h.dial_err(op, DialError::Refused);
    // control + retiring + 4094 awaiting = 4096 held.
    h.idle_streams(c, 4094);
    let over = h.data(c);
    assert!(h.reset(over), "the retiring stream still counts");
    // Retiring: StreamReadable is answered with stream_recv.
    let n = h.recv_caps(s).len();
    h.feed(s, b"junk", false);
    assert!(h.recv_caps(s).len() > n);
    assert!(!h.reset(s));
    // The peer resets it: consumed by stream_recv, reset, entry released.
    let n = h.recv_caps(s).len();
    h.t.expect_stream_recv(s, Err(StreamError::Reset));
    h.event(Event::StreamReadable(s));
    assert_eq!(h.recv_caps(s).len(), n + 1);
    assert!(h.reset(s));
    let fits = h.data(c);
    assert!(!h.reset(fits), "budget entry returned");
}

#[test]
fn limit_maps_to_policy_denied() {
    let mut h = H::new(cfg());
    // Fill the shard's socket cap with dials in progress across two connections
    // (each holds at most 4096 app streams, control included).
    let (a, _) = h.authed();
    let (b, _) = h.authed();
    for i in 0..SOCKET_CAP {
        let conn = if i < 4095 { a } else { b };
        let s = h.push_data(conn);
        h.t.expect_stream_recv(s, Ok((CONNECT_REQ_C.to_vec(), false)));
        h.t.push_event(Event::StreamReadable(s));
    }
    h.drive();
    assert_eq!(h.reqs().len(), SOCKET_CAP, "all dials reached the driver");
    // At the cap: the shard answers with Limit, the client gets POLICY_DENIED.
    let s = h.data(b);
    h.feed(s, CONNECT_REQ_C, false);
    h.drive();
    assert!(h.dial().is_none(), "never reached the driver");
    assert_eq!(h.t.sent_bytes(s), connect_resp(1, 4));
    assert_eq!(h.send_fins(s), [true]);
    assert!(!h.reset(s));
}
