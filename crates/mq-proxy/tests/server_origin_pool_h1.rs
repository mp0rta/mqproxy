// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §7.7 "h1 conns", §7.2 step 2: the h1 pool hit, idleness, the class
//! B / C / E decisions at the settling and the one retry, driven through
//! `OriginHost` with plain HTTP/1.1 bytes played by the test.

mod origin_harness;

use mq_http::headers::HttpVer;
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec, upload_byte};
use mq_proxy::server::origin::{
    Accepted, Completion, IDLE_MAX, OriginConnId, OriginFailure, RecordState, UPLOAD_CAP,
};
use mq_runtime::{IoRequest, TcpId};
use mq_transport_api::H3ReqId;
use origin_harness::{OH, cfg, get, tls};
use std::time::Duration;

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";

fn oh() -> OH {
    OH::new(cfg(), tls())
}

/// A plain-http start whose dial succeeded: (h3, tcp, conn).
fn dialled(oh: &mut OH, spec: StartSpec) -> (H3ReqId, TcpId, OriginConnId) {
    let h3 = oh.start(spec);
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    (h3, tcp, conn)
}

/// `dialled`, with the request taken off the socket.
fn plain(oh: &mut OH, spec: StartSpec) -> (H3ReqId, TcpId, OriginConnId) {
    let r = dialled(oh, spec);
    oh.tcp_out_all(r.1);
    r
}

/// A plain-http exchange run to its end: the conn is idle in the pool.
fn idle_plain(oh: &mut OH) -> (H3ReqId, TcpId, OriginConnId) {
    let (h3, tcp, conn) = plain(oh, get("http://o.test/"));
    oh.tcp_in(tcp, OK);
    assert!(end_of(oh, h3).is_some(), "{:?}", oh.events());
    assert_eq!(pool_len(oh), 1);
    (h3, tcp, conn)
}

fn post(path: &str, n: u64) -> StartSpec {
    StartSpec {
        method: "POST",
        body: BodySpec::Known(n),
        ..get(&format!("http://o.test{path}"))
    }
}

fn end_of(oh: &OH, h3: H3ReqId) -> Option<Completion> {
    oh.events().into_iter().find_map(|e| match e {
        BridgeEv::End(x, c) if x == h3 => Some(c),
        _ => None,
    })
}

fn failures(oh: &OH) -> Vec<(H3ReqId, OriginFailure)> {
    let ev = oh.events().into_iter();
    ev.filter_map(|e| match e {
        BridgeEv::Failure(h, f, _) => Some((h, f)),
        _ => None,
    })
    .collect()
}

fn frames(oh: &OH, h3: H3ReqId) -> Vec<u8> {
    let ev = oh.events().into_iter();
    let f = ev.filter_map(|e| match e {
        BridgeEv::Frame(x, d) if x == h3 => Some(d),
        _ => None,
    });
    f.collect::<Vec<_>>().concat()
}

fn conn_of(oh: &mut OH, h3: H3ReqId) -> Option<OriginConnId> {
    oh.with_host(|h, _| h.origin().conn_of(h3))
}

fn record_state(oh: &mut OH, h3: H3ReqId) -> Option<RecordState> {
    oh.with_host(|h, _| h.origin().record_state(h3))
}

fn pool_len(oh: &mut OH) -> usize {
    oh.with_host(|h, _| h.origin().pool_len())
}

fn closing_len(oh: &mut OH) -> usize {
    oh.with_host(|h, _| h.origin().closing_len())
}

fn pipe_dead(oh: &mut OH, conn: OriginConnId) -> bool {
    oh.with_host(|h, _| h.origin().pipe_dead(conn))
}

fn closed_gracefully(oh: &mut OH, tcp: TcpId) -> bool {
    oh.io().contains(&IoRequest::TcpClose { tcp, abort: false })
}

fn socket_calls(oh: &mut OH, tcp: TcpId) -> usize {
    oh.io()
        .iter()
        .filter(|r| matches!(r, IoRequest::TcpClose { tcp: t, .. } if *t == tcp))
        .count()
}

/// A response head with one `len`-byte field (the gateway's field cap is 8192).
fn head_with(len: usize) -> Vec<u8> {
    let mut h = b"HTTP/1.1 200 OK\r\n".to_vec();
    h.extend(format!("x-big: {}\r\n", "v".repeat(len)).bytes());
    h.extend(b"content-length: 2\r\n\r\nok");
    h
}

#[test]
fn pool_hit_requires_accepted_proto() {
    let mut oh = oh();
    let first = oh.start(get("http://o.test/"));
    let (op, _, _) = oh.dial().expect("a dial");
    oh.advance(Duration::from_millis(5));
    let tcp = oh.dial_ok(op);
    let conn = conn_of(&mut oh, first).expect("a conn");
    oh.tcp_out_all(tcp);
    oh.tcp_in(tcp, OK);
    assert_eq!(end_of(&oh, first).expect("ends").connect_ms, 5);
    let spec = StartSpec {
        ver: HttpVer::H1,
        ..get("http://o.test/b")
    };
    let h3 = oh.start(spec);
    assert!(oh.dial().is_none(), "the idle h1 conn is taken");
    assert_eq!(conn_of(&mut oh, h3), Some(conn));
    let out = oh.tcp_out_all(tcp);
    assert!(out.starts_with(b"GET /b HTTP/1.1\r\n"), "{out:?}");
    oh.tcp_in(tcp, OK);
    let done = end_of(&oh, h3).expect("the exchange ends");
    assert_eq!((done.reused, done.connect_ms), (true, 0), "§7.2 step 2");
}

#[test]
fn h1_idle_since_set_once_on_transition_not_refreshed() {
    let mut oh = oh();
    let (_, tcp, _) = idle_plain(&mut oh);
    let pump_for = |oh: &mut OH, secs: u32| {
        for _ in 0..secs {
            oh.advance(Duration::from_secs(1));
            oh.with_host(|h, cx| h.pump(cx));
        }
    };
    let secs = IDLE_MAX.as_secs() as u32;
    pump_for(&mut oh, secs - 1);
    assert_eq!(pool_len(&mut oh), 1, "idle {}s", secs - 1);
    assert!(!oh.closed(tcp));
    pump_for(&mut oh, 1);
    assert_eq!(
        pool_len(&mut oh),
        0,
        "expired at IDLE_MAX after the transition"
    );
    assert!(closed_gracefully(&mut oh, tcp), "class A");
}

#[test]
fn h1_retry_once_when_handed_back() {
    let mut oh = oh();
    let (_, tcp1, conn1) = idle_plain(&mut oh);
    // Queued on the idle conn without a pump: hyper sees the EOF first.
    let h3 = oh.with_host(|h, cx| h.start_unpumped(cx, get("http://o.test/r")));
    assert_eq!(conn_of(&mut oh, h3), Some(conn1), "a pool hit");
    oh.tcp_eof(tcp1);
    assert_eq!(record_state(&mut oh, h3), Some(RecordState::Connecting));
    assert!(failures(&oh).is_empty(), "{:?}", failures(&oh));
    assert!(closed_gracefully(&mut oh, tcp1), "class B");
    let (op, _, _) = oh.dial().expect("one fresh dial");
    let tcp2 = oh.dial_ok(op);
    assert_ne!(conn_of(&mut oh, h3), Some(conn1));
    let out = oh.tcp_out_all(tcp2);
    assert!(out.starts_with(b"GET /r HTTP/1.1\r\n"), "{out:?}");
    oh.tcp_in(tcp2, OK);
    let done = end_of(&oh, h3).expect("the retried exchange ends");
    assert!(!done.reused, "origin_reuse 0 on the retried exchange");
    assert!(oh.dial().is_none(), "one retry");
    assert!(failures(&oh).is_empty());
}

#[test]
fn h1_bodiless_retry_on_incomplete_message_zero_bytes() {
    let mut oh = oh();
    let (_, tcp1, conn1) = idle_plain(&mut oh);
    let h3 = oh.start(get("http://o.test/r"));
    assert_eq!(conn_of(&mut oh, h3), Some(conn1));
    let out = oh.tcp_out_all(tcp1);
    assert!(
        out.starts_with(b"GET /r HTTP/1.1\r\n"),
        "sent on the reused conn"
    );
    oh.tcp_eof(tcp1); // IncompleteMessage, no response byte
    assert!(failures(&oh).is_empty(), "{:?}", failures(&oh));
    assert_eq!(record_state(&mut oh, h3), Some(RecordState::Connecting));
    let (op, _, _) = oh.dial().expect("the retry");
    let tcp2 = oh.dial_ok(op);
    let out = oh.tcp_out_all(tcp2);
    assert!(out.starts_with(b"GET /r HTTP/1.1\r\n"), "{out:?}");
    oh.tcp_in(tcp2, OK);
    assert!(!end_of(&oh, h3).expect("ends").reused);
    assert!(oh.dial().is_none(), "one retry");
}

#[test]
fn h1_no_retry_after_body_written() {
    let mut oh = oh();
    let (_, tcp1, _) = idle_plain(&mut oh);
    let h3 = oh.start(post("/up", 10));
    let out = oh.tcp_out_all(tcp1);
    let body: Vec<u8> = (0..10).map(upload_byte).collect();
    assert!(out.ends_with(&body), "the body was written: {out:?}");
    oh.tcp_eof(tcp1);
    let f = failures(&oh);
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].0, f[0].1.curl), (h3, 52));
    assert!(oh.dial().is_none(), "never retried");
}

#[test]
fn h1_connection_completion_does_not_fail_assigned() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    oh.tcp_in(
        tcp,
        b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 10\r\n\r\n01234",
    );
    assert_eq!(frames(&oh, h3), b"01234", "held on the H3 side");
    // hyper queues the last frame into `Incoming` and completes the conn.
    oh.tcp_in(tcp, b"56789");
    assert_eq!(frames(&oh, h3), b"01234");
    assert_eq!(record_state(&mut oh, h3), Some(RecordState::Assigned));
    assert_eq!((pool_len(&mut oh), closing_len(&mut oh)), (0, 1));
    assert!(pipe_dead(&mut oh, conn));
    assert!(!oh.closed(tcp), "B's tcp_close waits for the record");
    oh.with_host(|h, cx| h.resume(cx, h3));
    assert!(failures(&oh).is_empty(), "{:?}", failures(&oh));
    assert_eq!(frames(&oh, h3), b"0123456789");
    assert_eq!(end_of(&oh, h3).expect("ends").delivered, 10);
    assert_eq!(closing_len(&mut oh), 0);
    assert!(closed_gracefully(&mut oh, tcp), "class B");
    assert_eq!(socket_calls(&mut oh, tcp), 1);
}

#[test]
fn h1_ended_unreleased_is_class_e_at_settling() {
    let mut oh = oh();
    // The whole upload is buffered (fin) but the socket is never drained:
    // hyper still holds the body when the early response ends.
    let (h3, tcp, conn) = dialled(&mut oh, post("/up", UPLOAD_CAP as u64));
    oh.tcp_in(tcp, OK);
    assert!(end_of(&oh, h3).is_some(), "{:?}", oh.events());
    assert!(failures(&oh).is_empty());
    assert!(oh.aborted(tcp), "class E: tcp_abort");
    assert!(pipe_dead(&mut oh, conn));
    assert_eq!((pool_len(&mut oh), closing_len(&mut oh)), (0, 0));
}

#[test]
fn h1_rejected_response_conn_not_pooled_class_c() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_in(tcp, &head_with(9 * 1024));
    let f = failures(&oh);
    assert!(
        f.len() == 1 && f[0].0 == h3 && f[0].1.upstream_protocol,
        "{f:?}"
    );
    assert!(closed_gracefully(&mut oh, tcp), "class C: tcp_close");
    assert!(!oh.aborted(tcp));
    assert!(pipe_dead(&mut oh, conn));
    assert_eq!(pool_len(&mut oh), 0);
}

#[test]
fn h1_cancel_after_head_is_class_c() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nok");
    assert_eq!(frames(&oh, h3), b"ok");
    oh.cancel(h3);
    // hyper also completes a dropped h1 exchange's conn, so B and C coincide
    // here; C alone is pinned by `h1_rejected_response_conn_not_pooled_class_c`.
    assert!(closed_gracefully(&mut oh, tcp), "tcp_close (class B or C)");
    assert!(!oh.aborted(tcp));
    assert!(pipe_dead(&mut oh, conn));
    assert_eq!(pool_len(&mut oh), 0);
}

#[test]
fn removal_sets_pipe_dead_for_b_and_c() {
    // B: `Connection` completed with no record left.
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_in(
        tcp,
        b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 2\r\n\r\nok",
    );
    assert!(end_of(&oh, h3).is_some());
    assert!(pipe_dead(&mut oh, conn), "B");
    assert!(closed_gracefully(&mut oh, tcp), "B: tcp_close");
    assert_eq!(socket_calls(&mut oh, tcp), 1);

    // A cancelled exchange: C, or B once hyper completed the conn — the
    // same `tcp_close` (C alone: `h1_rejected_response_conn_not_pooled_class_c`).
    let mut oh = self::oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nok");
    oh.cancel(h3);
    assert!(pipe_dead(&mut oh, conn), "B or C");
    assert!(closed_gracefully(&mut oh, tcp), "B or C: tcp_close");
    assert_eq!(socket_calls(&mut oh, tcp), 1);
}
