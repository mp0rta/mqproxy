// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §7.7: request records, the settling point, the removal classes A, D,
//! E and E′, `closing`, `by_h3` upkeep, the idle sweep and shutdown, driven
//! through `OriginHost` with plain HTTP/1.1 bytes (B and C:
//! `server_origin_pool_h1.rs`).

mod origin_harness;

use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec};
use mq_proxy::server::origin::{Accepted, IDLE_MAX, OriginConnId, RecordState};
use mq_runtime::{IoRequest, TcpId};
use mq_transport_api::H3ReqId;
use origin_harness::{OH, TlsPeer, cfg, get, tls};
use std::cell::Cell;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;

/// An undecryptable plaintext record after the handshake: fatal, sticky.
const ALERT: &[u8] = &[0x15, 3, 3, 0, 2, 2, 0x28];

fn oh() -> OH {
    OH::new(cfg(), tls())
}

/// A plain-http exchange whose request was sent: (h3, tcp, conn).
fn plain(oh: &mut OH, spec: StartSpec) -> (H3ReqId, TcpId, OriginConnId) {
    let h3 = oh.start(spec);
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    oh.tcp_out_all(tcp);
    (h3, tcp, conn)
}

/// A plain-http exchange run to its end: the conn is idle in the pool.
fn idle_plain(oh: &mut OH) -> (H3ReqId, TcpId, OriginConnId) {
    let (h3, tcp, conn) = plain(oh, get("http://o.test/"));
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    assert!(end_seen(oh, h3), "{:?}", oh.events());
    (h3, tcp, conn)
}

/// An https h1 exchange past the TLS handshake, its request at the peer.
fn tls_h1(oh: &mut OH) -> (H3ReqId, TcpId, OriginConnId, TlsPeer) {
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let mut peer = TlsPeer::h1();
    peer.pump(oh, tcp);
    peer.pump(oh, tcp);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    (h3, tcp, conn, peer)
}

/// An https start whose dial succeeded and whose handshake is never answered.
fn starved_tls(oh: &mut OH) -> (H3ReqId, TcpId, OriginConnId) {
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    (h3, tcp, conn)
}

fn end_seen(oh: &OH, h3: H3ReqId) -> bool {
    oh.events()
        .iter()
        .any(|e| matches!(e, BridgeEv::End(x, _) if *x == h3))
}

fn frames(oh: &OH) -> Vec<u8> {
    let ev = oh.events();
    let f = ev.iter().filter_map(|e| match e {
        BridgeEv::Frame(_, d) => Some(&d[..]),
        _ => None,
    });
    f.collect::<Vec<_>>().concat()
}

fn no_failure(oh: &OH) {
    let ev = oh.events();
    let f: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e, BridgeEv::Failure(..)))
        .collect();
    assert!(f.is_empty(), "{f:?}");
}

fn socket_calls(oh: &mut OH, tcp: TcpId) -> usize {
    oh.io()
        .iter()
        .filter(|r| matches!(r, IoRequest::TcpClose { tcp: t, .. } if *t == tcp))
        .count()
}

fn closed_gracefully(oh: &mut OH, tcp: TcpId) -> bool {
    oh.io().contains(&IoRequest::TcpClose { tcp, abort: false })
}

fn pipe_dead(oh: &mut OH, conn: OriginConnId) -> bool {
    oh.with_host(|h, _| h.origin().pipe_dead(conn))
}

fn ended_records(oh: &mut OH, conn: OriginConnId) -> usize {
    oh.with_host(|h, _| h.origin().ended_records(conn))
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

fn armed(oh: &mut OH) -> bool {
    oh.with_host(|h, _| h.origin().idle_timer_armed())
}

#[test]
fn assigned_to_ended_on_body_end_and_dropped_at_settle() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    assert_eq!(record_state(&mut oh, h3), Some(RecordState::Assigned));
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    assert!(end_seen(&oh, h3));
    // Every pump settles before it returns: only the post-settle state shows.
    assert_eq!(record_state(&mut oh, h3), None);
    assert_eq!(ended_records(&mut oh, conn), 0, "released → dropped");
    assert_eq!(pool_len(&mut oh), 1, "the conn stays pooled");
}

#[test]
fn cancel_while_assigned_moves_to_ended() {
    // Before the head.
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.with_host(|h, cx| h.origin_mut().cancel(cx, h3)); // not pumped
    assert_eq!(ended_records(&mut oh, conn), 1, "Ended, not dropped");
    assert_eq!(record_state(&mut oh, h3), None);
    oh.with_host(|h, cx| h.pump(cx));
    assert_eq!(ended_records(&mut oh, conn), 0, "dropped once released");
    assert!(oh.events().is_empty(), "{:?}", oh.events());
    assert!(
        closed_gracefully(&mut oh, tcp),
        "tcp_close (class B or C: indistinguishable here)"
    );

    // After the head, with the upload still incomplete.
    let mut oh = self::oh();
    let spec = StartSpec {
        method: "POST",
        body: BodySpec::Known(1024 * 1024),
        ..get("http://o.test/up")
    };
    let (h3, tcp, conn) = plain(&mut oh, spec);
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc");
    assert_eq!(frames(&oh), b"abc");
    let seen = oh.events().len();
    oh.with_host(|h, cx| h.origin_mut().cancel(cx, h3));
    assert_eq!(ended_records(&mut oh, conn), 1);
    oh.with_host(|h, cx| h.pump(cx));
    // hyper closes an h1 conn whose exchange was dropped and lets go of the
    // body (§7.7); the abort itself is pinned in-module
    // (`end_aborts_only_an_incomplete_upload`).
    assert_eq!(ended_records(&mut oh, conn), 0, "released → dropped");
    assert_eq!(oh.events().len(), seen, "nothing after the cancel");
    assert!(
        pipe_dead(&mut oh, conn) && !oh.aborted(tcp),
        "tcp_close (class B or C: indistinguishable here)"
    );
    oh.tcp_out_all(tcp); // a graceful close follows the queued upload bytes
    assert!(closed_gracefully(&mut oh, tcp));
}

#[test]
fn removal_sets_pipe_dead_for_a_d_e_eprime() {
    // A: idle expiry, `tcp_close`.
    let mut oh = oh();
    let (_, tcp, conn) = idle_plain(&mut oh);
    assert!(!pipe_dead(&mut oh, conn));
    oh.advance(IDLE_MAX);
    assert!(pipe_dead(&mut oh, conn), "A");
    assert!(closed_gracefully(&mut oh, tcp), "A: tcp_close");
    assert!(!oh.aborted(tcp));

    // D: the requester cancelled during the TLS handshake, `tcp_abort`.
    let mut oh = self::oh();
    let (h3, tcp, conn) = starved_tls(&mut oh);
    oh.cancel(h3);
    assert!(pipe_dead(&mut oh, conn), "D");
    assert!(oh.aborted(tcp), "D: tcp_abort");

    // E: a fatal TLS error after the handshake, `tcp_abort` at removal.
    let mut oh = self::oh();
    let (_, tcp, conn, mut peer) = tls_h1(&mut oh);
    peer.write_raw(&mut oh, tcp, ALERT);
    assert!(pipe_dead(&mut oh, conn), "E");
    assert!(oh.aborted(tcp), "E: tcp_abort");

    // E′: the connect deadline during the TLS handshake, `tcp_abort`.
    let mut oh = self::oh();
    let (_, tcp, conn) = starved_tls(&mut oh);
    oh.advance(cfg().connect_timeout);
    assert!(pipe_dead(&mut oh, conn), "E′");
    assert!(oh.aborted(tcp), "E′: tcp_abort");
}

#[test]
fn idle_expiry_removes_class_a_at_sweep() {
    let mut oh = oh();
    let (_, tcp, _) = idle_plain(&mut oh);
    oh.advance(IDLE_MAX - Duration::from_millis(100));
    assert_eq!(pool_len(&mut oh), 1, "younger than IDLE_MAX");
    assert!(!oh.closed(tcp));
    oh.advance(cfg().sweep); // the next sweep
    assert_eq!(pool_len(&mut oh), 0, "expired at the sweep");
    assert!(closed_gracefully(&mut oh, tcp));
    assert_eq!(socket_calls(&mut oh, tcp), 1);
}

#[test]
fn closing_keeps_records_until_ended() {
    let mut oh = oh();
    let (h3, tcp, conn, mut peer) = tls_h1(&mut oh);
    let body = b"0123456789".repeat(100);
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
    peer.write_plain(&[head.as_bytes(), &body].concat());
    peer.pump(&mut oh, tcp);
    assert!(!frames(&oh).is_empty(), "the first frame, held");
    assert!(!end_seen(&oh, h3));
    peer.write_raw(&mut oh, tcp, ALERT);
    assert!(pipe_dead(&mut oh, conn), "class E");
    assert!(oh.aborted(tcp), "tcp_abort at removal");
    assert_eq!(closing_len(&mut oh), 1, "the record keeps the conn");
    assert_eq!(pool_len(&mut oh), 0);
    assert_eq!(record_state(&mut oh, h3), Some(RecordState::Assigned));
    let calls = socket_calls(&mut oh, tcp);
    oh.with_host(|h, cx| h.resume(cx, h3));
    no_failure(&oh);
    assert_eq!(frames(&oh), body, "the buffered body still arrives");
    assert!(end_seen(&oh, h3));
    assert_eq!(closing_len(&mut oh), 0, "the conn left closing");
    assert_eq!(socket_calls(&mut oh, tcp), calls, "no second socket call");
}

#[test]
fn idle_sweep_armed_only_while_pool_or_closing_nonempty() {
    let mut oh = oh();
    assert!(!armed(&mut oh));
    let h3 = oh.start(get("http://o.test/"));
    assert!(!armed(&mut oh), "a dial is neither pool nor closing");
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    assert!(armed(&mut oh), "pooled");
    oh.tcp_out_all(tcp);
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    assert!(end_seen(&oh, h3));
    assert!(armed(&mut oh), "idle in the pool");
    oh.advance(IDLE_MAX);
    assert_eq!(pool_len(&mut oh), 0);
    assert!(!armed(&mut oh), "pool and closing empty");
    assert_eq!(oh.sh.next_timeout(), None, "cancelled in the shard too");

    // Closing alone keeps it armed.
    let mut oh = self::oh();
    let (h3, tcp, _, mut peer) = tls_h1(&mut oh);
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    peer.write_plain(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc");
    peer.pump(&mut oh, tcp);
    peer.write_raw(&mut oh, tcp, ALERT);
    assert_eq!((pool_len(&mut oh), closing_len(&mut oh)), (0, 1));
    assert!(armed(&mut oh), "closing");
    oh.with_host(|h, cx| h.resume(cx, h3));
    assert_eq!(closing_len(&mut oh), 0);
    assert!(!armed(&mut oh));
}

#[test]
fn by_h3_removed_at_h3closed_ended_lookup_is_noop() {
    let mut oh = oh();
    let (h3, tcp, conn) = idle_plain(&mut oh);
    assert_eq!(
        oh.with_host(|h, _| h.origin().conn_of(h3)),
        Some(conn),
        "kept until H3Closed"
    );
    let seen = oh.events().len();
    oh.cancel(h3);
    assert_eq!(oh.with_host(|h, _| h.origin().conn_of(h3)), None);
    assert_eq!(oh.events().len(), seen);
    assert_eq!(pool_len(&mut oh), 1, "the conn is untouched");
    assert!(!oh.closed(tcp));
    assert!(!pipe_dead(&mut oh, conn));
}

#[test]
fn settle_runs_at_end_of_every_pump_even_when_capped() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    let polls = Rc::new(Cell::new(0));
    let p = polls.clone();
    let spin = std::future::poll_fn(move |cx: &mut Context<'_>| {
        p.set(p.get() + 1);
        cx.waker().wake_by_ref(); // dirty again: every pump hits the cap
        Poll::<()>::Pending
    });
    oh.with_host(|h, _| h.origin_mut().spawn_test_task(Box::pin(spin)));
    oh.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    assert!(end_seen(&oh, h3));
    assert_eq!(polls.get() % 16, 0, "capped pumps only");
    assert_eq!(oh.sh.next_timeout(), Some(oh.now), "still capped");
    assert_eq!(ended_records(&mut oh, conn), 0, "settled anyway");
}

#[test]
fn shutdown_marks_every_pipe_dead_and_cancels_dials() {
    let mut oh = oh();
    let (h3_a, tcp_a, conn_a) = plain(&mut oh, get("http://o.test/a"));
    let (h3_b, tcp_b, conn_b) = starved_tls(&mut oh);
    let h3_c = oh.start(get("http://o.test/c"));
    let (op_c, _, _) = oh.dial().unwrap();
    oh.with_host(|h, cx| {
        h.origin_mut()
            .spawn_test_task(Box::pin(std::future::pending()));
        h.origin_mut().shutdown(cx);
    });
    assert!(pipe_dead(&mut oh, conn_a) && pipe_dead(&mut oh, conn_b));
    assert!(oh.aborted(tcp_a) && oh.aborted(tcp_b), "class E: tcp_abort");
    assert!(oh.io().contains(&IoRequest::CancelDial { op: op_c }));
    assert_eq!(oh.with_host(|h, _| h.origin().task_count()), 0);
    assert_eq!(pool_len(&mut oh), 0);
    assert_eq!(record_state(&mut oh, h3_b), None);
    assert_eq!(record_state(&mut oh, h3_c), None);
    oh.advance(cfg().connect_timeout);
    // `a`'s exchange is reported from the dead pipe; then nothing is left.
    assert_eq!(closing_len(&mut oh), 0);
    assert!(!armed(&mut oh));
    assert_eq!(oh.sh.next_timeout(), None);
    oh.cancel(h3_a);
    assert_eq!(oh.with_host(|h, _| h.origin().conn_of(h3_a)), None);
    // No event for a dropped `Connecting` record (the gateway resets every
    // request itself, §6.6).
    let ev = oh.events();
    let late = |x: H3ReqId| {
        ev.iter().any(|e| match e {
            BridgeEv::Response(h, _)
            | BridgeEv::Frame(h, _)
            | BridgeEv::End(h, _)
            | BridgeEv::Failure(h, ..)
            | BridgeEv::WantH3(h) => *h == x,
        })
    };
    assert!(late(h3_a), "{ev:?}");
    assert!(!late(h3_b) && !late(h3_c), "{ev:?}");
}

/// A conn already in `closing` (class E, its `tcp_abort` done) stays there
/// at shutdown with no second socket action.
#[test]
fn shutdown_of_a_closing_conn_acts_once() {
    let mut oh = oh();
    let (_, tcp, conn, mut peer) = tls_h1(&mut oh);
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    peer.write_plain(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc");
    peer.pump(&mut oh, tcp);
    peer.write_raw(&mut oh, tcp, ALERT);
    assert_eq!(closing_len(&mut oh), 1);
    oh.with_host(|h, cx| h.origin_mut().shutdown(cx));
    assert_eq!(closing_len(&mut oh), 1, "the record still keeps it");
    assert!(pipe_dead(&mut oh, conn));
    assert_eq!(socket_calls(&mut oh, tcp), 1, "one TcpClose");
}
