// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §6 intro, §6.7: H3 connections in the server's tables, composed
//! with the gateway.

mod server_harness;

use mq_proxy::config::ServerConfig;
use mq_runtime::testing::log_capture;
use mq_runtime::{Host, IoRequest, IoResult, Target};
use mq_transport_api::{ConnStats, PathStats, StreamKind};
use server_harness::*;
use std::time::Duration;

fn stats(app_bytes: u64) -> ConnStats {
    ConnStats {
        mp_state: 1,
        app_bytes,
        standby_bytes: 0,
        paths: vec![PathStats {
            id: 0,
            state: 2,
            ..PathStats::default()
        }],
    }
}

fn conn_lines() -> Vec<String> {
    log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq.conn"))
        .collect()
}

#[test]
fn h3_conn_has_no_auth_timer() {
    let mut h = H::with_gateway(cfg());
    let raw = h.conn();
    let c = h.h3_conn();
    h.advance(Duration::from_secs(10));
    assert_eq!(h.close_conn_count(raw), 1, "the raw conn's auth deadline");
    assert_eq!(h.close_conn_count(c), 0, "no auth deadline on H3");
    h.advance(Duration::from_secs(60));
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn h3_conn_closed_prints_no_udp_stats_line() {
    log_capture::install();
    let mut h = H::with_gateway(cfg());
    let c = h.h3_conn();
    let raw = h.conn();
    log_capture::take();
    h.closed(c);
    let stats_lines = |l: Vec<String>| l.iter().filter(|l| l.contains("mq_udp_srv: stats")).count();
    assert_eq!(stats_lines(log_capture::take()), 0, "H3 conn");
    h.closed(raw);
    assert_eq!(stats_lines(log_capture::take()), 1, "raw conn");
}

#[test]
fn h3_conn_never_becomes_active_metrics_conn() {
    let mut h = H::with_gateway(cfg());
    let raw = h.conn();
    h.h3_conn();
    assert_eq!(h.sh.app().active_conn(), Some(raw));
    let mut h = H::with_gateway(cfg());
    h.h3_conn();
    assert_eq!(h.sh.app().active_conn(), None);
}

#[test]
fn metrics_tick_prints_active_then_last_h3() {
    log_capture::install();
    let mut h = H::with_gateway(ServerConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..cfg()
    });
    let old = h.h3_conn();
    h.t.set_conn_stats(old, stats(1));
    let b = h.h3_conn(); // the most recent H3 conn
    h.t.set_conn_stats(b, stats(222));
    let a = h.conn(); // accepted last, still printed first
    h.t.set_conn_stats(a, stats(111));
    log_capture::take();
    h.advance(Duration::from_secs(1));
    assert_eq!(
        conn_lines(),
        [
            "INFO mq.conn mp_state=1 paths=1 app_bytes=111 standby_bytes=0",
            "INFO mq.conn mp_state=1 paths=1 app_bytes=222 standby_bytes=0",
        ]
    );
    // The older H3 conn closing does not clear `last_h3`.
    h.closed(old);
    h.advance(Duration::from_secs(1));
    assert_eq!(conn_lines().len(), 2);
    // `last_h3` closing clears it: only the raw block.
    h.closed(b);
    h.advance(Duration::from_secs(1));
    assert_eq!(
        conn_lines(),
        ["INFO mq.conn mp_state=1 paths=1 app_bytes=111 standby_bytes=0"]
    );
    // Only an H3 conn: its block alone.
    h.closed(a);
    let c = h.h3_conn();
    h.t.set_conn_stats(c, stats(333));
    h.advance(Duration::from_secs(1));
    assert_eq!(
        conn_lines(),
        ["INFO mq.conn mp_state=1 paths=1 app_bytes=333 standby_bytes=0"]
    );
}

#[test]
fn h3_conn_counts_for_shutdown_exit() {
    let mut h = H::with_gateway(cfg());
    let c = h.h3_conn();
    h.sh.on_shutdown_signal(h.now);
    assert_eq!(h.close_conn_count(c), 1);
    assert_eq!(
        h.sh.exit_status(),
        None,
        "waits for the H3 conn's ConnClosed"
    );
    h.drive();
    assert_eq!(h.sh.exit_status(), Some(0));
}

#[test]
fn raw_and_h3_shutdown_exit_waits_for_h3() {
    let mut h = H::with_gateway(cfg());
    let raw = h.conn();
    let c = h.h3_conn();
    h.t.hold_conn_closed(true);
    h.sh.on_shutdown_signal(h.now);
    h.drive();
    assert_eq!((h.close_conn_count(raw), h.close_conn_count(c)), (1, 1));
    h.closed(raw);
    assert_eq!(h.sh.exit_status(), None, "the H3 conn is still open");
    h.closed(c);
    assert_eq!(h.sh.exit_status(), Some(0));
}

#[test]
fn raw_connect_tcp_relay_unaffected_by_gateway() {
    let mut h = H::with_gateway(cfg());
    let (c, _) = h.authed();
    let (s, op) = h.request(c, b"early");
    let tcp = h.dial_ok(op);
    assert_eq!(h.t.sent_bytes(s), connect_resp(0, 0));
    assert_eq!(h.tcp_out_all(tcp), b"early", "relaying");
    h.tcp_in(tcp, b"pong");
    h.drive();
    let mut want = connect_resp(0, 0);
    want.extend_from_slice(b"pong");
    assert_eq!(h.t.sent_bytes(s), want);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    h.drive();
    assert_eq!(h.send_fins(s).last(), Some(&true), "origin EOF → FIN");
    assert!(!h.reset(s));
}

#[test]
fn new_stream_on_h3_conn_is_reset() {
    let mut h = H::with_gateway(cfg());
    let c = h.h3_conn();
    // QUIC id 0 would be a raw conn's control stream.
    let s0 = h.stream(c, 0, StreamKind::Bidi);
    let s4 = h.stream(c, 4, StreamKind::Bidi);
    assert!(h.reset(s0) && h.reset(s4));
    assert_eq!(h.sh.app().held(c), Some(0));
}

#[test]
fn unknown_dial_result_still_aborted() {
    let mut h = H::with_gateway(cfg());
    // A dial nobody in the server asked for: neither the bridge's nor a stream's.
    let target = Target {
        host: Host::Domain("o.test".into()),
        port: 80,
    };
    let op =
        h.sh.with_app(h.now, |_, cx| cx.dial(target, Duration::from_secs(1)));
    h.reqs();
    let tcp =
        h.sh.on_dial_result(h.now, op, Ok(origin()))
            .expect("a socket");
    h.drive();
    assert!(h.reqs().contains(&IoRequest::TcpClose { tcp, abort: true }));
}
