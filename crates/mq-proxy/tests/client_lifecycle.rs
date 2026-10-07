// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.2 tunnel loss / reconnect / `--no-reconnect`, §6.5 metrics, §6.6 shutdown.

mod common;

use common::*;
use mq_proxy::client::backoff::Backoff;
use mq_proxy::config::ClientConfig;
use mq_proxy::metrics::format_metrics;
use mq_runtime::Rng;
use mq_runtime::testing::{Call, log_capture};
use mq_transport_api::{CloseReason, ConnId, ConnStats, ConnectError, ErrType, Event, PathStats};
use std::time::Duration;

fn closed_ev(c: ConnId) -> Event {
    Event::ConnClosed(
        c,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

fn stats() -> ConnStats {
    let p = |id| PathStats {
        id,
        state: 1,
        srtt_us: 12_345,
        est_bw: 1000,
        sent_bytes: 10 * id,
        recv_bytes: 20,
        lost_count: 0,
        min_rtt_us: 9_000,
        cwnd: 4,
        bytes_in_flight: 5,
    };
    ConnStats {
        mp_state: 1,
        app_bytes: 100,
        standby_bytes: 0,
        paths: vec![p(0), p(1)],
    }
}

#[test]
fn tunnel_lost_closes_relays_fails_opens_enters_backoff_at_conn_closed() {
    let mut h = H::new(cfg());
    h.serving();
    // One relaying socket, one open awaiting its response.
    let s1 = h.next_stream(h.conn);
    let relayed = h.socks_request(b"");
    h.t.expect_stream_recv(s1, Ok((connect_resp(0, 0), false)));
    h.event(Event::StreamReadable(s1));
    assert_eq!(h.reply(relayed), SOCKS_OK);
    let s2 = h.next_stream(h.conn);
    let waiting = h.socks_request(b"");
    h.reqs();
    assert_eq!(h.sh.next_timeout(), None, "no timer before the loss");
    h.event(closed_ev(h.conn));
    assert_eq!(h.reply(waiting), SOCKS_REFUSED, "in-flight open refused");
    let reqs = h.reqs();
    assert!(
        H::closed(&reqs, relayed),
        "relay closed by the shard's sweep"
    );
    assert!(H::closed(&reqs, waiting));
    let _ = s2;
    // The reconnect timer was armed at ConnClosed.
    let wait = h.sh.next_timeout().expect("reconnect armed at ConnClosed") - h.now;
    assert!(
        (Duration::from_millis(250)..=Duration::from_millis(500)).contains(&wait),
        "{wait:?}"
    );
    assert_eq!(h.connects(), 1);
    h.advance(wait);
    assert_eq!(h.connects(), 2);
}

#[test]
fn backoff_schedule_matches_c() {
    let mut h = H::new(ClientConfig {
        reconnect_max_backoff: Duration::from_secs(2),
        ..cfg()
    });
    let mut reference = Backoff::new(Duration::from_secs(2));
    let mut rng = Rng::new(SEED);
    let mut conn = h.conn;
    for attempt in 1..=6u32 {
        // Handshake failure: ConnClosed without ConnEstablished.
        h.event(closed_ev(conn));
        let wait = h.sh.next_timeout().expect("reconnect armed") - h.now;
        let want = reference.next_delay(h.now, rng.next_u64());
        assert_eq!(wait, want, "attempt {attempt}");
        let d = (250u64 << attempt).min(2000);
        assert!(
            (Duration::from_millis(d / 2)..=Duration::from_millis(d)).contains(&wait),
            "attempt {attempt}: {wait:?} outside [{}, {d}] ms",
            d / 2
        );
        conn = h.t.new_conn_id();
        h.t.expect_connect(Ok(conn));
        h.advance(wait);
        assert_eq!(h.connects(), attempt as usize + 1);
    }
}

#[test]
fn no_reconnect_terminal_refuses_new() {
    let mut h = H::new(ClientConfig {
        reconnect: false,
        ..cfg()
    });
    h.establish();
    let pending = h.socks_request(b"");
    h.event(closed_ev(h.conn));
    assert_eq!(h.reply(pending), SOCKS_REFUSED, "pending refused");
    assert!(H::closed(&h.reqs(), pending));
    let late = h.socks_request(b"");
    assert_eq!(h.reply(late), SOCKS_REFUSED, "new request refused");
    assert!(H::closed(&h.reqs(), late));
    h.advance(Duration::from_secs(60));
    assert_eq!(h.connects(), 1, "no reconnect");
    assert_eq!(h.sh.exit_status(), None, "the process keeps running");
}

#[test]
fn metrics_interval_logs_lines() {
    log_capture::install();
    let mut h = H::new(ClientConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..cfg()
    });
    h.serving();
    h.t.set_conn_stats(h.conn, stats());
    log_capture::take();
    h.advance(Duration::from_secs(1));
    let want: Vec<String> = format_metrics(Some(&stats()))
        .into_iter()
        .map(|l| format!("INFO {l}"))
        .collect();
    assert_eq!(want.len(), 3);
    let lines: Vec<String> = log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq."))
        .collect();
    assert_eq!(lines, want);
    // Every interval.
    h.advance(Duration::from_secs(1));
    let n = log_capture::take()
        .iter()
        .filter(|l| l.contains("mq.path"))
        .count();
    assert_eq!(n, 2);
}

#[test]
fn metrics_tick_silent_without_conn() {
    log_capture::install();
    let (mut h, c) = {
        let h = H::new(ClientConfig {
            metrics_interval: Some(Duration::from_secs(1)),
            reconnect_max_backoff: Duration::from_secs(1),
            ..cfg()
        });
        let c = h.conn;
        (h, c)
    };
    h.t.set_conn_stats(c, stats());
    // Every reconnect attempt fails at once: the client never holds a conn.
    h.t.on_connect(|_| Err(ConnectError::Other(-1)));
    h.event(closed_ev(c));
    log_capture::take();
    for _ in 0..5 {
        h.advance(Duration::from_secs(1));
    }
    assert!(h.connects() > 2, "reconnecting meanwhile");
    let noisy: Vec<String> = log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq.conn") || l.contains("mq_conn") || l.contains("mq.path"))
        .collect();
    assert!(noisy.is_empty(), "{noisy:?}");
}

#[test]
fn shutdown_dumps_mq_path_lines_then_closes_then_exits_0() {
    log_capture::install();
    let mut h = H::new(cfg());
    h.serving();
    h.t.set_conn_stats(h.conn, stats());
    log_capture::take();
    let before = h.log().len();
    h.sh.on_shutdown_signal(h.now);
    let lines = log_capture::take();
    let paths: Vec<&String> = lines.iter().filter(|l| l.contains("mq.path id=")).collect();
    assert_eq!(paths.len(), 2, "{lines:?}");
    assert_eq!(h.log()[before..], [Call::CloseConn(h.conn)]);
    assert!(!h.sh.accepting(), "stops accepting");
    assert_eq!(h.sh.exit_status(), None, "exit waits for ConnClosed");
    h.drive(); // dispatches the ConnClosed close_conn queued
    assert_eq!(h.sh.exit_status(), Some(0));
    assert_eq!(h.connects(), 1, "no reconnect while shutting down");
}
