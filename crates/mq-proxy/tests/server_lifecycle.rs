//! spec §6.5 metrics for the most recently accepted connection and §6.6 shutdown.

mod server_harness;

use mq_proxy::config::ServerConfig;
use mq_runtime::testing::log_capture;
use mq_transport_api::{ConnStats, PathStats};
use server_harness::*;
use std::time::Duration;

fn metrics_cfg() -> ServerConfig {
    ServerConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..cfg()
    }
}

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

fn metric_lines() -> Vec<String> {
    log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq.conn") || l.contains("mq_conn") || l.contains("mq.path"))
        .collect()
}

#[test]
fn shutdown_closes_all_then_exits_0() {
    // Nothing to close: exit at once.
    let mut h = H::new(cfg());
    h.sh.on_shutdown_signal(h.now);
    assert_eq!(h.sh.exit_status(), Some(0));

    let mut h = H::new(cfg());
    let (a, _) = h.authed();
    let b = h.conn(); // not yet authenticated
    h.sh.on_shutdown_signal(h.now);
    assert_eq!(h.close_conn_count(a), 1);
    assert_eq!(h.close_conn_count(b), 1);
    assert_eq!(h.sh.exit_status(), None, "waits for ConnClosed");
    // The transport reports both closes in the next drive.
    h.drive();
    assert_eq!(h.sh.exit_status(), Some(0));
    assert_eq!(h.close_conn_count(a), 1, "closed once");
}

#[test]
fn metrics_interval_most_recent_conn() {
    log_capture::install();
    let mut h = H::new(metrics_cfg());
    log_capture::take();
    let (a, _) = h.authed();
    h.t.set_conn_stats(a, stats(111));
    // B is accepted after A and has not authenticated: it is the most recent.
    let b = h.conn();
    h.t.set_conn_stats(b, stats(222));
    assert_eq!(h.sh.app().active_conn(), Some(b));
    h.advance(Duration::from_secs(1));
    let lines = metric_lines();
    assert_eq!(
        lines,
        [
            "INFO mq.conn mp_state=1 paths=1 app_bytes=222 standby_bytes=0",
            "INFO mq.path id=0 state=2 srtt_ms=0 bw_Bps=0 sent=0 recv=0 lost=0 min_rtt_ms=0 cwnd=0 inflight=0",
        ]
    );
    // A closing does not clear B.
    h.closed(a);
    assert_eq!(h.sh.app().active_conn(), Some(b));
    h.advance(Duration::from_secs(1));
    assert!(metric_lines()[0].contains("app_bytes=222"));
    // B closing clears it: the tick is silent, not A.
    h.closed(b);
    assert_eq!(h.sh.app().active_conn(), None);
    h.advance(Duration::from_secs(1));
    assert!(metric_lines().is_empty());
    assert_eq!(
        h.close_conn_count(a),
        0,
        "closed by the peer, not by the server"
    );
}

#[test]
fn metrics_tick_silent_without_conn() {
    log_capture::install();
    let mut h = H::new(metrics_cfg());
    log_capture::take();
    h.advance(Duration::from_secs(3));
    assert!(metric_lines().is_empty(), "nothing accepted");
    let c = h.conn();
    h.t.set_conn_stats(c, stats(5));
    h.advance(Duration::from_secs(1));
    assert_eq!(metric_lines().len(), 2, "ticking");
    h.closed(c);
    h.advance(Duration::from_secs(3));
    assert!(metric_lines().is_empty(), "the only connection closed");
}
