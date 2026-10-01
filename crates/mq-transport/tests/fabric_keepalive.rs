//! spec §8.4 (end): keepalive in virtual time — an idle tunnel with keepalive on survives
//! past its idle timeout, and a peer that stops answering is detected and the connection
//! closes.
mod common;

use common::pair::{Opts, Pair};
use std::time::Duration;

/// Above xquic's fixed 15 s client PING interval (`XQC_PING_TIMEOUT`), as `--keepalive-idle` must be.
const IDLE: Duration = Duration::from_secs(30);

fn keepalive_pair() -> Pair {
    Pair::with(Opts {
        idle: Some(IDLE),
        ..Opts::default()
    })
}

/// Follows both sides' deadlines (and only them) for `until` or until `stop`.
fn run_until(p: &mut Pair, until: Duration, stop: impl Fn(&Pair) -> bool) {
    let end = p.now + until;
    while p.now < end && !stop(p) {
        assert!(p.follow_timeout(), "no deadline on a live connection");
    }
}

#[test]
fn idle_tunnel_with_keepalive_survives_past_idle_timeout() {
    let mut p = keepalive_pair();
    let start = p.now;
    p.record = true;
    run_until(&mut p, 6 * IDLE, |p| {
        p.client_closed().is_some() || p.server_closed().is_some()
    });
    assert_eq!(
        p.client_closed(),
        None,
        "client closed at {:?}",
        p.now - start
    );
    assert_eq!(
        p.server_closed(),
        None,
        "server closed at {:?}",
        p.now - start
    );
    assert!(p.now - start >= 6 * IDLE);
    // Kept alive by the client's PINGs: at least one per idle period.
    let from_client = p
        .wire
        .iter()
        .filter(|d| d.to == common::pair::srv_addr())
        .count();
    assert!(
        from_client >= 6,
        "only {from_client} client datagrams while idle"
    );
}

#[test]
fn keepalive_detects_a_silent_peer() {
    let mut p = keepalive_pair();
    p.lose = true; // the server stops answering (and hears nothing)
    let start = p.now;
    run_until(&mut p, 10 * IDLE, |p| p.client_closed().is_some());
    let r = p.client_closed();
    assert!(r.is_some(), "client still open after {:?}", p.now - start);
    assert!(
        p.now - start <= 2 * IDLE,
        "detected only after {:?}",
        p.now - start
    );
}
