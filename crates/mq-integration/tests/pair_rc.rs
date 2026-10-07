// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Client reconnect on the shard pair (spec §8.1 "Shard pair", §6.2
//! reconnect), real `Client` and `Server`. Case 3 covers the TCP half only
//! (UDP reconnect is SP2).
//!
//! A connection drop is `Cx::close_conn` on the client's connection;
//! "re-authed" is the server's `auth_attempts`; an open is a SOCKS5 request
//! whose reply stands for the open callback. Case 7's "server gone" is a
//! fabric black hole (every datagram dropped both ways) instead of tearing
//! the server down and rebuilding it on the same port. Case 8 runs with
//! reconnect off from the start (the `ClientConfig` is fixed at
//! construction).
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::Client;
use mq_proxy::config::ClientConfig;
use mq_proxy::server::Server;
use mq_runtime::testing::Op;
use std::time::Duration;

type P = Pair<Server, Client>;

fn reconnecting() -> ClientConfig {
    ClientConfig {
        reconnect: true,
        ..client_cfg()
    }
}

fn pair(cfg: ClientConfig) -> P {
    let p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(cfg));
    p.origin(OriginMode::Echo);
    p
}

fn auths(p: &mut P, n: u64, limit: Duration) {
    assert!(
        p.run_until(limit, |p| p.auth_attempts() >= n),
        "{} auths",
        p.auth_attempts()
    );
}

/// Open, "ping", byte-exact echo.
fn echo_flow(p: &mut P) {
    let s = p.socks_open(origin_addr(), b"");
    assert!(
        p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK),
        "open failed: {:?}",
        p.app_written(s)
    );
    p.app_send(s, b"ping");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s)[12..] == *b"ping"));
}

fn current(p: &P) -> Option<mq_transport_api::ConnId> {
    p.client_conns().last().copied()
}

/// Drops the client's connection and runs until the loss is registered.
fn drop_conn(p: &mut P) {
    let c = current(p).expect("a connection");
    p.close_client_conn(c);
    assert!(p.run_until(4 * SEC, |p| p.client_conns().is_empty()));
}

#[test]
fn pair_rc_case1_tcp_reconnect() {
    let mut p = pair(reconnecting());
    auths(&mut p, 1, 5 * SEC);
    echo_flow(&mut p);

    // (a) An in-flight open, then the connection is dropped: the open fails
    // cleanly (a CONN_REFUSED reply and a close), it does not hang.
    let s = p.socks_open(origin_addr(), b"");
    p.step();
    p.close_client_conn(current(&p).unwrap());
    assert!(p.run_until(8 * SEC, |p| p.app_closed(s).is_some()));
    assert_eq!(&p.app_written(s)[2..4], [5, 5]);

    auths(&mut p, 2, 8 * SEC);
    assert_eq!(p.auth_attempts(), 2);
    assert!(current(&p).is_some());
    echo_flow(&mut p);

    // (b) Drop again, and drop the next connection too if one is up 50 ms
    // later: the client keeps recovering.
    p.close_client_conn(current(&p).unwrap());
    p.run_for(50 * MS);
    if let Some(c2) = current(&p) {
        p.close_client_conn(c2);
    }
    auths(&mut p, 3, 16 * SEC);
    echo_flow(&mut p);
}

#[test]
fn pair_rc_case3_open_during_window() {
    let mut p = pair(reconnecting());
    auths(&mut p, 1, 5 * SEC);
    drop_conn(&mut p);
    // In the backoff window: the open is queued, not failed.
    let s = p.socks_open(origin_addr(), b"");
    p.step();
    assert_eq!(p.app_written(s), [5, 0], "queued");
    assert_eq!(p.app_closed(s), None);
    auths(&mut p, 2, 8 * SEC);
    assert_eq!(p.auth_attempts(), 2);
    assert!(p.run_until(8 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    p.app_send(s, b"ping");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s)[12..] == *b"ping"));
}

#[test]
fn pair_rc_case4_queue_carryover() {
    let mut p = pair(reconnecting());
    auths(&mut p, 1, 5 * SEC);
    drop_conn(&mut p);
    let s = p.socks_open(origin_addr(), b"");
    auths(&mut p, 2, 8 * SEC);
    assert_eq!(p.auth_attempts(), 2);
    assert!(p.run_until(8 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    p.app_send(s, b"ping");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s)[12..] == *b"ping"));
}

#[test]
fn pair_rc_case6_keepalive_holds() {
    let mut p = pair(ClientConfig {
        keepalive_idle: Some(4 * SEC),
        ..reconnecting()
    });
    auths(&mut p, 1, 5 * SEC);
    let c = current(&p).expect("connected");
    p.run_for(1500 * MS);
    assert_eq!(p.auth_attempts(), 1, "no drop + reconnect");
    assert_eq!(current(&p), Some(c));
    assert_eq!(p.with_client(|n| n.tap().established().len()), 1);
    echo_flow(&mut p);
}

#[test]
fn pair_rc_case7_persistent_outage() {
    let mut p = pair(reconnecting());
    auths(&mut p, 1, 5 * SEC);
    echo_flow(&mut p);

    // The server becomes unreachable, then the client's connection is dropped.
    p.blackhole = true;
    p.close_client_conn(current(&p).unwrap());
    assert!(p.run_until(4 * SEC, |p| p.client_conns().is_empty()));
    // Across several backoff cycles: no false recovery.
    let sends = |p: &P| {
        p.with_client(|n| {
            (n.io().ops().iter())
                .filter(|o| matches!(o, Op::SendUdp(..)))
                .count()
        })
    };
    let before = sends(&p);
    let ok = p.run_until(3500 * MS, |p| {
        assert_eq!(p.auth_attempts(), 1);
        assert!(p.client_conns().is_empty(), "established while unreachable");
        false
    });
    assert!(!ok);
    assert!(sends(&p) > before, "no re-dial during the outage");

    // The server is back: the client's re-dials land, it re-authenticates.
    p.blackhole = false;
    auths(&mut p, 2, 16 * SEC);
    assert_eq!(p.auth_attempts(), 2);
    assert!(current(&p).is_some());
    echo_flow(&mut p);
}

#[test]
fn pair_rc_case8_open_after_terminal() {
    let mut p = pair(client_cfg()); // reconnect off
    auths(&mut p, 1, 5 * SEC);
    drop_conn(&mut p);
    p.run_for(1500 * MS);
    assert_eq!(p.auth_attempts(), 1);
    assert_eq!(p.with_client(|n| n.tap().established().len()), 1);
    assert!(p.client_conns().is_empty());
    // Fast fail: refused in the iteration that reads the request.
    let s = p.socks_open(origin_addr(), b"");
    p.step();
    assert_eq!(p.app_closed(s), Some(false));
    assert_eq!(p.app_written(s), [5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
}
