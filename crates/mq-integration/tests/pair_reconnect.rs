// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Shard-pair reconnect tests (spec §8.4 "QUIC connection lost", "Accept
//! during reconnect"; §6.2 Backoff and pending requests).
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::{Client, TRANSPARENT};
use mq_proxy::config::ClientConfig;
use mq_proxy::server::Server;
use mq_transport_api::Event;

fn pair(cfg: ClientConfig) -> Pair<Server, Client> {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(cfg));
    p.origin(OriginMode::Echo);
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    p
}

/// spec §8.4 "QUIC connection lost": the path goes silent; the connection
/// dies; its relay is closed; the client backs off, then reconnects and
/// serves again.
#[test]
fn pair_conn_lost_reconnects() {
    let mut p = pair(ClientConfig {
        reconnect: true,
        keepalive_idle: Some(5 * SEC),
        ..client_cfg()
    });
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    let c = p.client_conns()[0];

    p.blackhole = true;
    assert!(
        p.run_until(60 * SEC, |p| p.client_conns().is_empty()),
        "never lost"
    );
    assert!(p.app_closed(s).is_some(), "relay left open");
    let lost = p.with_client(move |n| {
        (n.tap().events.iter())
            .find(|(_, e)| matches!(e, Event::ConnClosed(x, _) if *x == c))
            .map(|(t, _)| *t)
            .unwrap()
    });

    p.blackhole = false;
    assert!(
        p.run_until(10 * SEC, |p| p.auth_attempts() == 2),
        "no reconnect"
    );
    let next = p.with_client(|n| {
        (n.tap().events.iter().rev())
            .find(|(_, e)| matches!(e, Event::ConnEstablished(_)))
            .map(|(t, _)| *t)
            .unwrap()
    });
    assert!(next - lost >= 250 * MS, "no backoff: {:?}", next - lost);

    let s = p.socks_open(origin_addr(), b"ping");
    let mut want = SOCKS5_OK.to_vec();
    want.extend_from_slice(b"ping");
    assert!(p.run_until(5 * SEC, move |p| p.app_written(s) == want));
}

/// spec §8.4 "Accept during reconnect": a request accepted while the client
/// is in Backoff is queued and served after re-auth (here through the
/// transparent listener).
#[test]
fn pair_accept_during_reconnect() {
    let mut p = pair(ClientConfig {
        reconnect: true,
        ..client_cfg()
    });
    let c = p.client_conns()[0];
    p.close_client_conn(c);
    assert!(p.run_until(4 * SEC, |p| p.client_conns().is_empty()));

    let s = p.with_client(|n| n.accept(TRANSPARENT, Some(origin_addr())));
    p.app_send(s, b"ping");
    p.step();
    assert_eq!(p.auth_attempts(), 1);
    assert_eq!(p.app_closed(s), None, "queued, not refused");
    assert!(p.run_until(8 * SEC, |p| p.app_written(s) == b"ping"));
    assert_eq!(p.auth_attempts(), 2);
}
