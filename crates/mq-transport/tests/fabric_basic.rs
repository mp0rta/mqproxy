// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §4.2, §4.8: a client and a server complete the handshake over the lockstep harness.
mod common;

use common::lockstep::{Peer, cfg, exchange, server_role};
use mq_transport_api::{
    ConnConfig, ConnId, ConnProto, Event, Role, StreamError, StreamKind, Time, TransportOps,
};
use std::net::SocketAddr;

const T0: Time = Time(1_000_000);

/// Client and server peers with a completed handshake: (client, server, client conn, server conn).
fn connected() -> (Peer, Peer, ConnId, ConnId) {
    let srv_addr: SocketAddr = "10.0.0.1:4433".parse().unwrap();
    let cli_addr: SocketAddr = "10.0.0.2:50000".parse().unwrap();
    let server = Peer::spawn(cfg(server_role()), vec![srv_addr]);
    let client = Peer::spawn(cfg(Role::Client), vec![cli_addr]);

    let cc = ConnConfig {
        peer: srv_addr,
        sni: "mqproxy",
        idle_timeout: None,
        proto: ConnProto::Raw,
    };
    let conn = client
        .call(T0, move |t, now| t.connect(now, &cc))
        .expect("connect");
    assert!(exchange(T0, &client, &server) > 0);

    let srv_ev = server.drain_events();
    let cli_ev = client.drain_events();
    let new_conn = srv_ev
        .iter()
        .find_map(|e| match e {
            Event::NewConn(c, _) => Some(*c),
            _ => None,
        })
        .expect("server NewConn");
    assert!(
        srv_ev.contains(&Event::ConnEstablished(new_conn)),
        "{srv_ev:?}"
    );
    assert!(cli_ev.contains(&Event::ConnEstablished(conn)), "{cli_ev:?}");
    (client, server, conn, new_conn)
}

#[test]
fn handshake_completes() {
    let (client, server, conn, srv_conn) = connected();
    assert_eq!(server.call(T0, |t, _| t.conn_count()), 1);
    assert_eq!(server.call(T0, |t, _| t.n_provisional()), 0);
    assert!(client.call(T0, move |t, _| t.conn_stats(conn)).is_ok());
    assert!(server.call(T0, move |t, _| t.conn_stats(srv_conn)).is_ok());
}

/// Smoke test of the stream methods and trampolines.
#[test]
fn stream_round_trip_and_reset_release_slots() {
    let (client, server, conn, srv_conn) = connected();
    let s = client
        .call(T0, move |t, now| t.open_stream(now, conn))
        .expect("open_stream");
    let n = client.call(T0, move |t, now| t.stream_send(now, s, b"hello", true));
    assert_eq!(n, Ok(5));
    exchange(T0, &client, &server);

    let ev = server.drain_events();
    let (ss, info) = ev
        .iter()
        .find_map(|e| match e {
            Event::NewStream(c, s, i) if *c == srv_conn => Some((*s, *i)),
            _ => None,
        })
        .expect("NewStream");
    assert_eq!(info.quic_id, 0);
    assert_eq!(info.kind, StreamKind::Bidi);
    assert!(ev.contains(&Event::StreamReadable(ss)), "{ev:?}");
    let got = server.call(T0, move |t, now| {
        let mut buf = [0u8; 64];
        t.stream_recv(now, ss, &mut buf)
            .map(|(n, f)| (buf[..n].to_vec(), f))
    });
    assert_eq!(got, Ok((b"hello".to_vec(), true)));
    // Probe after FIN: consumes nothing.
    assert_eq!(
        server.call(T0, move |t, now| t.stream_recv(now, ss, &mut [])),
        Ok((0, true))
    );
    assert_eq!(server.call(T0, move |t, _| t.stream_count(srv_conn)), 1);

    // The server resets; the client consumes the reset. Both slots are released when the
    // stream-close timers (3 × PTO) fire, without any other traffic to wake the connections.
    server.call(T0, move |t, now| t.stream_reset(now, ss));
    let mut now = T0;
    let mut client_saw_reset = false;
    for _ in 0..100 {
        now = Time(now.0 + 10_000);
        client.drive(now);
        server.drive(now);
        exchange(now, &client, &server);
        if client.drain_events().contains(&Event::StreamReadable(s)) {
            let r = client.call(now, move |t, now| t.stream_recv(now, s, &mut [0u8; 64]));
            assert_eq!(r, Err(StreamError::Reset));
            client_saw_reset = true;
        }
        let done = client.call(now, move |t, _| t.stream_count(conn)) == 0
            && server.call(now, move |t, _| t.stream_count(srv_conn)) == 0;
        if done {
            break;
        }
    }
    assert!(client_saw_reset);
    assert!(
        now < Time(T0.0 + 1_000_000),
        "released within 1 s of virtual time"
    );
    assert_eq!(client.call(now, move |t, _| t.stream_count(conn)), 0);
    assert_eq!(server.call(now, move |t, _| t.stream_count(srv_conn)), 0);
    assert_eq!(
        client.call(now, move |t, _| t.stream_info(s)),
        Err(mq_transport_api::Error::Stale)
    );

    // Closing: both sides see ConnClosed and release the counted unit.
    client.call(now, move |t, now| t.close_conn(now, conn));
    let mut closed = (false, false);
    for _ in 0..500 {
        now = Time(now.0 + 10_000);
        client.drive(now);
        server.drive(now);
        exchange(now, &client, &server);
        closed.0 |= client
            .drain_events()
            .iter()
            .any(|e| matches!(e, Event::ConnClosed(c, _) if *c == conn));
        closed.1 |= server
            .drain_events()
            .iter()
            .any(|e| matches!(e, Event::ConnClosed(c, _) if *c == srv_conn));
        if closed == (true, true) {
            break;
        }
    }
    assert_eq!(closed, (true, true));
    assert_eq!(server.call(now, |t, _| t.conn_count()), 0);
}
