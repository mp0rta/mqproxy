//! spec §4.7, §8.4 "Incomplete ClientHello flood": provisional connections are refused at
//! the provisional cap; closing starts exactly 10 s after acceptance (the transport's
//! deadline, not xquic's re-armed idle timer); every slot is released exactly once after
//! draining, and the capacity is available again.
mod common;

use common::initial::{client_hello_fragment, initial};
use common::lockstep::{Peer, cfg, exchange_many, server_role};
use common::pair::{T0, cli_addr, conn_cfg, srv_addr};
use mq_transport_api::{Event, Role, Time, TransportOps, TxKey};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

const FLOOD: usize = 300;
/// spec §4.7: max(64, 4 × max_conns) with max_conns = 1.
const CAP: usize = 64;

fn addr(i: usize) -> SocketAddr {
    SocketAddr::from(([10, 2, (i >> 8) as u8, i as u8], 40000))
}

fn dcid(i: usize) -> [u8; 8] {
    [0xd0, (i >> 8) as u8, i as u8, 1, 2, 3, 4, 5]
}

fn scid(i: usize) -> [u8; 8] {
    [0x5c, (i >> 8) as u8, i as u8, 5, 4, 3, 2, 1]
}

fn n_provisional(s: &Peer) -> usize {
    s.call(Time::ZERO, |t, _| t.n_provisional()) as usize
}

/// Commits everything the server queued (sent to nobody); returns the destinations.
fn discard(s: &Peer, now: Time) -> BTreeSet<SocketAddr> {
    s.pump_out(now).into_iter().map(|d| d.to).collect()
}

#[test]
fn incomplete_client_hello_flood() {
    let mut scfg = cfg(server_role());
    scfg.max_conns = 1;
    let server = Peer::spawn(scfg, vec![srv_addr()]);
    let srv = srv_addr();

    // t = acceptance: the first Initial of each ClientHello (300 of its 4004 bytes).
    let accepted_at = T0;
    for i in 0..FLOOD {
        let pkt = initial(&dcid(i), &scid(i), 0, 0, &client_hello_fragment(0, 300));
        server.deliver(accepted_at, srv, addr(i), pkt);
        assert_eq!(
            n_provisional(&server),
            (i + 1).min(CAP),
            "after Initial {i}"
        );
    }
    server.drive(accepted_at);
    // Each accepted connection decrypted its Initial and answered it.
    let answered = discard(&server, accepted_at);
    assert!(
        (0..CAP).all(|i| answered.contains(&addr(i))),
        "{answered:?}"
    );
    assert_eq!(
        n_provisional(&server),
        CAP,
        "refused beyond the cap in server_accept"
    );
    assert_eq!(server.call(T0, |t, _| t.conn_count()), 0);

    // Until 9 s: follow the deadlines; nothing may close yet.
    let t9 = accepted_at + Duration::from_secs(9);
    let mut now = accepted_at;
    while let Some(d) = server.next_timeout().filter(|d| *d < t9) {
        now = now.max(d);
        server.drive(now);
        discard(&server, now);
    }
    assert_eq!(n_provisional(&server), CAP);

    // t = 9 s: one more incomplete Initial for each provisional connection (re-arms xquic's
    // idle timer to 19 s), then silence.
    for i in 0..CAP {
        let pkt = initial(&dcid(i), &scid(i), 1, 300, &client_hello_fragment(300, 300));
        server.deliver(t9, srv, addr(i), pkt);
    }
    server.drive(t9);
    let answered = discard(&server, t9);
    assert_eq!(
        answered,
        (0..CAP).map(addr).collect(),
        "the 9 s Initials were processed"
    );
    assert_eq!(n_provisional(&server), CAP);

    // From here on: only `next_timeout()`.
    let first = server.next_timeout().expect("a deadline");
    assert_eq!(
        first,
        accepted_at + Duration::from_secs(10),
        "the transport's deadline"
    );
    server.drive(first);
    now = first;
    // Closing started for each: every provisional connection queued its CONNECTION_CLOSE
    // (left unsent: the queues must be dropped when the slots are released).
    let keys: Vec<TxKey> = server.call(now, |t, _| {
        let mut k = Vec::new();
        t.pending_transmit(&mut k);
        k.retain(|k| k.0.is_some());
        k
    });
    assert_eq!(keys.len(), CAP, "{keys:?}");
    let dsts: BTreeSet<SocketAddr> = server.call(now, {
        let keys = keys.clone();
        move |t, _| {
            keys.iter()
                .map(|k| t.peek_transmit(*k).unwrap().dst)
                .collect()
        }
    });
    assert_eq!(dsts, (0..CAP).map(addr).collect());
    assert_eq!(n_provisional(&server), CAP, "released only after draining");

    let mut steps = 0;
    while n_provisional(&server) > 0 {
        let d = server
            .next_timeout()
            .expect("draining connections have deadlines");
        now = now.max(d);
        server.drive(now);
        steps += 1;
        assert!(
            steps < 10_000 && now < T0 + Duration::from_secs(60),
            "never released"
        );
    }
    assert_eq!(n_provisional(&server), 0);
    assert_eq!(server.call(now, |t, _| t.conn_count()), 0);
    for k in keys {
        assert_eq!(server.call(now, move |t, _| t.queued_bytes(k)), 0, "{k:?}");
    }
    assert_eq!(server.drain_events(), vec![], "never admitted: no events");

    // The provisional capacity is available again: a fresh client completes its handshake.
    let client = Peer::spawn(cfg(Role::Client), vec![cli_addr(0)]);
    let cc = conn_cfg(None);
    let c = client.call(now, move |t, now| t.connect(now, &cc)).unwrap();
    exchange_many(now, &[&client, &server]);
    assert!(client.drain_events().contains(&Event::ConnEstablished(c)));
    assert!(
        server
            .drain_events()
            .iter()
            .any(|e| matches!(e, Event::NewConn(..)))
    );
    assert_eq!(
        server.call(now, |t, _| (t.conn_count(), t.n_provisional())),
        (1, 0)
    );
}
