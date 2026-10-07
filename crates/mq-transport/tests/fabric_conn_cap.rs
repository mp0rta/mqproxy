// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Spec §8.3, §4.7: with `max_conns = 1` a second client is refused
//! in `server_accept`; after the first connection is destroyed a third client connects;
//! `conn_count()` follows.
mod common;

use common::lockstep::{Peer, cfg, exchange_many, server_role};
use common::pair::{MS, T0, cli_addr, conn_cfg, srv_addr};
use mq_transport_api::{ConnId, Event, Role, Time, TransportOps};

struct World {
    server: Peer,
    now: Time,
}

impl World {
    fn client(&self, k: usize) -> (Peer, ConnId) {
        let c = Peer::spawn(cfg(Role::Client), vec![cli_addr(k)]);
        let cc = conn_cfg(None);
        let id = c.call(self.now, move |t, now| t.connect(now, &cc)).unwrap();
        (c, id)
    }

    /// Steps 1 ms at a time, driving and exchanging among `clients` and the server.
    fn run(&mut self, clients: &[&Peer], steps: usize) {
        for _ in 0..steps {
            self.now = self.now + MS;
            let mut all: Vec<&Peer> = clients.to_vec();
            all.push(&self.server);
            for p in &all {
                p.drive(self.now);
            }
            exchange_many(self.now, &all);
        }
    }

    fn count(&self) -> (u32, u32) {
        self.server
            .call(self.now, |t, _| (t.conn_count(), t.n_provisional()))
    }
}

fn established(ev: &[Event], c: ConnId) -> bool {
    ev.contains(&Event::ConnEstablished(c))
}

fn new_conns(ev: &[Event]) -> Vec<ConnId> {
    ev.iter()
        .filter_map(|e| match e {
            Event::NewConn(c, _) => Some(*c),
            _ => None,
        })
        .collect()
}

/// spec §4.7: at the cap a newcomer evicts the oldest unauthenticated conn, which is closed
/// with the eviction code; an authenticated conn is kept.
#[test]
fn newcomer_evicts_oldest_unauthed_conn() {
    let mut scfg = cfg(server_role());
    scfg.max_conns = 2;
    let mut w = World {
        server: Peer::spawn(scfg, vec![srv_addr()]),
        now: T0,
    };
    let (c1, id1) = w.client(0);
    w.run(&[&c1], 5);
    let (c2, id2) = w.client(1);
    w.run(&[&c1, &c2], 5);
    assert!(established(&c1.drain_events(), id1));
    assert!(established(&c2.drain_events(), id2));
    let s = new_conns(&w.server.drain_events());
    assert_eq!(s.len(), 2);
    let (s1, s2) = (s[0], s[1]);
    w.server.call(w.now, move |t, _| t.mark_conn_authed(s1));
    assert_eq!(w.count(), (2, 0));

    // The third client is admitted; s2 (unauthed) is evicted, s1 (authed, older) kept.
    let (c3, id3) = w.client(2);
    let mut sev = Vec::new();
    let mut c2ev = Vec::new();
    for _ in 0..1000 {
        w.run(&[&c1, &c2, &c3], 10);
        sev.extend(w.server.drain_events());
        c2ev.extend(c2.drain_events());
        if sev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(established(&c3.drain_events(), id3));
    let closed: Vec<_> = sev
        .iter()
        .filter_map(|e| match e {
            Event::ConnClosed(c, _) => Some(*c),
            _ => None,
        })
        .collect();
    assert_eq!(closed, [s2], "{sev:?}");
    assert_eq!(new_conns(&sev).len(), 1);
    assert_eq!(w.count(), (2, 0));
    // The evicted client sees the application close code.
    w.run(&[&c1, &c2, &c3], 100);
    c2ev.extend(c2.drain_events());
    assert!(
        c2ev.iter()
            .any(|e| matches!(e, Event::ConnClosed(c, r) if *c == id2 && r.code == 0x1002)),
        "{c2ev:?}"
    );
    assert!(
        !c1.drain_events()
            .iter()
            .any(|e| matches!(e, Event::ConnClosed(..)))
    );
}

#[test]
fn second_client_refused_until_first_is_gone() {
    let mut scfg = cfg(server_role());
    scfg.max_conns = 1;
    let mut w = World {
        server: Peer::spawn(scfg, vec![srv_addr()]),
        now: T0,
    };
    assert_eq!(w.count(), (0, 0));

    let (c1, id1) = w.client(0);
    w.run(&[&c1], 5);
    assert!(established(&c1.drain_events(), id1));
    let s1 = new_conns(&w.server.drain_events());
    assert_eq!(s1.len(), 1);
    assert_eq!(w.count(), (1, 0));
    // Authenticated, so no eviction victim (spec §4.7).
    let s1 = s1[0];
    w.server.call(w.now, move |t, _| t.mark_conn_authed(s1));

    // The second client: refused in server_accept, before any slot (not even provisional).
    let (c2, id2) = w.client(1);
    w.run(&[&c1, &c2], 50);
    assert!(!established(&c2.drain_events(), id2));
    assert!(
        !w.server
            .drain_events()
            .iter()
            .any(|e| matches!(e, Event::NewConn(..)))
    );
    assert_eq!(w.count(), (1, 0));

    // The first connection closes; once the server destroyed it the unit is free again.
    c1.call(w.now, move |t, now| t.close_conn(now, id1));
    let mut sev = Vec::new();
    for _ in 0..1000 {
        w.run(&[&c1, &c2], 10);
        sev.extend(w.server.drain_events());
        if sev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(
        sev.iter().any(|e| matches!(e, Event::ConnClosed(..))),
        "{sev:?}"
    );
    assert_eq!(w.count(), (0, 0));

    let (c3, id3) = w.client(2);
    w.run(&[&c3], 5);
    assert!(established(&c3.drain_events(), id3));
    assert!(
        w.server
            .drain_events()
            .iter()
            .any(|e| matches!(e, Event::NewConn(..)))
    );
    assert_eq!(w.count(), (1, 0));
}
