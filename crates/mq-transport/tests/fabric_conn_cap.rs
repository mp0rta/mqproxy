//! Ports `test_max_conns` (spec §8.3, §4.7): with `max_conns = 1` a second client is refused
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
    let sev = w.server.drain_events();
    assert_eq!(
        sev.iter()
            .filter(|e| matches!(e, Event::NewConn(..)))
            .count(),
        1
    );
    assert_eq!(w.count(), (1, 0));

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
