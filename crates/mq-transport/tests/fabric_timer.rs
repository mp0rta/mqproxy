//! spec §4.3, §8.4 "Timer hygiene": a deadline set during `connect` is visible at once; after
//! `drive` on an idle connection `next_timeout()` is not in the past.
mod common;

use common::lockstep::{Peer, cfg};
use common::pair::{MS, Pair, T0, cli_addr, conn_cfg};
use mq_transport_api::{Role, TransportOps};
use std::time::Duration;

#[test]
fn deadline_from_connect_is_visible_at_once() {
    let client = Peer::spawn(cfg(Role::Client), vec![cli_addr(0)]);
    assert_eq!(
        client.next_timeout(),
        None,
        "no deadline before any connection"
    );
    let cc = conn_cfg(None);
    client
        .call(T0, move |t, now| t.connect(now, &cc))
        .expect("connect");
    let d = client.next_timeout().expect("connect armed a deadline");
    assert!(d >= T0, "{d:?} before {T0:?}");
}

#[test]
fn idle_drive_never_leaves_a_past_deadline() {
    let mut p = Pair::new();
    // Follow the deadlines of the idle connection, and also wake early in between, until just
    // before xquic's default idle timeout (120 s) would close it.
    let stop = T0 + Duration::from_secs(100);
    let (mut followed, mut early) = (0, 0);
    while p.now < stop {
        let next = [p.client.next_timeout(), p.server.next_timeout()]
            .into_iter()
            .flatten()
            .min()
            .expect("an established connection always has a deadline");
        if next < stop && followed <= early {
            assert!(p.follow_timeout());
            followed += 1;
        } else {
            p.tick(if early % 2 == 0 { MS } else { 997 * MS }); // before the deadline
            early += 1;
        }
        for (side, peer) in [("client", &p.client), ("server", &p.server)] {
            let d = peer.next_timeout().expect("a deadline after drive");
            assert!(
                d >= p.now,
                "{side}: next_timeout {d:?} is before now {:?}",
                p.now
            );
        }
    }
    assert!(
        followed >= 1 && early > 100,
        "{followed} deadlines, {early} early wakeups"
    );
    assert!(
        p.now > T0 + Duration::from_secs(1),
        "time advanced: {:?}",
        p.now
    );
    assert!(p.client_closed().is_none() && p.server_closed().is_none());
}
