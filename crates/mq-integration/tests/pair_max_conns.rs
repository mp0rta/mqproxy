//! `max_conns` on the shard pair (spec §8.1 "Shard pair", §4.7 `max_conns`):
//! clients A, B and C are three connections of one `RawClient` (each sends the
//! `AUTH_REQUEST`), counted by `Transport::conn_count`.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;

#[test]
fn pair_max_conns_e2e() {
    let mut p = Pair::new(spawn_server(server_cfg(), 1), spawn_raw(false));
    let count = |p: &Pair<_, RawClient>| p.with_server(|n| n.transport().conn_count());

    // (A) connects and authenticates: one counted connection.
    let a = p.raw_connect(true);
    assert_eq!(count(&p), 1);

    // (B) a second connection is refused at the cap (in `server_accept`,
    // before the handshake, spec §4.7): it is never established on either
    // side and never authenticates.
    let b = p.with_client(|n| n.with_app(|r, cx| r.connect(cx, true)));
    p.run_for(2 * SEC);
    assert_ne!(p.with_client(move |n| n.app().auth_status(b)), Some(0));
    assert_eq!(p.with_client(|n| n.tap().established().len()), 1);
    assert_eq!(p.server_conns().len(), 1);
    assert_eq!(p.with_server(|n| n.transport().n_provisional()), 0);
    assert_eq!(count(&p), 1);
    assert_eq!(p.auth_attempts(), 1);

    // (C) close A: after draining, the slot is free.
    p.with_client(move |n| n.with_app(|r, cx| r.close_conn(cx, a)));
    assert!(p.run_until(3 * SEC, |p| count(p) == 0));

    // (D) a new connection fits in the freed slot.
    p.raw_connect(true);
    assert_eq!(count(&p), 1);
    assert_eq!(p.auth_attempts(), 2);
}
