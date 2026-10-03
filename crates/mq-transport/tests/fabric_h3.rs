//! spec §3.2, §3.3 (conn rows): H3 connections share the raw connections' slot table,
//! admission, provisional expiry and close reporting.
mod common;

use common::initial::{client_hello_fragment, initial};
use common::lockstep::{Peer, cfg, exchange_many, server_role};
use common::pair::{MS, Opts, Pair, T0, cli_addr, conn_cfg, srv_addr};
use mq_transport_api::{ConnId, ConnProto, Event, Role, Time, TransportConfig, TransportOps};
use std::net::SocketAddr;
use std::time::Duration;

fn h3_cfg(role: Role) -> TransportConfig {
    TransportConfig {
        h3: true,
        ..cfg(role)
    }
}

fn h3_opts(proto: ConnProto) -> Opts {
    Opts {
        server: h3_cfg(server_role()),
        client: h3_cfg(Role::Client),
        proto,
        ..Opts::default()
    }
}

fn new_conns(ev: &[Event]) -> Vec<(ConnId, ConnProto)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::NewConn(c, p) => Some((*c, *p)),
            _ => None,
        })
        .collect()
}

#[test]
fn h3_connect_established_both_sides() {
    let p = Pair::with(h3_opts(ConnProto::H3)); // asserts ConnEstablished on both sides
    assert_eq!(new_conns(&p.sev), vec![(p.srv_conn, ConnProto::H3)]);
}

#[test]
fn raw_and_h3_on_one_engine() {
    let mut p = Pair::with(h3_opts(ConnProto::Raw));
    assert_eq!(new_conns(&p.sev), vec![(p.srv_conn, ConnProto::Raw)]);
    let mut cc = conn_cfg(None);
    cc.proto = ConnProto::H3;
    let c2 = p
        .client
        .call(p.now, move |t, now| t.connect(now, &cc))
        .expect("connect h3");
    p.exchange();
    assert!(p.cev.contains(&Event::ConnEstablished(c2)), "{:?}", p.cev);
    let news = new_conns(&p.sev);
    assert_eq!(news.len(), 2, "{news:?}");
    assert_eq!(news[1].1, ConnProto::H3);
    assert!(p.sev.contains(&Event::ConnEstablished(news[1].0)));
    assert_eq!(p.server.call(p.now, |t, _| t.conn_count()), 2);
}

#[test]
fn h3_conn_counts_toward_max_conns() {
    let mut scfg = h3_cfg(server_role());
    scfg.max_conns = 1;
    let server = Peer::spawn(scfg, vec![srv_addr()]);
    let mut now = T0;
    let client = |k: usize, now: Time| {
        let c = Peer::spawn(h3_cfg(Role::Client), vec![cli_addr(k)]);
        let mut cc = conn_cfg(None);
        cc.proto = ConnProto::H3;
        let id = c.call(now, move |t, now| t.connect(now, &cc)).unwrap();
        (c, id)
    };
    let run = |peers: &[&Peer], now: &mut Time, steps: usize| {
        for _ in 0..steps {
            *now = *now + MS;
            for p in peers {
                p.drive(*now);
            }
            exchange_many(*now, peers);
        }
    };
    let count = |s: &Peer| s.call(T0, |t, _| (t.conn_count(), t.n_provisional()));

    let (c1, id1) = client(0, now);
    run(&[&c1, &server], &mut now, 5);
    assert!(c1.drain_events().contains(&Event::ConnEstablished(id1)));
    let news = new_conns(&server.drain_events());
    assert!(matches!(news[..], [(_, ConnProto::H3)]), "{news:?}");
    assert_eq!(count(&server), (1, 0));

    // The second H3 client is refused at the shared cap, before any slot.
    let (c2, id2) = client(1, now);
    run(&[&c1, &c2, &server], &mut now, 50);
    assert!(!c2.drain_events().contains(&Event::ConnEstablished(id2)));
    assert!(new_conns(&server.drain_events()).is_empty());
    assert_eq!(count(&server), (1, 0));

    // Closing the first H3 connection releases its unit.
    c1.call(now, move |t, now| t.close_conn(now, id1));
    let mut sev = Vec::new();
    for _ in 0..1000 {
        run(&[&c1, &c2, &server], &mut now, 10);
        sev.extend(server.drain_events());
        if sev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(
        sev.iter().any(|e| matches!(e, Event::ConnClosed(..))),
        "{sev:?}"
    );
    assert_eq!(count(&server), (0, 0));
}

/// The canned ClientHello carries no ALPN: this only pins that an `h3: true` engine still
/// expires provisionals (the provisional path is ALPN-agnostic, `fabric_provisional.rs`).
#[test]
fn h3_conn_provisional_expiry() {
    let server = Peer::spawn(h3_cfg(server_role()), vec![srv_addr()]);
    let from: SocketAddr = "10.2.0.1:40000".parse().unwrap();
    let pkt = initial(
        &[0xd0, 0, 1, 1, 2, 3, 4, 5],
        &[0x5c, 0, 1, 5, 4, 3, 2, 1],
        0,
        0,
        &client_hello_fragment(0, 300),
    );
    server.deliver(T0, srv_addr(), from, pkt);
    server.drive(T0);
    server.pump_out(T0);
    let n_prov = |s: &Peer| s.call(Time::ZERO, |t, _| t.n_provisional());
    assert_eq!(n_prov(&server), 1);
    let mut now = T0;
    while n_prov(&server) > 0 {
        let d = server.next_timeout().expect("provisional deadline");
        now = now.max(d);
        server.drive(now);
        server.pump_out(now);
        assert!(now < T0 + Duration::from_secs(60), "never released");
    }
    assert!(
        now >= T0 + Duration::from_secs(10),
        "not before the 10 s deadline"
    );
    assert_eq!(server.call(now, |t, _| t.conn_count()), 0);
    assert_eq!(server.drain_events(), vec![], "never admitted: no events");
}

#[test]
fn h3_conn_close_reported() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let c = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, c));
    assert!(p.pump_until(10 * MS, 1000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    assert_eq!(p.server.call(p.now, |t, _| t.conn_count()), 0);
}
