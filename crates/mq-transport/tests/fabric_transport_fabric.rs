//! Ports `test_transport_fabric` and `test_conn_handshake` (spec §8.3): a full handshake and
//! a stream echo with FIN both ways, entirely in memory; per-connection `MpReady` with two
//! connections on one client transport, one of which then closes.
//!
//! Not ported: the C mp-ready subscriber table (`mq_transport_add/remove_mp_ready_cb`) and its
//! capacity tests — the facade has no subscriber table; `MpReady` carries the connection id.
mod common;

use common::pair::{MS, Pair, conn_cfg, new_streams, recv, send};
use mq_transport_api::{ConnId, Event, StreamKind, TransportOps};

const PAYLOAD: &[u8] = b"the quick brown fox jumps over the lazy dog";

/// `test_conn_handshake`: handshake, `NewConn`, one client stream seen by the server, close,
/// teardown.
#[test]
fn conn_handshake() {
    let mut p = Pair::new(); // asserts ConnEstablished on both sides and NewConn
    assert_eq!(
        p.sev
            .iter()
            .filter(|e| matches!(e, Event::NewConn(..)))
            .count(),
        1
    );
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"hi\0".to_vec(), true), Ok(3));
    p.exchange();
    let news = new_streams(&p.sev);
    assert_eq!(news.len(), 1);
    assert_eq!(news[0].1.kind, StreamKind::Bidi);

    let c = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, c));
    assert!(p.pump_until(10 * MS, 1000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    assert_eq!(p.server.call(p.now, |t, _| t.conn_count()), 0);
    // Teardown: the peers drop their transports on their own threads.
}

/// `test_transport_fabric`: the server echoes the client's payload with FIN; byte integrity
/// and a clean FIN in both directions.
#[test]
fn stream_echo_round_trip() {
    let mut p = Pair::new();
    let cs = p.open();
    assert_eq!(
        send(&p.client, p.now, cs, PAYLOAD.to_vec(), true),
        Ok(PAYLOAD.len())
    );
    p.exchange();
    let ss = new_streams(&p.sev)[0].0;
    assert!(p.sev.contains(&Event::StreamReadable(ss)));
    assert_eq!(
        recv(&p.server, p.now, ss, 1500),
        Ok((PAYLOAD.to_vec(), true))
    );
    assert_eq!(
        send(&p.server, p.now, ss, PAYLOAD.to_vec(), true),
        Ok(PAYLOAD.len())
    );
    p.exchange();
    assert!(p.cev.contains(&Event::StreamReadable(cs)));
    assert_eq!(
        recv(&p.client, p.now, cs, 1500),
        Ok((PAYLOAD.to_vec(), true))
    );
}

fn mp_ready(ev: &[Event], c: ConnId) -> bool {
    ev.contains(&Event::MpReady(c))
}

/// `test_mp_ready_broadcast`: each connection gets its own `MpReady`; closing one leaves the
/// other working.
#[test]
fn mp_ready_per_connection_and_close_one_keep_one() {
    let mut p = Pair::new();
    let c1 = p.conn;
    assert!(p.pump_until(MS, 2000, |p| mp_ready(&p.cev, c1)));

    let cc = conn_cfg(None);
    let c2 = p
        .client
        .call(p.now, move |t, now| t.connect(now, &cc))
        .unwrap();
    assert_ne!(c1, c2);
    let seen = p.cev.len();
    assert!(p.pump_until(MS, 2000, |p| mp_ready(&p.cev[seen..], c2)));
    assert!(p.cev.contains(&Event::ConnEstablished(c2)));
    // Every MpReady names one of the two connections.
    assert!(p.cev.iter().all(|e| match e {
        Event::MpReady(c) => *c == c1 || *c == c2,
        _ => true,
    }));

    // Close the first; the second keeps working.
    p.client.call(p.now, move |t, now| t.close_conn(now, c1));
    assert!(p.pump_until(10 * MS, 1000, |p| p.client_closed().is_some()));
    assert!(p.client.call(p.now, move |t, _| t.conn_stats(c2)).is_ok());
    let s = p
        .client
        .call(p.now, move |t, now| t.open_stream(now, c2))
        .unwrap();
    assert_eq!(
        send(&p.client, p.now, s, PAYLOAD.to_vec(), true),
        Ok(PAYLOAD.len())
    );
    let before = new_streams(&p.sev).len();
    p.exchange();
    let ss = new_streams(&p.sev)[before].0;
    assert_eq!(
        recv(&p.server, p.now, ss, 1500),
        Ok((PAYLOAD.to_vec(), true))
    );
    assert!(p.client.call(p.now, move |t, _| t.conn_stats(c1)).is_err());
}
