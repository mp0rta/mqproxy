//! H3 connection setup over the `Rig` (adoption spec §4.2, §4.4, §4.5).

mod common;

use common::Rig;
use h3wire::StreamId as Q;
use mq_h3::H3Wire;
use mq_runtime::testing::{Call, ScriptedTransport};
use mq_transport_api::{ConnId, ConnProto, Error, Event, Time, TransportOps};

fn close_codes(r: &Rig) -> Vec<u64> {
    r.h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::CloseConnWith { conn, code } if conn == r.conn => Some(code),
            _ => None,
        })
        .collect()
}

/// `peer_uni`: the quic ids of the peer's control, encoder and decoder streams.
fn setup_exchange(mut r: Rig, peer_uni: [u64; 3]) {
    r.pump();
    let opens =
        r.h.log()
            .iter()
            .filter(|c| **c == Call::OpenUni(r.conn))
            .count();
    assert_eq!(opens, 3);
    assert!(r.peer_events.contains(&h3wire::Event::PeerSettings));
    let ps = r.peer.peer_settings().expect("peer saw our SETTINGS");
    assert_eq!(ps.max_field_section_size, Some(65536));
    assert_eq!(ps.qpack_max_table_capacity, 0);
    for q in peer_uni {
        let s = r.peer_stream(Q(q));
        assert!(r.h.log().contains(&Call::StreamRecv { s, cap: 4096 }));
        assert_eq!(r.h.recv_pending(s), 0, "peer stream {q} read to the end");
    }
    assert!(close_codes(&r).is_empty());
}

#[test]
fn server_setup_exchange() {
    setup_exchange(Rig::server(), [2, 6, 10]);
}

#[test]
fn client_setup_exchange() {
    setup_exchange(Rig::client(), [3, 7, 11]);
}

#[test]
fn peer_critical_stream_reset_closes() {
    let mut r = Rig::server();
    r.pump();
    let ctrl = r.peer_stream(Q(2));
    r.h.push_event(Event::StreamPeerReset(ctrl, 0x10c));
    r.w.drive(r.now);
    assert_eq!(close_codes(&r), [0x104]);
}

#[test]
fn unexpected_frame_on_control_closes() {
    let mut r = Rig::server();
    r.pump();
    // DATA (type 0x00), length 1, one payload byte.
    r.deliver(Q(2), &[0x00, 0x01, 0xaa], false);
    r.pump();
    assert_eq!(close_codes(&r), [0x105]);
}

#[test]
fn open_uni_failure_closes() {
    let (t, h) = ScriptedTransport::new();
    let mut w = H3Wire::new(t);
    let c: ConnId = h.new_conn_id();
    h.expect_open_uni(Err(Error::Other));
    h.push_event(Event::NewConn(c, ConnProto::H3));
    w.drive(Time::ZERO);
    let calls: Vec<_> = h
        .log()
        .into_iter()
        .filter(|c| !matches!(c, Call::Drive(_)))
        .collect();
    assert_eq!(
        calls,
        [
            Call::OpenUni(c),
            Call::CloseConnWith {
                conn: c,
                code: 0x101
            }
        ]
    );
}

#[test]
fn core_bytes_resume_on_writable() {
    let mut r = Rig::server();
    let ctrl = r.peer_stream(Q(3)); // w's control stream
    r.limit(ctrl, Some(3));
    r.w.drive(r.now);
    assert_eq!(r.h.sent_bytes(ctrl).len(), 3);
    r.h.push_event(Event::StreamWritable(ctrl));
    r.w.drive(r.now);
    assert!(r.h.sent_bytes(ctrl).len() > 3);
    let sends =
        r.h.log()
            .into_iter()
            .filter(|c| matches!(c, Call::StreamSend { s, .. } if *s == ctrl));
    assert_eq!(sends.count(), 2, "one short write, then the rest");
    r.pump();
    assert!(r.peer_events.contains(&h3wire::Event::PeerSettings));
    assert!(close_codes(&r).is_empty());
}

/// The raw stream events of an H3 conn stay inside `H3Wire` (adoption spec §4.1).
#[test]
fn raw_stream_events_of_h3_conns_are_consumed() {
    let mut r = Rig::server();
    r.pump();
    assert_eq!(r.events(), [Event::NewConn(r.conn, ConnProto::H3)]);
}

/// A blocked core-bytes write is retried by any call that takes `now`, without a
/// `StreamWritable` (adoption spec §4.5).
#[test]
fn core_bytes_retried_on_bare_drive() {
    let mut r = Rig::server();
    let ctrl = r.peer_stream(Q(3)); // w's control stream
    r.limit(ctrl, Some(0));
    r.w.drive(r.now);
    assert!(r.h.sent_bytes(ctrl).is_empty());
    r.w.drive(r.now);
    assert!(!r.h.sent_bytes(ctrl).is_empty());
    r.pump();
    assert!(r.peer_events.contains(&h3wire::Event::PeerSettings));
    assert!(close_codes(&r).is_empty());
}
