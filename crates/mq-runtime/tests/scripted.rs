//! spec §5.1, §8.1: `ScriptedTransport` scripts every `TransportOps` result.

use mq_runtime::testing::{Call, ScriptedTransport};
use mq_transport_api::{ConnConfig, DatagramError, Event, PathId, StreamError, Time, TransportOps};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

fn cfg() -> ConnConfig {
    ConnConfig {
        peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
        sni: "mqproxy",
        idle_timeout: None,
    }
}

const T: Time = Time(1000);

#[test]
fn defaults_accept_send_and_block_recv() {
    let (mut t, h) = ScriptedTransport::new();
    let c = t.connect(T, &cfg()).unwrap();
    let s = t.open_stream(T, c).unwrap();
    assert_eq!(t.stream_send(T, s, b"hello", false), Ok(5));
    assert_eq!(h.sent_bytes(s), b"hello");
    let mut buf = [0u8; 16];
    assert_eq!(t.stream_recv(T, s, &mut buf), Err(StreamError::Blocked));
    assert_eq!(t.add_path(T, c, false), Ok(PathId(1)));
    assert_eq!(t.add_path(T, c, true), Ok(PathId(2)));
    assert_eq!(t.next_timeout(), None);
    assert!(!t.resume_pending());
    t.close_conn(T, c);
    assert!(matches!(t.poll_event(), Some(Event::ConnClosed(id, _)) if id == c));
    assert_eq!(t.poll_event(), None);
}

#[test]
fn scripted_recv_sequence_with_fin_and_split() {
    let (mut t, h) = ScriptedTransport::new();
    let s = h.new_stream_id();
    h.expect_stream_recv(s, Ok((b"abcdef".to_vec(), false)));
    h.expect_stream_recv(s, Err(StreamError::Blocked));
    h.expect_stream_recv(s, Ok((b"xy".to_vec(), true)));
    let mut buf = [0u8; 4];
    assert_eq!(t.stream_recv(T, s, &mut buf), Ok((4, false)));
    assert_eq!(&buf, b"abcd");
    assert_eq!(t.stream_recv(T, s, &mut buf), Ok((2, false)));
    assert_eq!(&buf[..2], b"ef");
    assert_eq!(t.stream_recv(T, s, &mut buf), Err(StreamError::Blocked));
    assert_eq!(t.stream_recv(T, s, &mut buf), Ok((2, true)));
    assert_eq!(&buf[..2], b"xy");
    // queue drained: back to the default
    assert_eq!(t.stream_recv(T, s, &mut buf), Err(StreamError::Blocked));
}

#[test]
fn scripted_blocked_then_writable_event() {
    let (mut t, h) = ScriptedTransport::new();
    let s = h.new_stream_id();
    h.expect_stream_send(s, Err(StreamError::Blocked));
    assert_eq!(
        t.stream_send(T, s, b"data", false),
        Err(StreamError::Blocked)
    );
    assert!(h.sent_bytes(s).is_empty());
    h.push_event(Event::StreamWritable(s));
    assert_eq!(t.poll_event(), Some(Event::StreamWritable(s)));
    assert_eq!(t.stream_send(T, s, b"data", true), Ok(4));
    assert_eq!(h.sent_bytes(s), b"data");
}

#[test]
fn injection_from_another_thread_delivered() {
    // the driver harness runs the transport on its own thread (spec §8.1)
    fn is_send<T: Send>() {}
    is_send::<ScriptedTransport>();
    is_send::<mq_runtime::testing::ScriptedHandle>();
    let (mut t, h) = ScriptedTransport::new();
    let s = h.new_stream_id();
    let h2 = h.clone();
    std::thread::spawn(move || h2.push_event(Event::StreamReadable(s)))
        .join()
        .unwrap();
    assert_eq!(t.poll_event(), Some(Event::StreamReadable(s)));
    assert_eq!(t.poll_event(), None);
}

#[test]
fn polling_mode_reports_1ms_deadline() {
    let (mut t, h) = ScriptedTransport::new();
    t.drive(T);
    h.set_polling(true);
    assert_eq!(t.next_timeout(), Some(T + Duration::from_millis(1)));
    h.set_polling(false);
    assert_eq!(t.next_timeout(), None);
    h.set_next_timeout(Some(Time(5)));
    assert_eq!(t.next_timeout(), Some(Time(5)));
}

#[test]
fn reactive_rule_runs_on_call() {
    let (mut t, h) = ScriptedTransport::new();
    h.on_stream_send(|h, s, data, _fin| {
        // pushing from inside the rule must not deadlock
        h.push_event(Event::StreamReadable(s));
        Ok(data.len())
    });
    let s = h.new_stream_id();
    assert_eq!(t.stream_send(T, s, b"AUTH", false), Ok(4));
    assert_eq!(t.poll_event(), Some(Event::StreamReadable(s)));
    assert_eq!(h.sent_bytes(s), b"AUTH");
    // the rule stays installed
    assert_eq!(t.stream_send(T, s, b"x", true), Ok(1));
    assert_eq!(t.poll_event(), Some(Event::StreamReadable(s)));
}

#[test]
fn log_records_order_and_bytes() {
    let (mut t, h) = ScriptedTransport::new();
    let c = t.connect(T, &cfg()).unwrap();
    let s = t.open_stream(T, c).unwrap();
    h.expect_stream_send(s, Ok(2));
    assert_eq!(t.stream_send(T, s, b"abcd", true), Ok(2));
    t.stream_reset(T, s);
    t.drive(Time(7));
    t.close_conn(T, c);
    assert_eq!(
        h.log(),
        vec![
            Call::Connect,
            Call::OpenStream(c),
            Call::StreamSend {
                s,
                bytes: b"abcd".to_vec(),
                fin: true
            },
            Call::StreamReset(s),
            Call::Drive(Time(7)),
            Call::CloseConn(c),
        ]
    );
    // only the accepted prefix counts as sent
    assert_eq!(h.sent_bytes(s), b"ab");
}

#[test]
fn peek_and_done_consume_scripted_transmits() {
    let (mut t, h) = ScriptedTransport::new();
    let key = (None, PathId(0));
    let dst = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    h.set_transmit(
        key,
        dst,
        vec![vec![1; 3], vec![2; 3], vec![3; 2], vec![4; 3]],
    );
    let mut keys = Vec::new();
    t.pending_transmit(&mut keys);
    assert_eq!(keys, vec![key]);
    let tx = t.peek_transmit(key).unwrap();
    assert_eq!((tx.dst, tx.segment_size), (dst, 3));
    // equal-length run; a shorter datagram closes it
    assert_eq!(tx.payload, &[1, 1, 1, 2, 2, 2, 3, 3]);
    t.transmit_done(key, 3);
    assert_eq!(t.peek_transmit(key).unwrap().payload, &[4, 4, 4]);
    t.transmit_done(key, 1);
    assert!(t.peek_transmit(key).is_none());
    keys.clear();
    t.pending_transmit(&mut keys);
    assert!(keys.is_empty());
}

#[test]
fn scripted_datagram_roundtrip() {
    let (mut t, h) = ScriptedTransport::new();
    let c = h.new_conn_id();
    for d in [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()] {
        h.inject_datagram(c, d);
    }
    // level flag: three injects, one event
    assert_eq!(t.poll_event(), Some(Event::DatagramReadable(c)));
    assert_eq!(t.poll_event(), None);
    let mut buf = [0u8; 64];
    assert_eq!(t.datagram_recv(c, &mut buf), Some(3));
    assert_eq!(&buf[..3], b"one");
    assert_eq!(t.datagram_recv(c, &mut buf), Some(3));
    assert_eq!(&buf[..3], b"two");
    assert_eq!(t.datagram_recv(c, &mut buf), Some(5));
    assert_eq!(&buf[..5], b"three");
    assert_eq!(t.datagram_recv(c, &mut buf), None);
    // the flag cleared at the pop: a later inject queues a new event
    h.inject_datagram(c, b"four".to_vec());
    assert_eq!(t.poll_event(), Some(Event::DatagramReadable(c)));
    assert_eq!(t.datagram_recv(c, &mut buf), Some(4));
    assert_eq!(&buf[..4], b"four");
}

#[test]
fn scripted_datagram_short_buf_drops_and_returns_zero() {
    let (mut t, h) = ScriptedTransport::new();
    let c = h.new_conn_id();
    h.inject_datagram(c, vec![7; 10]);
    h.inject_datagram(c, vec![8; 2]);
    let mut buf = [0u8; 4];
    // the real facade's contract (spec §3.1): too small to hold it -> drop, count, Some(0)
    assert_eq!(t.datagram_recv(c, &mut buf), Some(0));
    assert_eq!(h.datagram_rx_dropped(c), 1);
    assert_eq!(t.datagram_recv(c, &mut buf), Some(2));
    assert_eq!(&buf[..2], &[8, 8]);
}

#[test]
fn scripted_datagram_send_scripted_error() {
    let (mut t, h) = ScriptedTransport::new();
    let c = h.new_conn_id();
    h.expect_datagram_send(c, Err(DatagramError::Blocked));
    assert_eq!(t.datagram_send(T, c, b"lost"), Err(DatagramError::Blocked));
    assert!(h.datagram_sends(c).is_empty());
    // queue drained: back to accepting
    assert_eq!(t.datagram_send(T, c, b"kept"), Ok(()));
    assert_eq!(h.datagram_sends(c), vec![b"kept".to_vec()]);
    // the call log holds everything offered, like `StreamSend`
    assert_eq!(
        h.log(),
        vec![
            Call::DatagramSend {
                conn: c,
                bytes: b"lost".to_vec()
            },
            Call::DatagramSend {
                conn: c,
                bytes: b"kept".to_vec()
            },
        ]
    );
}

#[test]
fn scripted_datagram_ring_cap_drops_and_counts() {
    let (mut t, h) = ScriptedTransport::new();
    let c = h.new_conn_id();
    h.set_datagram_ring_cap(c, 100);
    h.inject_datagram(c, vec![1; 64]);
    h.inject_datagram(c, vec![2; 64]);
    assert_eq!(h.datagram_rx_dropped(c), 1);
    let mut buf = [0u8; 128];
    assert_eq!(t.datagram_recv(c, &mut buf), Some(64));
    assert_eq!(buf[0], 1);
    assert_eq!(t.datagram_recv(c, &mut buf), None);
    // draining frees the room
    h.inject_datagram(c, vec![3; 64]);
    assert_eq!(h.datagram_rx_dropped(c), 1);
    assert_eq!(t.datagram_recv(c, &mut buf), Some(64));
}

#[test]
fn scripted_datagram_mss_calls_counted() {
    let (t, h) = ScriptedTransport::new();
    let (c, other) = (h.new_conn_id(), h.new_conn_id());
    assert_eq!(t.datagram_mss(c), 1200);
    h.set_datagram_mss(c, 900);
    assert_eq!(t.datagram_mss(c), 900);
    assert_eq!(t.datagram_mss(other), 1200);
    assert_eq!(h.datagram_mss_calls(c), 2);
    assert_eq!(h.datagram_mss_calls(other), 1);
}
