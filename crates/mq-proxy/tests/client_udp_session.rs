//! spec §6.3 client UDP sessions: sid, 1024 cap, `PendingAuth`, optimistic
//! OPEN with the partial-write retry, outbound and inbound datagram paths.

mod common;

use common::*;
use mq_runtime::testing::Call;
use mq_runtime::{IoRequest, UdpSocketId};
use mq_transport_api::{Error, Event, StreamError, StreamId};
use mq_wire::frames::FEAT_UDP_RELAY;
use mq_wire::udp_msg::UdpMsgHdr;
use std::net::SocketAddr;

/// SOCKS5 UDP ASSOCIATE, DST 0.0.0.0:0.
const ASSOCIATE: &[u8] = &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
/// Type `0x02` then `UDP_SESSION_OPEN` { sid 1, flags 0, IPv4 10.0.0.9, port 53, idle 0 }.
const OPEN_SID1_53: &[u8] = &[
    0x02, // MQ_STREAM_TYPE_UDP_SESSION
    0x01, // session_id
    0x00, // flags
    0x01, // address_type = IPv4
    0x04, 10, 0, 0, 9, // host
    0x00, 0x35, // port 53
    0x00, // idle_timeout_ms = 0 (server default)
    0x00, // padding_length
];

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The association's client: on the control connection's peer IP (`meta(None)`).
fn src() -> SocketAddr {
    sa("127.0.0.1:6000")
}

/// An association on a new control connection whose UDP socket opened.
fn assoc(h: &mut H) -> UdpSocketId {
    let tcp = h.accept(h.socks, meta(None));
    h.rx(tcp, &[SOCKS_GREETING, ASSOCIATE].concat());
    let op = h.reqs().into_iter().find_map(|r| match r {
        IoRequest::OpenUdpSocket { op, .. } => Some(op),
        _ => None,
    });
    let sock = h.sh.on_udp_socket(
        h.now,
        op.expect("socket requested"),
        Ok(sa("127.0.0.1:40000")),
    );
    sock.expect("opened")
}

/// Authenticated, the server relays UDP: `Available`.
fn serving_udp(h: &mut H) -> StreamId {
    let ctrl = h.establish();
    let resp = auth_resp_features(0, 0, FEAT_UDP_RELAY);
    h.t.expect_stream_recv(ctrl, Ok((resp, false)));
    h.event(Event::StreamReadable(ctrl));
    ctrl
}

/// A SOCKS5 UDP request to 10.0.0.9:`port`.
fn to_v4(port: u16, payload: &[u8]) -> Vec<u8> {
    [
        &[0, 0, 0, 0x01, 10, 0, 0, 9][..],
        &port.to_be_bytes(),
        payload,
    ]
    .concat()
}

/// A datagram from the association's client.
fn send(h: &mut H, sock: UdpSocketId, d: &[u8]) {
    h.sh.on_udp_rx(h.now, sock, src(), d);
}

fn hdr(sid: u32, packet_id: u16, frag_id: u8, frag_count: u8) -> Vec<u8> {
    let mut b = [0u8; 9];
    UdpMsgHdr {
        session_id: sid,
        packet_id,
        flags: 0,
        frag_id,
        frag_count,
    }
    .encode(&mut b);
    b.to_vec()
}

/// The tunnel datagrams accepted so far, split into header and payload.
fn dgrams(h: &H) -> Vec<(UdpMsgHdr, Vec<u8>)> {
    let sent = h.t.datagram_sends(h.conn);
    sent.iter()
        .map(|d| (UdpMsgHdr::decode(d).unwrap(), d[9..].to_vec()))
        .collect()
}

/// A datagram from the server, delivered as the driver would.
fn inbound(h: &mut H, d: Vec<u8>) {
    h.t.inject_datagram(h.conn, d);
    h.drive();
}

/// What the app socket sent (drains its ring).
fn udp_out(h: &mut H, sock: UdpSocketId) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(t) = h.sh.peek_transmit(sock) {
        out.push((t.dst, t.payload.to_vec()));
        h.sh.transmit_done(sock, 1);
    }
    out
}

/// The stream opens, stream sends and datagram sends logged from `from` on.
fn session_calls(h: &H, from: usize) -> Vec<Call> {
    let log = h.log();
    log[from..]
        .iter()
        .filter(|c| {
            matches!(
                c,
                Call::OpenStream(_) | Call::StreamSend { .. } | Call::DatagramSend { .. }
            )
        })
        .cloned()
        .collect()
}

#[test]
fn first_datagram_opens_and_sends_optimistically() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    let s = h.next_stream(h.conn);
    let from = h.log().len();
    send(&mut h, sock, &to_v4(53, b"ping"));
    assert_eq!(
        session_calls(&h, from),
        [
            Call::OpenStream(h.conn),
            Call::StreamSend {
                s,
                bytes: OPEN_SID1_53.to_vec(),
                fin: false,
            },
            Call::DatagramSend {
                conn: h.conn,
                bytes: [hdr(1, 0, 0, 1), b"ping".to_vec()].concat(),
            },
        ]
    );
}

#[test]
fn second_dst_gets_new_sid() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"a"));
    send(&mut h, sock, &to_v4(54, b"b"));
    send(&mut h, sock, &to_v4(53, b"c"));
    let d = dgrams(&h);
    assert_eq!(d.len(), 3);
    assert_ne!(d[0].0.session_id, d[1].0.session_id, "a new DST, a new sid");
    assert_eq!(
        d[2].0.session_id, d[0].0.session_id,
        "same DST, same session"
    );
    assert_eq!(d[2].0.packet_id, 1);
    assert_eq!(h.opens(), 3, "control + two sessions");
}

#[test]
fn cap_1024_drops_new_dst() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    // 16 associations × 64 DSTs.
    for _ in 0..16 {
        let sock = assoc(&mut h);
        for port in 0..64 {
            send(&mut h, sock, &to_v4(port, b"x"));
        }
    }
    assert_eq!(h.opens(), 1 + 1024);
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"x"));
    assert_eq!(h.opens(), 1 + 1024, "no OPEN for the 1025th session");
    assert_eq!(dgrams(&h).len(), 1024);
}

#[test]
fn pending_counts_in_1024_cap() {
    let mut h = H::new(cfg());
    for _ in 0..16 {
        let sock = assoc(&mut h);
        for port in 0..64 {
            send(&mut h, sock, &to_v4(port, b"x"));
        }
    }
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"x"));
    assert_eq!(h.opens(), 0, "nothing opens before auth");
    serving_udp(&mut h);
    assert_eq!(h.opens(), 1 + 1024, "the 1025th was never admitted");
    assert_eq!(dgrams(&h).len(), 1024);
}

#[test]
fn pending_auth_queue_8_or_8k() {
    let mut h = H::new(cfg());
    let sock = assoc(&mut h);
    let evictions = |h: &H| h.sh.app().udp_counters().sendq_evictions;
    for i in 0..9u8 {
        send(&mut h, sock, &to_v4(53, &[i]));
    }
    assert_eq!(evictions(&h), 1, "the 9th evicts the oldest");
    send(&mut h, sock, &to_v4(53, &[0xEE; 9 * 1024]));
    assert_eq!(evictions(&h), 2, "an item over 8 KiB alone is dropped");
    // The byte bound: a second 5 KiB item evicts the first.
    send(&mut h, sock, &to_v4(54, &[1; 5 * 1024]));
    send(&mut h, sock, &to_v4(54, &[2; 5 * 1024]));
    assert_eq!(evictions(&h), 3);
    assert!(dgrams(&h).is_empty());

    h.t.set_datagram_mss(h.conn, 9000); // every item in one datagram
    serving_udp(&mut h);
    let d = dgrams(&h);
    let payloads: Vec<Vec<u8>> = d.iter().map(|(_, p)| p.clone()).collect();
    let mut want: Vec<Vec<u8>> = (1..9u8).map(|i| vec![i]).collect();
    want.push(vec![2; 5 * 1024]);
    assert_eq!(payloads, want);
}

#[test]
fn pending_auth_flush_order_after_auth() {
    let mut h = H::new(cfg());
    let sock = assoc(&mut h);
    for p in [b"a", b"b", b"c"] {
        send(&mut h, sock, &to_v4(53, p));
    }
    assert_eq!(h.opens(), 0);
    assert!(dgrams(&h).is_empty(), "held until auth");
    let ctrl = h.establish();
    let s = h.next_stream(h.conn);
    let from = h.log().len();
    let resp = auth_resp_features(0, 0, FEAT_UDP_RELAY);
    h.t.expect_stream_recv(ctrl, Ok((resp, false)));
    h.event(Event::StreamReadable(ctrl));
    let dg = |pid, p: &[u8]| Call::DatagramSend {
        conn: h.conn,
        bytes: [hdr(1, pid, 0, 1), p.to_vec()].concat(),
    };
    assert_eq!(
        session_calls(&h, from),
        [
            Call::OpenStream(h.conn),
            Call::StreamSend {
                s,
                bytes: OPEN_SID1_53.to_vec(),
                fin: false,
            },
            dg(0, b"a"),
            dg(1, b"b"),
            dg(2, b"c"),
        ]
    );
}

#[test]
fn inbound_unknown_sid_dropped() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"x"));
    inbound(&mut h, [hdr(99, 0, 0, 1), b"y".to_vec()].concat());
    assert_eq!(h.sh.app().udp_counters().drops_unknown_sid, 1);
    assert!(udp_out(&mut h, sock).is_empty());
}

#[test]
fn inbound_reassembled_to_learned_with_dst_echoed() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    let dst = [
        &[0, 0, 0, 0x03, 11][..],
        b"example.com",
        &443u16.to_be_bytes(),
    ]
    .concat();
    send(&mut h, sock, &[&dst[..], b"q"].concat());
    let sid = dgrams(&h)[0].0.session_id;
    for (i, part) in [&b"aaa"[..], b"bbb", b"cc"].into_iter().enumerate() {
        h.t.inject_datagram(h.conn, [hdr(sid, 7, i as u8, 3), part.to_vec()].concat());
    }
    h.drive();
    assert_eq!(
        udp_out(&mut h, sock),
        [(src(), [&dst[..], b"aaabbbcc"].concat())],
        "one datagram to the learned source, the domain DST echoed as sent"
    );
    assert_eq!(h.sh.app().udp_counters().frags_reassembled, 1);
}

#[test]
fn inbound_empty_payload_relayed() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"x"));
    inbound(&mut h, hdr(1, 0, 0, 1));
    assert_eq!(udp_out(&mut h, sock), [(src(), to_v4(53, b""))]);
}

#[test]
fn inbound_oversize_dropped() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"x"));
    let room = 65_535 - to_v4(53, b"").len(); // payload bytes that fit one reply
    inbound(&mut h, [hdr(1, 0, 0, 1), vec![7; room + 1]].concat());
    assert_eq!(h.sh.app().udp_counters().drops_oversize, 1);
    assert!(udp_out(&mut h, sock).is_empty());
    inbound(&mut h, [hdr(1, 1, 0, 1), vec![7; room]].concat());
    let out = udp_out(&mut h, sock);
    assert_eq!(out.len(), 1, "the next packet passes");
    assert_eq!(out[0].1.len(), 65_535);
}

#[test]
fn open_blocked_retried_on_writable() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    let s = h.next_stream(h.conn);
    h.t.expect_stream_send(s, Err(StreamError::Blocked));
    send(&mut h, sock, &to_v4(53, b"x"));
    assert!(h.t.sent_bytes(s).is_empty());
    assert_eq!(
        dgrams(&h).len(),
        1,
        "the datagram does not wait for the OPEN"
    );
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), OPEN_SID1_53);
    assert!(!h.reset(s));
}

#[test]
fn open_stream_failure_ends_closed_no_negcache() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    h.t.expect_open_stream(Err(Error::Ceiling));
    let from = h.log().len();
    send(&mut h, sock, &to_v4(53, b"x"));
    assert_eq!(session_calls(&h, from), [Call::OpenStream(h.conn)]);
    assert_eq!(h.sh.app().udp_negcache_len(), 0);
    // Gone and not cached: the next datagram opens again.
    let s = h.next_stream(h.conn);
    send(&mut h, sock, &to_v4(53, b"y"));
    assert_eq!(h.t.sent_bytes(s)[0], 0x02);
    assert_eq!(dgrams(&h)[0].1, b"y");
}

#[test]
fn open_retry_terminal_error_ends_closed() {
    let mut h = H::new(cfg());
    serving_udp(&mut h);
    let sock = assoc(&mut h);
    let s = h.next_stream(h.conn);
    h.t.expect_stream_send(s, Ok(3));
    h.t.expect_stream_send(s, Err(StreamError::Conn));
    send(&mut h, sock, &to_v4(53, b"x"));
    assert_eq!(h.t.sent_bytes(s), OPEN_SID1_53[..3]);
    h.event(Event::StreamWritable(s));
    assert!(h.reset(s));
    assert_eq!(h.sh.app().udp_negcache_len(), 0);
    // Gone: its sid is unknown, and the DST opens anew.
    inbound(&mut h, [hdr(1, 0, 0, 1), b"late".to_vec()].concat());
    assert_eq!(h.sh.app().udp_counters().drops_unknown_sid, 1);
    let s2 = h.next_stream(h.conn);
    send(&mut h, sock, &to_v4(53, b"y"));
    assert_eq!(h.t.sent_bytes(s2)[0], 0x02);
}

#[test]
fn open_send_reset_mid_flush_continues() {
    let mut h = H::new(cfg());
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"a"));
    send(&mut h, sock, &to_v4(54, b"b"));
    let ctrl = h.establish();
    let (s1, s2) = (h.next_stream(h.conn), h.next_stream(h.conn));
    h.t.expect_stream_send(s1, Err(StreamError::Reset));
    let resp = auth_resp_features(0, 0, FEAT_UDP_RELAY);
    h.t.expect_stream_recv(ctrl, Ok((resp, false)));
    h.event(Event::StreamReadable(ctrl));
    assert!(h.reset(s1), "the failed session's stream is reset");
    assert!(!h.reset(s2));
    let mut open2 = OPEN_SID1_53.to_vec();
    (open2[1], open2[10]) = (2, 54);
    assert_eq!(h.t.sent_bytes(s2), open2, "the flush went on to the second");
    let d = dgrams(&h);
    assert_eq!(d.len(), 1, "only the second session's datagram");
    assert_eq!((d[0].0.session_id, &d[0].1[..]), (2, &b"b"[..]));
}
