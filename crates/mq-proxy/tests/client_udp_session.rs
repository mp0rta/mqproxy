//! spec §6.3 client UDP sessions: sid, 1024 cap, `PendingAuth`, optimistic
//! OPEN with the partial-write retry, outbound and inbound datagram paths;
//! spec §6.4 the session stream's RESP, its ends and the negative cache.

mod common;

use common::*;
use mq_proxy::udp::{NEG_CACHE, SESSION_RESP_WAIT};
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{IoRequest, IoResult, TcpId, UdpSocketId};
use mq_transport_api::{CloseReason, ConnectError, ErrType, Error, Event, StreamError, StreamId};
use mq_wire::frames::{FEAT_UDP_RELAY, UdpSessionResp};
use mq_wire::udp_msg::UdpMsgHdr;
use std::net::SocketAddr;
use std::time::Duration;

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
    assoc_on(h).1
}

/// As `assoc`, with its control socket; the ASSOCIATE reply is taken.
fn assoc_on(h: &mut H) -> (TcpId, UdpSocketId) {
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
    h.tx_all(tcp);
    (tcp, sock.expect("opened"))
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

fn resp(status: u8, error_code: u64, idle_timeout_ms: u64) -> Vec<u8> {
    let mut b = [0u8; 512];
    let r = UdpSessionResp {
        status,
        error_code,
        message: b"",
        idle_timeout_ms,
    };
    let n = r.encode(&mut b).unwrap();
    b[..n].to_vec()
}

/// Serving with UDP, one association, and session 1 (DST 10.0.0.9:53) on
/// stream `s`, awaiting its RESP.
fn opened(h: &mut H) -> (TcpId, UdpSocketId, StreamId) {
    serving_udp(h);
    let (tcp, sock) = assoc_on(h);
    let s = h.next_stream(h.conn);
    send(h, sock, &to_v4(53, b"x"));
    (tcp, sock, s)
}

/// One `StreamReadable` on `s` whose read returns `r`.
fn readable(h: &mut H, s: StreamId, r: Result<(Vec<u8>, bool), StreamError>) {
    h.t.expect_stream_recv(s, r);
    h.event(Event::StreamReadable(s));
}

fn resets(h: &H, s: StreamId) -> usize {
    h.count(|c| *c == Call::StreamReset(s))
}

/// Whether session `sid` is gone: a datagram naming it is an unknown sid.
fn ended(h: &mut H, sid: u32) -> bool {
    let before = h.sh.app().udp_counters().drops_unknown_sid;
    inbound(h, hdr(sid, 0x7777, 0, 1));
    h.sh.app().udp_counters().drops_unknown_sid > before
}

fn negcache(h: &H) -> usize {
    h.sh.app().udp_negcache_len()
}

fn conn_closed(h: &H) -> Event {
    Event::ConnClosed(
        h.conn,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

/// `OPEN_SID1_53` for `sid`.
fn open_for(sid: u8) -> Vec<u8> {
    let mut b = OPEN_SID1_53.to_vec();
    b[1] = sid;
    b
}

/// After a `ConnClosed`: the reconnect, to a new `h.conn`.
fn reconnect(h: &mut H) {
    let conn2 = h.t.new_conn_id();
    h.t.expect_connect(Ok(conn2));
    let wait = h.sh.next_timeout().expect("reconnect armed") - h.now;
    h.advance(wait);
    h.conn = conn2;
}

#[test]
fn resp_ok_opens() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (_, sock, s) = opened(&mut h);
    log_capture::take();
    readable(&mut h, s, Ok((resp(0, 0, 60_000), false)));
    let lines = log_capture::take();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("DEBUG") && l.contains("60000")),
        "the server's idle is logged at debug: {lines:?}"
    );
    h.advance(SESSION_RESP_WAIT);
    assert_eq!(resets(&h, s), 0, "no deadline once open");
    send(&mut h, sock, &to_v4(53, b"y"));
    assert_eq!(h.opens(), 2, "the same session carries on");
    assert_eq!(dgrams(&h)[1].0.session_id, 1);
    assert!(!ended(&mut h, 1));
}

#[test]
fn negative_cache_blocks_2s_then_opens() {
    let mut h = H::new(cfg());
    let (_, sock, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(1, 1, 0), false)));
    h.advance(NEG_CACHE - Duration::from_millis(1));
    send(&mut h, sock, &to_v4(53, b"y"));
    assert_eq!(h.opens(), 2, "cached: no OPEN");
    assert_eq!(dgrams(&h).len(), 1, "and nothing sent");
    h.advance(Duration::from_millis(2));
    let s2 = h.next_stream(h.conn);
    send(&mut h, sock, &to_v4(53, b"z"));
    assert_eq!(h.t.sent_bytes(s2), open_for(2), "a new session, a new sid");
    let d = dgrams(&h);
    assert_eq!((d[1].0.session_id, &d[1].1[..]), (2, &b"z"[..]));
}

#[test]
fn resp_ok_with_fin_same_read_closes() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(0, 0, 0), true)));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0);
    assert_eq!(resets(&h, s), 1);
}

#[test]
fn resp_error_sets_negcache_and_resets() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(1, 1, 0), false)));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 1);
    assert_eq!(resets(&h, s), 1);
}

#[test]
fn resp_error_with_fin_still_negcache() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(1, 4, 0), true)));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 1);
    assert_eq!(resets(&h, s), 1);
}

#[test]
fn malformed_resp_closed() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    // Status OK with error_code 5: rejected by the codec.
    readable(&mut h, s, Ok((vec![0x00, 0x05, 0x00, 0x00, 0x00], false)));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0);
    assert_eq!(resets(&h, s), 1);
}

#[test]
fn fin_before_resp_closed() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(1, 1, 0)[..2].to_vec(), false)));
    assert!(!ended(&mut h, 1), "a partial RESP waits");
    readable(&mut h, s, Ok((vec![], true)));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0, "never decoded: no negative cache");
    assert_eq!(resets(&h, s), 1);
}

#[test]
fn await_resp_deadline_10s() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    h.advance(SESSION_RESP_WAIT - Duration::from_millis(1));
    assert_eq!(resets(&h, s), 0);
    h.advance(Duration::from_millis(1));
    assert_eq!(resets(&h, s), 1);
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0);
}

#[test]
fn open_phase_reset_closes() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(0, 0, 0), false)));
    readable(&mut h, s, Err(StreamError::Reset));
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0);
    assert_eq!(resets(&h, s), 1, "reset once, by the read that saw it");
}

#[test]
fn drain_until_blocked_sees_fin_after_2k() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    h.t.expect_stream_recv(s, Ok((resp(0, 0, 0), false)));
    h.t.expect_stream_recv(s, Ok((vec![7; 1500], false)));
    h.t.expect_stream_recv(s, Ok((vec![], true)));
    h.event(Event::StreamReadable(s));
    assert_eq!(resets(&h, s), 1, "the FIN behind the bytes ended it");
    assert!(ended(&mut h, 1));
    assert_eq!(negcache(&h), 0);
}

#[test]
fn stream_closed_after_end_ignored() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    readable(&mut h, s, Ok((resp(1, 1, 0), false)));
    h.event(Event::StreamClosed(s));
    assert_eq!(resets(&h, s), 1, "no second reset");
    assert_eq!(negcache(&h), 1);
}

#[test]
fn stream_closed_ends_live_session() {
    let mut h = H::new(cfg());
    let (_, _, s) = opened(&mut h);
    h.event(Event::StreamClosed(s));
    assert!(ended(&mut h, 1));
    assert_eq!(resets(&h, s), 0, "the facade no longer holds it");
    assert_eq!(negcache(&h), 0);
}

#[test]
fn conn_closed_ends_all_assoc_survives() {
    let mut h = H::new(cfg());
    let (tcp, sock, s) = opened(&mut h);
    h.event(conn_closed(&h));
    assert_eq!(resets(&h, s), 0, "the connection took its streams");
    let reqs = h.reqs();
    assert!(!H::closed(&reqs, tcp), "the association survives");
    assert!(!reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    // `Unknown`: a new ASSOCIATE is accepted optimistically.
    let other = h.accept(h.socks, meta(None));
    h.rx(other, &[SOCKS_GREETING, ASSOCIATE].concat());
    let reqs = h.reqs();
    let opening = |r: &IoRequest| matches!(r, IoRequest::OpenUdpSocket { .. });
    assert!(reqs.iter().any(opening));
    // Reconnected and re-authed, on a connection with its own mss.
    reconnect(&mut h);
    h.t.set_datagram_mss(h.conn, 100);
    serving_udp(&mut h);
    assert!(ended(&mut h, 1), "session 1 went with the connection");
    let s2 = h.next_stream(h.conn);
    send(&mut h, sock, &to_v4(53, &[9; 150]));
    assert_eq!(
        h.t.sent_bytes(s2),
        open_for(2),
        "the first datagram re-opens"
    );
    let d = dgrams(&h);
    assert_eq!(d.len(), 2, "split under the new connection's mss");
    assert_eq!((d[0].0.session_id, d[0].0.frag_count), (2, 2));
}

#[test]
fn unavailable_sweep_drops_sessions() {
    let mut h = H::new(cfg());
    let sock = assoc(&mut h);
    send(&mut h, sock, &to_v4(53, b"held"));
    // Authenticated without the feature: the sweep.
    let ctrl = h.establish();
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(0, 0), false)));
    h.event(Event::StreamReadable(ctrl));
    assert!(ended(&mut h, 1));
    // Reconnected, now relaying: nothing of the swept session is left to flush.
    h.event(conn_closed(&h));
    reconnect(&mut h);
    serving_udp(&mut h);
    assert_eq!(h.opens(), 2, "the two control streams only");
    assert!(dgrams(&h).is_empty());
}

#[test]
fn shutdown_closes_assocs() {
    let mut h = H::new(cfg());
    let (tcp, sock, s) = opened(&mut h);
    h.sh.on_shutdown_signal(h.now);
    let reqs = h.reqs();
    assert!(H::closed(&reqs, tcp));
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    let log = h.log();
    let reset = log.iter().position(|c| *c == Call::StreamReset(s));
    let close = log.iter().position(|c| *c == Call::CloseConn(h.conn));
    assert!(
        reset.expect("reset") < close.expect("closed"),
        "reset, then close"
    );

    // Without a connection (the first connect failed; reconnecting).
    let mut h = H::start(cfg(), Some(ConnectError::Other(-1)));
    let (tcp, sock) = assoc_on(&mut h);
    h.sh.on_shutdown_signal(h.now);
    let reqs = h.reqs();
    assert!(H::closed(&reqs, tcp));
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    assert_eq!(h.sh.exit_status(), Some(0));
}

#[test]
fn local_close_resets_stream() {
    let mut h = H::new(cfg());
    let (tcp, sock, s) = opened(&mut h);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert_eq!(resets(&h, s), 1);
    let reqs = h.reqs();
    assert!(H::closed(&reqs, tcp));
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    assert!(ended(&mut h, 1));
}
