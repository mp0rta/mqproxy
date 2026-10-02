//! spec §7.2: the server's datagram paths — the auth gate, the pre-OPEN
//! buffer and its flush, client → target with reassembly, target → client
//! with the peer check and the fragment send policy, the idle timer, and
//! §7.2/§7.3 the reaps, `ConnClosed`, shutdown and the stats line.

mod server_harness;

use mq_proxy::config::ServerConfig;
use mq_proxy::udp::{Counters, PREOPEN_BYTES};
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{DialError, IoRequest, UdpSocketId};
use mq_transport_api::{ConnId, DatagramError, Event, StreamError, StreamId};
use mq_wire::frames::AddrType;
use mq_wire::udp_msg::UdpMsgHdr;
use server_harness::*;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
/// The IPv4 target of `open_ip`.
fn target() -> SocketAddr {
    sa("10.0.0.1:5353")
}
fn open_ip(sid: u32, idle_ms: u64) -> Vec<u8> {
    udp_open(sid, AddrType::Ipv4, &[10, 0, 0, 1], 5353, idle_ms)
}
fn open_domain(sid: u32) -> Vec<u8> {
    udp_open(sid, AddrType::Domain, b"example.com", 53, 0)
}
fn no_udp() -> ServerConfig {
    ServerConfig {
        udp_enabled: false,
        ..cfg()
    }
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A tunnel datagram: the 9-byte header, then `payload`.
fn dgram(sid: u32, packet_id: u16, frag_id: u8, frag_count: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 9];
    UdpMsgHdr {
        session_id: sid,
        packet_id,
        flags: 0,
        frag_id,
        frag_count,
    }
    .encode(&mut b);
    [&b[..], payload].concat()
}

/// A session taken to `Live` by `open`; its stream and socket.
fn live_with(h: &mut H, c: ConnId, open: &[u8]) -> (StreamId, UdpSocketId) {
    let s = h.data(c);
    h.feed(s, open, false);
    let (op, _) = h.socket_open().unwrap();
    (s, h.socket_ok(op))
}
fn live(h: &mut H, c: ConnId, sid: u32, idle_ms: u64) -> (StreamId, UdpSocketId) {
    live_with(h, c, &open_ip(sid, idle_ms))
}

/// A datagram from the client on `c`, signalled as the transport would.
fn inbound(h: &mut H, c: ConnId, d: Vec<u8>) {
    h.t.inject_datagram(c, d);
    h.drive();
}

/// A datagram on the session socket `sock` from `peer`.
fn reply(h: &mut H, sock: UdpSocketId, peer: SocketAddr, data: &[u8]) {
    h.sh.on_udp_rx(h.now, sock, peer, data);
    h.drive();
}

/// What `sock` sent toward its target (drains its ring).
fn udp_out(h: &mut H, sock: UdpSocketId) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(t) = h.sh.peek_transmit(sock) {
        out.push((t.dst, t.payload.to_vec()));
        h.sh.transmit_done(sock, 1);
    }
    out
}

/// The tunnel datagrams sent on `c`, split into header and payload.
fn dgrams(h: &H, c: ConnId) -> Vec<(UdpMsgHdr, Vec<u8>)> {
    let sent = h.t.datagram_sends(c);
    sent.iter()
        .map(|d| (UdpMsgHdr::decode(d).unwrap(), d[9..].to_vec()))
        .collect()
}

fn counters(h: &H, c: ConnId) -> Counters {
    h.sh.app().udp_counters(c).unwrap()
}

#[test]
fn preauth_datagram_dropped_counted() {
    let mut h = H::new(cfg());
    let c = h.conn();
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"early"));
    assert_eq!(counters(&h, c).drops_preauth, 1);
    // Dropped, not buffered: once authenticated, a Live sid 7 gets nothing.
    h.ctrl(c, &auth_req(b"secret"), false);
    let (_, sock) = live(&mut h, c, 7, 0);
    assert!(udp_out(&mut h, sock).is_empty());
    assert_eq!(counters(&h, c).preopen_evictions, 0);

    // Authenticated under --no-udp: every datagram is dropped the same way.
    let mut h = H::new(no_udp());
    let (c, _) = h.authed();
    h.t.inject_datagram(c, dgram(7, 0, 0, 1, b"a"));
    h.t.inject_datagram(c, dgram(8, 0, 0, 1, b"b"));
    h.drive();
    assert_eq!(counters(&h, c).drops_preauth, 2, "drained to the end");
}

#[test]
fn datagram_before_open_delivered_after_live() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"early"));
    let (_, sock) = live(&mut h, c, 7, 0);
    assert_eq!(udp_out(&mut h, sock), [(target(), b"early".to_vec())]);
}

#[test]
fn preopen_ttl_at_flush_without_intervening_push() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"early"));
    h.advance(ms(300));
    let (_, sock) = live(&mut h, c, 7, 0);
    assert!(udp_out(&mut h, sock).is_empty(), "past 250 ms at the flush");
}

#[test]
fn preopen_oversize_single_dropped() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"small"));
    inbound(&mut h, c, dgram(7, 1, 0, 1, &vec![0; PREOPEN_BYTES]));
    assert_eq!(counters(&h, c).preopen_evictions, 1);
    let (_, sock) = live(&mut h, c, 7, 0);
    assert_eq!(
        udp_out(&mut h, sock),
        [(target(), b"small".to_vec())],
        "the buffer was not emptied for it"
    );
}

#[test]
fn fin_during_resolving_discards_preopen_entries() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"stale"));
    let s = h.data(c);
    h.feed(s, &open_domain(7), false);
    let (op, ..) = h.resolve().unwrap();
    h.feed(s, b"", true);
    assert_eq!(h.reqs(), [IoRequest::CancelResolve { op }]);
    // Within the TTL: only a discard keeps "stale" from the new session.
    let (_, sock) = live(&mut h, c, 7, 0);
    assert!(udp_out(&mut h, sock).is_empty());
}

#[test]
fn refused_session_discards_preopen_entries() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // The resolve fails (DnsFailed) ...
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"stale"));
    let s = h.data(c);
    h.feed(s, &open_domain(7), false);
    let (op, ..) = h.resolve().unwrap();
    h.sh.on_resolve_result(h.now, op, Err(DialError::Dns));
    h.drive();
    assert_eq!(h.t.sent_bytes(s), udp_resp(1, 1, 0));
    // ... or the socket open fails (SocketFailed).
    inbound(&mut h, c, dgram(8, 0, 0, 1, b"stale"));
    let s = h.data(c);
    h.feed(s, &open_ip(8, 0), false);
    let (op, _) = h.socket_open().unwrap();
    h.sh.on_udp_socket(h.now, op, Err(io::ErrorKind::Other));
    h.drive();
    assert_eq!(h.t.sent_bytes(s), udp_resp(1, 2, 0));
    // Within the TTL, the same sids go Live: nothing from the buffer.
    for sid in [7, 8] {
        let (_, sock) = live(&mut h, c, sid, 0);
        assert!(udp_out(&mut h, sock).is_empty(), "{sid}");
    }
}

#[test]
fn live_reassembly_to_target() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (_, sock) = live(&mut h, c, 7, 0);
    // One readable event, out of order: drained to the end.
    h.t.inject_datagram(c, dgram(7, 5, 2, 3, b"cc"));
    h.t.inject_datagram(c, dgram(7, 5, 0, 3, b"aaa"));
    h.t.inject_datagram(c, dgram(7, 5, 1, 3, b"bbb"));
    h.drive();
    assert_eq!(udp_out(&mut h, sock), [(target(), b"aaabbbcc".to_vec())]);
    assert_eq!(counters(&h, c).frags_reassembled, 1);
}

#[test]
fn empty_payload_to_target_dropped_counted_no_rearm() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live(&mut h, c, 7, 2000);
    h.advance(ms(1500));
    inbound(&mut h, c, dgram(7, 0, 0, 1, b""));
    assert!(udp_out(&mut h, sock).is_empty());
    assert_eq!(counters(&h, c).drops_empty, 1);
    h.advance(ms(500));
    assert!(h.reset(s), "expired at the deadline armed at Live");
}

#[test]
fn peer_mismatch_dropped() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (_, sock) = live(&mut h, c, 7, 0);
    reply(&mut h, sock, sa("10.0.0.1:5354"), b"x");
    reply(&mut h, sock, sa("10.0.0.2:5353"), b"x");
    assert!(h.t.datagram_sends(c).is_empty());
    reply(&mut h, sock, target(), b"x");
    assert_eq!(h.t.datagram_sends(c), [dgram(7, 0, 0, 1, b"x")]);
}

#[test]
fn v4_mapped_target_reply_accepted() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets();
    let open = udp_open(7, AddrType::Ipv6, &mapped, 5353, 0);
    let (_, sock) = live_with(&mut h, c, &open);
    // The driver reports the peer unmapped.
    reply(&mut h, sock, sa("127.0.0.1:5353"), b"pong");
    assert_eq!(h.t.datagram_sends(c), [dgram(7, 0, 0, 1, b"pong")]);
}

#[test]
fn unspecified_target_reply_from_loopback_accepted() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (_, v4) = live_with(&mut h, c, &udp_open(1, AddrType::Ipv4, &[0; 4], 5353, 0));
    let (_, v6) = live_with(&mut h, c, &udp_open(2, AddrType::Ipv6, &[0; 16], 5353, 0));
    reply(&mut h, v4, sa("127.0.0.1:5353"), b"a");
    reply(&mut h, v6, sa("[::1]:5353"), b"b");
    assert_eq!(
        h.t.datagram_sends(c),
        [dgram(1, 0, 0, 1, b"a"), dgram(2, 0, 0, 1, b"b")]
    );
}

#[test]
fn target_reply_split_and_sent() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (_, sock) = live(&mut h, c, 7, 0);
    // mss 1 200 (the scripted default): 1 191 payload bytes per fragment.
    let p: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    reply(&mut h, sock, target(), &p);
    let d = dgrams(&h, c);
    assert_eq!(d.len(), 3);
    for (i, (hdr, _)) in d.iter().enumerate() {
        assert_eq!(
            (hdr.session_id, hdr.packet_id, hdr.frag_id, hdr.frag_count),
            (7, 0, i as u8, 3)
        );
    }
    let joined: Vec<u8> = d.iter().flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(joined, p);
    assert_eq!(counters(&h, c).frags_sent, 3);
    reply(&mut h, sock, target(), b"next");
    assert_eq!(dgrams(&h, c)[3].0.packet_id, 1);
}

#[test]
fn idle_renews_inbound_only_with_negotiated_len() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live(&mut h, c, 7, 2000);
    h.advance(ms(1500));
    inbound(&mut h, c, dgram(7, 0, 0, 1, b"x"));
    assert_eq!(udp_out(&mut h, sock).len(), 1);
    h.advance(ms(500));
    assert!(!h.reset(s), "renewed at 1.5 s");
    h.advance(ms(1499));
    assert!(!h.reset(s));
    h.advance(ms(1));
    assert!(h.reset(s), "2 s after the renewal, not the 60 s default");
}

#[test]
fn idle_renews_target_only() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live(&mut h, c, 7, 2000);
    h.advance(ms(1500));
    reply(&mut h, sock, target(), b"x");
    assert_eq!(h.t.datagram_sends(c).len(), 1);
    h.advance(ms(500));
    assert!(!h.reset(s), "renewed at 1.5 s");
    h.advance(ms(1500));
    assert!(h.reset(s));
}

#[test]
fn idle_rearm_needs_one_fragment_sent() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (none, none_sock) = live(&mut h, c, 7, 2000);
    let (one, one_sock) = live(&mut h, c, 8, 2000);
    h.advance(ms(1500));
    for _ in 0..3 {
        h.t.expect_datagram_send(c, Err(DatagramError::Blocked));
    }
    reply(&mut h, none_sock, target(), &[0; 3000]);
    assert_eq!(counters(&h, c).drops_send_fail, 3);
    // Two of three fail, the last is sent.
    h.t.expect_datagram_send(c, Err(DatagramError::Blocked));
    h.t.expect_datagram_send(c, Err(DatagramError::Blocked));
    reply(&mut h, one_sock, target(), &[0; 3000]);
    assert_eq!(h.t.datagram_sends(c).len(), 1);
    h.advance(ms(500));
    assert!(h.reset(none), "all fragments failed: no renewal");
    assert!(!h.reset(one), "one fragment sent: renewed");
}

#[test]
fn idle_expiry_logs_and_resets() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live(&mut h, c, 7, 2000);
    h.reqs();
    log_capture::take();
    h.advance(ms(2000));
    let lines: Vec<String> = log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq_udp_srv"))
        .collect();
    assert_eq!(
        lines,
        [
            "INFO mq_udp_srv: session 7 idle-expired",
            "INFO mq_udp_srv: session 7 closed"
        ]
    );
    assert!(h.reset(s));
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn idle_timer_keyed_by_conn_and_sid() {
    let mut h = H::new(cfg());
    let (c1, _) = h.authed();
    let (s1, _) = live(&mut h, c1, 7, 2000);
    h.advance(ms(1000));
    let (c2, _) = h.authed();
    let (s2, _) = live(&mut h, c2, 7, 2000);
    h.advance(ms(1000));
    assert!(h.reset(s1));
    assert!(!h.reset(s2));
    assert_eq!(h.sh.app().udp_sessions(c1), Some(0));
    assert_eq!(h.sh.app().udp_sessions(c2), Some(1));
    h.advance(ms(1000));
    assert!(h.reset(s2));
}

#[test]
fn late_inbound_after_reap_goes_preopen_then_ttl() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, _) = live(&mut h, c, 7, 2000);
    h.advance(ms(2000));
    assert!(h.reset(s));
    // An unknown sid again: buffered, and subject to the TTL.
    inbound(&mut h, c, dgram(7, 9, 0, 1, b"late"));
    h.advance(ms(300));
    inbound(&mut h, c, dgram(7, 10, 0, 1, b"later"));
    let (_, sock) = live(&mut h, c, 7, 0);
    assert_eq!(udp_out(&mut h, sock), [(target(), b"later".to_vec())]);
    assert_eq!(counters(&h, c).preopen_evictions, 0);
}

#[test]
fn late_target_packet_after_reap_dropped() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live(&mut h, c, 7, 2000);
    h.advance(ms(2000));
    assert!(h.reset(s));
    reply(&mut h, sock, target(), b"late");
    assert!(h.t.datagram_sends(c).is_empty());
}

/// The `mq_udp_srv` lines logged since the last call.
fn srv_log() -> Vec<String> {
    log_capture::take()
        .into_iter()
        .filter(|l| l.contains("mq_udp_srv"))
        .collect()
}

/// What one reap of session `sid` (stream `s`, socket `sock`) did, once:
/// the `closed` line, the socket close, one reset, the slot and budget freed.
fn assert_reaped_once(h: &mut H, c: ConnId, sid: u32, s: StreamId, sock: UdpSocketId) {
    assert_eq!(
        srv_log(),
        [format!("INFO mq_udp_srv: session {sid} closed")]
    );
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert_eq!(h.count(|x| *x == Call::StreamReset(s)), 1);
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
    assert_eq!(h.sh.app().held(c), Some(1), "only the control stream");
}

/// A `Live` session 7 with the log and request queues cleared.
fn live_quiet(h: &mut H, c: ConnId) -> (StreamId, UdpSocketId) {
    let r = live(h, c, 7, 0);
    h.reqs();
    srv_log();
    r
}

#[test]
fn client_fin_in_live_reaps() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live_quiet(&mut h, c);
    h.feed(s, b"", true);
    assert_reaped_once(&mut h, c, 7, s, sock);
}

#[test]
fn client_reset_in_live_reaps() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live_quiet(&mut h, c);
    h.t.expect_stream_recv(s, Err(StreamError::Reset));
    h.event(Event::StreamReadable(s));
    assert_reaped_once(&mut h, c, 7, s, sock);
}

#[test]
fn stream_closed_in_live_reaps() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s, sock) = live_quiet(&mut h, c);
    h.event(Event::StreamClosed(s));
    assert_reaped_once(&mut h, c, 7, s, sock);
}

#[test]
fn reap_is_idempotent_across_paths() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let (s7, sock7) = live(&mut h, c, 7, 2000);
    let (s8, sock8) = live(&mut h, c, 8, 0);
    h.reqs();
    srv_log();
    // Idle expiry reaps 7; the transport's late StreamClosed finds nothing.
    h.advance(ms(2000));
    h.event(Event::StreamClosed(s7));
    h.event(Event::StreamReadable(s7));
    // A client FIN reaps 8; the late StreamClosed too, then the connection.
    h.feed(s8, b"", true);
    h.event(Event::StreamClosed(s8));
    h.closed(c);
    let lines: Vec<String> = srv_log()
        .into_iter()
        .filter(|l| !l.contains("stats"))
        .collect();
    assert_eq!(
        lines,
        [
            "INFO mq_udp_srv: session 7 idle-expired",
            "INFO mq_udp_srv: session 7 closed",
            "INFO mq_udp_srv: session 8 closed",
        ]
    );
    assert_eq!(
        h.reqs(),
        [
            IoRequest::CloseUdpSocket { sock: sock7 },
            IoRequest::CloseUdpSocket { sock: sock8 }
        ]
    );
    for s in [s7, s8] {
        assert_eq!(h.count(|x| *x == Call::StreamReset(s)), 1, "{s:?}");
    }
}

#[test]
fn conn_closed_reaps_all_and_logs_stats_once() {
    const STATS: &str = "INFO mq_udp_srv: stats frags_sent=3 frags_reassembled=1 \
        drops_send_fail=2 drops_oversize=4 defrag_drops=5 preopen_evictions=6 \
        drops_preauth=7 drops_empty=8";
    log_capture::install();
    let mut h = H::new(cfg());
    let c = h.conn();
    for i in 0..7 {
        h.t.inject_datagram(c, dgram(9, i, 0, 1, b"early"));
    }
    h.drive();
    h.ctrl(c, &auth_req(b"secret"), false);
    h.t.set_datagram_mss(c, 10); // 1 payload byte per fragment
    // One session per phase: Live, Opening, Resolving.
    let (live_s, sock) = live(&mut h, c, 1, 0);
    let opening = h.data(c);
    h.feed(opening, &open_ip(2, 0), false);
    let (open_op, _) = h.socket_open().unwrap();
    let resolving = h.data(c);
    h.feed(resolving, &open_domain(3), false);
    let (resolve_op, ..) = h.resolve().unwrap();
    // A different count for each counter, so a swapped field shows.
    inbound(&mut h, c, dgram(1, 0, 0, 2, b"a"));
    inbound(&mut h, c, dgram(1, 0, 1, 2, b"b")); // frags_reassembled
    for i in 0..8 {
        inbound(&mut h, c, dgram(1, 10 + i, 0, 1, b"")); // drops_empty
    }
    for i in 0..5 {
        inbound(&mut h, c, dgram(1, 20 + i, 2, 2, b"x")); // defrag_drops
    }
    for i in 0..6 {
        inbound(&mut h, c, dgram(99, i, 0, 1, &vec![0; PREOPEN_BYTES])); // preopen_evictions
    }
    for _ in 0..2 {
        h.t.expect_datagram_send(c, Err(DatagramError::Blocked));
        reply(&mut h, sock, target(), b"x"); // drops_send_fail
    }
    for _ in 0..4 {
        reply(&mut h, sock, target(), &[0; 300]); // drops_oversize: 300 > 255 fragments
    }
    reply(&mut h, sock, target(), b"abc"); // frags_sent
    assert_eq!(h.t.datagram_sends(c).len(), 3);
    log_capture::take();

    h.closed(c);
    let lines = srv_log();
    // Every session is reaped before the one stats line.
    let (reaped, stats) = lines.split_at(3);
    let mut reaped = reaped.to_vec();
    reaped.sort();
    assert_eq!(
        reaped,
        [
            "INFO mq_udp_srv: session 1 closed",
            "INFO mq_udp_srv: session 2 closed",
            "INFO mq_udp_srv: session 3 closed",
        ]
    );
    assert_eq!(stats, [STATS]);
    let mut reqs = h.reqs();
    reqs.sort_by_key(|r| format!("{r:?}"));
    assert_eq!(
        reqs,
        [
            IoRequest::CancelResolve { op: resolve_op },
            IoRequest::CancelUdpSocket { op: open_op },
            IoRequest::CloseUdpSocket { sock },
        ]
    );
    for s in [live_s, opening, resolving] {
        assert!(!h.reset(s), "died with the connection: {s:?}");
    }

    // Once: a repeated ConnClosed is unknown, and another connection counts
    // from zero.
    h.closed(c);
    let (d, _) = h.authed();
    h.closed(d);
    assert_eq!(
        srv_log(),
        [
            "INFO mq_udp_srv: stats frags_sent=0 frags_reassembled=0 drops_send_fail=0 \
             drops_oversize=0 defrag_drops=0 preopen_evictions=0 drops_preauth=0 drops_empty=0"
        ]
    );
}

#[test]
fn shutdown_logs_stats_once_per_conn() {
    log_capture::install();
    let mut h = H::new(cfg());
    let (a, _) = h.authed();
    let (s, sock) = live(&mut h, a, 7, 0);
    inbound(&mut h, a, dgram(7, 0, 0, 1, b"")); // a's line: drops_empty=1
    let b = h.conn(); // never authenticated
    h.reqs();
    srv_log();
    h.sh.on_shutdown_signal(h.now);
    // Shutdown only closes: no reap, no stats until each ConnClosed.
    assert_eq!((h.close_conn_count(a), h.close_conn_count(b)), (1, 1));
    assert!(srv_log().is_empty());
    assert_eq!(h.sh.app().udp_sessions(a), Some(1));
    assert_eq!(h.sh.exit_status(), None);
    // The transport reports both closes in the next drive.
    h.drive();
    h.event(Event::ConnClosed(a, closed_reason())); // a repeat changes nothing
    // One stats line per connection (their order is the transport's), a's
    // after the reap of its session.
    let lines = srv_log();
    assert_eq!(lines.len(), 3, "{lines:?}");
    let pos = |f: &dyn Fn(&String) -> bool| lines.iter().position(f);
    let closed = pos(&|l| l.ends_with("session 7 closed")).expect("reaped");
    let a_stats =
        pos(&|l| l.starts_with("INFO mq_udp_srv: stats ") && l.ends_with("drops_empty=1"));
    assert!(a_stats.expect("a's stats") > closed, "{lines:?}");
    assert_eq!(
        lines.iter().filter(|l| l.contains(": stats ")).count(),
        2,
        "{lines:?}"
    );
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert!(!h.reset(s));
    assert_eq!((h.close_conn_count(a), h.close_conn_count(b)), (1, 1));
    assert_eq!(h.sh.exit_status(), Some(0));
}
