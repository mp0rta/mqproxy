//! spec §7.1: UDP session streams — the `UDP_SESSION_OPEN`, the admission
//! gates, the resolve and the app socket, the RESP, and a FIN in every phase.

mod server_harness;

use mq_proxy::config::ServerConfig;
use mq_runtime::{DialError, Host, IoRequest, Target};
use mq_transport_api::{Event, StreamError};
use mq_wire::frames::AddrType;
use mq_wire::varint;
use server_harness::*;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// The IPv4 target of `open_ip`.
fn target() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 5353))
}
fn open_ip(sid: u32, idle_ms: u64) -> Vec<u8> {
    udp_open(sid, AddrType::Ipv4, &[10, 0, 0, 1], 5353, idle_ms)
}
fn open_domain(sid: u32) -> Vec<u8> {
    udp_open(sid, AddrType::Domain, b"example.com", 53, 0)
}
fn resp_ok(idle_ms: u64) -> Vec<u8> {
    udp_resp(0, 0, idle_ms)
}
/// C `srv_open_reject`: an error RESP carries idle 0.
fn resp_err(code: u64) -> Vec<u8> {
    udp_resp(1, code, 0)
}
fn no_udp() -> ServerConfig {
    ServerConfig {
        udp_enabled: false,
        ..cfg()
    }
}

#[test]
fn open_ip_target_resolves_immediately_then_socket_then_resp_ok() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), false);
    // No driver round trip for an IP target: the socket open follows at once.
    let reqs = h.reqs();
    let [IoRequest::OpenUdpSocket { op, local_ip }] = reqs.as_slice() else {
        panic!("{reqs:?}");
    };
    assert_eq!(*local_ip, IpAddr::from(Ipv4Addr::UNSPECIFIED));
    assert!(h.t.sent_bytes(s).is_empty(), "no RESP before the socket");
    h.socket_ok(*op);
    assert_eq!(h.t.sent_bytes(s), resp_ok(60_000));
    assert_eq!(h.send_fins(s), [false]);
    assert!(!h.reset(s));
    assert_eq!(h.sh.app().udp_target(c, 7), Some(target()));
}

#[test]
fn malformed_open_resets() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    for bad in [
        &[0x02, 0x07, 0x00, 0x09, 0x00][..],   // address_type 0x09
        &[0x02, 0xC0, 0, 0, 1, 0, 0, 0, 0],    // session_id 2^32
        &[0x02, 0x07, 0x00, 0x03, 0x41, 0x00], // a host longer than 255
    ] {
        let s = h.data(c);
        h.feed(s, bad, false);
        assert!(h.reset(s), "{bad:?}");
        assert!(h.t.sent_bytes(s).is_empty(), "no RESP, as C");
    }
    assert!(h.reqs().is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn open_with_fin_same_read_resets() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), true);
    assert!(h.reset(s));
    assert!(h.t.sent_bytes(s).is_empty());
    assert!(h.reqs().is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn open_drain_sees_fin_after_2k() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    // One notification: the OPEN, 1 500 bytes the server discards, then FIN.
    h.t.expect_stream_recv(s, Ok((open_domain(7), false)));
    h.t.expect_stream_recv(s, Ok((vec![0xAA; 1500], false)));
    h.t.expect_stream_recv(s, Ok((Vec::new(), true)));
    h.event(Event::StreamReadable(s));
    let reqs = h.reqs();
    let [IoRequest::Resolve { op, .. }, cancel] = reqs.as_slice() else {
        panic!("{reqs:?}");
    };
    assert_eq!(*cancel, IoRequest::CancelResolve { op: *op });
    assert!(h.reset(s));
    assert!(h.t.sent_bytes(s).is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn open_domain_target_uses_resolve_request() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_domain(7), false);
    let (op, target, deadline) = h.resolve().unwrap();
    assert_eq!(
        target,
        Target {
            host: Host::Domain("example.com".into()),
            port: 53
        }
    );
    assert_eq!(deadline, Duration::from_secs(15), "the dial deadline");
    // The socket is opened in the resolved address's family.
    let addr: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
    h.resolve_ok(op, addr);
    let (op, local_ip) = h.socket_open().unwrap();
    assert_eq!(local_ip, IpAddr::from(Ipv6Addr::UNSPECIFIED));
    h.socket_ok(op);
    assert_eq!(h.t.sent_bytes(s), resp_ok(60_000));
    assert_eq!(h.sh.app().udp_target(c, 7), Some(addr));
}

#[test]
fn open_requested_idle_min_with_server() {
    let max = Duration::from_secs(u64::MAX);
    for (server, requested, applied) in [
        (Duration::from_secs(60), 5_000, 5_000),
        (Duration::from_secs(60), 0, 60_000),
        (Duration::from_secs(60), 90_000, 60_000),
        // Unbounded in config: saturates at the largest varint, no overflow.
        (max, 0, varint::MAX),
        (max, 5_000, 5_000),
    ] {
        let mut h = H::new(ServerConfig {
            udp_idle_timeout: server,
            ..cfg()
        });
        let (c, _) = h.authed();
        let s = h.data(c);
        h.feed(s, &open_ip(7, requested), false);
        let (op, _) = h.socket_open().unwrap();
        h.socket_ok(op);
        assert_eq!(
            h.t.sent_bytes(s),
            resp_ok(applied),
            "{server:?} {requested}"
        );
    }
}

/// spec §7.1: `Dns` and `Timeout` are both `DnsFailed` (C has no other code).
fn resolve_fails_with(e: DialError) {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_domain(7), false);
    let (op, ..) = h.resolve().unwrap();
    h.sh.on_resolve_result(h.now, op, Err(e));
    h.drive();
    assert_eq!(h.t.sent_bytes(s), resp_err(1), "DNS_FAILED");
    assert_eq!(h.send_fins(s), [true]);
    assert!(!h.reset(s), "a reset would discard the RESP");
    assert!(h.reqs().is_empty(), "no socket");
    assert_eq!(h.sh.app().udp_sessions(c), Some(0), "sid and slot freed");
    assert_eq!(h.sh.app().held(c), Some(2), "the retiring stream is held");
}

#[test]
fn resolve_err_dns_failed_with_fin() {
    resolve_fails_with(DialError::Dns);
}

#[test]
fn resolve_timeout_dns_failed() {
    resolve_fails_with(DialError::Timeout);
}

#[test]
fn socket_err_socket_failed() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), false);
    let (op, _) = h.socket_open().unwrap();
    assert!(
        h.sh.on_udp_socket(h.now, op, Err(io::ErrorKind::Other))
            .is_none()
    );
    h.drive();
    assert_eq!(h.t.sent_bytes(s), resp_err(2), "SOCKET_FAILED");
    assert_eq!(h.send_fins(s), [true]);
    assert!(!h.reset(s));
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn unauth_reset() {
    let mut h = H::new(cfg());
    let c = h.conn();
    let s = h.data(c);
    assert!(h.reset(s), "reset at NewStream, as a TCP stream");
    h.feed(s, &open_ip(7, 0), false);
    assert!(h.reqs().is_empty());
    assert!(h.t.sent_bytes(s).is_empty());
}

#[test]
fn no_udp_policy_denied() {
    let mut h = H::new(no_udp());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), false);
    assert_eq!(h.t.sent_bytes(s), resp_err(3), "POLICY_DENIED");
    assert_eq!(h.send_fins(s), [true]);
    assert!(!h.reset(s));
    assert!(h.reqs().is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn duplicate_sid_resets_new_keeps_old() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let first = h.data(c);
    h.feed(first, &open_domain(7), false);
    let (op, ..) = h.resolve().unwrap();
    // While the first is `Resolving`: the new stream is reset, no RESP, no resolve.
    let dup = h.data(c);
    h.feed(dup, &open_ip(7, 0), false);
    assert!(h.reset(dup));
    assert!(h.t.sent_bytes(dup).is_empty());
    assert!(h.reqs().is_empty());
    assert!(!h.reset(first));
    // The existing session carries on to `Live` ...
    h.resolve_ok(op, target());
    let (op, _) = h.socket_open().unwrap();
    h.socket_ok(op);
    assert_eq!(h.t.sent_bytes(first), resp_ok(60_000));
    // ... where a duplicate is reset the same way.
    let dup = h.data(c);
    h.feed(dup, &open_ip(7, 0), false);
    assert!(h.reset(dup));
    assert!(!h.reset(first));
    assert_eq!(h.sh.app().udp_sessions(c), Some(1));
}

#[test]
fn cap_1025_session_limit_before_resolve() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    for sid in 0..1024 {
        let s = h.push_data(c);
        h.t.expect_stream_recv(s, Ok((open_domain(sid), false)));
        h.t.push_event(Event::StreamReadable(s));
    }
    h.drive();
    assert_eq!(h.reqs().len(), 1024, "every admitted OPEN resolves");
    assert_eq!(h.sh.app().udp_sessions(c), Some(1024));
    // Every one is still `Resolving`: the 1025th is refused at admission.
    let s = h.data(c);
    h.feed(s, &open_domain(1024), false);
    assert_eq!(h.t.sent_bytes(s), resp_err(4), "SESSION_LIMIT");
    assert_eq!(h.send_fins(s), [true]);
    assert!(h.reqs().is_empty(), "no resolve");
}

#[test]
fn undialable_host_dns_failed() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // An IPv4 address of 3 bytes and a name that is not UTF-8 (C
    // `srv_resolve_udp_target`): answered, not reset.
    for open in [
        udp_open(7, AddrType::Ipv4, &[10, 0, 0], 53, 0),
        udp_open(8, AddrType::Domain, &[0xFF, 0xFE], 53, 0),
    ] {
        let s = h.data(c);
        h.feed(s, &open, false);
        assert_eq!(h.t.sent_bytes(s), resp_err(1), "DNS_FAILED");
        assert_eq!(h.send_fins(s), [true]);
        assert!(!h.reset(s));
    }
    assert!(h.reqs().is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn unspecified_target_becomes_loopback() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets();
    for (sid, atype, host, local_ip, canonical) in [
        (
            1,
            AddrType::Ipv4,
            &[0u8; 4][..],
            "0.0.0.0",
            "127.0.0.1:5353",
        ),
        (2, AddrType::Ipv6, &[0u8; 16], "::", "[::1]:5353"),
        // spec §7.2: an IPv4-mapped target is kept unmapped.
        (3, AddrType::Ipv6, &mapped, "::", "127.0.0.1:5353"),
    ] {
        let s = h.data(c);
        h.feed(s, &udp_open(sid, atype, host, 5353, 0), false);
        let (_, ip) = h.socket_open().unwrap();
        assert_eq!(ip, local_ip.parse::<IpAddr>().unwrap(), "{sid}");
        let want = canonical.parse().unwrap();
        assert_eq!(h.sh.app().udp_target(c, sid), Some(want), "{sid}");
    }
}

#[test]
fn fin_before_open_resets() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let half = h.data(c);
    h.feed(half, &open_ip(7, 0)[..5], true);
    let bare = h.data(c);
    h.feed(bare, b"", true);
    for s in [half, bare] {
        assert!(h.reset(s));
        assert!(h.t.sent_bytes(s).is_empty());
    }
    assert!(h.reqs().is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn fin_during_resolving_cancels_and_resets() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_domain(7), false);
    let (op, ..) = h.resolve().unwrap();
    h.feed(s, b"", true);
    assert_eq!(h.reqs(), [IoRequest::CancelResolve { op }]);
    assert!(h.reset(s));
    assert!(h.t.sent_bytes(s).is_empty());
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
}

#[test]
fn fin_during_opening_cancels_open() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), false);
    let (op, _) = h.socket_open().unwrap();
    h.feed(s, b"", true);
    // A cancelled open never yields a socket id: nothing to close.
    assert_eq!(h.reqs(), [IoRequest::CancelUdpSocket { op }]);
    assert!(h.reset(s));
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
    // The shard drops a late completion (the driver closes the OS socket).
    let local = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 40000));
    assert!(h.sh.on_udp_socket(h.now, op, Ok(local)).is_none());
    h.drive();
    assert!(h.t.sent_bytes(s).is_empty(), "no RESP");
}

#[test]
fn resp_ok_partial_completed_on_writable_while_live() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &open_ip(7, 0), false);
    let (op, _) = h.socket_open().unwrap();
    h.t.expect_stream_send(s, Ok(2));
    let sock = h.socket_ok(op);
    let resp = resp_ok(60_000);
    assert_eq!(h.t.sent_bytes(s), resp[..2]);
    h.t.expect_stream_send(s, Err(StreamError::Blocked));
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), resp[..2], "blocked: kept");
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), resp, "the rest");
    assert!(h.send_fins(s).iter().all(|f| !f));
    assert!(!h.reset(s));
    // The session was `Live` throughout: its end closes the socket.
    h.feed(s, b"", true);
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert!(h.reset(s));
}

#[test]
fn resp_ok_send_reset_reaps() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // The first write fails (our send side was reset by a STOP_SENDING).
    let s = h.data(c);
    h.feed(s, &open_ip(1, 0), false);
    let (op, _) = h.socket_open().unwrap();
    h.t.expect_stream_send(s, Err(StreamError::Reset));
    let sock = h.socket_ok(op);
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert!(h.reset(s));
    // The rest of a partial RESP fails on StreamWritable.
    let s = h.data(c);
    h.feed(s, &open_ip(2, 0), false);
    let (op, _) = h.socket_open().unwrap();
    h.t.expect_stream_send(s, Ok(2));
    let sock = h.socket_ok(op);
    h.t.expect_stream_send(s, Err(StreamError::Reset));
    h.event(Event::StreamWritable(s));
    assert_eq!(h.reqs(), [IoRequest::CloseUdpSocket { sock }]);
    assert!(h.reset(s));
    assert_eq!(h.sh.app().udp_sessions(c), Some(0));
    assert_eq!(h.sh.app().held(c), Some(1), "only the control stream");
}

#[test]
fn error_resp_partial_completed_with_fin() {
    let mut h = H::new(no_udp());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.t.expect_stream_send(s, Ok(3));
    h.feed(s, &open_ip(7, 0), false);
    let resp = resp_err(3);
    assert_eq!(h.t.sent_bytes(s), resp[..3]);
    h.event(Event::StreamWritable(s));
    assert_eq!(h.t.sent_bytes(s), resp);
    assert_eq!(h.send_fins(s), [true, true]);
    assert!(!h.reset(s));
}

#[test]
fn error_resp_partial_then_reset() {
    let mut h = H::new(no_udp());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.t.expect_stream_send(s, Ok(3));
    h.feed(s, &open_ip(7, 0), false);
    h.t.expect_stream_send(s, Err(StreamError::Reset));
    h.event(Event::StreamWritable(s));
    assert!(h.reset(s));
    assert_eq!(h.sh.app().held(c), Some(1), "stream gone");
}

#[test]
fn error_resp_counts_in_4096_budget() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let s = h.data(c);
    h.feed(s, &udp_open(7, AddrType::Ipv4, &[10, 0, 0], 53, 0), false);
    assert_eq!(h.t.sent_bytes(s), resp_err(1));
    // control + retiring + 4094 awaiting = 4096 held.
    h.idle_streams(c, 4094);
    let over = h.data(c);
    assert!(h.reset(over), "the retiring stream still counts");
    // The peer finishes it: the entry is returned.
    h.event(Event::StreamClosed(s));
    let fits = h.data(c);
    assert!(!h.reset(fits));
}

#[test]
fn request_timeout_10s_resets() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let slow = h.data(c);
    h.feed(slow, &open_ip(7, 0)[..4], false);
    let admitted = h.data(c);
    h.feed(admitted, &open_domain(8), false);
    h.advance(Duration::from_millis(9_999));
    assert!(!h.reset(slow));
    h.advance(Duration::from_millis(1));
    assert!(h.reset(slow), "10 s after NewStream");
    h.advance(Duration::from_secs(20));
    assert!(
        !h.reset(admitted),
        "an admitted session has no request deadline"
    );
    assert_eq!(h.sh.app().udp_sessions(c), Some(1));
}

#[test]
fn conn_closed_disposes_of_sessions() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let live = h.data(c);
    h.feed(live, &open_ip(1, 0), false);
    let (op, _) = h.socket_open().unwrap();
    let sock = h.socket_ok(op);
    let resolving = h.data(c);
    h.feed(resolving, &open_domain(2), false);
    let (op, ..) = h.resolve().unwrap();
    h.closed(c);
    let reqs = h.reqs();
    assert!(
        reqs.contains(&IoRequest::CloseUdpSocket { sock }),
        "{reqs:?}"
    );
    assert!(reqs.contains(&IoRequest::CancelResolve { op }), "{reqs:?}");
    assert!(
        !h.reset(live) && !h.reset(resolving),
        "died with the connection"
    );
}
