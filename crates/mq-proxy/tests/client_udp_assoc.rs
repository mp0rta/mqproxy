//! spec §6.1 UDP ASSOCIATE, §6.2 availability, §6.3 source learning.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::{AcceptMeta, IoRequest, IoResult, SocketOpId, TcpId, UdpSocketId};
use mq_transport_api::{CloseReason, ConnectError, ErrType, Event, StreamId};
use mq_wire::frames::FEAT_UDP_RELAY;
use std::io;
use std::net::{IpAddr, SocketAddr};

/// SOCKS5 UDP ASSOCIATE, DST 0.0.0.0:0.
const ASSOCIATE: &[u8] = &[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn meta_at(local: &str, peer: &str) -> AcceptMeta {
    AcceptMeta {
        peer: sa(peer),
        local: sa(local),
        original_dst: None,
    }
}

/// The `OpenUdpSocket` requests issued (drains the requests).
fn socket_opens(h: &mut H) -> Vec<(SocketOpId, IpAddr)> {
    h.reqs()
        .into_iter()
        .filter_map(|r| match r {
            IoRequest::OpenUdpSocket { op, local_ip } => Some((op, local_ip)),
            _ => None,
        })
        .collect()
}

/// Greeting, ASSOCIATE and `extra` in one read on a new SOCKS5 socket.
fn associate_from(h: &mut H, m: AcceptMeta, extra: &[u8]) -> TcpId {
    let tcp = h.accept(h.socks, m);
    h.rx(tcp, &[SOCKS_GREETING, ASSOCIATE, extra].concat());
    tcp
}

fn associate(h: &mut H) -> TcpId {
    associate_from(h, meta(None), b"")
}

/// An association whose UDP socket opened at `local`.
fn bound(h: &mut H, m: AcceptMeta, local: &str) -> (TcpId, UdpSocketId) {
    let tcp = associate_from(h, m, b"");
    let opens = socket_opens(h);
    assert_eq!(opens.len(), 1, "one socket per association");
    let sock = h.sh.on_udp_socket(h.now, opens[0].0, Ok(sa(local)));
    (tcp, sock.expect("opened"))
}

/// Authenticated with `features`; returns the control stream.
fn serving_with(h: &mut H, features: u64) -> StreamId {
    let ctrl = h.establish();
    let resp = auth_resp_features(0, 0, features);
    h.t.expect_stream_recv(ctrl, Ok((resp, false)));
    h.event(Event::StreamReadable(ctrl));
    ctrl
}

/// REP 0x07 (command not supported), the socket closed, no UDP socket.
fn refused(h: &mut H, tcp: TcpId) {
    assert_eq!(h.reply(tcp), [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    let reqs = h.reqs();
    assert!(H::closed(&reqs, tcp));
    assert!(
        !reqs
            .iter()
            .any(|r| matches!(r, IoRequest::OpenUdpSocket { .. })),
        "no UDP socket"
    );
}

fn closed_ev(h: &H) -> Event {
    Event::ConnClosed(
        h.conn,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

#[test]
fn associate_opens_app_socket_on_local_ip() {
    let mut h = H::new(cfg());
    let tcp = associate_from(&mut h, meta_at("10.0.0.5:1080", "10.0.0.7:5000"), b"");
    let opens = socket_opens(&mut h);
    assert_eq!(opens.len(), 1);
    assert_eq!(opens[0].1, sa("10.0.0.5:0").ip());
    assert!(h.reply(tcp).is_empty(), "no reply before the socket");
    // The op the client stored: completing it answers this association.
    h.sh.on_udp_socket(h.now, opens[0].0, Ok(sa("10.0.0.5:40000")));
    assert_eq!(h.tx_all(tcp)[..2], [5, 0]);
}

#[test]
fn associate_reply_carries_bnd_addr() {
    let mut h = H::new(cfg());
    let m = meta_at("10.0.0.5:1080", "10.0.0.7:5000");
    let (tcp, _) = bound(&mut h, m, "10.0.0.5:40000");
    assert_eq!(
        h.reply(tcp),
        [0x05, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x05, 0x9C, 0x40]
    );
    assert!(!H::closed(&h.reqs(), tcp), "the control socket stays open");
}

#[test]
fn assoc_unmaps_v4_mapped_peer() {
    let mut h = H::new(cfg());
    let m = meta_at("[::ffff:10.0.0.5]:1080", "[::ffff:10.0.0.7]:5000");
    let tcp = associate_from(&mut h, m, b"");
    let opens = socket_opens(&mut h);
    assert_eq!(opens[0].1, sa("10.0.0.5:0").ip(), "bound on the V4 address");
    let sock =
        h.sh.on_udp_socket(h.now, opens[0].0, Ok(sa("10.0.0.5:40000")));
    let sock = sock.unwrap();
    assert_eq!(h.reply(tcp)[..4], [5, 0, 0, 0x01], "BND.ADDR is V4");
    h.sh.on_udp_rx(h.now, sock, sa("10.0.0.7:6000"), b"x");
    assert_eq!(
        h.sh.app().udp_learned(tcp),
        Some(sa("10.0.0.7:6000")),
        "a V4 datagram from the peer is accepted"
    );
}

#[test]
fn associate_socket_err_rep_01() {
    let mut h = H::new(cfg());
    let tcp = associate(&mut h);
    let op = socket_opens(&mut h)[0].0;
    let r =
        h.sh.on_udp_socket(h.now, op, Err(io::ErrorKind::AddrNotAvailable));
    assert_eq!(r, None);
    assert_eq!(h.reply(tcp), [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(H::closed(&h.reqs(), tcp));
}

#[test]
fn associate_refused_when_unavailable() {
    let mut h = H::new(cfg());
    serving_with(&mut h, 0);
    let tcp = associate(&mut h);
    refused(&mut h, tcp);
}

#[test]
fn unknown_to_unavailable_sweeps() {
    let mut h = H::new(cfg());
    let ctrl = h.establish();
    // Accepted optimistically: one with its socket (no datagram), one opening.
    let (idle, sock) = bound(&mut h, meta(None), "127.0.0.1:40000");
    assert_eq!(h.reply(idle)[..2], [5, 0]);
    let opening = associate(&mut h);
    let op = socket_opens(&mut h)[0].0;
    h.tx_all(opening);
    // AUTH_RESPONSE without the feature bit.
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(0, 0), false)));
    h.event(Event::StreamReadable(ctrl));
    let reqs = h.reqs();
    assert!(H::closed(&reqs, idle) && H::closed(&reqs, opening));
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    assert!(reqs.contains(&IoRequest::CancelUdpSocket { op }));
    let late = associate(&mut h);
    refused(&mut h, late);
}

#[test]
fn available_requires_feature_and_mss() {
    let mut h = H::new(cfg());
    serving_with(&mut h, FEAT_UDP_RELAY);
    associate(&mut h);
    assert_eq!(socket_opens(&mut h).len(), 1, "feature and mss: accepted");

    let mut h = H::new(cfg());
    h.t.set_datagram_mss(h.conn, 0);
    serving_with(&mut h, FEAT_UDP_RELAY);
    let tcp = associate(&mut h);
    refused(&mut h, tcp);
}

#[test]
fn auth_refused_is_unavailable() {
    // The refusal sweeps (the `ConnClosed` it causes would only make it `Unknown`).
    let mut h = H::new(cfg());
    let ctrl = h.establish();
    let (tcp, sock) = bound(&mut h, meta(None), "127.0.0.1:40000");
    h.tx_all(tcp);
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(1, 1), false)));
    h.event(Event::StreamReadable(ctrl));
    let reqs = h.reqs();
    assert!(H::closed(&reqs, tcp));
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));

    // Without a reconnect it stays so.
    let mut h = H::new(ClientConfig {
        reconnect: false,
        ..cfg()
    });
    let ctrl = h.establish();
    h.t.expect_stream_recv(ctrl, Ok((auth_resp(1, 1), false)));
    h.event(Event::StreamReadable(ctrl));
    let tcp = associate(&mut h);
    refused(&mut h, tcp);
}

#[test]
fn shutdown_while_authing_stays_unavailable() {
    let mut h = H::new(cfg());
    let ctrl = h.establish();
    let tcp = h.accept(h.socks, meta(None));
    h.t.hold_conn_closed(true); // the closing period: events still arrive
    h.sh.on_shutdown_signal(h.now);
    // An AUTH_RESPONSE xquic had already buffered, read while the conn closes.
    let resp = auth_resp_features(0, 0, FEAT_UDP_RELAY);
    h.t.expect_stream_recv(ctrl, Ok((resp, false)));
    h.event(Event::StreamReadable(ctrl));
    h.rx(tcp, &[SOCKS_GREETING, ASSOCIATE].concat());
    refused(&mut h, tcp);
}

#[test]
fn control_eof_tears_down() {
    let mut h = H::new(cfg());
    let (tcp, sock) = bound(&mut h, meta(None), "127.0.0.1:40000");
    h.tx_all(tcp);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    let reqs = h.reqs();
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    assert!(H::closed(&reqs, tcp));

    // The socket open still in flight.
    let tcp = associate(&mut h);
    let op = socket_opens(&mut h)[0].0;
    h.tx_all(tcp);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    let reqs = h.reqs();
    assert!(reqs.contains(&IoRequest::CancelUdpSocket { op }));
    assert!(H::closed(&reqs, tcp));

    // A socket error ends it too (the shard closed the socket).
    let (tcp, sock) = bound(&mut h, meta(None), "127.0.0.1:40001");
    h.sh.on_tcp_error(h.now, tcp, io::ErrorKind::ConnectionReset);
    assert!(h.reqs().contains(&IoRequest::CloseUdpSocket { sock }));
}

#[test]
fn control_rx_limit_8k() {
    let mut h = H::new(cfg());
    let tcp = associate(&mut h);
    assert!(h.sh.tcp_interest(tcp).read, "read interest stays on");
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 8192);
}

#[test]
fn control_bytes_discarded() {
    let mut h = H::new(cfg());
    let tcp = associate_from(&mut h, meta(None), b"early");
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 8192, "trailing bytes discarded");
    h.rx(tcp, &[0xAB; 100]);
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 8192, "later bytes discarded");
    assert!(h.reply(tcp).is_empty(), "nothing written");
    assert!(!H::closed(&h.reqs(), tcp));
}

#[test]
fn sync_connect_failure_no_reconnect_is_unavailable() {
    let cfg = ClientConfig {
        reconnect: false,
        ..cfg()
    };
    let mut h = H::start(cfg, Some(ConnectError::Other(-1)));
    let tcp = associate(&mut h);
    refused(&mut h, tcp);
}

#[test]
fn reconnect_backoff_is_unknown() {
    let mut h = H::new(cfg());
    serving_with(&mut h, 0);
    let refused_tcp = associate(&mut h);
    refused(&mut h, refused_tcp);
    h.event(closed_ev(&h));
    associate(&mut h);
    assert_eq!(socket_opens(&mut h).len(), 1, "accepted optimistically");
}
