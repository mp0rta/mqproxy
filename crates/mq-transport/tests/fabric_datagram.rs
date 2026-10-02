//! SP2 spec §3.1–§3.2: the datagram lane over real xquic — send, the receive ring,
//! `DatagramReadable` coalescing, drop counting and the multipath-aware mss.
//!
//! Every send is followed by `tick(Duration::ZERO)`, which drives the sender before the
//! exchange, so a deferred flush (spec §3.3) is picked up too.
mod common;

use common::lockstep::{Peer, cfg};
use common::pair::{
    ACTIVE, MS, Opts, Pair, T0, add_path, cli_addr, conn_cfg, mp_ready_count, path_state,
};
use mq_transport_api::{ConnId, DatagramError, Event, Role, Time, TransportOps};
use std::time::Duration;

const MIB: usize = 1024 * 1024;

/// Datagram `i` of `n` bytes; distinct per `i`.
fn payload(i: usize, n: usize) -> Vec<u8> {
    (0..n).map(|k| (i * 7 + k * 31) as u8).collect()
}

fn dsend(p: &Peer, now: Time, c: ConnId, data: Vec<u8>) -> Result<(), DatagramError> {
    p.call(now, move |t, now| t.datagram_send(now, c, &data))
}

fn mss(p: &Peer, c: ConnId) -> usize {
    p.call(Time::ZERO, move |t, _| t.datagram_mss(c))
}

/// One `datagram_recv` into a `cap`-byte buffer.
fn drecv(p: &Peer, c: ConnId, cap: usize) -> Option<Vec<u8>> {
    p.call(Time::ZERO, move |t, _| {
        let mut buf = vec![0u8; cap];
        t.datagram_recv(c, &mut buf).map(|n| buf[..n].to_vec())
    })
}

/// `datagram_recv` until `None`.
fn drain(p: &Peer, c: ConnId) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| drecv(p, c, 65535)).collect()
}

fn dropped(p: &Peer, c: ConnId) -> u64 {
    p.call(Time::ZERO, move |t, _| t.dgram_rx_dropped(c))
}

fn readable(ev: &[Event], c: ConnId) -> usize {
    ev.iter()
        .filter(|e| **e == Event::DatagramReadable(c))
        .count()
}

/// Transmit queues of `p` with something to send.
fn pending(p: &Peer) -> usize {
    p.call(Time::ZERO, |t, _| {
        let mut keys = Vec::new();
        t.pending_transmit(&mut keys);
        keys.len()
    })
}

/// Client → server, then drive the sender and exchange.
fn send_c2s(p: &mut Pair, data: &[u8]) {
    assert_eq!(dsend(&p.client, p.now, p.conn, data.to_vec()), Ok(()));
    p.tick(Duration::ZERO);
}

/// Sends `count` datagrams of `n` bytes client → server, ticking whenever xquic is
/// `Blocked`, then lets everything arrive. The server never calls `datagram_recv`.
fn burst(p: &mut Pair, n: usize, count: usize) {
    let c = p.conn;
    let mut sent = 0;
    while sent < count {
        let from = sent;
        sent = p.client.call(p.now, move |t, now| {
            let mut i = from;
            while i < count {
                match t.datagram_send(now, c, &payload(i, n)) {
                    Ok(()) => i += 1,
                    Err(DatagramError::Blocked) => break,
                    Err(e) => panic!("datagram {i}: {e:?}"),
                }
            }
            i
        });
        p.tick(Duration::ZERO);
        if sent == from {
            p.tick(MS);
        }
    }
    // xquic takes the whole burst into its send queue (18 000 packets) and paces it out:
    // tick until the wire goes quiet.
    loop {
        p.now = p.now + MS;
        p.client.drive(p.now);
        p.server.drive(p.now);
        if p.exchange() == 0 {
            break;
        }
    }
}

#[test]
fn datagram_echo_small() {
    let mut p = Pair::new();
    let data = payload(1, 64);
    let seen = p.sev.len();
    send_c2s(&mut p, &data);
    assert_eq!(readable(&p.sev[seen..], p.srv_conn), 1, "{:?}", p.sev);
    let got = drecv(&p.server, p.srv_conn, 65535).expect("a datagram");
    assert_eq!(got, data);
    assert_eq!(drecv(&p.server, p.srv_conn, 65535), None);

    // And back: the client's ring is bound the same way.
    let seen = p.cev.len();
    assert_eq!(dsend(&p.server, p.now, p.srv_conn, got), Ok(()));
    p.tick(Duration::ZERO);
    assert_eq!(readable(&p.cev[seen..], p.conn), 1, "{:?}", p.cev);
    assert_eq!(drecv(&p.client, p.conn, 65535), Some(data));
    assert_eq!(drecv(&p.client, p.conn, 65535), None);
}

/// SP2 spec §3.3: with `defer_send_flush` a lone send only queues; the 1 µs wakeup it asked
/// for is the backstop that flushes it when nothing else drives the transport.
#[test]
fn deferred_flush_backstop() {
    let mut p = Pair::new();
    assert_eq!(pending(&p.client), 0, "quiet before the send");
    let data = payload(1, 64);
    assert_eq!(dsend(&p.client, p.now, p.conn, data.clone()), Ok(()));
    assert_eq!(pending(&p.client), 0, "the send was deferred, not flushed");
    let at = p.now + Duration::from_micros(1);
    assert_eq!(p.client.next_timeout(), Some(at));

    p.now = at;
    p.client.drive(p.now);
    assert_eq!(pending(&p.client), 1, "the wakeup flushed the datagram");
    p.exchange();
    assert_eq!(drecv(&p.server, p.srv_conn, 65535), Some(data));
}

#[test]
fn datagram_readable_coalesces_until_pop() {
    let mut p = Pair::new();
    let (c, s) = (p.conn, p.srv_conn);
    let seen = p.sev.len();
    assert_eq!(dsend(&p.client, p.now, c, payload(1, 10)), Ok(()));
    assert_eq!(dsend(&p.client, p.now, c, payload(2, 10)), Ok(()));
    p.tick(Duration::ZERO); // both arrive before the server's events are polled
    assert_eq!(readable(&p.sev[seen..], s), 1, "{:?}", p.sev);
    // The pop cleared the flag although nothing was read: the next datagram queues again.
    send_c2s(&mut p, &payload(3, 10));
    assert_eq!(readable(&p.sev[seen..], s), 2, "{:?}", p.sev);
    let want: Vec<_> = (1..=3).map(|i| payload(i, 10)).collect();
    assert_eq!(drain(&p.server, s), want);
}

#[test]
fn datagram_recv_short_buf_drops_and_counts() {
    let mut p = Pair::new();
    send_c2s(&mut p, &payload(1, 64));
    assert_eq!(drecv(&p.server, p.srv_conn, 16), Some(Vec::new()));
    assert_eq!(drecv(&p.server, p.srv_conn, 16), None);
    assert_eq!(dropped(&p.server, p.srv_conn), 1);
}

#[test]
fn datagram_zero_length_delivered() {
    let mut p = Pair::new();
    let seen = p.sev.len();
    send_c2s(&mut p, &[]);
    assert_eq!(readable(&p.sev[seen..], p.srv_conn), 1, "{:?}", p.sev);
    assert_eq!(drecv(&p.server, p.srv_conn, 65535), Some(Vec::new()));
    assert_eq!(drecv(&p.server, p.srv_conn, 65535), None);
    assert_eq!(dropped(&p.server, p.srv_conn), 0, "delivered, not dropped");
}

#[test]
fn ring_absorbs_two_mib_burst() {
    let mut p = Pair::new();
    let n = mss(&p.client, p.conn);
    assert!(n > 0 && n < 1200, "mss {n}");
    let count = (2 * MIB).div_ceil(n);
    burst(&mut p, n, count);
    let got = drain(&p.server, p.srv_conn);
    assert_eq!(dropped(&p.server, p.srv_conn), 0);
    assert_eq!(got.len(), count, "every datagram arrived and was kept");
    assert!(got.iter().enumerate().all(|(i, d)| *d == payload(i, n)));
}

#[test]
fn ring_full_counts_drops() {
    let mut p = Pair::new();
    let n = mss(&p.client, p.conn);
    assert!(n > 0, "mss {n}");
    let count = (17 * MIB).div_ceil(n);
    burst(&mut p, n, count);
    let got = drain(&p.server, p.srv_conn);
    let drops = dropped(&p.server, p.srv_conn);
    assert!(drops > 0);
    assert_eq!(got.len() + drops as usize, count, "kept + dropped = sent");
    assert!(got.len() * (n + 2) <= 16 * MIB);
    assert!(
        got.iter().enumerate().all(|(i, d)| *d == payload(i, n)),
        "the first datagrams are intact"
    );
}

#[test]
fn datagram_send_stale_conn() {
    let mut p = Pair::new();
    let old = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, old));
    assert!(p.pump_until(10 * MS, 1000, |p| p.client_closed().is_some()));
    assert_eq!(
        dsend(&p.client, p.now, old, b"x".to_vec()),
        Err(DatagramError::Stale)
    );
    assert_eq!(mss(&p.client, old), 0);
    assert_eq!(drecv(&p.client, old, 65535), None);
}

#[test]
fn datagram_too_large() {
    let p = Pair::new();
    let n = mss(&p.client, p.conn);
    assert_eq!(
        dsend(&p.client, p.now, p.conn, vec![0; 65536]),
        Err(DatagramError::TooLarge)
    );
    assert_eq!(
        dsend(&p.client, p.now, p.conn, vec![0; n + 1]),
        Err(DatagramError::TooLarge)
    );
    assert_eq!(dsend(&p.client, p.now, p.conn, vec![0; n]), Ok(()));
}

#[test]
fn datagram_mss_zero_before_handshake() {
    let client = Peer::spawn(cfg(Role::Client), vec![cli_addr(0)]);
    let cc = conn_cfg(None);
    let c = client
        .call(T0, move |t, now| t.connect(now, &cc))
        .expect("connect");
    assert_eq!(mss(&client, c), 0);
}

#[test]
fn datagram_mss_two_paths_bounded() {
    let mut p = Pair::with(Opts {
        paths: 2,
        ..Opts::default()
    });
    let single = mss(&p.client, p.conn);
    assert!(single > 0);
    assert!(p.pump_until(MS, 2000, |p| mp_ready_count(p) > 0));
    let pid = add_path(&p).expect("add_path");
    assert!(p.pump_until(MS, 5000, |p| path_state(p, pid.0) == Some(ACTIVE)));
    let two = mss(&p.client, p.conn);
    // Loopback paths share one MTU, so the min cannot be told apart from `single` here.
    assert!(
        two > 0 && two <= single,
        "two paths {two}, one path {single}"
    );
}
