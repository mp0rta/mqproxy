//! Port of C `tests/integration/test_socks5_listener.c` (spec §8.1, §6.1):
//! the real `Client`'s SOCKS5 and HTTP CONNECT listeners under the production
//! driver; the test is the ingress client, and the scripted transport stands
//! in for the server (AUTH answered by the rig, CONNECT answered here) where C
//! used a mock `tcp_open`.
//!
//! Ported: `socks5_happy`, `socks5_unsupported`, `socks5_malformed`,
//! `http_connect_smoke`, `socks5_pipelined_prebuf`, `http_pipelined_prebuf`,
//! `assoc_refused_no_udp`, `assoc_refused_unavail`. Not ported (SP2, UDP
//! ASSOCIATE served): `assoc_establish_free`, `assoc_tcp_close_teardown`,
//! `assoc_mixed_shutdown`, `assoc_no_close_after_err`,
//! `assoc_availability_sweep`, `assoc_dst_reclaim_churn`.
#![forbid(unsafe_code)]

mod common;

use common::{CONNECT_REQ_C, ClientRig, connect_resp, feed, read_n, read_to_eof};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

const SOCKS_OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
const HTTP_HEAD: &[u8] = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
const HTTP_OK: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// SOCKS5 CONNECT example.com:443 (domain).
fn socks_connect() -> Vec<u8> {
    let mut b = vec![0x05, 0x01, 0x00, 0x03, 11];
    b.extend_from_slice(b"example.com");
    b.extend_from_slice(&443u16.to_be_bytes());
    b
}

/// Connected, greeted with no-auth, method reply read.
fn greeted(addr: SocketAddr) -> TcpStream {
    let mut c = TcpStream::connect(addr).unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).unwrap();
    assert_eq!(read_n(&mut c, 2), [0x05, 0x00], "method reply");
    c
}

fn with(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}

/// The request was read with its trailing `early` bytes: the stream carries
/// only the `CONNECT_TCP_REQUEST` until the OK, then `early`, in order.
fn prebuf_held_until_ok(r: &ClientRig, c: &mut TcpStream, reply: &[u8]) {
    let s = r.stream(1);
    r.wait_sent(s, CONNECT_REQ_C);
    thread::sleep(Duration::from_millis(50)); // room for an early forward
    assert_eq!(r.t.sent_bytes(s), CONNECT_REQ_C, "payload before the OK");
    feed(&r.t, s, &connect_resp(0, 0), false);
    assert_eq!(read_n(c, reply.len()), reply);
    r.wait_sent(s, &with(CONNECT_REQ_C, b"ping"));
}

#[test]
fn socks5_happy() {
    let r = ClientRig::serving();
    let mut c = greeted(r.socks());
    c.write_all(&socks_connect()).unwrap();
    let s = r.stream(1);
    r.wait_sent(s, CONNECT_REQ_C); // the right target
    feed(&r.t, s, &connect_resp(0, 0), false);
    assert_eq!(read_n(&mut c, 10), SOCKS_OK);
    // Relayed both ways through the stream.
    c.write_all(b"ping").unwrap();
    r.wait_sent(s, &with(CONNECT_REQ_C, b"ping"));
    feed(&r.t, s, b"pong", false);
    assert_eq!(read_n(&mut c, 4), b"pong");
    r.stop();
}

#[test]
fn socks5_unsupported() {
    let r = ClientRig::serving();
    let mut c = greeted(r.socks());
    // CMD = BIND (0x02) → REP 0x07, closed, nothing opened.
    c.write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
        .unwrap();
    assert_eq!(read_to_eof(&mut c), [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(r.opened(), 1, "only the control stream");
    r.stop();
}

#[test]
fn socks5_malformed() {
    let r = ClientRig::serving();
    let mut c = TcpStream::connect(r.socks()).unwrap();
    c.write_all(&[0x04, 0x01, 0x00]).unwrap(); // bad VER
    assert_eq!(read_to_eof(&mut c), b"", "closed without a reply");
    assert_eq!(r.opened(), 1, "only the control stream");
    r.stop();
}

#[test]
fn http_connect_smoke() {
    let r = ClientRig::serving();
    let mut c = TcpStream::connect(r.http()).unwrap();
    c.write_all(HTTP_HEAD).unwrap();
    let s = r.stream(1);
    r.wait_sent(s, CONNECT_REQ_C);
    feed(&r.t, s, &connect_resp(0, 0), false);
    assert_eq!(read_n(&mut c, HTTP_OK.len()), HTTP_OK);
    r.stop();
}

#[test]
fn socks5_pipelined_prebuf() {
    let r = ClientRig::serving();
    let mut c = greeted(r.socks());
    c.write_all(&with(&socks_connect(), b"ping")).unwrap(); // one write
    prebuf_held_until_ok(&r, &mut c, &SOCKS_OK);
    r.stop();
}

#[test]
fn http_pipelined_prebuf() {
    let r = ClientRig::serving();
    let mut c = TcpStream::connect(r.http()).unwrap();
    c.write_all(&with(HTTP_HEAD, b"ping")).unwrap(); // one write
    prebuf_held_until_ok(&r, &mut c, HTTP_OK);
    r.stop();
}

/// ASSOCIATE DST 0.0.0.0:0 → REP 0x07 and close; no stream opened.
fn associate_refused(r: &ClientRig, opened: usize) {
    let mut c = greeted(r.socks());
    c.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    let reply = read_n(&mut c, 10);
    assert_eq!(reply[..2], [0x05, 0x07], "command not supported");
    assert_eq!(read_to_eof(&mut c), b"");
    assert_eq!(r.opened(), opened);
}

/// C: a listener without the UDP boundary. Here: no tunnel at all.
#[test]
fn assoc_refused_no_udp() {
    let r = ClientRig::spawn(false);
    associate_refused(&r, 0);
    r.stop();
}

/// C: UDP availability 0. Here: serving, the `AUTH_RESPONSE` without
/// `MQ_FEAT_UDP_RELAY`.
#[test]
fn assoc_refused_unavail() {
    let r = ClientRig::serving();
    associate_refused(&r, 1);
    r.stop();
}
