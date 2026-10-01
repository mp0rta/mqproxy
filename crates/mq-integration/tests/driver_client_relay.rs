//! Driver tests with the real `Client` (spec §8.1, §8.4, §6.2): a SOCKS5
//! request through the production driver, the scripted transport answering
//! the open, then the relay.
#![forbid(unsafe_code)]

mod common;

use common::{
    CONNECT_REQ_C, ClientRig, T, connect_resp, feed, read_n, read_to_eof, sent_fin, wait,
};
use std::io::Write;
use std::net::{Shutdown, TcpStream};

/// Mirrors 7.2's `driver_peer_shutdown_with_queued_bytes` through the client
/// and its relay: the peer's bytes queued behind the request, then its
/// half-close, reach the stream as data then FIN — and the stream's data then
/// FIN reach the half-closed peer as data then EOF.
#[test]
fn driver_client_peer_shutdown_with_queued_bytes() {
    let r = ClientRig::serving();
    let mut c = TcpStream::connect(r.socks()).unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).unwrap();
    assert_eq!(read_n(&mut c, 2), [0x05, 0x00]);
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
    req.extend_from_slice(b"example.com");
    req.extend_from_slice(&443u16.to_be_bytes());
    req.extend_from_slice(b"hello");
    c.write_all(&req).unwrap();
    c.shutdown(Shutdown::Write).unwrap();

    // The open is in flight; "hello" and the EOF wait in the client.
    let s = r.stream(1);
    r.wait_sent(s, CONNECT_REQ_C);
    assert!(!sent_fin(&r.t, s));

    feed(&r.t, s, &connect_resp(0, 0), false);
    assert_eq!(read_n(&mut c, 10), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(wait(T, || sent_fin(&r.t, s)), "no FIN: {:?}", r.t.log());
    let mut want = CONNECT_REQ_C.to_vec();
    want.extend_from_slice(b"hello");
    assert_eq!(r.t.sent_bytes(s), want, "every queued byte before the FIN");

    feed(&r.t, s, b"world", true);
    assert_eq!(read_to_eof(&mut c), b"world");
    r.stop();
}
