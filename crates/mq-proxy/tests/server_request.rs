//! spec §6.3 "Other streams" / "Data streams": the stream type, the
//! `CONNECT_TCP_REQUEST`, its 10 s deadline and 1 KiB buffer, and the
//! 4096-stream budget.

mod server_harness;

use mq_transport_api::{Event, StreamError};
use server_harness::*;
use std::time::Duration;

#[test]
fn unknown_type_reset() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // 0x02 UDP_SESSION is not served in SP1; 0x05 is unknown.
    let udp = h.data(c);
    h.feed(udp, &[0x02, 0x00, 0x00], false);
    let unk = h.data(c);
    h.feed(unk, &[0x05, 0x00], false);
    assert!(h.reset(udp));
    assert!(h.reset(unk));
    assert!(h.dial().is_none());
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn malformed_request_reset() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // address_type 0x09.
    let bad_type = h.data(c);
    h.feed(bad_type, &[0x01, 0x00, 0x09, 0x00, 0x00, 0x50, 0x00], false);
    // A host longer than 255.
    let long_host = h.data(c);
    h.feed(long_host, &[0x01, 0x00, 0x03, 0x41, 0x00], false);
    // Truncated, then FIN.
    let truncated = h.data(c);
    h.feed(truncated, &CONNECT_REQ_C[..6], true);
    for s in [bad_type, long_host, truncated] {
        assert!(h.reset(s), "{s:?}");
        assert!(h.t.sent_bytes(s).is_empty(), "no response, as C");
    }
    assert!(h.dial().is_none());
}

#[test]
fn request_deadline_10s_reset() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    let slow = h.data(c);
    h.advance(Duration::from_secs(4));
    h.feed(slow, &CONNECT_REQ_C[..3], false); // data does not extend the deadline
    // A stream that completes its request is not reset by the deadline.
    let (quick, _) = h.request(c, b"");
    h.advance(Duration::from_millis(5_999));
    assert!(!h.reset(slow));
    h.advance(Duration::from_millis(1));
    assert!(h.reset(slow), "10 s after NewStream");
    h.advance(Duration::from_secs(20));
    assert!(
        !h.reset(quick),
        "dialling: the request deadline no longer applies"
    );
    assert_eq!(h.close_conn_count(c), 0);
}

#[test]
fn request_buffer_1k() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // padding_length 2048: cannot complete within 1 KiB.
    let mut big = CONNECT_REQ_C.to_vec();
    big.pop();
    big.extend_from_slice(&[0x48, 0x00]);
    big.resize(1200, 0);
    let over = h.data(c);
    h.feed(over, &big, false);
    assert!(h.reset(over));
    assert!(
        h.recv_caps(over).iter().sum::<usize>() <= 1024,
        "1 KiB buffer"
    );
    assert!(h.dial().is_none());
    // padding that fits in 1 KiB completes.
    let mut fits = CONNECT_REQ_C.to_vec();
    fits.pop();
    fits.extend_from_slice(&[0x43, 0x84]); // padding_length 900
    fits.resize(fits.len() + 900, 0);
    assert!(fits.len() <= 1024);
    let ok = h.data(c);
    h.feed(ok, &fits, false);
    assert!(!h.reset(ok));
    assert!(h.dial().is_some());
}

#[test]
fn stream_budget_4096_excludes_relaying() {
    let mut h = H::new(cfg());
    let (c, _) = h.authed();
    // One stream relaying: not counted.
    let (relayed, op) = h.request(c, b"");
    h.dial_ok(op);
    assert_eq!(h.t.sent_bytes(relayed), connect_resp(0, 0));
    // The control stream + 4095 awaiting requests = 4096 held.
    let held = h.idle_streams(c, 4095);
    assert!(held.iter().all(|s| !h.reset(*s)), "within the budget");
    let over = h.data(c);
    assert!(h.reset(over), "the 4097th held stream");
    // One leaves (peer reset): its entry is returned.
    h.t.expect_stream_recv(held[0], Err(StreamError::Reset));
    h.event(Event::StreamReadable(held[0]));
    let again = h.data(c);
    assert!(!h.reset(again));
    let over2 = h.data(c);
    assert!(h.reset(over2));
    // A dialling stream counts until its relay starts.
    let mut b = CONNECT_REQ_C.to_vec();
    b.push(b'x');
    h.feed(again, &b, false);
    let (op2, _, _) = h.dial().unwrap();
    let over3 = h.data(c);
    assert!(h.reset(over3), "dialling still held");
    h.dial_ok(op2);
    let fits = h.data(c);
    assert!(!h.reset(fits), "relaying: released");
    // The budget is per connection.
    let (c2, _) = h.authed();
    let other = h.data(c2);
    assert!(!h.reset(other));
}
