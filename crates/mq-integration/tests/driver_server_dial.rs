//! Driver tests with the real `Server` (spec §8.1, §8.4, §6.3): the dial of a
//! data stream's `CONNECT_TCP_REQUEST` through the production driver — its
//! resolver, connect deadline and late answers — with the transport scripted.
#![forbid(unsafe_code)]

mod common;

use common::{ServerRig, T, connect_resp, sent_fin, wait, was_reset};
use mq_integration::driver_harness::syn_sent_to;
use mq_wire::frames::{STATUS_ERROR, STATUS_OK, TcpErr};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// An origin that must see no connection: nonblocking, so `accept` can be probed.
fn quiet_origin() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

fn assert_no_connect(l: &TcpListener) {
    thread::sleep(Duration::from_millis(300)); // what a started connect would need
    assert_eq!(
        l.accept().map(|_| ()).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "a connect was started"
    );
}

fn timeout_resp() -> Vec<u8> {
    connect_resp(STATUS_ERROR, TcpErr::Timeout as u64)
}

/// Waits for the full `CONNECT_TCP_RESPONSE` `want` on `s`.
fn wait_resp(r: &ServerRig, s: mq_transport_api::StreamId, want: &[u8]) {
    assert!(
        wait(T, || r.t.sent_bytes(s) == want),
        "sent on {s:?}: {:?}, want {want:?}",
        r.t.sent_bytes(s)
    );
}

#[test]
fn driver_server_connect_timeout() {
    // A full accept queue: further SYNs are dropped, so the connect hangs.
    let l = mq_linux::TcpListenerBuilder::new("127.0.0.1:0".parse().unwrap())
        .backlog(1)
        .build()
        .unwrap();
    let addr = l.local_addr().unwrap();
    let mut fill = Vec::new();
    while fill.len() < 8 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(s) => fill.push(s),
            Err(_) => break,
        }
    }
    assert!(fill.len() < 8, "the backlog never filled");

    let r = ServerRig::spawn(Duration::from_millis(300));
    let c = r.authed();
    let s = r.request(c, "blackhole.test", addr.port());
    let req = r.resolver.next(T).expect("resolution started");
    assert_eq!(
        (req.host.as_str(), req.port),
        ("blackhole.test", addr.port())
    );
    req.answer(Ok(vec![addr]));
    assert!(
        wait(Duration::from_millis(250), || syn_sent_to(addr.port()) == 1),
        "the connect is not pending"
    );
    wait_resp(&r, s, &timeout_resp());
    assert!(sent_fin(&r.t, s), "the error response ends with FIN");
    assert!(
        !was_reset(&r.t, s),
        "an error response is never followed by a reset"
    );
    // The connect was cancelled.
    assert!(wait(T, || syn_sent_to(addr.port()) == 0));
    r.stop();
    drop(fill);
}

#[test]
fn driver_server_slow_resolution_deadline() {
    // Answered before the deadline: the dial goes ahead and succeeds.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    origin.set_nonblocking(true).unwrap();
    let oaddr = origin.local_addr().unwrap();
    let r = ServerRig::spawn(Duration::from_millis(600));
    let c = r.authed();
    let s = r.request(c, "slow.test", oaddr.port());
    let req = r.resolver.next(T).expect("resolution started");
    thread::sleep(Duration::from_millis(200)); // a slow resolver, inside the deadline
    req.answer(Ok(vec![oaddr]));
    wait_resp(&r, s, &connect_resp(STATUS_OK, 0));
    assert!(!sent_fin(&r.t, s) && !was_reset(&r.t, s));
    assert!(
        wait(T, || origin.accept().is_ok()),
        "the origin saw no connection"
    );
    r.stop();

    // Answered after the deadline: TIMEOUT, and the late answer dials nothing.
    let (quiet, qaddr) = quiet_origin();
    let r = ServerRig::spawn(Duration::from_millis(300));
    let c = r.authed();
    let s = r.request(c, "slow.test", qaddr.port());
    let req = r.resolver.next(T).expect("resolution started");
    wait_resp(&r, s, &timeout_resp());
    assert!(sent_fin(&r.t, s) && !was_reset(&r.t, s));
    req.answer(Ok(vec![qaddr]));
    assert_no_connect(&quiet);
    r.stop();
}

#[test]
fn driver_server_late_resolve_after_stream_closed() {
    let (quiet, qaddr) = quiet_origin();
    let r = ServerRig::spawn(Duration::from_secs(15));
    let c = r.authed();
    let s = r.request(c, "held.test", qaddr.port());
    let req = r.resolver.next(T).expect("resolution started");
    r.t.push_event(mq_transport_api::Event::StreamClosed(s));
    assert!(wait(T, || was_reset(&r.t, s)), "{:?}", r.t.log());
    req.answer(Ok(vec![qaddr]));
    assert_no_connect(&quiet);
    assert!(r.t.sent_bytes(s).is_empty(), "no response after the close");
    r.stop();
}
