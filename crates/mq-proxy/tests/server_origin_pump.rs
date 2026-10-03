//! spec §7.3–§7.6: the origin pump (TCP ↔ pipe ↔ rustls, budget, EOF
//! ordering), request send and response delivery, driven through
//! `OriginHost` with raw HTTP/1.1 bytes played by the test.

mod origin_harness;

use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec, upload_byte};
use mq_proxy::server::origin::{
    Accepted, Completion, OriginConnId, OriginFailure, OriginProto, PUMP_CAP, TlsOutcome,
};
use mq_runtime::{IoResult, TcpId};
use mq_transport_api::H3ReqId;
use origin_harness::{OH, ORIGIN_CRT, ORIGIN_KEY, TlsPeer, cfg, get, tls};
use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

const KIB: usize = 1024;

fn oh() -> OH {
    OH::new(cfg(), tls())
}

/// A plain-http exchange whose request was sent: (h3, tcp, conn).
fn plain(oh: &mut OH, spec: StartSpec) -> (H3ReqId, TcpId, OriginConnId) {
    let h3 = oh.start(spec);
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    (h3, tcp, conn)
}

/// An https h1 exchange past the TLS handshake, its request at the peer.
fn tls_h1(oh: &mut OH, spec: StartSpec) -> (H3ReqId, TcpId, OriginConnId, TlsPeer) {
    let h3 = oh.start(spec);
    let (op, _, _) = oh.dial().expect("a dial");
    let tcp = oh.dial_ok(op);
    let mut peer = TlsPeer::h1();
    peer.pump(oh, tcp); // ClientHello → server flight
    peer.pump(oh, tcp); // client Finished + request → session tickets
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).expect("a conn");
    (h3, tcp, conn, peer)
}

/// Every plaintext byte the peer has received.
fn peer_read(peer: &mut TlsPeer) -> Vec<u8> {
    let mut v = Vec::new();
    match peer.conn.reader().read_to_end(&mut v) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => v,
        r => panic!("peer reader: {r:?}"),
    }
}

/// What the peer has to send, sealed (`write_plain` + records).
fn sealed(peer: &mut TlsPeer, plain: &[u8]) -> Vec<u8> {
    peer.conn.set_buffer_limit(None);
    peer.write_plain(plain);
    let mut b = Vec::new();
    while peer.conn.wants_write() {
        peer.conn.write_tls(&mut b).unwrap();
    }
    b
}

/// The body bytes offered to `on_body_frame`, concatenated.
fn frames(ev: &[BridgeEv]) -> Vec<u8> {
    let f = ev.iter().filter_map(|e| match e {
        BridgeEv::Frame(_, d) => Some(&d[..]),
        _ => None,
    });
    f.collect::<Vec<_>>().concat()
}

fn end_of(ev: &[BridgeEv], h3: H3ReqId) -> Option<Completion> {
    ev.iter().find_map(|e| match e {
        BridgeEv::End(x, c) if *x == h3 => Some(c.clone()),
        _ => None,
    })
}

fn no_failure(ev: &[BridgeEv]) {
    let f: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e, BridgeEv::Failure(..)))
        .collect();
    assert!(f.is_empty(), "{f:?}");
}

/// The only failure, before the head.
fn failure(oh: &OH, h3: H3ReqId) -> OriginFailure {
    match &oh.events()[..] {
        [BridgeEv::Failure(x, f, false)] if *x == h3 => f.clone(),
        ev => panic!("want one failure of {h3:?} before the head, got {ev:?}"),
    }
}

/// A `content-length` response head.
fn head_cl(n: usize) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\ncontent-length: {n}\r\n\r\n").into_bytes()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 253) as u8).collect()
}

#[test]
fn plain_pump_moves_rx_and_tx_in_slices() {
    let mut oh = oh();
    let total = 300 * KIB;
    let spec = StartSpec {
        method: "POST",
        body: BodySpec::Known(total as u64),
        ..get("http://o.test/up")
    };
    let (h3, tcp, _) = plain(&mut oh, spec);
    assert_eq!(oh.sh.tcp_tx_buf(tcp).len(), 64 * KIB, "4 slices fill it");
    // A partial drain frees 20 KiB: exactly one 16 KiB slice fits there (a
    // single write of the whole `tx` would not fit at all).
    let mut wire = oh.sh.tcp_tx_buf(tcp)[..20 * KIB].to_vec();
    oh.sh.tcp_tx_commit(oh.now, tcp, IoResult::Bytes(20 * KIB));
    oh.with_host(|h, cx| h.pump(cx));
    assert_eq!(oh.sh.tcp_tx_buf(tcp).len(), (44 + 16) * KIB, "one slice");
    // The upload leaves through the 64 KiB send buffer; each full drain is
    // an `on_tcp_writable` that lets the pump write the next slices.
    loop {
        let out = oh.tcp_out_all(tcp);
        assert!(out.len() <= 64 * KIB, "never more than the send buffer");
        if out.is_empty() {
            break;
        }
        wire.extend(out);
    }
    let head_end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&wire[..head_end]);
    assert!(head.starts_with("POST /up HTTP/1.1\r\n"), "{head}");
    assert!(
        head.contains(&format!("content-length: {total}\r\n")),
        "{head}"
    );
    let want: Vec<u8> = (0..total as u64).map(upload_byte).collect();
    assert!(
        wire[head_end..] == want[..],
        "the upload, whole and in order"
    );

    let body = pattern(200 * KIB);
    oh.tcp_in(tcp, &head_cl(body.len()));
    oh.tcp_in(tcp, &body);
    let ev = oh.events();
    no_failure(&ev);
    assert!(frames(&ev) == body, "the download, whole and in order");
    let done = end_of(&ev, h3).expect("body end");
    assert_eq!(
        (done.delivered, done.cl),
        (body.len() as u64, Some(body.len() as u64))
    );
}

#[test]
fn request_sent_and_response_delivered() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    assert_eq!(
        String::from_utf8(oh.tcp_out_all(tcp)).unwrap(),
        "GET / HTTP/1.1\r\nhost: o.test\r\naccept: */*\r\n\r\n"
    );
    oh.tcp_in(
        tcp,
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-a: b\r\n\r\nhello",
    );
    let connect_ms = oh.with_host(|h, _| h.origin().connect_ms(conn)).unwrap();
    let ev = oh.events();
    let [
        BridgeEv::Response(r, head),
        BridgeEv::Frame(f, data),
        BridgeEv::End(e, done),
    ] = &ev[..]
    else {
        panic!("{ev:?}")
    };
    assert_eq!((*r, *f, *e), (h3, h3, h3));
    assert_eq!(
        (head.status, head.version, head.proto, head.cl),
        (200, "http/1.1", OriginProto::H1, Some(5))
    );
    assert!(head.headers.contains(&(b"x-a".to_vec(), b"b".to_vec())));
    assert_eq!(data, b"hello");
    assert_eq!(
        *done,
        Completion {
            reused: false,
            connect_ms,
            tls: TlsOutcome::Na,
            delivered: 5,
            cl: Some(5),
        }
    );
}

#[test]
fn partial_holds_until_resume() {
    let mut oh = oh();
    let (h3, tcp, _) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_out_all(tcp);
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(1)));
    oh.tcp_in(tcp, &[&head_cl(5)[..], b"hel"].concat());
    assert_eq!(frames(&oh.events()), b"hel");
    oh.tcp_in(tcp, b"lo");
    oh.advance(Duration::from_secs(1));
    assert_eq!(oh.events().len(), 2, "held: no frame, no end");
    oh.with_host(|h, cx| h.resume(cx, h3));
    let ev = oh.events();
    assert_eq!(frames(&ev), b"hello");
    assert_eq!(end_of(&ev, h3).expect("body end").delivered, 5);
}

#[test]
fn head_error_delivered_as_failure() {
    let reply = b"HTTP/1.1 101 Switching Protocols\r\nupgrade: x\r\n\r\n";
    let check = |f: OriginFailure, tls| {
        assert!(f.upstream_protocol, "{f:?}");
        assert_eq!(
            (f.status, f.proto, f.tls),
            (502, Some(OriginProto::H1), tls)
        );
    };
    let mut oh = oh();
    let (h3, tcp, _) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_out_all(tcp);
    oh.tcp_in(tcp, reply);
    check(failure(&oh, h3), TlsOutcome::Na);

    let mut oh = self::oh();
    let (h3, tcp, _, mut peer) = tls_h1(&mut oh, get("https://localhost/"));
    peer.write_plain(reply);
    peer.pump(&mut oh, tcp);
    check(failure(&oh, h3), TlsOutcome::ConnectFail);
}

#[test]
fn io_error_before_head_maps_curl_56() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    assert!(!oh.tcp_out_all(tcp).is_empty(), "the request was sent");
    oh.tcp_error(tcp, io::ErrorKind::ConnectionReset);
    let f = failure(&oh, h3);
    assert_eq!(
        (f.curl, f.status, f.tls, f.proto),
        (56, 502, TlsOutcome::Na, Some(OriginProto::H1)),
        "{f:?}"
    );
    assert!(oh.with_host(|h, _| h.origin().pipe_dead(conn)), "class E");
}

#[test]
fn eof_before_byte_maps_curl_52() {
    let mut oh = oh();
    let (h3, tcp, _) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_out_all(tcp);
    oh.tcp_eof(tcp);
    let f = failure(&oh, h3);
    assert_eq!(
        (f.curl, f.status, f.tls, f.proto),
        (52, 502, TlsOutcome::Na, Some(OriginProto::H1)),
        "{f:?}"
    );
}

/// Releases the hyper hold and pumps, then lets the pump's zero-delay timer
/// carry on (no socket event is left) until `h3`'s body ends.
fn release_until_end(oh: &mut OH, conn: OriginConnId, h3: H3ReqId) {
    oh.with_host(|h, cx| {
        h.origin_mut().hold_public_poll(conn, false);
        h.pump(cx);
    });
    while end_of(&oh.events(), h3).is_none() && oh.sh.next_timeout() == Some(oh.now) {
        oh.drive();
    }
}

#[test]
fn tcp_readeof_published_after_buffers_drain() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_out_all(tcp);
    // hyper reads nothing: the pipe takes 64 KiB, `tcp_rx` the next 64 KiB.
    oh.with_host(|h, _| h.origin_mut().hold_public_poll(conn, true));
    // A close-delimited body: an early `rx_eof` would end it short, cleanly.
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    let resp = [&head[..], &pattern(200 * KIB)].concat();
    let fed = oh.tcp_in_some(tcp, &resp);
    assert_eq!(fed, 128 * KIB, "pipe and receive buffer full");
    oh.tcp_eof(tcp); // with 64 KiB still in `tcp_rx`
    release_until_end(&mut oh, conn, h3);
    let ev = oh.events();
    no_failure(&ev);
    let body = &resp[head.len()..fed];
    assert!(frames(&ev) == body, "every buffered byte before the EOF");
    let done = end_of(&ev, h3).expect("body end");
    assert_eq!((done.delivered, done.cl), (body.len() as u64, None));
}

#[test]
fn tls_pump_reader_drained_before_read_tls() {
    let mut oh = oh();
    let (h3, tcp, _, mut peer) = tls_h1(&mut oh, get("https://localhost/"));
    let body = pattern(150 * KIB);
    let mut ct = sealed(&mut peer, &[&head_cl(body.len())[..], &body].concat());
    // The first frame is held: the pipe fills and rustls retains plaintext
    // (`wants_read` is false then), which must move before any `read_tls`.
    oh.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    for _ in 0..1000 {
        let n = oh.tcp_in_some(tcp, &ct);
        ct.drain(..n);
        oh.with_host(|h, cx| h.resume(cx, h3));
        if end_of(&oh.events(), h3).is_some() {
            break;
        }
    }
    assert!(ct.is_empty(), "every record was read");
    let ev = oh.events();
    no_failure(&ev);
    assert!(frames(&ev) == body, "whole and in order");
    let done = end_of(&ev, h3).expect("body end");
    assert_eq!(
        (done.delivered, done.tls),
        (body.len() as u64, TlsOutcome::Ok)
    );
}

#[test]
fn tls_plaintext_full_is_backpressure_not_error() {
    let mut oh = oh();
    let (h3, tcp, conn, mut peer) = tls_h1(&mut oh, get("https://localhost/"));
    oh.with_host(|h, _| h.origin_mut().hold_public_poll(conn, true));
    // 64 KiB fill the pipe exactly; then a 16 KiB record and a small one are
    // decrypted by the same read, so rustls holds more than its 16 KiB
    // plaintext limit when the TCP EOF arrives with `tcp_rx` empty: the EOF
    // `read_tls` answers "received plaintext buffer full" — backpressure,
    // retried once hyper drained the pipe.
    let head = b"HTTP/1.1 200 OK\r\n\r\n";
    let first = [&head[..], &pattern(64 * KIB - head.len())].concat();
    let mut ct = sealed(&mut peer, &first);
    ct.extend(sealed(&mut peer, &pattern(16 * KIB)));
    ct.extend(sealed(&mut peer, &pattern(100)));
    let mut fed = 0;
    for _ in 0..10 {
        fed += oh.tcp_in_some(tcp, &ct[fed..]);
    }
    assert_eq!(fed, ct.len(), "every record was read");
    oh.tcp_eof(tcp);
    release_until_end(&mut oh, conn, h3);
    let ev = oh.events();
    no_failure(&ev);
    let body = [&first[head.len()..], &pattern(16 * KIB), &pattern(100)].concat();
    assert!(frames(&ev) == body, "whole and in order");
    let done = end_of(&ev, h3).expect("the EOF ends the close-delimited body");
    assert_eq!((done.delivered, done.cl), (body.len() as u64, None));
}

#[test]
fn close_notify_publishes_eof_before_tcp_fin() {
    let mut oh = oh();
    let (h3, tcp, _, mut peer) = tls_h1(&mut oh, get("https://localhost/"));
    assert!(peer_read(&mut peer).starts_with(b"GET / HTTP/1.1\r\n"));
    peer.write_plain(b"HTTP/1.1 200 OK\r\n\r\nabc");
    peer.conn.send_close_notify();
    peer.pump(&mut oh, tcp);
    let ev = oh.events();
    assert_eq!(frames(&ev), b"abc");
    let done = end_of(&ev, h3).expect("close_notify ends the body, no FIN");
    assert_eq!(
        (done.delivered, done.cl, done.tls),
        (3, None, TlsOutcome::Ok)
    );
}

#[test]
fn budget_hit_arms_zero_timer_and_continues() {
    let mut oh = oh();
    let polls = Rc::new(Cell::new(0));
    let p = polls.clone();
    let task = std::future::poll_fn(move |cx: &mut Context<'_>| {
        p.set(p.get() + 1);
        if p.get() == 20 {
            return Poll::Ready(());
        }
        cx.waker().wake_by_ref(); // dirty again
        Poll::Pending
    });
    let at = oh.now;
    oh.with_host(|h, cx| {
        h.origin_mut().spawn_test_task(Box::pin(task));
        h.pump(cx);
    });
    assert_eq!(polls.get(), PUMP_CAP, "one poll per round, capped");
    assert_eq!(oh.with_host(|h, _| h.origin().task_count()), 1);
    assert_eq!(oh.sh.next_timeout(), Some(at), "a zero-delay pump timer");
    oh.drive(); // no socket event, no time passing
    assert_eq!(polls.get(), 20);
    assert_eq!(oh.with_host(|h, _| h.origin().task_count()), 0);
    assert_eq!(oh.sh.next_timeout(), None, "done: no timer left");
}

#[test]
fn fatal_tls_alert_marks_pipe_dead() {
    let mut oh = oh();
    let (h3, tcp, conn, mut peer) = tls_h1(&mut oh, get("https://localhost/"));
    assert!(!oh.aborted(tcp));
    peer.write_raw(&mut oh, tcp, &[0x15, 3, 3, 0, 2, 2, 0x28]);
    assert!(oh.with_host(|h, _| h.origin().pipe_dead(conn)), "class E");
    assert!(oh.aborted(tcp), "tcp_abort at removal");
    // Not ended by fiat: hyper reports the exchange from the dead pipe (§7.7).
    let f = failure(&oh, h3);
    assert_eq!((f.curl, f.tls), (56, TlsOutcome::ConnectFail), "{f:?}");
}

#[test]
fn tx_shutdown_recorded_and_ignored() {
    let mut oh = oh();
    let (h3, tcp, conn) = plain(&mut oh, get("http://o.test/"));
    oh.tcp_out_all(tcp);
    oh.tcp_in(
        tcp,
        b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 2\r\n\r\nok",
    );
    assert_eq!(end_of(&oh.events(), h3).expect("body end").delivered, 2);
    assert!(
        oh.with_host(|h, _| h.origin().tx_shutdown(conn)),
        "recorded"
    );
    assert!(
        !oh.closed(tcp),
        "ignored: no half-close, no close by the pump"
    );
}

/// The connect timer is cancelled at assignment, not merely ignored when it
/// fires (5.2 review gap): the shard holds no timer for it any more — the
/// only one left is the idle sweep of the pooled conn (§7.7).
#[test]
fn connect_timer_gone_from_shard_at_assignment() {
    let mut oh = oh();
    let (_, tcp, _, _) = tls_h1(&mut oh, get("https://localhost/"));
    assert!(!oh.closed(tcp));
    assert_eq!(oh.sh.next_timeout(), Some(oh.now + cfg().sweep));
}

/// A dirty-forever task never starves the shard: each pump stops at the cap
/// and one `OriginTimer::Pump` is pending, however many pumps capped. Each
/// timer that fires runs one capped pump (`PUMP_CAP` polls), so the poll
/// count after one `drive` tells how many were armed.
#[test]
fn pump_timer_is_armed_once() {
    let polls = Rc::new(Cell::new(0));
    let p = polls.clone();
    let spin = std::future::poll_fn(move |cx: &mut Context<'_>| {
        p.set(p.get() + 1);
        cx.waker().wake_by_ref();
        Poll::<()>::Pending
    });
    let mut oh = oh();
    oh.with_host(|h, cx| {
        h.origin_mut().spawn_test_task(Box::pin(spin));
        h.pump(cx);
        h.pump(cx);
    });
    assert_eq!(polls.get(), 2 * PUMP_CAP);
    let at = oh.now;
    assert_eq!(oh.sh.next_timeout(), Some(at));
    oh.drive();
    assert_eq!(polls.get(), 3 * PUMP_CAP, "one timer fired, not two");
    assert_eq!(
        oh.sh.next_timeout(),
        Some(at),
        "re-armed by the timer's pump"
    );
    oh.drive();
    assert_eq!(polls.get(), 4 * PUMP_CAP, "still one");
}

/// A ticketer whose TLS 1.3 tickets are `len` bytes of junk.
#[derive(Debug)]
struct HugeTickets(usize);
impl rustls::server::ProducesTickets for HugeTickets {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        3600
    }
    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        Some(vec![7; self.0])
    }
    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// A hostile origin: a post-handshake handshake message (a NewSessionTicket
/// of ~64 KiB) overflows rustls's deframer, whose `read_tls` then fails with
/// a sticky "message buffer full". That is fatal (class E), never
/// backpressure: the bytes would sit in `tcp_rx` and the request hang.
#[test]
fn deframer_overflow_after_handshake_is_fatal() {
    let mut oh = oh();
    let mut c = TlsPeer::config(ORIGIN_CRT, ORIGIN_KEY, &[b"http/1.1"]);
    c.ticketer = Arc::new(HugeTickets(65_400));
    c.send_tls13_tickets = 1;
    let mut peer = TlsPeer::from_config(c);
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    peer.pump(&mut oh, tcp); // ClientHello → server flight
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).unwrap();
    // Client Finished + request → the huge ticket, fed as far as the socket
    // lives (the bridge aborts it mid-flight).
    let out = oh.tcp_out_all(tcp);
    let mut s = &out[..];
    while !s.is_empty() {
        peer.conn.read_tls(&mut s).unwrap();
        peer.conn.process_new_packets().unwrap();
    }
    let req = peer_read(&mut peer);
    assert!(req.starts_with(b"GET / HTTP/1.1\r\n"), "sent");
    let ticket = sealed(&mut peer, b"");
    assert!(ticket.len() > 64 * KIB);
    let fed = oh.tcp_in_some(tcp, &ticket);
    assert!(oh.with_host(|h, _| h.origin().pipe_dead(conn)), "class E");
    assert!(oh.aborted(tcp), "tcp_abort at removal");
    let f = failure(&oh, h3);
    assert_eq!((f.curl, f.tls), (56, TlsOutcome::ConnectFail), "{f:?}");
    assert!(fed < ticket.len(), "the socket died mid-flight");
}
