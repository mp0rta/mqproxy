//! SP3 spec §6.3–§6.5, §10.2 (server): the relay — upload H3 → origin,
//! download origin → H3, the body checks — first with `BridgeEvents` driven
//! directly through `gw_core_mut()`, then on the composed server against a
//! real `Origin` fed hand-written HTTP/1.1 bytes (§6.7 routing, pump after
//! every callback).

mod server_harness;

use mq_proxy::server::gateway::{
    Accepted, BridgeEvents, Completion, GwCore, OriginFailure, RelayHead,
};
use mq_proxy::server::origin::{OriginProto, TlsOutcome, UPLOAD_CAP};
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{Cx, IoRequest, TcpId};
use mq_transport_api::{Event, H3Close, H3ReqId, H3ReqStats, StreamError};
use server_harness::*;
use std::io::ErrorKind;
use std::time::Duration;

type Hs = Vec<(Vec<u8>, Vec<u8>)>;

fn hs(pairs: &[(&str, &str)]) -> Hs {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// An authenticated request for `scheme://o.test/p`, `extra` appended
/// (pseudo-headers in `extra` replace the default).
fn request(extra: &[(&str, &str)]) -> Hs {
    let mut h = hs(&[
        (":method", "GET"),
        (":scheme", "http"),
        (":authority", "o.test"),
        (":path", "/p"),
        ("x-mq-auth", "Bearer secret"),
    ]);
    for (n, v) in extra {
        h.retain(|(x, _)| !(n.starts_with(':') && x == n.as_bytes()));
        h.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
    }
    h
}

/// A request admitted to the origin (its dial pending): `(r, dial op)`.
fn admitted(h: &mut H, extra: &[(&str, &str)], fin: bool) -> (H3ReqId, mq_runtime::DialOpId) {
    let c = h.h3_conn();
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_headers(r, request(extra), fin);
    h.drive();
    assert!(h.t.h3_headers_sent(r).is_empty(), "admitted");
    let (op, _, _) = h.dial().expect("the origin is dialled");
    (r, op)
}

/// `f` on the gateway core, outside any callback.
fn core<R>(h: &mut H, f: impl FnOnce(&mut GwCore, &mut Cx<'_>) -> R) -> R {
    let now = h.now;
    h.sh.with_app(now, |s, cx| f(s.gw_core_mut().expect("gateway"), cx))
}

fn head(status: u16, headers: &[(&str, &str)], cl: Option<u64>) -> RelayHead {
    RelayHead {
        status,
        version: "http/1.1",
        proto: OriginProto::H1,
        headers: hs(headers),
        content_encoding: None,
        cl,
    }
}

fn done(delivered: u64, cl: Option<u64>) -> Completion {
    Completion {
        reused: false,
        connect_ms: 3,
        tls: TlsOutcome::Na,
        delivered,
        cl,
    }
}

fn failure(curl: u32, status: u16) -> OriginFailure {
    OriginFailure {
        curl,
        status,
        tls: TlsOutcome::Na,
        proto: Some(OriginProto::H1),
        upstream_protocol: false,
        start_failed: false,
        cause: "origin went away".into(),
    }
}

fn error_reply(status: &str, xmq: &str) -> Vec<(Hs, bool)> {
    vec![(
        hs(&[
            (":status", status),
            ("x-mq-error", xmq),
            ("content-length", "0"),
        ]),
        true,
    )]
}

fn calls(h: &H, want: Call) -> usize {
    h.count(|c| *c == want)
}

fn closed(h: &mut H, r: H3ReqId) {
    let stats = H3ReqStats {
        send_body: 0,
        recv_body: 0,
        begin_us: 0,
        header_send_us: 0,
        fin_send_us: 0,
        fin_ack_us: 0,
        mp_state: 0,
        stream_err: 0,
        close_msg: None,
    };
    h.t.close_h3(
        r,
        H3Close {
            stats,
            unread: None,
        },
    );
    h.drive();
}

// ---- (a) BridgeEvents driven directly ----

#[test]
fn response_head_sent_immediately_with_origin_protocol() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    let hd = head(
        200,
        &[("content-type", "text/plain"), ("content-length", "5")],
        Some(5),
    );
    core(&mut h, |g, cx| g.on_response(cx, r, hd));
    let want = hs(&[
        (":status", "200"),
        ("x-mq-origin-protocol", "http/1.1"),
        ("content-type", "text/plain"),
        ("content-length", "5"),
    ]);
    assert_eq!(h.t.h3_headers_sent(r), vec![(want, false)]);
}

#[test]
fn response_head_blocked_held_until_writable() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    h.t.expect_h3_send_headers(r, Err(StreamError::Blocked));
    core(&mut h, |g, cx| g.on_response(cx, r, head(200, &[], None)));
    assert!(h.t.h3_headers_sent(r).is_empty());
    // A frame behind the held head is kept whole.
    let a = core(&mut h, |g, cx| g.on_body_frame(cx, r, b"abc"));
    assert_eq!(a, Accepted::Partial(0));
    assert!(h.t.h3_sends(r).is_empty());
    h.event(Event::H3Writable(r));
    assert_eq!(h.t.h3_headers_sent(r).len(), 1);
    assert_eq!(h.t.h3_sends(r), vec![b"abc".to_vec()]);
}

#[test]
fn status_999_sent_as_502_logged_raw() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| g.on_response(cx, r, head(999, &[], None)));
    let sent = h.t.h3_headers_sent(r);
    assert_eq!(sent[0].0[0], (b":status".to_vec(), b"502".to_vec()));
    assert_eq!(
        core(&mut h, |g, _| g.status(r)),
        Some(999),
        "mq.req keeps it"
    );
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| g.on_response(cx, r, head(100, &[], None)));
    assert_eq!(h.t.h3_headers_sent(r)[0].0[0].1, b"100");
}

#[test]
fn body_relayed_one_frame_pending_on_blocked() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| g.on_response(cx, r, head(200, &[], None)));
    assert_eq!(
        core(&mut h, |g, cx| g.on_body_frame(cx, r, b"ab")),
        Accepted::All
    );
    h.t.expect_h3_send_body(r, Ok(3));
    let a = core(&mut h, |g, cx| g.on_body_frame(cx, r, b"hello world"));
    assert_eq!(a, Accepted::Partial(3));
    // Still short: a second partial acceptance keeps the rest.
    h.t.expect_h3_send_body(r, Ok(2));
    h.event(Event::H3Writable(r));
    h.event(Event::H3Writable(r));
    assert_eq!(
        h.t.h3_sends(r),
        ["ab", "hel", "lo", " world"].map(|s| s.as_bytes().to_vec())
    );
    h.t.expect_h3_send_body(r, Err(StreamError::Blocked));
    let a = core(&mut h, |g, cx| g.on_body_frame(cx, r, b"xyz"));
    assert_eq!(a, Accepted::Partial(0));
    h.event(Event::H3Writable(r));
    assert_eq!(h.t.h3_sends(r).last().unwrap(), b"xyz");
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
}

#[test]
fn origin_eof_sends_h3_finish() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(200, &[("content-length", "5")], Some(5)));
        assert_eq!(g.on_body_frame(cx, r, b"hello"), Accepted::All);
        g.on_body_end(cx, r, done(5, Some(5)));
    });
    assert_eq!(calls(&h, Call::H3Finish(r)), 1);
    assert_eq!(calls(&h, Call::H3Reset(r)), 0);
    // Without a content-length there is nothing to check.
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(200, &[], None));
        g.on_body_end(cx, r, done(0, None));
    });
    assert_eq!(calls(&h, Call::H3Finish(r)), 1);
}

#[test]
fn server_body_check_resets_short_response() {
    let mut h = H::with_gateway(cfg());
    let short = |h: &mut H, method: &str, status: u16| {
        let (r, _) = admitted(h, &[(":method", method)], true);
        core(h, |g, cx| {
            g.on_response(cx, r, head(status, &[("content-length", "100")], Some(100)));
            g.on_body_end(cx, r, done(50, Some(100)));
        });
        (calls(h, Call::H3Reset(r)), calls(h, Call::H3Finish(r)))
    };
    assert_eq!(short(&mut h, "GET", 200), (1, 0), "truncation → reset");
    for (m, s) in [("HEAD", 200), ("GET", 204), ("GET", 304), ("GET", 103)] {
        assert_eq!(short(&mut h, m, s), (0, 1), "{m} {s} exempt");
    }
    // Complete: finished.
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(200, &[], Some(100)));
        g.on_body_end(cx, r, done(100, Some(100)));
    });
    assert_eq!(calls(&h, Call::H3Finish(r)), 1);
}

#[test]
fn upload_short_cl_aborts_and_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(
        &mut h,
        &[(":method", "POST"), ("content-length", "10")],
        false,
    );
    let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
    h.t.inject_h3_body(r, b"12345".to_vec(), true);
    h.drive();
    assert!(up.borrow().is_aborted());
    assert!(!up.borrow().fin, "never a fake complete body");
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
}

#[test]
fn upload_excess_cl_aborts_and_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(
        &mut h,
        &[(":method", "POST"), ("content-length", "5")],
        false,
    );
    let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
    h.t.inject_h3_body(r, b"1234567890".to_vec(), true);
    h.drive();
    assert!(up.borrow().is_aborted());
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    // An exact body is complete.
    let (r, _) = admitted(
        &mut h,
        &[(":method", "POST"), ("content-length", "5")],
        false,
    );
    let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
    h.t.inject_h3_body(r, b"12345".to_vec(), true);
    h.drive();
    let u = up.borrow();
    assert!(u.fin && !u.is_aborted());
    assert_eq!(u.data, b"12345");
}

#[test]
fn upload_recv_reset_ends_request() {
    let mut h = H::with_gateway(cfg());
    let (r, op) = admitted(&mut h, &[(":method", "POST")], false);
    let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
    h.t.inject_h3_body(r, vec![7; 100], false);
    h.drive();
    assert_eq!(up.borrow().data.len(), 100);
    h.t.inject_h3_error(r, StreamError::Reset);
    h.drive();
    assert!(up.borrow().is_aborted());
    assert!(
        h.reqs().contains(&IoRequest::CancelDial { op }),
        "the origin record is cancelled"
    );
    assert!(
        core(&mut h, |g, _| g.upload(r).is_none()),
        "the request is done"
    );
}

#[test]
fn want_h3_refill_from_h3() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[(":method", "PUT")], false);
    let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
    let total = UPLOAD_CAP + 1000;
    // Queued, not yet notified: only `want_h3` reads it.
    h.t.inject_h3_body(r, vec![1; total], true);
    core(&mut h, |g, cx| g.want_h3(cx, r));
    assert_eq!(up.borrow().data.len(), UPLOAD_CAP, "the 256 KiB bound");
    assert_eq!(h.t.h3_body_unread(r), 1000);
    assert!(!up.borrow().fin);
    up.borrow_mut().data.clear(); // hyper took it
    core(&mut h, |g, cx| g.want_h3(cx, r));
    let u = up.borrow();
    assert_eq!(u.data.len(), 1000);
    assert!(u.fin && !u.is_aborted());
}

#[test]
fn want_h3_refill_detects_cl_short_and_excess() {
    let mut h = H::with_gateway(cfg());
    for body in [&b"12345"[..], b"1234567890ab"] {
        let (r, _) = admitted(
            &mut h,
            &[(":method", "POST"), ("content-length", "10")],
            false,
        );
        let up = core(&mut h, |g, _| g.upload(r)).expect("live upload");
        // Queued, not yet notified: only `want_h3` reads it.
        h.t.inject_h3_body(r, body.to_vec(), true);
        core(&mut h, |g, cx| g.want_h3(cx, r));
        assert!(up.borrow().is_aborted(), "{} bytes", body.len());
        assert!(!up.borrow().fin);
        assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    }
}

#[test]
fn send_headers_err_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    h.t.expect_h3_send_headers(r, Err(StreamError::Reset));
    core(&mut h, |g, cx| g.on_response(cx, r, head(200, &[], None)));
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    assert!(core(&mut h, |g, _| g.upload(r).is_none()), "finished");
}

#[test]
fn send_body_err_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| g.on_response(cx, r, head(200, &[], None)));
    h.t.expect_h3_send_body(r, Err(StreamError::Reset));
    let a = core(&mut h, |g, cx| g.on_body_frame(cx, r, b"abc"));
    assert_eq!(a, Accepted::All, "discarded");
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    assert_eq!(calls(&h, Call::H3Finish(r)), 0);
}

#[test]
fn origin_failure_without_curl_warns_xmq_token() {
    log_capture::install();
    let mut h = H::with_gateway(cfg());
    let warns = || -> Vec<String> {
        log_capture::take()
            .into_iter()
            .filter(|l| l.starts_with("WARN"))
            .collect()
    };
    let (r, _) = admitted(&mut h, &[], true);
    warns();
    let f = OriginFailure {
        upstream_protocol: true,
        cause: "101 response".into(),
        ..failure(0, 502)
    };
    core(&mut h, |g, cx| g.on_failure(cx, r, f, false));
    assert_eq!(
        warns(),
        ["WARN mq_gw_server: origin o.test upstream-protocol (101 response)"]
    );
    let (r, _) = admitted(&mut h, &[], true);
    warns();
    let f = OriginFailure {
        start_failed: true,
        proto: None,
        cause: "socket limit".into(),
        ..failure(0, 502)
    };
    core(&mut h, |g, cx| g.on_failure(cx, r, f, false));
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "origin-start-failed")
    );
    assert_eq!(
        warns(),
        ["WARN mq_gw_server: origin o.test origin-start-failed (socket limit)"]
    );
}

#[test]
fn origin_failure_before_head_send_error_curl_n() {
    log_capture::install();
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    log_capture::take();
    core(&mut h, |g, cx| g.on_failure(cx, r, failure(52, 502), false));
    assert_eq!(h.t.h3_headers_sent(r), error_reply("502", "curl:52"));
    let warns: Vec<_> = log_capture::take()
        .into_iter()
        .filter(|l| l.starts_with("WARN"))
        .collect();
    assert_eq!(
        warns,
        ["WARN mq_gw_server: origin o.test curl:52 (origin went away)"]
    );
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| g.on_failure(cx, r, failure(28, 504), false));
    assert_eq!(h.t.h3_headers_sent(r), error_reply("504", "curl:28"));
}

#[test]
fn origin_failure_after_head_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(200, &[], Some(10)));
        g.on_body_frame(cx, r, b"12345");
        g.on_failure(cx, r, failure(56, 502), true);
    });
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    assert_eq!(h.t.h3_headers_sent(r).len(), 1, "only the response head");
    assert_eq!(calls(&h, Call::H3Finish(r)), 0, "never a fake FIN");
}

#[test]
fn origin_failure_upstream_protocol_sends_502_upstream_protocol() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    let f = OriginFailure {
        curl: 0,
        status: 502,
        upstream_protocol: true,
        ..failure(0, 502)
    };
    core(&mut h, |g, cx| g.on_failure(cx, r, f, false));
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "upstream-protocol")
    );
}

#[test]
fn finished_request_ignores_late_events() {
    let mut h = H::with_gateway(cfg());
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_failure(cx, r, failure(52, 502), false);
        g.on_failure(cx, r, failure(7, 502), false);
    });
    assert_eq!(
        h.t.h3_headers_sent(r),
        error_reply("502", "curl:52"),
        "once"
    );
    // A finished response is never reset afterwards.
    let (r, _) = admitted(&mut h, &[], true);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(200, &[], None));
        g.on_body_end(cx, r, done(0, None));
        g.on_failure(cx, r, failure(56, 502), true);
        assert_eq!(g.on_body_frame(cx, r, b"late"), Accepted::All);
    });
    assert_eq!(calls(&h, Call::H3Reset(r)), 0);
    assert_eq!(h.t.h3_headers_sent(r).len(), 1);
}

// ---- (b) the composed server against a real `Origin` ----

/// An admitted request whose origin dial succeeded and whose request bytes
/// were taken off the socket: `(r, tcp, request bytes)`.
fn connected(h: &mut H, extra: &[(&str, &str)], fin: bool) -> (H3ReqId, TcpId, Vec<u8>) {
    let (r, op) = admitted(h, extra, fin);
    let tcp = h.dial_ok(op);
    let out = h.tcp_out_all(tcp);
    h.drive();
    (r, tcp, out)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// libcurl parity: Nagle on the origin socket held the second write of a
/// request behind the origin's delayed ACK (~40 ms per 20 KB upload).
#[test]
fn origin_dial_sets_nodelay() {
    let mut h = H::with_gateway(cfg());
    let (_r, op) = admitted(&mut h, &[], true);
    h.reqs();
    let tcp = h.dial_ok(op);
    assert!(h.reqs().contains(&IoRequest::TcpSetNodelay { tcp }));
}

#[test]
fn composed_h1_roundtrip() {
    let mut h = H::with_gateway(cfg());
    let (r, op) = admitted(
        &mut h,
        &[(":method", "POST"), ("content-length", "3")],
        false,
    );
    h.t.inject_h3_body(r, b"abc".to_vec(), true);
    h.drive();
    let tcp = h.dial_ok(op);
    let req = text(&h.tcp_out_all(tcp));
    h.drive();
    assert!(req.starts_with("POST /p HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("host: o.test\r\n") && req.contains("content-length: 3\r\n"));
    assert!(req.ends_with("\r\n\r\nabc"), "{req}");
    // The head goes out at once; a partly accepted frame holds the next one.
    h.t.expect_h3_send_body(r, Ok(2));
    h.tcp_in(
        tcp,
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-o: 1\r\n\r\nhel",
    );
    h.drive();
    let want = hs(&[
        (":status", "200"),
        ("x-mq-origin-protocol", "http/1.1"),
        ("content-length", "5"),
        ("x-o", "1"),
    ]);
    assert_eq!(h.t.h3_headers_sent(r), vec![(want, false)]);
    assert_eq!(h.t.h3_sends(r), vec![b"he".to_vec()]);
    h.tcp_in(tcp, b"lo");
    h.drive();
    assert_eq!(
        h.t.h3_sends(r),
        vec![b"he".to_vec()],
        "the next frame is not polled"
    );
    h.event(Event::H3Writable(r));
    let sends = h.t.h3_sends(r);
    assert_eq!(sends, ["he", "l", "lo"].map(|s| s.as_bytes().to_vec()));
    assert_eq!(calls(&h, Call::H3Finish(r)), 1);
    assert_eq!(calls(&h, Call::H3Reset(r)), 0);
}

#[test]
fn composed_origin_eof_before_byte_curl52() {
    let mut h = H::with_gateway(cfg());
    let (r, tcp, out) = connected(&mut h, &[], true);
    assert!(text(&out).starts_with("GET /p HTTP/1.1\r\n"));
    h.tcp_eof(tcp);
    h.drive();
    assert_eq!(h.t.h3_headers_sent(r), error_reply("502", "curl:52"));
}

#[test]
fn composed_abort_before_head_curl56() {
    let mut h = H::with_gateway(cfg());
    let (r, tcp, _) = connected(&mut h, &[], true);
    h.tcp_error(tcp, ErrorKind::ConnectionReset);
    h.drive();
    assert_eq!(h.t.h3_headers_sent(r), error_reply("502", "curl:56"));
}

#[test]
fn composed_eof_mid_body_resets() {
    let mut h = H::with_gateway(cfg());
    let (r, tcp, _) = connected(&mut h, &[], true);
    h.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n12345");
    h.drive();
    assert_eq!(h.t.h3_sends(r), vec![b"12345".to_vec()]);
    h.tcp_eof(tcp);
    h.drive();
    assert_eq!(calls(&h, Call::H3Reset(r)), 1);
    assert_eq!(calls(&h, Call::H3Finish(r)), 0);
    assert_eq!(h.t.h3_headers_sent(r).len(), 1);
}

#[test]
fn composed_h3closed_closes_h1_conn_at_settle() {
    let mut h = H::with_gateway(cfg());
    let (r, tcp, _) = connected(&mut h, &[], true);
    h.tcp_in(tcp, b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n12345");
    h.drive();
    h.reqs();
    closed(&mut h, r);
    assert!(
        h.reqs()
            .contains(&IoRequest::TcpClose { tcp, abort: false }),
        "class C: the h1 conn is closed, never pooled"
    );
}

#[test]
fn composed_bridge_timer_routed_to_origin() {
    let mut h = H::with_gateway(cfg());
    let (r, tcp, hello) = connected(&mut h, &[(":scheme", "https")], true);
    assert!(!hello.is_empty(), "the ClientHello went out");
    // No TLS byte comes back: the bridge's connect deadline (armed at the
    // dial result) fires through `Server::on_timer` → `gw.on_timer`.
    h.advance(Duration::from_secs(9));
    assert!(h.t.h3_headers_sent(r).is_empty());
    h.advance(Duration::from_secs(1));
    assert_eq!(h.t.h3_headers_sent(r), error_reply("504", "curl:28"));
    assert!(h.reqs().contains(&IoRequest::TcpClose { tcp, abort: true }));
}
