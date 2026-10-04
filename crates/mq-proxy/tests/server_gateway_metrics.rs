//! SP3 spec §6.6: `mq.req` per request (formatted by `mq_http::metrics`),
//! request ends, cancellation and shutdown on the composed server.

mod server_harness;

use mq_proxy::config::{GatewayConfig, ServerConfig};
use mq_proxy::server::gateway::{BridgeEvents, Completion, GwCore, OriginFailure, RelayHead};
use mq_proxy::server::origin::{OriginProto, TlsOutcome};
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{Cx, DialOpId, IoRequest};
use mq_transport_api::{ConnId, H3Close, H3ReqId, H3ReqStats};
use server_harness::*;

type Hs = Vec<(Vec<u8>, Vec<u8>)>;

fn hs(pairs: &[(&str, &[u8])]) -> Hs {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.to_vec()))
        .collect()
}

/// `--request-metrics` on.
fn mcfg() -> ServerConfig {
    ServerConfig {
        gateway: Some(GatewayConfig {
            request_metrics: true,
            ..GatewayConfig::default()
        }),
        ..cfg()
    }
}

/// A GET for `http://o.test/p` with a good token, `edit` replacing / adding.
fn request(edit: &[(&str, &[u8])]) -> Hs {
    let mut h = hs(&[
        (":method", b"GET"),
        (":scheme", b"http"),
        (":authority", b"o.test"),
        (":path", b"/p"),
        ("x-mq-auth", b"Bearer secret"),
    ]);
    for (n, v) in edit {
        h.retain(|(x, _)| x != n.as_bytes());
        h.push((n.as_bytes().to_vec(), v.to_vec()));
    }
    h
}

/// A peer request on `c` (QUIC ids 0, 4, 8, … per conn).
fn open_on(h: &mut H, c: ConnId, edit: &[(&str, &[u8])], fin: bool) -> H3ReqId {
    let r = h.t.new_h3_request(c);
    h.t.inject_h3_headers(r, request(edit), fin);
    h.drive();
    r
}

fn open(h: &mut H, edit: &[(&str, &[u8])], fin: bool) -> H3ReqId {
    let c = h.h3_conn();
    open_on(h, c, edit, fin)
}

/// An admitted request whose dial is pending.
fn admitted(h: &mut H, edit: &[(&str, &[u8])]) -> (H3ReqId, DialOpId) {
    let r = open(h, edit, true);
    assert!(h.t.h3_headers_sent(r).is_empty(), "admitted");
    let (op, _, _) = h.dial().expect("the origin is dialled");
    (r, op)
}

fn core<R>(h: &mut H, f: impl FnOnce(&mut GwCore, &mut Cx<'_>) -> R) -> R {
    let now = h.now;
    h.sh.with_app(now, |s, cx| f(s.gw_core_mut().expect("gateway"), cx))
}

fn head(proto: OriginProto, cl: Option<u64>, ce: Option<&[u8]>) -> RelayHead {
    RelayHead {
        status: 200,
        version: match proto {
            OriginProto::H1 => "http/1.1",
            OriginProto::H2 => "h2",
        },
        proto,
        headers: vec![],
        content_encoding: ce.map(<[u8]>::to_vec),
        cl,
    }
}

fn done(tls: TlsOutcome, delivered: u64, cl: Option<u64>) -> Completion {
    Completion {
        reused: true,
        connect_ms: 0,
        tls,
        delivered,
        cl,
    }
}

fn failure(proto: Option<OriginProto>) -> OriginFailure {
    OriginFailure {
        curl: 56,
        status: 502,
        tls: TlsOutcome::ConnectFail,
        proto,
        upstream_protocol: false,
        start_failed: false,
        cause: "reset".into(),
    }
}

fn stats0() -> H3ReqStats {
    H3ReqStats {
        send_body: 0,
        recv_body: 0,
        begin_us: 0,
        header_send_us: 0,
        fin_send_us: 0,
        fin_ack_us: 0,
        mp_state: 0,
        stream_err: 0,
        close_msg: None,
    }
}

/// `H3Closed` with `stats`; returns every log line it produced.
fn close_log(h: &mut H, r: H3ReqId, stats: H3ReqStats) -> Vec<String> {
    log_capture::take();
    h.t.close_h3(
        r,
        H3Close {
            stats,
            unread: None,
        },
    );
    h.drive();
    log_capture::take()
}

/// The `mq.req` lines of `close_log`.
fn close(h: &mut H, r: H3ReqId, stats: H3ReqStats) -> Vec<String> {
    let mut v = close_log(h, r, stats);
    v.retain(|l| l.contains("mq.req"));
    v
}

/// The single `mq.req` line of `close`.
fn line(h: &mut H, r: H3ReqId, stats: H3ReqStats) -> String {
    let mut v = close(h, r, stats);
    assert_eq!(v.len(), 1, "{v:?}");
    v.pop().unwrap()
}

/// `key=value` of a line (`key="…"` keeps its quotes).
fn field(l: &str, key: &str) -> String {
    let at = l.find(&format!(" {key}=")).expect(key) + key.len() + 2;
    let rest = &l[at..];
    if let Some(q) = rest.strip_prefix('"') {
        format!("\"{}\"", &q[..q.find('"').unwrap()])
    } else {
        rest.split(' ').next().unwrap().to_string()
    }
}

/// `(origin_protocol, origin_tls, origin_reuse, origin_connect_ms)`.
fn origin(l: &str) -> [String; 4] {
    [
        "origin_protocol",
        "origin_tls",
        "origin_reuse",
        "origin_connect_ms",
    ]
    .map(|k| field(l, k))
}

fn o(p: &str, t: &str, reuse: &str, ms: &str) -> [String; 4] {
    [p, t, reuse, ms].map(String::from)
}

#[test]
fn mq_req_golden_success_http_origin() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let (r, _) = admitted(&mut h, &[(":path", b"/p?q=1")]);
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(OriginProto::H1, Some(5), None));
        g.on_body_frame(cx, r, b"hello");
        let d = Completion {
            reused: false,
            connect_ms: 3,
            ..done(TlsOutcome::Na, 5, Some(5))
        };
        g.on_body_end(cx, r, d);
    });
    assert_eq!(h.count(|c| *c == Call::H3Finish(r)), 1);
    let stats = H3ReqStats {
        send_body: 5,
        recv_body: 0,
        begin_us: 2_000_000,
        header_send_us: 2_010_000,
        fin_send_us: 2_020_500,
        fin_ack_us: 2_031_000,
        mp_state: 1,
        ..stats0()
    };
    assert_eq!(
        line(&mut h, r, stats),
        "INFO mq.req cid=- sid=0 method=GET status=200 authority=\"o.test\" path=\"/p\" \
req_bytes=0 resp_bytes=5 ttfb_ms=10 duration_ms=20 origin_protocol=h1 origin_tls=na \
content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=3 mp_state=1 \
completion_ms=31 reset=\"\""
    );
}

#[test]
fn mq_req_golden_https_ok() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let c = h.h3_conn();
    let first = open_on(&mut h, c, &[], true);
    h.reqs();
    let r = open_on(
        &mut h,
        c,
        &[(":scheme", b"https"), (":method", b"post")],
        false,
    );
    h.t.inject_h3_body(r, vec![b'u'; 7], true);
    h.drive();
    core(&mut h, |g, cx| {
        g.on_response(cx, r, head(OriginProto::H2, None, Some(b"gzip")));
        g.on_body_end(cx, r, done(TlsOutcome::Ok, 0, None));
    });
    let stats = H3ReqStats {
        recv_body: 7,
        begin_us: 1_000_000,
        header_send_us: 1_000_999,
        ..stats0()
    };
    assert_eq!(
        line(&mut h, r, stats),
        "INFO mq.req cid=- sid=4 method=post status=200 authority=\"o.test\" path=\"/p\" \
req_bytes=7 resp_bytes=0 ttfb_ms=0 duration_ms=-1 origin_protocol=h2 origin_tls=ok \
content_encoding=gzip cache=bypass origin_reuse=1 origin_connect_ms=0 mp_state=0 \
completion_ms=-1 reset=\"\""
    );
    assert_eq!(close(&mut h, first, stats0()).len(), 1);
}

#[test]
fn mq_req_intake_reject_has_dash_fields() {
    log_capture::install();
    // Off by default: no line.
    let mut h = H::with_gateway(cfg());
    let r = open(&mut h, &[("x-mq-auth", b"Bearer nope")], true);
    assert!(close(&mut h, r, stats0()).is_empty());
    let mut h = H::with_gateway(mcfg());
    let r = open(&mut h, &[("x-mq-auth", b"Bearer nope")], true);
    assert_eq!(
        line(&mut h, r, stats0()),
        "INFO mq.req cid=- sid=0 method=- status=403 authority=\"-\" path=\"-\" req_bytes=0 \
resp_bytes=0 ttfb_ms=-1 duration_ms=-1 origin_protocol=none origin_tls=na content_encoding=none \
cache=bypass origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=-1 reset=\"\""
    );
    // Step 7 (after auth): still nothing recorded.
    let r = open(&mut h, &[(":path", b"/a#b")], true);
    let l = line(&mut h, r, stats0());
    assert!(
        l.contains(" method=- status=400 authority=\"-\" path=\"-\" "),
        "{l}"
    );
}

#[test]
fn mq_req_path_cut_256_no_marker_query_stripped() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let mut long = vec![b'/'];
    long.extend_from_slice(&[b'a'; 300]);
    let cut = format!("\"/{}\"", "a".repeat(255));
    for (path, want) in [
        (long.clone(), cut.clone()),
        (b"/x?y=1&z=2".to_vec(), "\"/x\"".to_string()),
        ([&long[..], b"?q"].concat(), cut.clone()),
    ] {
        let r = open(&mut h, &[(":path", &path)], true);
        assert_eq!(field(&line(&mut h, r, stats0()), "path"), want);
    }
}

#[test]
fn mq_req_origin_tls_na_for_unreached() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let none_na = o("none", "na", "0", "-1");
    // An intake reject, https included.
    let r = open(&mut h, &[(":scheme", b"https"), ("x-mq-auth", b"x")], true);
    assert_eq!(origin(&line(&mut h, r, stats0())), none_na);
    // origin-start-failed (synchronous) for an https URL.
    let r = open(
        &mut h,
        &[(":scheme", b"https"), (":authority", b"a{b")],
        true,
    );
    assert_eq!(origin(&line(&mut h, r, stats0())), none_na);
    // An http origin in flight.
    let (r, _) = admitted(&mut h, &[]);
    assert_eq!(origin(&line(&mut h, r, stats0())), none_na);
}

#[test]
fn mq_req_origin_protocol_known_at_head() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    for (scheme, tls) in [("http", "na"), ("https", "connect_fail")] {
        let (r, _) = admitted(&mut h, &[(":scheme", scheme.as_bytes())]);
        core(&mut h, |g, cx| {
            g.on_response(cx, r, head(OriginProto::H1, None, None))
        });
        // Head relayed, no body yet, then the client goes away.
        let l = line(&mut h, r, stats0());
        assert_eq!(origin(&l), o("h1", tls, "0", "-1"), "{scheme}");
        assert_eq!(field(&l, "status"), "200");
    }
}

#[test]
fn mq_req_reset_stream_err_fallback() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    for (err, msg, want) in [
        (3, None, "\"stream-err\""),
        (3, Some("remote reset"), "\"remote reset\""),
        (0, Some("ignored"), "\"\""),
    ] {
        let (r, _) = admitted(&mut h, &[]);
        let stats = H3ReqStats {
            stream_err: err,
            close_msg: msg.map(String::from),
            ..stats0()
        };
        assert_eq!(field(&line(&mut h, r, stats), "reset"), want);
    }
}

#[test]
fn mq_req_body_check_failure_is_transfer_error() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    for (scheme, tls) in [("https", "connect_fail"), ("http", "na")] {
        let (r, _) = admitted(&mut h, &[(":scheme", scheme.as_bytes())]);
        core(&mut h, |g, cx| {
            g.on_response(cx, r, head(OriginProto::H1, Some(100), None));
            let d = Completion {
                connect_ms: 5,
                ..done(TlsOutcome::Ok, 50, Some(100))
            };
            g.on_body_end(cx, r, d);
        });
        assert_eq!(h.count(|c| *c == Call::H3Reset(r)), 1);
        let l = line(&mut h, r, stats0());
        assert_eq!(origin(&l), o("h1", tls, "0", "-1"), "{scheme}");
    }
}

#[test]
fn mq_req_https_in_flight_is_connect_fail() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let (r, _) = admitted(&mut h, &[(":scheme", b"https")]);
    let l = line(&mut h, r, stats0());
    assert_eq!(origin(&l), o("none", "connect_fail", "0", "-1"));
    assert_eq!(field(&l, "status"), "0");
}

#[test]
fn mq_req_start_failed_keeps_method_authority() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    // §6.2 step 9 (as 6.2's `authority_http_refuses_502_origin_start_failed`).
    let r = open(&mut h, &[(":authority", b"a{b")], false);
    let l = line(&mut h, r, stats0());
    assert!(
        l.contains(" method=GET status=502 authority=\"a{b\" path=\"/p\" "),
        "{l}"
    );
    assert_eq!(origin(&l), o("none", "na", "0", "-1"));
}

#[test]
fn mq_req_origin_protocol_on_failure_after_negotiation() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    for (proto, want) in [(Some(OriginProto::H2), "h2"), (None, "none")] {
        let (r, _) = admitted(&mut h, &[(":scheme", b"https")]);
        core(&mut h, |g, cx| g.on_failure(cx, r, failure(proto), false));
        let l = line(&mut h, r, stats0());
        assert_eq!(origin(&l), o(want, "connect_fail", "0", "-1"));
        assert_eq!(field(&l, "status"), "502");
    }
}

#[test]
fn mq_req_dropped_line_logs_warn() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    // Authority and path at their caps, every byte escaped (`\` is a path byte).
    let mut path = vec![b'/'];
    path.extend_from_slice(&[b'\\'; 255]);
    let r = open(
        &mut h,
        &[(":authority", &[b'"'; 255]), (":path", &path)],
        true,
    );
    assert_eq!(
        close_log(&mut h, r, stats0()),
        ["WARN mq.req line truncated (dropped)"]
    );
}

#[test]
fn mq_req_non_utf8_logs_replacement_char() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let r = open(&mut h, &[(":authority", b"a\xffb")], true);
    let l = line(&mut h, r, stats0());
    assert_eq!(field(&l, "authority"), "\"a\u{FFFD}b\"");
}

#[test]
fn h3closed_cancels_live_origin() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    let (r, op) = admitted(&mut h, &[]);
    assert_eq!(close(&mut h, r, stats0()).len(), 1, "exactly once");
    assert!(h.reqs().contains(&IoRequest::CancelDial { op }));
    assert!(core(&mut h, |g, _| g.status(r)).is_none(), "removed");
}

#[test]
fn shutdown_aborts_origin_sockets_and_resets() {
    log_capture::install();
    let mut h = H::with_gateway(mcfg());
    // In flight on an h1 conn (http), dialling (https), finished (403), in intake.
    let (r1, op1) = admitted(&mut h, &[]);
    let tcp = h.dial_ok(op1);
    h.tcp_out_all(tcp);
    let (r2, op2) = admitted(&mut h, &[(":scheme", b"https")]);
    let r3 = open(&mut h, &[("x-mq-auth", b"Bearer nope")], true);
    let c = h.h3_conn();
    let r4 = h.t.new_h3_request(c);
    h.drive();
    h.reqs();
    assert!(
        h.sh.next_timeout().is_some(),
        "the origin idle sweep is armed"
    );
    h.sh.on_shutdown_signal(h.now);
    let reqs = h.reqs();
    assert!(
        reqs.contains(&IoRequest::TcpClose { tcp, abort: true }),
        "{reqs:?}"
    );
    assert!(
        reqs.contains(&IoRequest::CancelDial { op: op2 }),
        "{reqs:?}"
    );
    assert_eq!(h.sh.next_timeout(), None, "no origin timer left");
    for r in [r1, r2, r3, r4] {
        assert_eq!(h.count(|c| *c == Call::H3Reset(r)), 1);
        assert_eq!(h.count(|c| *c == Call::H3Finish(r)), 0);
    }
    // Each request still gets exactly one `mq.req` at its `H3Closed`.
    let l = line(&mut h, r1, stats0());
    assert_eq!(origin(&l), o("none", "na", "0", "-1"));
    let l = line(&mut h, r2, stats0());
    assert_eq!(origin(&l), o("none", "connect_fail", "0", "-1"));
    let l = line(&mut h, r3, stats0());
    assert_eq!(field(&l, "status"), "403");
    let l = line(&mut h, r4, stats0());
    assert!(
        l.contains(" method=- status=0 authority=\"-\" path=\"-\" "),
        "{l}"
    );
}
