//! The origin bridge against a real hyper h1 origin (spec §7.7 "h1 conns",
//! §10.3), on the `OriginLoop` / `OriginServer` harness.

use mq_http::headers::HttpVer;
use mq_integration::driver_harness::ResolveRequest;
use mq_integration::origin_loop::OriginLoop;
use mq_integration::origin_server::{
    Handler, ORIGIN_CA, ORIGIN_CRT, OriginServer, OriginServerMode, Proto, Then,
};
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec, upload_byte};
use mq_proxy::server::origin::{
    Accepted, Completion, ErrClass, OriginCfg, OriginFailure, OriginProto, RecordState, RelayHead,
    SWEEP, TlsOutcome, UPLOAD_CAP, build_client_config,
};
use mq_transport_api::H3ReqId;
use std::cell::Cell;
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);
const MIB: u64 = 1024 * 1024;

fn cfg() -> OriginCfg {
    OriginCfg {
        connect_timeout: Duration::from_secs(10),
        sweep: SWEEP,
    }
}

/// A bridge trusting `ca` only.
fn loop_with(cfg: OriginCfg, ca: &str) -> OriginLoop {
    let tls = build_client_config(Some(ca.as_ref()), &Vec::new).unwrap();
    OriginLoop::new(cfg, tls)
}

/// A bridge trusting the test origin CA only.
fn plain_loop() -> OriginLoop {
    loop_with(cfg(), ORIGIN_CA)
}

fn spec(method: &'static str, url: String, body: BodySpec) -> StartSpec {
    StartSpec {
        method,
        url,
        headers: Vec::new(),
        ver: HttpVer::Default,
        body,
    }
}

fn get(url: String) -> StartSpec {
    spec("GET", url, BodySpec::None)
}

fn spawn(proto: Proto, handler: Handler) -> OriginServer {
    OriginServer::spawn(OriginServerMode::new(proto, handler))
}

fn raw_h1(reply: &[u8]) -> OriginServer {
    let proto = Proto::RawH1 {
        tls: false,
        reply: reply.to_vec(),
    };
    spawn(proto, Handler::Echo)
}

fn keep_alive(replies: u32, then: Then) -> OriginServer {
    spawn(Proto::RawH1KeepAlive { replies, then }, Handler::Echo)
}

/// One request's events, gathered.
#[derive(Debug, Default)]
struct Outcome {
    head: Option<RelayHead>,
    body: Vec<u8>,
    frames: usize,
    end: Option<Completion>,
    fail: Option<(OriginFailure, bool)>,
}

impl Outcome {
    fn of(lp: &OriginLoop, h3: H3ReqId) -> Outcome {
        let mut o = Outcome::default();
        for e in lp.host().events() {
            match e {
                BridgeEv::Response(id, h) if *id == h3 => o.head = Some(h.clone()),
                BridgeEv::Frame(id, d) if *id == h3 => {
                    o.body.extend_from_slice(d);
                    o.frames += 1;
                }
                BridgeEv::End(id, done) if *id == h3 => o.end = Some(done.clone()),
                BridgeEv::Failure(id, f, after) if *id == h3 => o.fail = Some((f.clone(), *after)),
                _ => {}
            }
        }
        o
    }

    fn completion(&self) -> &Completion {
        assert!(self.fail.is_none(), "{self:?}");
        self.end.as_ref().expect("on_body_end")
    }

    /// A failure before the head.
    fn failure(&self) -> &OriginFailure {
        assert!(self.end.is_none(), "{self:?}");
        let (f, after) = self.fail.as_ref().expect("on_failure");
        assert!(!after, "{f:?}");
        f
    }
}

/// Runs until `h3` ended or failed.
fn wait(lp: &mut OriginLoop, h3: H3ReqId) -> Outcome {
    assert!(
        lp.run_until(T, |h| finished_in(h.events(), h3)),
        "{:?}",
        lp.host().events()
    );
    Outcome::of(lp, h3)
}

fn finished_in(evs: &[BridgeEv], h3: H3ReqId) -> bool {
    evs.iter()
        .any(|e| matches!(e, BridgeEv::End(id, _) | BridgeEv::Failure(id, ..) if *id == h3))
}

fn fetch(lp: &mut OriginLoop, s: StartSpec) -> (H3ReqId, Outcome) {
    let h3 = lp.start(s);
    (h3, wait(lp, h3))
}

/// Iterates until the loop hands a resolution to the resolver: `cx.dial`
/// only queues the dial, the next iterations start it.
fn next_resolve(lp: &mut OriginLoop) -> ResolveRequest {
    let end = Instant::now() + T;
    loop {
        lp.run_until(Duration::from_millis(5), |_| false);
        if let Some(r) = lp.resolver().next(Duration::from_millis(5)) {
            return r;
        }
        assert!(Instant::now() < end, "resolution started");
    }
}

fn pattern(n: u64) -> Vec<u8> {
    (0..n).map(upload_byte).collect()
}

fn url(srv: &OriginServer, path: &str) -> String {
    format!("http://{}{path}", srv.addr)
}

/// (curl, status, origin_tls) of a failure.
fn row(f: &OriginFailure) -> (u32, u16, TlsOutcome) {
    (f.curl, f.status, f.tls)
}

#[test]
fn h1_plain_echo_relays() {
    let srv = spawn(Proto::H1Plain, Handler::Echo);
    let mut lp = plain_loop();
    let (_, o) = fetch(
        &mut lp,
        spec("POST", url(&srv, "/echo"), BodySpec::Known(100_000)),
    );
    assert_eq!(o.completion().delivered, 100_000);
    let head = o.head.expect("on_response");
    assert_eq!((head.status, head.proto), (200, OriginProto::H1));
    assert!(o.body == pattern(100_000));
}

#[test]
fn h1_tls_echo_with_origin_ca() {
    const N: u64 = 100_000;
    let srv = spawn(Proto::H1Tls, Handler::Echo);
    let mut lp = plain_loop();
    let u = format!("https://{}/echo", srv.addr);
    let (_, o) = fetch(&mut lp, spec("POST", u, BodySpec::Known(N)));
    let done = o.completion();
    assert_eq!((done.delivered, done.tls), (N, TlsOutcome::Ok));
    let head = o.head.as_ref().expect("on_response");
    assert_eq!((head.status, head.proto), (200, OriginProto::H1));
    assert_eq!(head.version, "http/1.1");
    assert!(o.body == pattern(N));
}

#[test]
fn verify_failure_is_60_verify_fail() {
    let srv = spawn(Proto::H1Tls, Handler::FileBytes(10));
    // The leaf alone in the store: its issuer (the CA) is unknown.
    let mut lp = loop_with(cfg(), ORIGIN_CRT);
    let (_, o) = fetch(&mut lp, get(format!("https://{}/", srv.addr)));
    let f = o.failure();
    assert_eq!(row(f), (60, 502, TlsOutcome::VerifyFail), "{f:?}");
    assert_eq!(f.proto, None);
}

#[test]
fn connection_refused_is_7() {
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }; // closed: nothing listens there now
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(format!("http://{addr}/")));
    assert_eq!(row(o.failure()), (7, 502, TlsOutcome::Na));
}

/// The resolver's answer is held past the 2 s `OriginCfg` deadline (env vars
/// are never set in `cargo test`); a blackhole IP would bypass the resolver.
#[test]
fn dial_held_past_2s_timeout_is_28() {
    let cfg = OriginCfg {
        connect_timeout: Duration::from_secs(2),
        sweep: SWEEP,
    };
    let mut lp = loop_with(cfg, ORIGIN_CA);
    let t0 = Instant::now();
    let h3 = lp.start(get("http://blackhole.test/".into()));
    let held = next_resolve(&mut lp);
    assert_eq!((held.host.as_str(), held.port), ("blackhole.test", 80));
    let o = wait(&mut lp, h3);
    let took = t0.elapsed();
    assert_eq!(row(o.failure()), (28, 504, TlsOutcome::Na));
    assert!(took >= Duration::from_secs(2), "{took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    drop(held);
}

/// 8 MiB each way: the upload is refilled past `UPLOAD_CAP` many times and
/// the download crosses the 64 KiB pipe repeatedly.
#[test]
fn eight_mib_download_and_upload_exercise_pipe_caps() {
    const N: u64 = 8 * MIB;
    let routes = vec![("/file", Handler::FileBytes(N)), ("/echo", Handler::Echo)];
    let srv = spawn(Proto::H1Plain, Handler::PerPath(routes));
    let mut lp = plain_loop();

    let (_, o) = fetch(&mut lp, get(url(&srv, "/file")));
    assert_eq!(o.completion().delivered, N);
    assert_eq!(o.completion().cl, Some(N));
    assert!(o.body == pattern(N), "the download, in order");
    assert!(
        o.frames > 128,
        "{} frames: no frame exceeds the pipe",
        o.frames
    );

    let (h3, o) = fetch(
        &mut lp,
        spec("POST", url(&srv, "/echo"), BodySpec::Known(N)),
    );
    assert_eq!(o.completion().delivered, N);
    assert!(o.body == pattern(N), "the upload echoed, in order");
    let refills = lp
        .host()
        .events()
        .iter()
        .filter(|e| matches!(e, BridgeEv::WantH3(id) if *id == h3))
        .count() as u64;
    assert!(refills >= N / UPLOAD_CAP as u64 - 1, "{refills} refills");
    assert_eq!(srv.accepted(), 1, "the conn was reused");
}

#[test]
fn head_204_304_finish() {
    const N: u64 = 5000;
    let routes = vec![
        ("/204", Handler::Status(204)),
        ("/304", Handler::Status(304)),
        ("/file", Handler::FileBytes(N)),
    ];
    let srv = spawn(Proto::H1Plain, Handler::PerPath(routes));
    let mut lp = plain_loop();
    for (method, path, status) in [
        ("GET", "/204", 204),
        ("GET", "/304", 304),
        ("HEAD", "/file", 200),
    ] {
        let (_, o) = fetch(&mut lp, spec(method, url(&srv, path), BodySpec::None));
        assert_eq!(o.head.as_ref().map(|h| h.status), Some(status), "{path}");
        assert_eq!(o.completion().delivered, 0, "{method} {path}");
        assert_eq!(o.frames, 0);
    }
    assert_eq!(srv.accepted(), 1, "each exchange left the conn reusable");
}

#[test]
fn one_xx_then_200_skipped() {
    let srv = raw_h1(
        b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>\r\n\r\n\
          HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
    );
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(o.head.as_ref().map(|h| h.status), Some(200));
    assert_eq!(
        (o.completion().delivered, o.body.as_slice()),
        (2, &b"ok"[..])
    );
}

#[test]
fn trailers_dropped() {
    // h1: chunked with a trailer section.
    let srv = raw_h1(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n\
          2\r\nok\r\n0\r\nx-trailer: done\r\n\r\n",
    );
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(
        (o.completion().delivered, o.body.as_slice()),
        (2, &b"ok"[..])
    );
    assert_eq!(o.frames, 1, "the trailers are no frame");

    // h2: a TRAILERS frame after the data.
    let srv = spawn(Proto::H2Tls, Handler::Trailers(1000));
    let (_, o) = fetch(&mut lp, get(format!("https://{}/", srv.addr)));
    assert_eq!(o.head.as_ref().map(|h| h.proto), Some(OriginProto::H2));
    assert_eq!(o.completion().delivered, 1000);
    assert!(o.body == pattern(1000));
}

#[test]
fn sixty_set_cookie_in_order() {
    let srv = spawn(Proto::H1Plain, Handler::SetCookies(60));
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    o.completion();
    let cookies: Vec<Vec<u8>> = o
        .head
        .expect("on_response")
        .headers
        .into_iter()
        .filter(|(n, _)| n == b"set-cookie")
        .map(|(_, v)| v)
        .collect();
    let want: Vec<Vec<u8>> = (0..60).map(|i| format!("c{i}={i}").into_bytes()).collect();
    assert_eq!(cookies, want);
}

/// The gateway's own 64-header cap (§6.4), well inside hyper's 256.
#[test]
fn sixty_five_forwarded_headers_overflow() {
    let srv = spawn(Proto::H1Plain, Handler::Headers(65, 8));
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert!(f.upstream_protocol && f.status == 502, "{f:?}");
    assert_eq!(f.proto, Some(OriginProto::H1));
    assert!(o.head.is_none());
    assert!(
        lp.host().origin().error_classes().is_empty(),
        "not hyper's limit"
    );
}

fn head_257() -> (OriginLoop, OriginServer, Outcome) {
    let srv = spawn(Proto::H1Plain, Handler::Headers(257, 1));
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    (lp, srv, o)
}

/// hyper's h1 limits (`max_headers(256)`, `max_buf_size(64 KiB)`): 502
/// `upstream-protocol` through `is_parse_too_large`, not the gateway's cap.
#[test]
fn h1_257_headers_or_70k_head_is_upstream_protocol() {
    let (lp, _srv, o) = head_257();
    let f = o.failure();
    assert!(f.upstream_protocol && f.status == 502, "{f:?}");
    assert_eq!(
        lp.host().origin().error_classes(),
        [ErrClass::ParseTooLarge]
    );

    let srv = spawn(Proto::H1Plain, Handler::HeaderListBytes(70 * 1024));
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert!(f.upstream_protocol && f.status == 502, "{f:?}");
    assert_eq!(
        lp.host().origin().error_classes(),
        [ErrClass::ParseTooLarge]
    );
}

#[test]
fn h1_101_is_upgrade_error() {
    let srv = spawn(Proto::H1Plain, Handler::Upgrade101);
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert!(f.upstream_protocol && f.status == 502, "{f:?}");
    assert!(o.head.is_none());
}

fn nul_header() -> (OriginLoop, OriginServer, Outcome) {
    let srv = raw_h1(b"HTTP/1.1 200 OK\r\nx-a: a\0b\r\ncontent-length: 2\r\n\r\nok");
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    (lp, srv, o)
}

#[test]
fn h1_nul_header_value_is_8() {
    let (_lp, _srv, o) = nul_header();
    assert_eq!(row(o.failure()), (8, 502, TlsOutcome::Na));
}

/// A close-delimited (HTTP/1.0, `Connection: close`) body while the H3 side
/// holds every frame (`Partial`): once the bridge took the last frame from
/// `Incoming`, hyper reads the EOF and completes the connection (the conn
/// moves to `closing`) before that frame was accepted; the record keeps
/// being pumped and the body arrives whole.
#[test]
fn h1_close_delimited_under_h3_backpressure_delivers_all() {
    const N: u64 = 40_000;
    let srv = spawn(Proto::H1Plain, Handler::CloseDelimited(N));
    let mut lp = plain_loop();
    lp.with_host(|h, _| (0..64).for_each(|_| h.push_accept(Accepted::Partial(0))));
    let h3 = lp.start(get(url(&srv, "/")));
    let (end, mut completed_while_held) = (Instant::now() + T, false);
    while !finished_in(lp.host().events(), h3) {
        assert!(Instant::now() < end, "{:?}", Outcome::of(&lp, h3));
        // Each frame is held until `resume`; after the last one the EOF
        // completes hyper's connection.
        lp.run_until(Duration::from_millis(50), |h| {
            h.origin().closing_len() == 1 || finished_in(h.events(), h3)
        });
        completed_while_held |=
            lp.host().origin().closing_len() == 1 && !finished_in(lp.host().events(), h3);
        lp.with_host(|h, cx| h.resume(cx, h3));
    }
    assert!(
        completed_while_held,
        "hyper completed the conn under backpressure"
    );
    let o = Outcome::of(&lp, h3);
    assert!(o.frames > 1, "{} frames", o.frames);
    assert_eq!(o.completion().delivered, N);
    assert!(o.body == pattern(N));
    assert!(lp.run_until(T, |h| h.origin().closing_len() == 0));
    assert_eq!(lp.host().origin().pool_len(), 0);
}

fn close_without_response() -> (OriginLoop, OriginServer, Outcome) {
    let srv = spawn(Proto::H1Plain, Handler::CloseWithoutResponse);
    let mut lp = plain_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    (lp, srv, o)
}

/// Spec §7.7 retries only on a reused conn.
#[test]
fn h1_close_without_response_on_fresh_conn_is_52() {
    let (_lp, srv, o) = close_without_response();
    assert_eq!(row(o.failure()), (52, 502, TlsOutcome::Na));
    assert_eq!(srv.accepted(), 1, "no retry");
}

/// A first exchange that leaves the conn pooled; returns its request.
fn first_exchange(lp: &mut OriginLoop, srv: &OriginServer, u: &str) -> H3ReqId {
    let (h3, o) = fetch(lp, get(u.into()));
    assert_eq!(o.body, b"ok");
    let done = o.completion();
    assert!(!done.reused);
    assert_eq!(srv.accepted(), 1);
    h3
}

#[test]
fn h1_bodiless_retry_once_on_reused_conn() {
    let srv = keep_alive(1, Then::CloseAfterNextHead);
    let mut lp = plain_loop();
    let u = url(&srv, "/");
    let first = first_exchange(&mut lp, &srv, &u);
    let h3 = lp.start(get(u.clone()));
    let conn = lp.host().origin().conn_of(first);
    assert!(conn.is_some());
    assert_eq!(
        lp.host().origin().conn_of(h3),
        conn,
        "sent on the reused conn"
    );
    let o = wait(&mut lp, h3);
    assert_eq!(o.body, b"ok");
    let done = o.completion();
    assert!(!done.reused, "completed on the fresh conn");
    assert_eq!(srv.accepted(), 2, "exactly one retry");

    // With an upload body: no retry, a pre-head failure.
    let srv = keep_alive(1, Then::CloseAfterNextHead);
    let mut lp = plain_loop();
    let u = url(&srv, "/");
    first_exchange(&mut lp, &srv, &u);
    let (_, o) = fetch(&mut lp, spec("POST", u, BodySpec::Known(100)));
    assert_eq!(row(o.failure()), (52, 502, TlsOutcome::Na));
    assert_eq!(srv.accepted(), 1, "no retry");
}

/// 5.5b carried: the retried exchange's `connect_ms` runs from the retry
/// instant, not from the request's start. The loop sleeps (without
/// iterating) before it sees the origin's close, and the retry's resolve is
/// held for a while.
#[test]
fn h1_retry_connect_ms_from_the_retry_instant() {
    const GAP: Duration = Duration::from_millis(600);
    const HOLD: Duration = Duration::from_millis(150);
    let srv = keep_alive(1, Then::CloseAfterNextHead);
    let mut lp = plain_loop();
    let u = format!("http://origin.test:{}/", srv.addr.port());
    let answer = |lp: &mut OriginLoop| {
        let r = next_resolve(lp);
        assert_eq!(r.host, "origin.test");
        r
    };
    let h3 = lp.start(get(u.clone()));
    answer(&mut lp).answer(Ok(vec![srv.addr]));
    assert_eq!(wait(&mut lp, h3).body, b"ok");

    let h3 = lp.start(get(u));
    thread::sleep(GAP); // the origin reads the head and closes meanwhile
    // The retry dials on the iteration that sees the close.
    assert!(lp.run_until(T, |h| {
        h.origin().record_state(h3) == Some(RecordState::Connecting)
    }));
    let r = answer(&mut lp);
    thread::sleep(HOLD);
    r.answer(Ok(vec![srv.addr]));
    let o = wait(&mut lp, h3);
    let done = o.completion();
    assert!(!done.reused);
    let ms = done.connect_ms;
    assert!(
        ms >= HOLD.as_millis() as i64,
        "{ms} ms: the held resolve counts"
    );
    assert!(
        ms < GAP.as_millis() as i64,
        "{ms} ms: measured from the retry, not from the start"
    );
    assert_eq!(srv.accepted(), 2);
}

/// 5.5b carried: a reused conn that sent part of a head (`HTTP/1.1 200`)
/// before its EOF is `curl:56` and is not retried (the `rx == 0` guard).
#[test]
fn h1_reused_partial_head_then_eof_is_56_no_retry() {
    let srv = keep_alive(1, Then::PartialHeadAfterNextHead);
    let mut lp = plain_loop();
    let u = url(&srv, "/");
    first_exchange(&mut lp, &srv, &u);
    let (_, o) = fetch(&mut lp, get(u));
    assert_eq!(row(o.failure()), (56, 502, TlsOutcome::Na));
    assert_eq!(srv.accepted(), 1, "no retry");
    assert_eq!(lp.host().origin().error_classes(), [ErrClass::Incomplete]);
}

/// `CloseEvery`: the retry's fresh conn closes after the head too; the
/// retried exchange fails and is not handed back a second time.
#[test]
fn h1_retry_exhausted_fails_52() {
    let srv = keep_alive(1, Then::CloseEvery);
    let mut lp = plain_loop();
    let u = url(&srv, "/");
    first_exchange(&mut lp, &srv, &u);
    let (_, o) = fetch(&mut lp, get(u));
    assert_eq!(row(o.failure()), (52, 502, TlsOutcome::Na));
    assert_eq!(srv.accepted(), 2, "one retry, then the failure");
}

/// The idle conn died while the loop was not iterating: an iterated EOF
/// would complete hyper's idle `Connection` and evict the conn before any
/// reuse (`pool_evicts_after_server_closes`). The request is queued on the
/// dead conn; hyper hands it back (`Canceled`), and it is retried once.
fn dead_idle_retry() -> (OriginLoop, OriginServer, Outcome) {
    let srv = keep_alive(1, Then::CloseIdle(Duration::from_millis(50)));
    let mut lp = plain_loop();
    let u = url(&srv, "/");
    let first = first_exchange(&mut lp, &srv, &u);
    thread::sleep(Duration::from_millis(300));
    let h3 = lp.with_host(|h, cx| h.start_unpumped(cx, get(u)));
    let o = lp.host().origin();
    assert_eq!(o.record_state(h3), Some(RecordState::Assigned));
    assert_eq!(o.conn_of(h3), o.conn_of(first), "queued on the dead conn");
    assert!(lp.run_until(T, |h| {
        h.origin().record_state(h3) == Some(RecordState::Connecting)
    }));
    let o = wait(&mut lp, h3);
    (lp, srv, o)
}

#[test]
fn h1_dead_idle_conn_retried_once() {
    let (_lp, srv, o) = dead_idle_retry();
    assert_eq!(o.body, b"ok");
    assert!(!o.completion().reused);
    assert_eq!(srv.accepted(), 2);
}

#[test]
fn h1_reuse_origin_reuse_0_then_1() {
    let srv = spawn(Proto::H1Plain, Handler::FileBytes(10));
    let mut lp = plain_loop();
    let (_, a) = fetch(&mut lp, get(url(&srv, "/")));
    let (_, b) = fetch(&mut lp, get(url(&srv, "/")));
    let (a, b) = (a.completion(), b.completion());
    assert!(!a.reused && a.connect_ms >= 0, "{a:?}");
    assert_eq!((b.reused, b.connect_ms), (true, 0));
    assert_eq!(srv.accepted(), 1);
}

#[test]
fn pool_evicts_after_server_closes() {
    let srv = keep_alive(1, Then::CloseIdle(Duration::ZERO));
    let mut lp = plain_loop();
    first_exchange(&mut lp, &srv, &url(&srv, "/"));
    assert!(
        lp.run_until(T, |h| h.origin().pool_len() == 0),
        "the closed conn left the pool"
    );
    assert_eq!(lp.host().origin().closing_len(), 0);
}

#[test]
fn tls_origin_closing_mid_handshake_is_35_immediately() {
    let srv = spawn(Proto::RawTlsCloseAfterClientHello, Handler::Echo);
    let mut lp = plain_loop(); // a 10 s connect deadline
    let t0 = Instant::now();
    let (_, o) = fetch(&mut lp, get(format!("https://{}/", srv.addr)));
    assert_eq!(row(o.failure()), (35, 502, TlsOutcome::ConnectFail));
    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
}

/// A post-handshake fatal TLS error before the head: the pipe dies (class
/// E) and hyper reports an I/O error → `curl:56`.
fn fatal_alert() -> (OriginLoop, OriginServer, Outcome) {
    let srv = spawn(Proto::H1Tls, Handler::FatalAlertAfterHandshake);
    let mut lp = plain_loop();
    let h3 = lp.start(get(format!("https://{}/", srv.addr)));
    // The request is out once the conn is busy with it.
    assert!(lp.run_until(T, |h| h.origin().conn_of(h3).is_some()));
    lp.run_until(Duration::from_millis(200), |_| false);
    srv.release();
    let o = wait(&mut lp, h3);
    (lp, srv, o)
}

/// spec §7.6: every `ErrClass` but `Other` (no deterministic producer) from
/// a real hyper error, one producer each.
#[test]
fn classify_covers_real_errors() {
    let classes = |lp: &OriginLoop| lp.host().origin().error_classes().to_vec();

    let (lp, _srv, o) = close_without_response();
    assert_eq!(o.failure().curl, 52);
    assert_eq!(classes(&lp), [ErrClass::Incomplete]);

    let (lp, _srv, o) = head_257();
    assert!(o.failure().upstream_protocol);
    assert_eq!(classes(&lp), [ErrClass::ParseTooLarge]);

    let (lp, _srv, o) = nul_header();
    assert_eq!(o.failure().curl, 8);
    assert_eq!(classes(&lp), [ErrClass::Parse]);

    let (lp, _srv, o) = fatal_alert();
    assert_eq!(row(o.failure()), (56, 502, TlsOutcome::ConnectFail));
    assert_eq!(classes(&lp), [ErrClass::Io]);

    let (lp, _srv, o) = dead_idle_retry();
    o.completion();
    assert_eq!(
        classes(&lp),
        [ErrClass::Canceled],
        "the handed-back request"
    );
}

#[test]
fn run_until_times_out_when_pred_never_true() {
    let mut lp = plain_loop();
    let limit = Duration::from_millis(200);
    let t0 = Instant::now();
    assert!(!lp.run_until(limit, |_| false));
    let took = t0.elapsed();
    assert!(took >= limit, "returned early: {took:?}");
    assert!(took < limit + Duration::from_millis(50), "took {took:?}");
}

#[test]
fn run_until_twice_second_call_does_not_wait_for_first_limit() {
    let mut lp = plain_loop();
    // True on the second check: one iteration ran with the 5 s limit armed,
    // so the loop's cached wait is that limit.
    let checks = Cell::new(0);
    let t0 = Instant::now();
    assert!(lp.run_until(Duration::from_secs(5), |_| {
        checks.set(checks.get() + 1);
        checks.get() >= 2
    }));
    assert!(t0.elapsed() < Duration::from_secs(1));
    let t1 = Instant::now();
    assert!(!lp.run_until(Duration::from_millis(200), |_| false));
    let took = t1.elapsed();
    assert!(took < Duration::from_millis(300), "took {took:?}");
}
