// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The origin bridge against a real hyper h2 origin (spec §7.7 "h2 conns",
//! "Idle sweep", §10.3), on the `OriginLoop` / `OriginServer` harness.

use mq_http::headers::HttpVer;
use mq_integration::origin_loop::OriginLoop;
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, OriginHost, StartSpec, upload_byte};
use mq_proxy::server::origin::{
    Accepted, Completion, ErrClass, OriginCfg, OriginConnId, OriginFailure, OriginProto,
    RecordState, RelayHead, SWEEP, TlsOutcome, UPLOAD_CAP, build_client_config,
};
use mq_runtime::driver::Io;
use mq_transport_api::{H3ReqId, Time};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);
const MIB: u64 = 1024 * 1024;
/// The sweep interval of the retirement cases.
const SWEEP_TEST: Duration = Duration::from_millis(200);

fn loop_with_sweep(sweep: Duration) -> OriginLoop {
    let cfg = OriginCfg {
        connect_timeout: Duration::from_secs(10),
        sweep,
    };
    let tls = build_client_config(Some(ORIGIN_CA.as_ref()), &Vec::new).unwrap();
    OriginLoop::new(cfg, tls)
}

fn origin_loop() -> OriginLoop {
    loop_with_sweep(SWEEP)
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

fn post(url: String, body: BodySpec) -> StartSpec {
    spec("POST", url, body)
}

fn h2(handler: Handler) -> OriginServer {
    OriginServer::spawn(OriginServerMode::new(Proto::H2Tls, handler))
}

fn url(srv: &OriginServer, path: &str) -> String {
    format!("https://{}{path}", srv.addr)
}

fn ended(evs: &[BridgeEv]) -> bool {
    evs.iter()
        .any(|e| matches!(e, BridgeEv::End(..) | BridgeEv::Failure(..)))
}

fn finished_in(evs: &[BridgeEv], h3: H3ReqId) -> bool {
    evs.iter()
        .any(|e| matches!(e, BridgeEv::End(id, _) | BridgeEv::Failure(id, ..) if *id == h3))
}

fn responded(evs: &[BridgeEv], h3: H3ReqId) -> bool {
    evs.iter()
        .any(|e| matches!(e, BridgeEv::Response(id, _) if *id == h3))
}

/// One request's events, gathered.
#[derive(Debug, Default)]
struct Outcome {
    head: Option<RelayHead>,
    body: Vec<u8>,
    end: Option<Completion>,
    fail: Option<(OriginFailure, bool)>,
}

impl Outcome {
    fn of(lp: &OriginLoop, h3: H3ReqId) -> Outcome {
        let mut o = Outcome::default();
        for e in lp.host().events() {
            match e {
                BridgeEv::Response(id, h) if *id == h3 => o.head = Some(h.clone()),
                BridgeEv::Frame(id, d) if *id == h3 => o.body.extend_from_slice(d),
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

fn fetch(lp: &mut OriginLoop, s: StartSpec) -> (H3ReqId, Outcome) {
    let h3 = lp.start(s);
    (h3, wait(lp, h3))
}

/// Body bytes delivered so far for `h3`.
fn body_len(evs: &[BridgeEv], h3: H3ReqId) -> usize {
    evs.iter()
        .map(|e| match e {
            BridgeEv::Frame(id, d) if *id == h3 => d.len(),
            _ => 0,
        })
        .sum()
}

fn wait_head(lp: &mut OriginLoop, h3: H3ReqId) {
    assert!(
        lp.run_until(T, |h| responded(h.events(), h3)),
        "{:?}",
        lp.host().events()
    );
}

fn conn(lp: &OriginLoop, h3: H3ReqId) -> OriginConnId {
    lp.host().origin().conn_of(h3).expect("on a conn")
}

fn pattern(n: u64) -> Vec<u8> {
    (0..n).map(upload_byte).collect()
}

/// (curl, status, origin_tls) of a failure.
fn row(f: &OriginFailure) -> (u32, u16, TlsOutcome) {
    (f.curl, f.status, f.tls)
}

/// The conn stays pooled at every observation while the loop clock is
/// before `since + SWEEP_TEST` (the record has not aged one sweep), then is
/// retired by a sweep.
fn retired_once_aged(lp: &mut OriginLoop, since: Time) {
    let aged = since + SWEEP_TEST;
    loop {
        // Read the clock first: every iteration so far ran at or before it.
        let now = lp.core.io().now();
        if now >= aged {
            break;
        }
        assert_eq!(
            lp.host().origin().pool_len(),
            1,
            "retired at {now:?} < {aged:?}"
        );
        lp.run_until(Duration::from_millis(5), |_| false);
    }
    assert!(lp.run_until(T, |h| h.origin().pool_len() == 0), "retired");
}

/// Nothing of the bridge is left: no conn, no record, no executor task.
fn all_gone(h: &OriginHost) -> bool {
    let o = h.origin();
    o.pool_len() == 0 && o.closing_len() == 0 && o.task_count() == 0
}

#[test]
fn h2_tls_alpn_echo() {
    const N: u64 = 100_000;
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::H2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let url = format!("https://{}/echo", srv.addr);
    let h3 = lp.start(spec("POST", url, BodySpec::Known(N)));
    assert!(
        lp.run_until(T, |h| ended(h.events())),
        "{:?}",
        lp.host().events()
    );
    let mut body = Vec::new();
    let mut head = None;
    for e in lp.host().events() {
        match e {
            BridgeEv::Response(id, h) if *id == h3 => head = Some(h.clone()),
            BridgeEv::Frame(id, d) if *id == h3 => body.extend_from_slice(d),
            BridgeEv::End(_, done) => assert_eq!(done.delivered, N),
            BridgeEv::Failure(..) => panic!("{e:?}"),
            _ => {}
        }
    }
    let head = head.expect("on_response");
    assert_eq!(head.status, 200);
    assert_eq!(head.proto, OriginProto::H2);
    assert_eq!(head.version, "h2");
    assert_eq!(body.len() as u64, N);
    assert!(
        body.iter()
            .enumerate()
            .all(|(i, b)| *b == upload_byte(i as u64))
    );
}

/// `RawH2Tls`: the head arrives without END_STREAM; `release()` sends
/// SETTINGS(MAX_CONCURRENT_STREAMS = 1), GOAWAY(1) and DATA(END_STREAM) for
/// stream 1, so the response ends cleanly; the client ACKs both SETTINGS.
#[test]
fn raw_h2_frame_order() {
    const DATA: u8 = 0;
    const HEADERS: u8 = 1;
    const SETTINGS: u8 = 4;
    const GOAWAY: u8 = 7;
    const ACK: u8 = 0x1;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;
    let settings_in =
        |srv: &OriginServer| srv.frames().iter().filter(|f| **f == (SETTINGS, 0)).count();
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::RawH2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let url = format!("https://{}/", srv.addr);
    let h3 = lp.start(spec("GET", url, BodySpec::None));
    let head = |evs: &[BridgeEv]| evs.iter().any(|e| matches!(e, BridgeEv::Response(..)));
    assert!(
        lp.run_until(T, |h| head(h.events())),
        "{:?}",
        lp.host().events()
    );
    let before = srv.frames();
    assert_eq!(
        before.first(),
        Some(&(SETTINGS, 0)),
        "the client's SETTINGS"
    );
    assert!(before.contains(&(HEADERS, 1)), "{before:?}");
    srv.release();
    assert!(
        lp.run_until(T, |h| ended(h.events())),
        "{:?}",
        lp.host().events()
    );
    match lp.host().events().last() {
        Some(BridgeEv::End(id, done)) => assert_eq!((*id, done.delivered), (h3, 0)),
        e => panic!("{e:?}"),
    }
    assert_eq!(
        srv.sent(),
        [
            (SETTINGS, 0),
            (SETTINGS, ACK),
            (HEADERS, END_HEADERS),
            (SETTINGS, 0),
            (GOAWAY, 0),
            (DATA, END_STREAM),
        ]
    );
    // Inbound SETTINGS frames: the client's own, its ACK of the server's
    // first SETTINGS and its ACK of the released one. Keep the loop running
    // (in short slices) so the last ACK is written.
    let end = Instant::now() + T;
    while settings_in(&srv) < 3 && Instant::now() < end {
        lp.run_until(Duration::from_millis(20), |_| false);
    }
    assert_eq!(settings_in(&srv), 3, "{:?}", srv.frames());
}

#[test]
fn h2_reuse_origin_reuse_0_then_1() {
    let srv = h2(Handler::FileBytes(10));
    let mut lp = origin_loop();
    let (a, oa) = fetch(&mut lp, get(url(&srv, "/")));
    let (b, ob) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(oa.head.as_ref().map(|h| h.proto), Some(OriginProto::H2));
    let (da, db) = (oa.completion(), ob.completion());
    assert!(!da.reused && da.connect_ms >= 0, "{da:?}");
    assert_eq!((db.reused, db.connect_ms), (true, 0));
    assert_eq!(conn(&lp, a), conn(&lp, b));
    assert_eq!(srv.accepted(), 1);
}

/// §7.2 step 2: `active < current_max_send_streams()`. The second `start`
/// follows the first `on_response`, so the server's SETTINGS were processed
/// (before them hyper's initial value is 100).
#[test]
fn h2_hit_limited_by_max_concurrent_streams_then_second_dial() {
    const N: u64 = 100_000;
    let srv = OriginServer::spawn(OriginServerMode {
        max_concurrent_streams: Some(1),
        ..OriginServerMode::new(Proto::H2Tls, Handler::FileBytes(N))
    });
    let mut lp = origin_loop();
    lp.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    let first = lp.start(get(url(&srv, "/")));
    wait_head(&mut lp, first);
    assert_eq!(
        lp.host().origin().record_state(first),
        Some(RecordState::Assigned),
        "held by the H3 side"
    );
    let second = lp.start(get(url(&srv, "/")));
    assert_eq!(
        lp.host().origin().record_state(second),
        Some(RecordState::Connecting),
        "the stream limit: a dial"
    );
    assert_eq!(wait(&mut lp, second).completion().delivered, N);
    assert_ne!(conn(&lp, first), conn(&lp, second));
    lp.with_host(|h, cx| h.resume(cx, first));
    let o = wait(&mut lp, first);
    assert_eq!(o.completion().delivered, N);
    assert!(o.body == pattern(N));
    assert_eq!(srv.accepted(), 2);
    assert_eq!(lp.host().origin().pool_len(), 2);
}

/// An `Ended`-unreleased record (an upload hyper holds at zero send
/// capacity) makes the conn drain; the origin's RST_STREAM(NO_ERROR)
/// releases it and the conn takes assignments again.
#[test]
fn h2_draining_blocks_new_assignments_until_released() {
    let srv = h2(Handler::PerPath(vec![
        ("/stall", Handler::EarlyOkKeepBodyUnread),
        ("/f", Handler::FileBytes(10)),
    ]));
    let mut lp = origin_loop();
    let (warm, _) = fetch(&mut lp, get(url(&srv, "/f")));
    let a = conn(&lp, warm);
    let (stall, o) = fetch(&mut lp, post(url(&srv, "/stall"), BodySpec::Known(8 * MIB)));
    o.completion();
    assert_eq!(conn(&lp, stall), a);
    let org = lp.host().origin();
    assert!(org.draining(a) && org.ended_records(a) == 1);

    let (other, o) = fetch(&mut lp, get(url(&srv, "/f")));
    assert!(!o.completion().reused, "draining: no assignment");
    assert_ne!(conn(&lp, other), a);
    assert_eq!(srv.accepted(), 2);

    srv.reset_stream("/stall");
    assert!(lp.run_until(T, |h| !h.origin().draining(a)));
    assert_eq!(lp.host().origin().ended_records(a), 0);
    let (again, o) = fetch(&mut lp, get(url(&srv, "/f")));
    assert!(o.completion().reused);
    assert_eq!(conn(&lp, again), a, "the first conn is hit again");
    assert_eq!(srv.accepted(), 2);
}

/// Dropping the response future resets the stream (RST_STREAM CANCEL) and
/// drops the body even while hyper holds it at zero send capacity: the
/// record is released at once, the conn never drains.
#[test]
fn h2_cancel_before_head_resets_stream_and_releases() {
    let srv = h2(Handler::PerPath(vec![
        ("/hang", Handler::HangNoResponse),
        ("/f", Handler::FileBytes(10)),
    ]));
    let mut lp = origin_loop();
    let (warm, _) = fetch(&mut lp, get(url(&srv, "/f")));
    let a = conn(&lp, warm);
    let h3 = lp.start(post(url(&srv, "/hang"), BodySpec::Known(8 * MIB)));
    assert_eq!(conn(&lp, h3), a);
    lp.run_until(Duration::from_millis(200), |_| false);
    assert!(Outcome::of(&lp, h3).head.is_none());
    lp.cancel(h3);
    let org = lp.host().origin();
    assert_eq!(org.ended_records(a), 0, "released at the cancel's settling");
    assert!(!org.draining(a));
    assert_eq!(org.task_count(), 1, "the ConnTask alone");
    let (again, o) = fetch(&mut lp, get(url(&srv, "/f")));
    assert!(o.completion().reused);
    assert_eq!(conn(&lp, again), a);
    assert!(
        !lp.host()
            .events()
            .iter()
            .any(|e| matches!(e, BridgeEv::Failure(id, ..) | BridgeEv::End(id, _) if *id == h3)),
        "a cancelled request reports nothing"
    );
}

/// 5.5a carried: a cancel after the head with the upload `Pending` on
/// `want_h3` (not at zero capacity) aborts it, hyper's next poll fails the
/// body and drops it — released at the cancel's settling, not draining.
/// The only external producer of `OriginReq::end`'s `!fin` abort.
#[test]
fn h2_cancel_after_head_incomplete_upload_releases_not_draining() {
    let srv = h2(Handler::Echo);
    let mut lp = origin_loop();
    let h3 = lp.start(post(url(&srv, "/echo"), BodySpec::Stalled(100_000)));
    wait_head(&mut lp, h3);
    let a = conn(&lp, h3);
    assert!(lp.run_until(T, |h| body_len(h.events(), h3) == 100_000));
    lp.cancel(h3);
    let org = lp.host().origin();
    assert_eq!(org.ended_records(a), 0, "released with the abort");
    assert!(!org.draining(a));
    let (again, o) = fetch(&mut lp, post(url(&srv, "/echo"), BodySpec::Known(10)));
    assert!(o.completion().reused);
    assert!(o.body == pattern(10));
    assert_eq!(conn(&lp, again), a);
    assert_eq!(srv.accepted(), 1);
}

/// §7.7: a `Completed` h2 conn with no record left is removed at the
/// settling where its last record dropped (class B) — not by the sweep,
/// which runs every 10 s here.
#[test]
fn h2_empty_completed_conn_removed_at_settling_class_b() {
    const AFTER: u64 = 64 * 1024;
    let srv = h2(Handler::GoawayMidResponse(AFTER));
    let mut lp = origin_loop();
    let t0 = Instant::now();
    let (h3, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(o.completion().delivered, 2 * AFTER);
    let a = conn(&lp, h3);
    assert!(lp.run_until(T, |h| h.origin().pool_len() == 0));
    assert!(t0.elapsed() < SWEEP);
    let org = lp.host().origin();
    assert!(org.pipe_dead(a));
    assert_eq!(org.closing_len(), 0);
    assert!(!org.idle_timer_armed(), "nothing left to sweep");
    assert!(lp.run_until(T, |h| h.origin().task_count() == 0));
}

#[test]
fn h2_idle_since_on_active_zero() {
    let srv = h2(Handler::FileBytes(1000));
    let mut lp = origin_loop();
    lp.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    let first = lp.start(get(url(&srv, "/")));
    wait_head(&mut lp, first);
    let a = conn(&lp, first);
    assert_eq!(lp.host().origin().idle_since(a), None, "active 1");
    lp.with_host(|h, cx| h.resume(cx, first));
    wait(&mut lp, first).completion();
    let t1 = lp.host().origin().idle_since(a).expect("active 0");
    let second = lp.start(get(url(&srv, "/")));
    assert_eq!(conn(&lp, second), a);
    assert_eq!(
        lp.host().origin().idle_since(a),
        None,
        "cleared on assignment"
    );
    wait(&mut lp, second).completion();
    let t2 = lp.host().origin().idle_since(a).expect("active 0 again");
    assert!(t2 > t1, "{t1:?} {t2:?}");
}

/// Review Focus 4: an origin that answers early (END_STREAM) and never reads
/// the 8 MiB upload — no WINDOW_UPDATE, no RST — leaves hyper's send side at
/// zero capacity with the `UploadBody` held: a stuck `Ended` record. The
/// conn drains and is retired (class E) at the sweep once the record aged
/// one interval. A bodiless warm-up exchange first, so the server's SETTINGS
/// (1 MiB windows) are processed before the upload starts.
#[test]
fn stuck_upload_drains_then_retires_at_sweep() {
    let srv = h2(Handler::EarlyOkKeepBodyUnread);
    let mut lp = loop_with_sweep(SWEEP_TEST);
    let (warm, _) = fetch(&mut lp, get(url(&srv, "/warm")));
    let a = conn(&lp, warm);
    let (_, o) = fetch(&mut lp, post(url(&srv, "/up"), BodySpec::Known(8 * MIB)));
    assert_eq!(o.head.as_ref().map(|h| h.status), Some(200));
    o.completion();
    drains_then_retires(&mut lp, &srv, a);
}

/// The cancel variant: the head comes without END_STREAM, the response body
/// is gated and the upload unread. Once hyper took the whole 1 MiB window the
/// pipe waits for capacity and never polls the body again; the client's
/// cancel then ends the `Assigned` record with the abort, unreleased — the
/// conn drains and is retired at the sweep as above.
#[test]
fn stuck_upload_cancelled_after_head_drains_then_retires_at_sweep() {
    let srv = h2(Handler::PerPath(vec![
        ("/warm", Handler::FileBytes(10)),
        ("/up", Handler::GatedKeepBodyUnread(1000)),
    ]));
    let mut lp = loop_with_sweep(SWEEP_TEST);
    let (warm, _) = fetch(&mut lp, get(url(&srv, "/warm")));
    let a = conn(&lp, warm);
    let h3 = lp.start(post(url(&srv, "/up"), BodySpec::Known(8 * MIB)));
    wait_head(&mut lp, h3);
    // `UploadBuf` is topped up to `UPLOAD_CAP` on every refill: past this
    // mark hyper has taken at least the 1 MiB window.
    let window_taken = MIB + UPLOAD_CAP as u64;
    assert!(
        lp.run_until(T, |h| h.upload_buffered(h3) >= window_taken),
        "{}",
        lp.host().upload_buffered(h3)
    );
    assert_eq!(
        lp.host().origin().record_state(h3),
        Some(RecordState::Assigned)
    );
    lp.cancel(h3);
    drains_then_retires(&mut lp, &srv, a);
}

/// The common tail: one aborted `Ended` record left unreleased, the conn
/// draining (a probe dials rather than joining it), retired once aged.
fn drains_then_retires(lp: &mut OriginLoop, srv: &OriginServer, a: OriginConnId) {
    let org = lp.host().origin();
    let [rec] = org.ended(a)[..] else {
        panic!("{:?}", org.ended(a))
    };
    assert!(!rec.fin && rec.aborted, "the incomplete upload is aborted");
    assert!(org.draining(a));
    assert_eq!(org.pool_len(), 1);

    // No new assignment: the probe dials; its dial is cancelled.
    let probe = lp.start(get(url(srv, "/warm")));
    assert_eq!(
        lp.host().origin().record_state(probe),
        Some(RecordState::Connecting)
    );
    lp.cancel(probe);
    assert_eq!(lp.host().origin().record_state(probe), None);

    retired_once_aged(lp, rec.since);
    assert!(lp.host().origin().pipe_dead(a));
    assert!(lp.run_until(T, all_gone));
}

#[test]
fn early_response_with_rst_no_error_keeps_conn_reusable() {
    let srv = h2(Handler::EarlyOkThenRstNoError);
    let mut lp = origin_loop();
    let (h3, o) = fetch(&mut lp, post(url(&srv, "/"), BodySpec::Known(8 * MIB)));
    o.completion();
    let a = conn(&lp, h3);
    assert!(lp.run_until(T, |h| {
        let o = h.origin();
        o.ended_records(a) == 0 && !o.draining(a)
    }));
    let (again, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert!(o.completion().reused);
    assert_eq!(conn(&lp, again), a);
    assert_eq!(srv.accepted(), 1);
}

/// hyper's public `Connection` completes on the graceful GOAWAY while the
/// `ConnTask` keeps driving the accepted stream: the response (larger than
/// the 2 MiB stream window, so WINDOW_UPDATEs flow after the GOAWAY) is
/// delivered whole, and a new request dials instead of being assigned.
#[test]
fn goaway_mid_response_completes_and_blocks_new() {
    const AFTER: u64 = 1536 * 1024;
    let srv = h2(Handler::PerPath(vec![
        ("/big", Handler::GoawayMidResponse(AFTER)),
        ("/f", Handler::FileBytes(10)),
    ]));
    let mut lp = origin_loop();
    lp.with_host(|h, _| h.push_accept(Accepted::Partial(0)));
    let first = lp.start(get(url(&srv, "/big")));
    wait_head(&mut lp, first);
    let a = conn(&lp, first);
    assert!(
        lp.run_until(T, |h| h.origin().draining(a)),
        "the GOAWAY completed the public future"
    );
    assert_eq!(
        lp.host().origin().record_state(first),
        Some(RecordState::Assigned)
    );
    let (second, o) = fetch(&mut lp, get(url(&srv, "/f")));
    assert!(!o.completion().reused);
    assert_ne!(conn(&lp, second), a);
    assert_eq!(srv.accepted(), 2);

    lp.with_host(|h, cx| h.resume(cx, first));
    let o = wait(&mut lp, first);
    assert_eq!(o.completion().delivered, 2 * AFTER);
    assert!(o.body == pattern(2 * AFTER));
    assert!(lp.run_until(T, |h| h.origin().pipe_dead(a)), "class B");
    assert_eq!(lp.host().origin().pool_len(), 1, "the second conn");
}

const HEADERS: u8 = 1;

/// spec §10.3 "queued behind the stream limit": the second request is on
/// hyper's dispatch channel when SETTINGS(MAX_CONCURRENT_STREAMS = 1) +
/// GOAWAY(1) arrive. The public `ClientTask` sees the GOAWAY before any
/// pending open (h2 0.4.19 streams.rs:1075) and returns
/// `Ok(Dispatched::Shutdown)` without taking it; the bridge drops the future
/// and the `SendRequest`, and the queued `Envelope` fails `Canceled`
/// (`curl:56`) instead of hanging.
#[test]
fn queued_request_behind_lowered_limit_fails_56_on_goaway() {
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::RawH2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let first = lp.start(get(url(&srv, "/")));
    wait_head(&mut lp, first);
    let a = conn(&lp, first);
    lp.with_host(|h, _| h.origin_mut().hold_public_poll(a, true));
    let second = lp.start(get(url(&srv, "/")));
    assert_eq!(conn(&lp, second), a, "a hit: active 1 < 100");
    srv.release();
    let o = wait(&mut lp, first);
    assert_eq!(o.completion().delivered, 0, "through the ConnTask");
    assert!(!srv.frames().contains(&(HEADERS, 3)), "{:?}", srv.frames());
    assert!(!finished_in(lp.host().events(), second));

    lp.with_host(|h, cx| {
        h.origin_mut().hold_public_poll(a, false);
        h.pump(cx);
    });
    let o = wait(&mut lp, second);
    assert_eq!(row(o.failure()), (56, 502, TlsOutcome::ConnectFail));
    assert_eq!(o.failure().proto, Some(OriginProto::H2));
    assert_eq!(lp.host().origin().error_classes(), [ErrClass::Canceled]);
    assert!(lp.run_until(T, all_gone));
    assert!(!srv.frames().contains(&(HEADERS, 3)));

    let third = lp.start(get(url(&srv, "/")));
    wait_head(&mut lp, third);
    assert_ne!(conn(&lp, third), a);
    assert_eq!(srv.accepted(), 2);
}

/// The same sequence without the gate: the pump polls the public future
/// before the executor tasks (§7.3 step 2), so stream 3 opens before
/// SETTINGS(1) is processed; GOAWAY(last_stream_id = 1) fails it (`curl:56`),
/// with no retry.
#[test]
fn stream_opened_before_lowered_limit_fails_56_on_goaway() {
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::RawH2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let first = lp.start(get(url(&srv, "/")));
    wait_head(&mut lp, first);
    let second = lp.start(get(url(&srv, "/")));
    assert_eq!(conn(&lp, second), conn(&lp, first));
    let end = Instant::now() + T;
    while !srv.frames().contains(&(HEADERS, 3)) {
        assert!(Instant::now() < end, "{:?}", srv.frames());
        lp.run_until(Duration::from_millis(10), |_| false);
    }
    srv.release();
    let o = wait(&mut lp, second);
    assert_eq!(row(o.failure()), (56, 502, TlsOutcome::ConnectFail));
    assert_eq!(wait(&mut lp, first).completion().delivered, 0);
    assert!(lp.run_until(T, all_gone));
    assert_eq!(srv.accepted(), 1, "no retry");
}

#[test]
fn h1_forced_request_against_h2_only_pool_dials_new() {
    let srv = h2(Handler::FileBytes(10));
    let mut lp = origin_loop();
    let (a, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(o.head.as_ref().map(|h| h.proto), Some(OriginProto::H2));
    let forced = StartSpec {
        ver: HttpVer::H1,
        ..get(url(&srv, "/"))
    };
    let (b, o) = fetch(&mut lp, forced);
    assert_eq!(o.head.as_ref().map(|h| h.proto), Some(OriginProto::H1));
    assert!(!o.completion().reused);
    assert_ne!(conn(&lp, a), conn(&lp, b));
    assert_eq!(lp.host().origin().pool_len(), 2);
    assert_eq!(srv.accepted(), 2);
}

/// A post-handshake fatal TLS error on an h2 conn with two exchanges: class
/// E, hyper reports each from the dead pipe (`curl:56` before the head), and
/// the conn leaves `closing` once both ended.
#[test]
fn fatal_tls_alert_two_exchanges_fail_and_conn_removed() {
    let srv = h2(Handler::FatalAlertAfterHandshake);
    let mut lp = origin_loop();
    let first = lp.start(get(url(&srv, "/")));
    assert!(lp.run_until(T, |h| {
        h.origin().record_state(first) == Some(RecordState::Assigned)
    }));
    let second = lp.start(get(url(&srv, "/")));
    let a = conn(&lp, first);
    assert_eq!(conn(&lp, second), a);
    assert_eq!(
        lp.host().origin().record_state(second),
        Some(RecordState::Assigned)
    );
    lp.run_until(Duration::from_millis(200), |_| false);
    srv.release();
    for h3 in [first, second] {
        let o = wait(&mut lp, h3);
        assert_eq!(row(o.failure()), (56, 502, TlsOutcome::ConnectFail));
    }
    assert!(lp.host().origin().pipe_dead(a));
    assert!(lp.run_until(T, all_gone));
}

/// Two stuck uploads next to a live download on one conn: not retired while
/// the download is `Assigned`; the origin resetting one stall releases it;
/// the other retires the conn at a sweep once the download ended.
#[test]
fn two_stalls_next_to_live_download_not_retired_until_done() {
    const DL: u64 = 8 * MIB;
    let srv = h2(Handler::PerPath(vec![
        ("/stall1", Handler::EarlyOkKeepBodyUnread),
        ("/stall2", Handler::EarlyOkKeepBodyUnread),
        ("/dl", Handler::FileBytesGated(DL)),
    ]));
    let mut lp = loop_with_sweep(SWEEP_TEST);
    let dl = lp.start(get(url(&srv, "/dl")));
    wait_head(&mut lp, dl);
    let a = conn(&lp, dl);
    // Two `start`s with no loop iteration between them (no response can
    // arrive): stall1's pump takes the whole 1 MiB connection window, which
    // is also its stream window; stall2 then waits at zero capacity with
    // nothing sent, so its reset frees no capacity that stall1 could use
    // (stall1 would then poll its aborted body and be released too).
    let stalls = [
        lp.start(post(url(&srv, "/stall1"), BodySpec::Known(8 * MIB))),
        lp.start(post(url(&srv, "/stall2"), BodySpec::Known(8 * MIB))),
    ];
    for s in stalls {
        wait(&mut lp, s).completion();
        assert_eq!(conn(&lp, s), a);
    }
    assert_eq!(lp.host().origin().ended_records(a), 2);
    assert!(lp.host().origin().draining(a));

    // Several sweeps with the download live: no retirement.
    lp.run_until(4 * SWEEP_TEST, |_| false);
    assert_eq!(lp.host().origin().pool_len(), 1);
    assert!(!finished_in(lp.host().events(), dl));

    srv.reset_stream("/stall2");
    assert!(lp.run_until(T, |h| h.origin().ended_records(a) == 1));
    assert_eq!(lp.host().origin().pool_len(), 1);

    srv.release();
    let o = wait(&mut lp, dl);
    assert_eq!(o.completion().delivered, DL);
    assert!(o.body == pattern(DL));
    assert!(lp.run_until(T, |h| h.origin().pool_len() == 0), "retired");
    assert!(lp.host().origin().pipe_dead(a));
    assert!(lp.run_until(T, all_gone));
}

/// A body of exactly the 1 MiB window + 1 byte: hyper sends 1 MiB, then
/// holds the final 1-byte DATA(END_STREAM) at zero capacity — the upload
/// reached its fin (no abort), yet the body is never released.
#[test]
fn stuck_eos_variant_retires() {
    let srv = h2(Handler::EarlyOkKeepBodyUnread);
    let mut lp = loop_with_sweep(SWEEP_TEST);
    let (warm, _) = fetch(&mut lp, get(url(&srv, "/warm")));
    let a = conn(&lp, warm);
    let (_, o) = fetch(&mut lp, post(url(&srv, "/up"), BodySpec::Known(MIB + 1)));
    o.completion();
    let org = lp.host().origin();
    let [rec] = org.ended(a)[..] else {
        panic!("{:?}", org.ended(a))
    };
    assert!(
        rec.fin && !rec.aborted,
        "the EOS variant: the whole upload is buffered, nothing aborted"
    );
    assert!(org.draining(a));
    retired_once_aged(&mut lp, rec.since);
    assert!(lp.host().origin().pipe_dead(a));
    assert!(lp.run_until(T, all_gone));
}

/// An origin answering 200 before reading an 8 MiB upload leaks neither a
/// conn nor a stream. h1: the conn is not pooled (class C/E) and nothing is
/// left. h2: the RST_STREAM(NO_ERROR) releases the stream and the conn stays
/// reusable (§7.7) — its `ConnTask` is the only executor task left.
#[test]
fn early_200_before_8mib_upload_leaks_nothing() {
    for (proto, pooled) in [(Proto::H1Plain, 0), (Proto::H2Tls, 1)] {
        let scheme = if pooled == 1 { "https" } else { "http" };
        let srv = OriginServer::spawn(OriginServerMode::new(proto, Handler::EarlyOkThenRstNoError));
        let mut lp = origin_loop();
        let u = format!("{scheme}://{}/", srv.addr);
        let h3 = lp.start(post(u, BodySpec::Known(8 * MIB)));
        assert!(lp.run_until(T, |h| finished_in(h.events(), h3)));
        let settled = |h: &OriginHost| {
            let o = h.origin();
            o.pool_len() == pooled && o.closing_len() == 0 && o.task_count() == pooled
        };
        assert!(lp.run_until(T, settled), "pooled={pooled}");
        let org = lp.host().origin();
        assert_eq!(org.record_state(h3), None);
        if pooled == 1 {
            let a = conn(&lp, h3);
            assert_eq!(org.ended_records(a), 0);
            assert!(!org.draining(a));
        }
    }
}

/// hyper's h2 `max_header_list_size` is `SECTION_MAX + 1` (SP4 spec §5): any
/// head over 32769 bytes is an h2 protocol error → `curl:56`.
#[test]
fn h2_head_over_section_is_56() {
    let srv = h2(Handler::HeaderListBytes(40 * 1024));
    let mut lp = origin_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert_eq!(row(f), (56, 502, TlsOutcome::ConnectFail));
    assert!(!f.upstream_protocol);
}

/// A head under hyper's h2 limit with one 9 KiB field reaches the gateway,
/// whose own 8192-byte field cap rejects it: 502 `upstream-protocol`.
#[test]
fn h2_single_9k_field_upstream_protocol() {
    let srv = h2(Handler::HeaderListBytes(9 * 1024));
    let mut lp = origin_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert!(f.upstream_protocol && f.status == 502, "{f:?}");
}

/// 257 forwarded headers exceed the gateway's 256 count (`:status` and
/// `x-mq-origin-protocol` included), under the h2 section limit (257 × ~46
/// bytes < 32769): `HeadError::Overflow` keeps the h2 context.
#[test]
fn h2_normalisation_overflow_keeps_h2_context() {
    let srv = h2(Handler::Headers(257, 1));
    let mut lp = origin_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    let f = o.failure();
    assert_eq!(
        (f.proto, f.tls, f.upstream_protocol, f.status),
        (Some(OriginProto::H2), TlsOutcome::ConnectFail, true, 502)
    );
    assert!(o.head.is_none());
    assert!(lp.host().origin().error_classes().is_empty());
}

/// Review Focus 5: hyper reports an h2 RST_STREAM(NO_ERROR) mid-body as a
/// clean end; `on_body_end` carries what the §6.4 body check needs.
#[test]
fn h2_cl_100_then_rst_no_error_reports_short_body() {
    let srv = h2(Handler::ClTooShort { cl: 100, send: 50 });
    let mut lp = origin_loop();
    let (_, o) = fetch(&mut lp, get(url(&srv, "/")));
    assert_eq!(o.head.as_ref().map(|h| h.cl), Some(Some(100)));
    let done = o.completion();
    assert_eq!((done.delivered, done.cl), (50, Some(100)));
    assert!(o.body == pattern(50));
}
