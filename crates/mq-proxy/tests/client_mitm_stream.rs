//! SP4 spec §7.5–§7.8: `MStream` — one h2 stream ⇄ one H3 exchange. The
//! upload and its backpressure, the download's §7.6 gates, the settlement
//! table, admission, and open-stream liveness. The H3 side is scripted.

mod common;
mod mitm_harness;

use h2::Reason;
use mitm_harness::*;
use mq_proxy::client::mitm::MitmTuning;
use mq_runtime::TcpId;
use mq_runtime::testing::Call;
use mq_transport_api::{ConnId, Event, H3ReqId, StreamError};
use std::time::Duration;

const US: Duration = Duration::from_micros(1);
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const PING: u8 = 0x6;
const WINDOW_UPDATE: u8 = 0x8;
/// The h2 default window: the browser's unless `Browser::windows`.
const WIN: usize = 65_535;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn hs(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    (pairs.iter())
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

/// A MITM conn with a live tunnel conn and a handshaken browser.
struct T {
    mh: MH,
    b: Browser,
    tcp: TcpId,
    conn: ConnId,
}

impl T {
    fn new() -> T {
        T::with(Browser::new("example.com"))
    }

    fn with(b: Browser) -> T {
        T::on(MH::p256(), b)
    }

    /// `ca-p256` with `tuning`.
    fn tuned(tuning: MitmTuning) -> T {
        let mut c = cfg("ca-p256");
        c.tuning = tuning;
        T::on(MH::new(c), Browser::new("example.com"))
    }

    fn on(mut mh: MH, mut b: Browser) -> T {
        let conn = mh.t.new_conn_id();
        let now = mh.now;
        mh.sh.with_app(now, |a, _| a.tunnel = Some(conn));
        let tcp = mh.connect(&mut b);
        T { mh, b, tcp, conn }
    }

    /// The id the next exchange opened on the tunnel gets.
    fn next(&self) -> H3ReqId {
        let r = self.mh.t.new_h3_req_id();
        self.mh.t.expect_open_h3_request(self.conn, Ok(r));
        r
    }

    fn flow(&mut self) {
        self.mh.flow(&mut self.b, self.tcp);
    }

    fn relay(&mut self) {
        self.mh.relay(&mut self.b, self.tcp);
    }

    /// A request that opens an exchange; its id.
    fn req(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StreamHandle, H3ReqId) {
        let r = self.next();
        let s = self.b.request(method, path, headers, body);
        self.flow();
        (s, r)
    }

    fn streaming(&mut self, method: &str) -> (StreamHandle, H3ReqId) {
        let r = self.next();
        let s = self.b.request_streaming(method, "/up", &[]);
        self.flow();
        (s, r)
    }

    fn head(&mut self, r: H3ReqId, status: &str, extra: &[(&str, &str)], fin: bool) {
        let mut h = hs(&[(":status", status)]);
        h.extend(hs(extra));
        self.mh.t.inject_h3_headers(r, h, fin);
        self.flow();
    }

    fn body(&mut self, r: H3ReqId, bytes: &[u8], fin: bool) {
        self.mh.t.inject_h3_body(r, bytes.to_vec(), fin);
        self.flow();
    }

    fn count(&self, f: impl Fn(&Call) -> bool) -> usize {
        self.mh.t.log().iter().filter(|c| f(c)).count()
    }

    fn resets(&self, r: H3ReqId) -> usize {
        self.count(|c| *c == Call::H3Reset(r))
    }

    fn recvs(&self, r: H3ReqId) -> usize {
        self.count(|c| matches!(c, Call::H3RecvBody { r: x, .. } if *x == r))
    }

    /// Body bytes the core took from the transport.
    fn taken(&self, r: H3ReqId, injected: usize) -> usize {
        injected - self.mh.t.h3_body_unread(r)
    }

    /// Retained `MStream`s (`streams=` of the `mq.mitm` line).
    fn streams(&self) -> usize {
        let m = self.mh.metrics();
        let v = m.split(' ').find_map(|f| f.strip_prefix("streams="));
        v.expect("an mq.mitm line").parse().unwrap()
    }

    fn has(&self, kv: &str) -> bool {
        self.mh.metrics().split(' ').any(|f| f == kv)
    }

    /// DATA payload bytes the browser sent on h2 stream `sid`.
    fn sent_data(&self, sid: u32) -> usize {
        (self.b.sent_frames().iter())
            .filter(|f| f.ty == DATA && f.sid == sid)
            .map(|f| f.payload.len())
            .sum()
    }

    /// PINGs (not ACKs) the proxy sent.
    fn pings(&self) -> usize {
        (self.b.frames().iter())
            .filter(|f| f.ty == PING && f.flags & 1 == 0)
            .count()
    }

    fn cont_armed(&self) -> bool {
        self.mh.sh.next_timeout() == Some(self.mh.now)
    }
}

fn header<'a>(h: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    h.iter()
        .find(|(n, _)| n == name.as_bytes())
        .map(|(_, v)| &v[..])
}

// ---- round trips ----

#[test]
fn get_roundtrip_byte_exact() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/x?y=1", &[("accept", "*/*")], b"");
    let sent = t.mh.t.h3_headers_sent(r);
    let (h, fin) = &sent[0];
    assert!(*fin, "no body: the FIN rides the head");
    assert_eq!(header(h, ":method"), Some(&b"GET"[..]));
    assert_eq!(header(h, ":authority"), Some(&b"example.com"[..]));
    assert_eq!(header(h, ":path"), Some(&b"/x?y=1"[..]));
    assert_eq!(header(h, "x-mq-auth"), Some(&b"Bearer secret"[..]));
    assert_eq!(header(h, "accept"), Some(&b"*/*"[..]));
    let body = pattern(300_000);
    t.head(r, "200", &[("content-length", "300000")], false);
    t.body(r, &body, true);
    let (head, got) = t.b.response(&s).expect("complete");
    assert_eq!(head.status, 200);
    assert_eq!(head.headers["content-length"], "300000");
    assert!(got == body, "byte-exact");
    assert_eq!(t.streams(), 0);
    assert_eq!(t.resets(r), 0);
    assert!(t.has("reqs=1") && t.has("rejects=0"), "{}", t.mh.metrics());
}

#[test]
fn upload_known_cl_forwards_cl_and_body() {
    let mut t = T::new();
    let body = pattern(100_000);
    let (s, r) = t.req("POST", "/up", &[("content-length", "100000")], &body);
    let sent = t.mh.t.h3_headers_sent(r);
    let (h, fin) = &sent[0];
    assert!(!*fin);
    assert_eq!(header(h, "content-length"), Some(&b"100000"[..]));
    assert!(t.mh.t.h3_sends(r).concat() == body);
    let fins: Vec<bool> = (t.mh.t.log().into_iter())
        .filter_map(|c| match c {
            Call::H3SendBody { r: x, fin, .. } if x == r => Some(fin),
            _ => None,
        })
        .collect();
    assert_eq!(fins.last(), Some(&true), "the FIN rides the last byte");
    assert!(fins[..fins.len() - 1].iter().all(|f| !f));
    assert_eq!(t.count(|c| *c == Call::H3Finish(r)), 0);
    t.head(r, "200", &[("content-length", "2")], false);
    t.body(r, b"ok", true);
    assert_eq!(t.b.response(&s).expect("complete").1, b"ok");
    assert_eq!(t.resets(r), 0);
}

#[test]
fn upload_streaming_bare_fin() {
    let mut t = T::new();
    let (s, r) = t.streaming("POST");
    t.b.send(&s, b"hello ", false);
    t.flow();
    t.b.send(&s, b"world", true);
    t.flow();
    let (h, fin) = &t.mh.t.h3_headers_sent(r)[0];
    assert!(!*fin);
    assert_eq!(header(h, "content-length"), None);
    assert_eq!(t.mh.t.h3_sends(r).concat(), b"hello world");
    let log = t.mh.t.log();
    let sends: Vec<usize> = (0..log.len())
        .filter(|&i| matches!(&log[i], Call::H3SendBody { r: x, .. } if *x == r))
        .collect();
    assert!(
        sends
            .iter()
            .all(|&i| matches!(&log[i], Call::H3SendBody { fin: false, .. }))
    );
    let finish: Vec<usize> = (0..log.len())
        .filter(|&i| log[i] == Call::H3Finish(r))
        .collect();
    assert_eq!(finish.len(), 1, "one bare FIN");
    assert!(finish[0] > *sends.last().unwrap());
}

#[test]
fn empty_data_frame_skipped() {
    let mut t = T::new();
    let (s, r) = t.streaming("POST");
    t.b.send(&s, b"", false);
    t.b.send(&s, b"abc", false);
    t.b.send(&s, b"", true); // hyper's END_STREAM terminator
    t.flow();
    let empty = (t.b.sent_frames().iter())
        .filter(|f| f.ty == DATA && f.payload.is_empty())
        .count();
    assert!(empty >= 1, "the browser sent empty DATA frames");
    assert_eq!(
        t.count(|c| matches!(c, Call::H3SendBody { bytes, .. } if bytes.is_empty())),
        0,
        "no zero-length h3_send_body"
    );
    assert_eq!(t.mh.t.h3_sends(r).concat(), b"abc");
    assert_eq!(t.count(|c| *c == Call::H3Finish(r)), 1);
}

// ---- upload backpressure ----

/// WINDOW_UPDATE increments the proxy granted on h2 stream `sid`.
fn grants(b: &Browser, sid: u32) -> u64 {
    (b.frames().iter())
        .filter(|f| f.ty == WINDOW_UPDATE && f.sid == sid)
        .map(|f| u32::from_be_bytes(f.payload[..4].try_into().unwrap()) as u64)
        .sum()
}

#[test]
fn upload_releases_capacity_only_as_accepted() {
    let mut t = T::new();
    let r = t.next();
    t.mh.t.expect_h3_send_body(r, Ok(1000));
    t.mh.t.expect_h3_send_body(r, Err(StreamError::Blocked));
    let s = t.b.request_streaming("POST", "/up", &[]);
    let body = pattern(600_000);
    t.b.send(&s, &body, true);
    t.flow();
    assert_eq!(t.mh.t.h3_sends(r).concat().len(), 1000);
    // Only the 256 KiB stream window went out, and no credit came back.
    assert_eq!(t.sent_data(1), 256 * 1024);
    assert_eq!(grants(&t.b, 1), 0);
    let tries = t.count(|c| matches!(c, Call::H3SendBody { r: x, .. } if *x == r));
    // Unrelated activity: no retry before `Writable`, no growth.
    let (s2, r2) = t.req("GET", "/other", &[], b"");
    t.head(r2, "200", &[("content-length", "2")], false);
    t.body(r2, b"ok", true);
    assert!(t.b.response(&s2).is_some());
    t.mh.advance(Duration::from_secs(1));
    t.flow();
    assert_eq!(
        t.count(|c| matches!(c, Call::H3SendBody { r: x, .. } if *x == r)),
        tries
    );
    assert_eq!(t.sent_data(1), 256 * 1024);
    assert_eq!(grants(&t.b, 1), 0);
    // Writable: the rest flows, credit returning as it is accepted.
    t.mh.t.push_event(Event::H3Writable(r));
    t.mh.drive();
    t.flow();
    assert!(t.mh.t.h3_sends(r).concat() == body);
    assert_eq!(t.count(|c| *c == Call::H3Finish(r)), 1);
    assert!(grants(&t.b, 1) > 0);
}

#[test]
fn cancel_blocked_upload_resets_once_conn_reusable() {
    let mut t = T::new();
    let r = t.next();
    t.mh.t.expect_h3_send_body(r, Err(StreamError::Blocked));
    let s = t.b.request_streaming("POST", "/up", &[]);
    t.b.send(&s, &pattern(600_000), false);
    t.flow();
    assert_eq!(t.sent_data(1), 256 * 1024);
    t.b.cancel(&s);
    t.flow();
    assert_eq!(t.resets(r), 1, "one reset");
    assert_eq!(t.streams(), 0);
    // No capacity leaked: two blocked uploads together get the whole
    // 512 KiB connection window again.
    let up: Vec<(StreamHandle, H3ReqId, Vec<u8>)> = (0..2)
        .map(|i| {
            let r = t.next();
            t.mh.t.expect_h3_send_body(r, Err(StreamError::Blocked));
            let s = t.b.request_streaming("POST", "/up", &[]);
            let body = pattern(300_000 + i);
            t.b.send(&s, &body, true);
            (s, r, body)
        })
        .collect();
    t.flow();
    assert_eq!(t.sent_data(3) + t.sent_data(5), 512 * 1024);
    for (_, r, _) in &up {
        t.mh.t.push_event(Event::H3Writable(*r));
    }
    t.mh.drive();
    t.flow();
    for (s, r, body) in &up {
        assert!(t.mh.t.h3_sends(*r).concat() == *body);
        t.head(*r, "200", &[("content-length", "2")], false);
        t.body(*r, b"ok", true);
        assert_eq!(t.b.response(s).expect("complete").1, b"ok");
    }
    assert_eq!(t.resets(r), 1);
}

// ---- download readiness and capacity ----

#[test]
fn download_waits_for_capacity_and_tls_room() {
    // Capacity: the browser holds its 64 KiB window.
    let mut t = T::new();
    t.b.hold_capacity(true);
    let (s, r) = t.req("GET", "/big", &[], b"");
    let body = pattern(1 << 20);
    t.head(r, "200", &[], false);
    t.body(r, &body, true);
    assert_eq!(t.taken(r, body.len()), WIN, "read only with capacity");
    t.mh.advance(Duration::from_secs(1));
    t.flow();
    assert_eq!(t.taken(r, body.len()), WIN);
    t.b.hold_capacity(false);
    t.b.release(&s);
    t.flow();
    assert!(t.b.response(&s).expect("complete").1 == body);

    // TLS room: huge windows, but the browser's socket is not read.
    let mut t = T::with(Browser::new("example.com").windows(1 << 24, 1 << 24));
    let (s, r) = t.req("GET", "/big", &[], b"");
    t.head(r, "200", &[], false);
    let body = pattern(2 << 20);
    t.mh.t.inject_h3_body(r, body.clone(), true);
    t.mh.drive();
    while t.cont_armed() {
        t.mh.drive();
    }
    let taken = t.taken(r, body.len());
    assert!((1..=512 * 1024).contains(&taken), "{taken}");
    t.mh.advance(Duration::from_secs(1));
    assert_eq!(t.taken(r, body.len()), taken, "no read without TLS room");
    t.flow();
    assert!(t.b.response(&s).expect("complete").1 == body);
}

#[test]
fn empty_end_stream_with_zero_capacity_completes() {
    let mut t = T::new();
    t.b.hold_capacity(true);
    let (a, ra) = t.req("GET", "/a", &[], b"");
    t.head(ra, "200", &[], false);
    t.body(ra, &pattern(WIN), false);
    assert_eq!(
        t.b.received(&a).len(),
        WIN,
        "the connection window is spent"
    );
    let (b, rb) = t.req("GET", "/b", &[], b"");
    t.head(rb, "200", &[], true);
    let (head, got) =
        t.b.response(&b)
            .expect("an empty END_STREAM needs no capacity");
    assert_eq!(head.status, 200);
    assert!(got.is_empty());
    assert_eq!(t.recvs(rb), 0, "the head's FIN: no transport read (R1)");
    assert_eq!(t.streams(), 1);
}

/// R1: a separate empty H3 FIN after a bodyless head is seen by the terminal
/// probe, so its END_STREAM needs no h2 credit, even with the upload open
/// before `H3Closed` arrives.
#[test]
fn separate_empty_fin_with_zero_capacity_and_open_upload_completes() {
    let mut t = T::new();
    t.b.hold_capacity(true);
    let (a, ra) = t.req("GET", "/a", &[], b"");
    t.head(ra, "200", &[], false);
    t.body(ra, &pattern(WIN), false);
    assert_eq!(
        t.b.received(&a).len(),
        WIN,
        "the connection window is spent"
    );
    let (b, rb) = t.streaming("POST");
    t.b.send(&b, b"abc", false);
    t.flow();
    t.head(rb, "200", &[("content-length", "0")], false);
    assert!(t.b.head(&b).is_some() && t.b.response(&b).is_none());
    t.body(rb, b"", true);
    let (head, got) = t.b.response(&b).expect("END_STREAM without credit");
    assert_eq!(head.status, 200);
    assert!(got.is_empty());
    assert_eq!(t.resets(rb), 1, "the early response resets the upload");
    assert_eq!(t.streams(), 1);
}

#[test]
fn buffered_data_capacity_grant_without_new_h3_event_delivers() {
    let mut t = T::new();
    t.b.hold_capacity(true);
    let (s, r) = t.req("GET", "/x", &[], b"");
    t.head(r, "200", &[], false);
    let body = pattern(WIN + 1000);
    t.body(r, &body, false);
    assert_eq!(t.b.received(&s).len(), WIN);
    assert_eq!(t.mh.t.h3_body_unread(r), 1000);
    // The grant alone, with no H3 notification, delivers the rest.
    t.b.hold_capacity(false);
    t.b.release(&s);
    t.flow();
    assert!(t.b.received(&s) == body);
    t.body(r, b"", true);
    assert!(t.b.response(&s).expect("complete").1 == body);
}

#[test]
fn idle_sse_quiescent_no_continuation() {
    let mut t = T::new();
    let (sse, r) = t.req("GET", "/events", &[], b"");
    t.head(r, "200", &[("content-type", "text/event-stream")], false);
    t.body(r, b"data: 1\n\n", false);
    assert_eq!(t.b.received(&sse), b"data: 1\n\n");
    // Payload reads; the terminal probe's empty read (R1) is not one.
    let payload =
        |t: &T| t.count(|c| matches!(c, Call::H3RecvBody { r: x, cap } if *x == r && *cap > 0));
    let reads = payload(&t);
    // Unrelated events: another stream's round trip, TCP writable, a timer.
    let (s2, r2) = t.req("GET", "/other", &[], b"");
    t.head(r2, "200", &[("content-length", "2")], false);
    t.body(r2, b"ok", true);
    assert!(t.b.response(&s2).is_some());
    t.mh.advance(Duration::from_secs(1));
    t.flow();
    assert_eq!(payload(&t), reads, "no read without readiness");
    assert!(!t.mh.sh.app().dirty(t.tcp), "dirty clear");
    assert!(!t.cont_armed(), "no continuation");
    assert_eq!(t.streams(), 1);
    t.body(r, b"data: 2\n\n", false);
    assert_eq!(t.b.received(&sse), b"data: 1\n\ndata: 2\n\n");
}

// ---- fairness ----

#[test]
fn four_idle_responses_do_not_starve_fifth() {
    let mut t = T::new(); // a 64 KiB browser connection window
    for i in 0..4 {
        let (_, r) = t.req("GET", &format!("/idle{i}"), &[], b"");
        t.head(r, "200", &[], false);
    }
    let (s, r) = t.req("GET", "/ready", &[], b"");
    let body = pattern(32 * 1024);
    t.head(r, "200", &[], false);
    t.body(r, &body, true);
    assert!(t.b.response(&s).expect("the fifth completes").1 == body);
    assert_eq!(t.streams(), 4);
}

#[test]
fn large_download_does_not_starve_second_stream() {
    let mut t = T::with(Browser::new("example.com").windows(1 << 24, 1 << 24));
    let (s1, r1) = t.req("GET", "/large", &[], b"");
    t.head(r1, "200", &[], false);
    let large = pattern(4 << 20);
    t.mh.t.inject_h3_body(r1, large.clone(), true);
    let mut pending = Vec::new();
    for _ in 0..3 {
        t.mh.flow_step(&mut t.b, t.tcp, &mut pending);
    }
    let r2 = t.next();
    let s2 = t.b.request("GET", "/small", &[], b"");
    for _ in 0..3 {
        t.mh.flow_step(&mut t.b, t.tcp, &mut pending);
    }
    assert!(
        t.mh.t.h3_headers_sent(r2).len() == 1,
        "the second exchange is open"
    );
    let small = pattern(64 * 1024);
    t.mh.t
        .inject_h3_headers(r2, hs(&[(":status", "200")]), false);
    t.mh.t.inject_h3_body(r2, small.clone(), true);
    let mut steps = 0;
    while t.b.response(&s2).is_none() {
        assert!(t.mh.flow_step(&mut t.b, t.tcp, &mut pending), "stalled");
        steps += 1;
    }
    assert!(t.b.response(&s2).unwrap().1 == small);
    assert!(t.b.response(&s1).is_none(), "the first is still going");
    let got = t.b.received(&s1).len();
    assert!(got > 0 && got < large.len(), "{got} after {steps} steps");
    t.flow();
    assert!(t.b.response(&s1).expect("complete").1 == large);
}

// ---- stream ends ----

#[test]
fn head_request_drains_exchange_and_removes_stream() {
    let mut t = T::new();
    let (s, r) = t.req("HEAD", "/h", &[], b"");
    t.head(r, "200", &[("content-length", "1234")], false);
    let (head, body) = t.b.response(&s).expect("ended toward the browser");
    assert_eq!(head.status, 200);
    assert_eq!(head.headers["content-length"], "1234");
    assert!(body.is_empty());
    assert_eq!(t.streams(), 1, "Drain until the H3 FIN");
    t.body(r, b"", true);
    assert_eq!(t.streams(), 0);
    assert_eq!(t.resets(r), 0);
}

#[test]
fn cancel_during_drain_resets_exchange() {
    let mut t = T::new();
    let (s, r) = t.streaming("POST");
    t.b.send(&s, b"abc", false);
    t.flow();
    t.head(r, "204", &[], false);
    assert_eq!(t.b.head(&s).expect("a head").status, 204);
    assert_eq!(t.streams(), 1, "Drain");
    t.b.cancel(&s);
    t.flow();
    assert_eq!(t.resets(r), 1);
    assert_eq!(t.streams(), 0);
}

#[test]
fn cancel_while_awaiting_head_resets() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/x", &[], b"");
    t.b.cancel(&s);
    t.flow();
    assert_eq!(t.resets(r), 1);
    assert_eq!(t.streams(), 0);
    t.head(r, "200", &[], true); // late: nobody reads it
    assert_eq!(t.resets(r), 1);
}

#[test]
fn early_response_then_rst_no_error_after_frames() {
    let mut t = T::new();
    let (s, r) = t.streaming("POST");
    t.b.send(&s, b"partial", false);
    t.flow();
    t.head(r, "200", &[("content-length", "5")], false);
    t.body(r, b"hello", true);
    let (head, body) = t.b.response(&s).expect("the full response");
    assert_eq!(head.status, 200);
    assert_eq!(body, b"hello");
    let frames: Vec<Frame> = t.b.frames().into_iter().filter(|f| f.sid == 1).collect();
    let types: Vec<u8> = frames.iter().map(|f| f.ty).collect();
    assert_eq!(types, vec![HEADERS, DATA, RST_STREAM], "{frames:?}");
    assert_eq!(frames[1].flags & 1, 1, "END_STREAM on the DATA");
    assert_eq!(frames[2].payload, 0u32.to_be_bytes(), "NO_ERROR");
    assert_eq!(t.resets(r), 1, "the core's early-response reset");
    assert_eq!(t.streams(), 0);
}

#[test]
fn fail_after_head_rst_internal_error() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/x", &[], b"");
    t.head(r, "200", &[], false);
    t.body(r, b"part", false);
    t.mh.t.inject_h3_error(r, StreamError::Reset);
    t.flow();
    assert_eq!(t.b.stream_reason(&s), Some(Reason::INTERNAL_ERROR));
    assert_eq!(t.b.received(&s), b"part");
    assert_eq!(t.streams(), 0);
}

#[test]
fn reject_before_head_xmq_error_response() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/x", &[], b"");
    t.mh.t.inject_h3_error(r, StreamError::Reset);
    t.flow();
    let (head, body) = t.b.response(&s).expect("a response");
    assert_eq!(head.status, 502);
    assert_eq!(head.headers["x-mq-error"], "upstream-reset");
    assert!(body.is_empty());
    assert_eq!(t.streams(), 0);
}

/// Task 5.1 ruling: a send error leaves the core `Failed` with no readiness
/// to follow, so the front pulls the download side after `SendOut::Done`.
#[test]
fn send_error_surfaces_without_an_h3_event() {
    // Before the head: 502 `upstream-reset`.
    let mut t = T::new();
    let r = t.next();
    t.mh.t.expect_h3_send_body(r, Err(StreamError::Reset));
    let s = t.b.request_streaming("POST", "/up", &[]);
    t.b.send(&s, b"abc", false);
    t.flow();
    let (head, _) = t.b.response(&s).expect("a response");
    assert_eq!(head.status, 502);
    assert_eq!(head.headers["x-mq-error"], "upstream-reset");
    assert_eq!(t.resets(r), 1);
    assert_eq!(t.streams(), 0);
    // After the head: RST_STREAM(INTERNAL_ERROR).
    let (s, r) = t.streaming("POST");
    t.head(r, "200", &[], false);
    assert!(t.b.head(&s).is_some());
    t.mh.t.expect_h3_send_body(r, Err(StreamError::Reset));
    t.b.send(&s, b"abc", false);
    t.flow();
    assert_eq!(t.b.stream_reason(&s), Some(Reason::INTERNAL_ERROR));
    assert_eq!(t.streams(), 0);
}

#[test]
fn stream_removed_only_when_ex_up_down_done() {
    let mut t = T::new();
    let (s, r) = t.streaming("POST");
    t.b.send(&s, b"abc", false);
    t.flow();
    assert_eq!(t.streams(), 1, "uploading, awaiting the head");
    t.b.send(&s, b"", true);
    t.flow();
    assert_eq!(t.mh.t.h3_sends(r).concat(), b"abc");
    assert_eq!(t.streams(), 1, "upload done, awaiting the head");
    t.head(r, "200", &[], false);
    assert_eq!(t.streams(), 1, "the body is pending");
    t.body(r, b"ok", true);
    assert_eq!(t.b.response(&s).expect("complete").1, b"ok");
    assert_eq!(t.streams(), 0);
}

// ---- admission ----

#[test]
fn admission_200_heads_delayed_fin_max_128_refused_stream() {
    let mut t = T::new();
    let mut open = Vec::new();
    for i in 0..200 {
        let r = (i < 128).then(|| t.next());
        let s = t.b.request("HEAD", &format!("/{i}"), &[], b"");
        t.flow();
        match r {
            Some(r) => {
                t.head(r, "200", &[], false);
                assert_eq!(t.b.response(&s).expect("a head").0.status, 200);
                open.push(r);
            }
            None => assert_eq!(t.b.stream_reason(&s), Some(Reason::REFUSED_STREAM)),
        }
        assert!(t.streams() <= 128);
    }
    assert_eq!(t.streams(), 128);
    assert_eq!(t.count(|c| matches!(c, Call::OpenH3Request(_))), 128);
    for r in open {
        t.mh.t.inject_h3_body(r, Vec::new(), true);
    }
    t.flow();
    assert_eq!(t.streams(), 0);
}

// ---- liveness ----

#[test]
fn open_stream_cancels_idle() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/slow", &[], b"");
    for _ in 0..6 {
        t.mh.advance(Duration::from_secs(30));
        t.relay();
    }
    assert_eq!(
        t.mh.close_of(t.tcp),
        None,
        "no idle close with an open stream"
    );
    assert!(!t.b.frames().iter().any(|f| f.ty == GOAWAY));
    assert!(t.pings() > 0, "the watchdog runs instead");
    t.head(r, "200", &[], true);
    assert!(t.b.response(&s).is_some());
    assert_eq!(t.streams(), 0);
    // Zero streams again: the idle timer applies.
    t.mh.advance(Duration::from_secs(60));
    t.relay();
    assert_eq!(t.mh.close_of(t.tcp), Some(false));
    assert_eq!(t.b.frame_types().last(), Some(&GOAWAY));
}

/// R7: a stream open for `open_for` with no inbound bytes, then ended; the
/// idle clock (10 s, PING after 60 s) starts when the count reaches zero.
fn idle_counts_from_the_last_stream_end(open_for: Duration) {
    let idle = Duration::from_secs(10);
    let mut t = T::tuned(MitmTuning {
        idle,
        ..MitmTuning::default()
    });
    let (s, r) = t.req("GET", "/sse", &[], b"");
    t.mh.advance(open_for);
    t.relay();
    assert_eq!(t.mh.close_of(t.tcp), None);
    assert_eq!(t.pings(), 0);
    t.head(r, "200", &[], true);
    assert!(t.b.response(&s).is_some());
    assert_eq!(t.streams(), 0);
    assert_eq!(t.mh.close_of(t.tcp), None, "not at the zero-crossing");
    t.mh.advance(idle - US);
    t.relay();
    assert_eq!(
        t.mh.close_of(t.tcp),
        None,
        "idle runs from the stream's end"
    );
    assert!(!t.b.frames().iter().any(|f| f.ty == GOAWAY));
    t.mh.advance(US);
    t.relay();
    assert_eq!(t.mh.close_of(t.tcp), Some(false));
    assert_eq!(t.b.frame_types().last(), Some(&GOAWAY));
}

#[test]
fn idle_starts_at_zero_crossing_after_long_quiet_stream() {
    idle_counts_from_the_last_stream_end(Duration::from_secs(50));
}

/// idle ≠ ping_after: the count going 1 → 0 re-arms to the idle deadline,
/// not the watchdog's (60 s), and not idle counted from the request.
#[test]
fn zero_crossing_rearms_to_idle_deadline() {
    idle_counts_from_the_last_stream_end(Duration::from_secs(1));
}

#[test]
fn watchdog_pings_at_60s_closes_at_90s_without_inbound() {
    let mut t = T::new();
    let (_, r) = t.req("GET", "/slow", &[], b"");
    t.b.stop_polling_h2(); // it acknowledges TCP but answers nothing
    t.mh.advance(Duration::from_secs(60) - US);
    t.relay();
    assert_eq!(t.pings(), 0);
    t.mh.advance(US);
    t.relay();
    assert_eq!(t.pings(), 1, "one PING at 60 s");
    t.mh.advance(Duration::from_secs(30) - US);
    t.relay();
    assert_eq!(t.mh.close_of(t.tcp), None);
    assert_eq!(t.pings(), 1, "one outstanding at most");
    t.mh.advance(US);
    t.relay();
    assert_eq!(t.mh.close_of(t.tcp), Some(false), "closed at 90 s");
    assert!(t.has("dead=1"), "{}", t.mh.metrics());
    assert_eq!(t.resets(r), 1, "its exchange is reset");
}

#[test]
fn watchdog_any_inbound_extends() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/sse", &[], b"");
    for _ in 0..20 {
        t.mh.advance(Duration::from_secs(30));
        t.relay();
    }
    assert_eq!(t.mh.close_of(t.tcp), None, "10 min of silence survived");
    assert!(t.pings() >= 5, "{}", t.pings());
    assert!(t.has("dead=0"), "{}", t.mh.metrics());
    t.head(r, "200", &[("content-length", "2")], false);
    t.body(r, b"ok", true);
    assert_eq!(t.b.response(&s).expect("complete").1, b"ok");
}

/// In memory a download stops on the TLS output gate after about nine
/// passes, so the budget is lowered to two: each pass reads one 16 KiB
/// chunk (the per-stream budget), then the continuation goes on.
#[test]
fn continuation_timer_when_budget_spent() {
    let mut t = T::with(Browser::new("example.com").windows(1 << 24, 1 << 24));
    let now = t.mh.now;
    t.mh.sh.with_app(now, |a, _| a.set_pump_budget(2));
    let (s, r) = t.req("GET", "/big", &[], b"");
    t.head(r, "200", &[], false);
    assert!(!t.cont_armed(), "a pump that finished arms nothing");
    let body = pattern(1 << 20);
    t.mh.t.inject_h3_body(r, body.clone(), true);
    t.mh.drive();
    assert!(t.cont_armed(), "the budget ran out with work left");
    assert_eq!(t.taken(r, body.len()), 2 * 16 * 1024);
    t.mh.drive(); // the continuation
    assert_eq!(t.taken(r, body.len()), 4 * 16 * 1024, "it went on");
    assert!(t.cont_armed());
    t.flow();
    assert!(t.b.response(&s).expect("complete").1 == body);
    assert!(!t.cont_armed());
}

/// R2/I13: a bodiless response's `Drain` discards one chunk per step too.
#[test]
fn drain_reads_one_chunk_per_step() {
    let mut t = T::new();
    let (s, r) = t.req("GET", "/x", &[], b"");
    t.head(r, "304", &[], false);
    assert_eq!(t.b.response(&s).expect("ended").0.status, 304);
    let now = t.mh.now;
    t.mh.sh.with_app(now, |a, _| a.set_pump_budget(2));
    let junk = pattern(256 * 1024);
    t.mh.t.inject_h3_body(r, junk.clone(), false);
    t.mh.drive();
    assert_eq!(t.taken(r, junk.len()), 2 * 16 * 1024);
    assert!(t.cont_armed(), "the continuation drains on");
    t.flow();
    assert_eq!(t.taken(r, junk.len()), junk.len());
    t.body(r, b"", true);
    assert_eq!(t.streams(), 0);
}
