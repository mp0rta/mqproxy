//! SP4 spec §4.2/§4.3: the H3 exchange core — open, the upload send rules,
//! the upload EOF rule, reset, event routing and failure settlement — on a
//! `Shard<ScriptedTransport, ExApp>`.

use mq_http::headers::{Reject, parse_method, parse_target};
use mq_proxy::client::exchange::{BodyLen, EofOut, Exchanges, Ready, ReqHead, SendOut};
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, Shard, SocketOpId, TcpEnd, TcpId,
    TimerId, UdpSocketId,
};
use mq_transport_api::{
    ConnId, Error, Event, H3Close, H3ReqId, H3ReqStats, StreamError, Time, Unread,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// A test `App` holding the core; every H3 event goes to `on_event`, whose
/// outputs are recorded.
struct ExApp {
    ex: Exchanges<u32>,
    out: Vec<(u32, H3ReqId, Ready)>,
}

impl App for ExApp {
    fn on_start(&mut self, _: &mut Cx<'_>) {}
    fn on_transport_event(&mut self, _: &mut Cx<'_>, ev: Event) {
        if let Some(o) = self.ex.on_event(&ev) {
            self.out.push(o);
        }
    }
    fn on_accepted(&mut self, _: &mut Cx<'_>, _: ListenerTag, _: TcpId, _: AcceptMeta) {}
    fn on_tcp_data(&mut self, _: &mut Cx<'_>, _: TcpId) {}
    fn on_tcp_end(&mut self, _: &mut Cx<'_>, _: TcpId, _: TcpEnd) {}
    fn on_dial_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<TcpId, DialError>) {}
    fn on_resolve_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<SocketAddr, DialError>) {
    }
    fn on_udp_socket(
        &mut self,
        _: &mut Cx<'_>,
        _: SocketOpId,
        _: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
    }
    fn on_udp_rx(&mut self, _: &mut Cx<'_>, _: UdpSocketId, _: SocketAddr, _: &[u8]) {}
    fn on_timer(&mut self, _: &mut Cx<'_>, _: TimerId) {}
    fn on_shutdown(&mut self, _: &mut Cx<'_>) {}
}

struct H {
    sh: Shard<ScriptedTransport, ExApp>,
    t: ScriptedHandle,
    now: Time,
    conn: ConnId,
}

impl H {
    fn new() -> H {
        let (transport, t) = ScriptedTransport::new();
        let conn = t.new_conn_id();
        let app = ExApp {
            ex: Exchanges::new(),
            out: Vec::new(),
        };
        let mut sh = Shard::new(
            transport,
            app,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            7,
        );
        let now = Time::from_micros(1_000_000);
        sh.start(now);
        H { sh, t, now, conn }
    }

    fn ex<R>(&mut self, f: impl FnOnce(&mut Exchanges<u32>, &mut Cx<'_>) -> R) -> R {
        self.sh.with_app(self.now, |a, cx| f(&mut a.ex, cx))
    }

    /// `open` with a scripted request id; the open must succeed.
    fn open(&mut self, body: BodyLen, owner: u32) -> H3ReqId {
        let r = self.t.new_h3_req_id();
        self.t.expect_open_h3_request(self.conn, Ok(r));
        let conn = self.conn;
        let got = self.ex(|ex, cx| ex.open(cx, conn, &head(body), owner));
        assert_eq!(got, Ok(r));
        r
    }

    fn try_open(&mut self, h: &ReqHead) -> Result<H3ReqId, Reject> {
        let conn = self.conn;
        self.ex(|ex, cx| ex.open(cx, conn, h, 7))
    }

    fn send(&mut self, r: H3ReqId, data: &[u8], fin: bool) -> SendOut {
        self.ex(|ex, cx| ex.send_body(cx, r, data, fin))
    }

    fn eof(&mut self, r: H3ReqId, buffered: u64) -> EofOut {
        self.ex(|ex, cx| ex.upload_eof(cx, r, buffered))
    }

    fn reset(&mut self, r: H3ReqId) {
        self.ex(|ex, cx| ex.reset(cx, r))
    }

    fn contains(&self, r: H3ReqId) -> bool {
        self.sh.app().ex.contains(r)
    }

    fn len(&self) -> usize {
        self.sh.app().ex.len()
    }

    /// Queue `e`, let the shard dispatch it, return the recorded outputs.
    fn event(&mut self, e: Event) -> Vec<(u32, H3ReqId, Ready)> {
        self.t.push_event(e);
        self.drive()
    }

    fn drive(&mut self) -> Vec<(u32, H3ReqId, Ready)> {
        self.sh.drive(self.now);
        self.sh
            .with_app(self.now, |a, _| std::mem::take(&mut a.out))
    }

    /// `H3Closed` for `r` with `unread`; the recorded outputs.
    fn closed(&mut self, r: H3ReqId, unread: Option<Unread>) -> Vec<(u32, H3ReqId, Ready)> {
        self.t.close_h3(
            r,
            H3Close {
                stats: stats(),
                unread,
            },
        );
        self.drive()
    }

    fn count(&self, f: impl Fn(&Call) -> bool) -> usize {
        self.t.log().iter().filter(|c| f(c)).count()
    }

    fn resets(&self, r: H3ReqId) -> usize {
        self.count(|c| *c == Call::H3Reset(r))
    }

    /// `(bytes offered, fin)` of every `h3_send_body` call on `r`.
    fn send_calls(&self, r: H3ReqId) -> Vec<(Vec<u8>, bool)> {
        self.t
            .log()
            .into_iter()
            .filter_map(|c| match c {
                Call::H3SendBody { r: x, bytes, fin } if x == r => Some((bytes, fin)),
                _ => None,
            })
            .collect()
    }
}

fn head(body: BodyLen) -> ReqHead {
    ReqHead {
        method: parse_method(b"POST").unwrap(),
        target: parse_target(b"https://example.com/p").unwrap(),
        auth: b"Bearer t".to_vec(),
        class: None,
        origin_proto: None,
        cache: None,
        accept_encoding: None,
        headers: vec![],
        body,
    }
}

fn stats() -> H3ReqStats {
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

#[test]
fn open_sends_fin_iff_empty_or_known_zero() {
    let mut h = H::new();
    let cases = [
        (BodyLen::Empty, true),
        (BodyLen::Known(0), true),
        (BodyLen::Known(5), false),
        (BodyLen::Unknown, false),
    ];
    for (body, fin) in cases {
        let r = h.open(body, 7);
        let sent = h.t.h3_headers_sent(r);
        assert_eq!(sent.len(), 1, "{body:?}");
        assert_eq!(sent[0].1, fin, "{body:?}");
        let cl = sent[0].0.iter().find(|(n, _)| n == b"content-length");
        let want = matches!(body, BodyLen::Known(5)).then(|| b"5".to_vec());
        assert_eq!(cl.map(|(_, v)| v.clone()), want, "{body:?}");
        // With the FIN sent, the upload is over: nothing more reaches the transport.
        if fin {
            assert_eq!(h.send(r, b"x", false), SendOut::Done, "{body:?}");
            assert!(h.send_calls(r).is_empty(), "{body:?}");
        }
        assert!(h.contains(r));
        assert_eq!(h.resets(r), 0);
    }
    assert_eq!(h.len(), 4);
}

#[test]
fn open_blocked_resets_and_tunnel_unavailable() {
    let mut h = H::new();
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(h.conn, Ok(r));
    h.t.expect_h3_send_headers(r, Err(StreamError::Blocked));
    assert_eq!(
        h.try_open(&head(BodyLen::Empty)),
        Err(Reject::TunnelUnavailable)
    );
    assert_eq!(h.resets(r), 1);
    assert!(!h.contains(r));
    // Every other send error too (no retry).
    for e in [StreamError::Reset, StreamError::Stale, StreamError::Conn] {
        let r = h.t.new_h3_req_id();
        h.t.expect_open_h3_request(h.conn, Ok(r));
        h.t.expect_h3_send_headers(r, Err(e));
        assert_eq!(
            h.try_open(&head(BodyLen::Known(3))),
            Err(Reject::TunnelUnavailable)
        );
        assert_eq!(h.resets(r), 1, "{e:?}");
    }
    // A failed open: nothing to reset.
    h.t.expect_open_h3_request(h.conn, Err(Error::Ceiling));
    assert_eq!(
        h.try_open(&head(BodyLen::Empty)),
        Err(Reject::TunnelUnavailable)
    );
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 4);
    assert_eq!(h.len(), 0);
}

#[test]
fn open_header_too_long_opens_nothing() {
    let mut h = H::new();
    let mut big = head(BodyLen::Empty);
    big.headers = vec![(b"x-big".to_vec(), vec![b'v'; 9000])];
    assert_eq!(h.try_open(&big), Err(Reject::HeaderTooLong));
    assert_eq!(h.count(|c| matches!(c, Call::OpenH3Request(_))), 0);
    assert_eq!(h.count(|c| matches!(c, Call::H3SendHeaders { .. })), 0);
    assert_eq!(h.len(), 0);
}

#[test]
fn send_known_drops_excess_fin_on_last_byte() {
    let mut h = H::new();
    let r = h.open(BodyLen::Known(5), 7);
    assert_eq!(h.send(r, b"hel", false), SendOut::Accepted(3));
    // The FIN rides the byte that ends the length; the excess is accepted and dropped.
    assert_eq!(h.send(r, b"lo-extra", false), SendOut::Accepted(8));
    assert_eq!(h.send(r, b"more", true), SendOut::Done);
    assert_eq!(
        h.send_calls(r),
        [(b"hel".to_vec(), false), (b"lo".to_vec(), true)]
    );
    assert_eq!(h.t.h3_sends(r).concat(), b"hello");

    // A partial accept of the last chunk: no FIN yet, the rest is resent with it.
    let r = h.open(BodyLen::Known(4), 7);
    h.t.expect_h3_send_body(r, Ok(1));
    assert_eq!(h.send(r, b"abcd", false), SendOut::Accepted(1));
    assert_eq!(h.send(r, b"bcd", false), SendOut::Accepted(3));
    assert_eq!(
        h.send_calls(r),
        [(b"abcd".to_vec(), true), (b"bcd".to_vec(), true)]
    );
    assert_eq!(h.t.h3_sends(r).concat(), b"abcd");

    // `Ok(0)` and `Blocked` are `Blocked`.
    let r = h.open(BodyLen::Known(4), 7);
    h.t.expect_h3_send_body(r, Ok(0));
    h.t.expect_h3_send_body(r, Err(StreamError::Blocked));
    assert_eq!(h.send(r, b"abcd", false), SendOut::Blocked);
    assert_eq!(h.send(r, b"abcd", false), SendOut::Blocked);
    assert_eq!(h.send(r, b"abcd", false), SendOut::Accepted(4));
    assert_eq!(h.resets(r), 0);
}

#[test]
fn send_streaming_bare_fin_is_h3_finish() {
    let mut h = H::new();
    let r = h.open(BodyLen::Unknown, 7);
    assert_eq!(h.send(r, b"ab", false), SendOut::Accepted(2));
    assert_eq!(h.send(r, b"", true), SendOut::Accepted(0));
    assert_eq!(h.send_calls(r), [(b"ab".to_vec(), false)]);
    assert_eq!(h.count(|c| *c == Call::H3Finish(r)), 1);
    assert_eq!(h.send(r, b"cd", false), SendOut::Done);

    // A FIN with data is passed through.
    let r = h.open(BodyLen::Unknown, 7);
    assert_eq!(h.send(r, b"xy", true), SendOut::Accepted(2));
    assert_eq!(h.send_calls(r), [(b"xy".to_vec(), true)]);
    assert_eq!(h.send(r, b"", true), SendOut::Done);
    assert_eq!(h.count(|c| *c == Call::H3Finish(r)), 0);
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
}

#[test]
fn send_stale_is_blocked_then_done_after_h3closed() {
    let mut h = H::new();
    let r = h.open(BodyLen::Known(5), 9);
    h.t.expect_h3_send_body(r, Err(StreamError::Stale));
    assert_eq!(h.send(r, b"hello", false), SendOut::Blocked);
    assert_eq!(h.resets(r), 0);
    assert_eq!(h.closed(r, None), [(9, r, Ready::Readable)]);
    assert_eq!(h.send(r, b"hello", false), SendOut::Done);
    assert!(h.contains(r));
    assert_eq!(h.send_calls(r).len(), 1);
    // `H3Closed` was seen: settlement does not reset a closed request.
    h.reset(r);
    assert_eq!(h.resets(r), 0);
    assert!(!h.contains(r));
}

#[test]
fn send_reset_error_marks_failed_returns_done() {
    for e in [StreamError::Reset, StreamError::Conn] {
        let mut h = H::new();
        let r = h.open(BodyLen::Known(5), 7);
        h.t.expect_h3_send_body(r, Err(e));
        assert_eq!(h.send(r, b"hello", false), SendOut::Done, "{e:?}");
        assert_eq!(h.resets(r), 1, "{e:?}");
        assert!(h.contains(r), "{e:?}");
        assert_eq!(h.send(r, b"hello", false), SendOut::Done, "{e:?}");
        assert_eq!(h.send_calls(r).len(), 1, "{e:?}");
        // Already reset: settlement does not reset it again.
        h.reset(r);
        assert_eq!(h.resets(r), 1, "{e:?}");
        assert!(!h.contains(r), "{e:?}");
    }
}

#[test]
fn upload_eof_truncated_resets_once() {
    let mut h = H::new();
    let r = h.open(BodyLen::Known(10), 7);
    assert_eq!(h.send(r, b"hello", false), SendOut::Accepted(5));
    assert_eq!(h.eof(r, 4), EofOut::Truncated);
    assert_eq!(h.resets(r), 1);
    assert!(!h.contains(r));
    // Gone: everything after is a no-op.
    h.reset(r);
    assert_eq!(h.eof(r, 0), EofOut::Complete);
    assert_eq!(h.send(r, b"x", false), SendOut::Done);
    assert_eq!(h.resets(r), 1);
    assert!(h.event(Event::H3Readable(r)).is_empty());
}

#[test]
fn upload_eof_complete_when_tail_buffered() {
    let mut h = H::new();
    let r = h.open(BodyLen::Known(5), 7);
    h.t.expect_h3_send_body(r, Err(StreamError::Blocked));
    assert_eq!(h.send(r, b"hello", false), SendOut::Blocked);
    // The tail is still in the front's buffer.
    assert_eq!(h.eof(r, 5), EofOut::Complete);
    assert_eq!(h.eof(r, 6), EofOut::Complete);
    assert_eq!(h.event(Event::H3Writable(r)), [(7, r, Ready::Writable)]);
    assert_eq!(h.send(r, b"hello", false), SendOut::Accepted(5));
    assert_eq!(h.send_calls(r).last(), Some(&(b"hello".to_vec(), true)));
    assert_eq!(h.eof(r, 0), EofOut::Complete, "upload done");

    // Streaming and no-body uploads complete; the front sends the FIN itself.
    let s = h.open(BodyLen::Unknown, 7);
    assert_eq!(h.eof(s, 0), EofOut::Complete);
    let e = h.open(BodyLen::Empty, 7);
    assert_eq!(h.eof(e, 0), EofOut::Complete);
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
    assert_eq!(h.len(), 3);
}

#[test]
fn reset_unknown_id_noop() {
    let mut h = H::new();
    let never = h.t.new_h3_req_id();
    h.reset(never);
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
    let r = h.open(BodyLen::Unknown, 7);
    h.reset(r);
    h.reset(r);
    assert_eq!(h.resets(r), 1);
    assert!(!h.contains(r));
    assert_eq!(h.len(), 0);
}

#[test]
fn on_event_unknown_id_none() {
    let mut h = H::new();
    let never = h.t.new_h3_req_id();
    assert!(h.event(Event::H3Readable(never)).is_empty());
    assert!(h.event(Event::H3Writable(never)).is_empty());
    assert!(h.closed(never, None).is_empty());
    assert!(h.event(Event::ConnEstablished(h.conn)).is_empty());
    let r = h.open(BodyLen::Unknown, 3);
    assert_eq!(h.event(Event::H3Readable(r)), [(3, r, Ready::Readable)]);
    assert_eq!(h.event(Event::H3Writable(r)), [(3, r, Ready::Writable)]);
    assert_eq!(h.len(), 1);
}

#[test]
fn drain_owner_resets_only_matching() {
    let mut h = H::new();
    let a = h.open(BodyLen::Unknown, 1);
    let b = h.open(BodyLen::Unknown, 2);
    let c = h.open(BodyLen::Unknown, 1);
    // `c` is closed already: drained without a reset.
    assert_eq!(h.closed(c, None), [(1, c, Ready::Readable)]);
    h.ex(|ex, cx| ex.drain_owner(cx, |o| *o == 1));
    assert_eq!((h.resets(a), h.resets(b), h.resets(c)), (1, 0, 0));
    assert!(!h.contains(a) && h.contains(b) && !h.contains(c));
    assert_eq!(h.len(), 1);
    h.ex(|ex, cx| ex.drain_owner(cx, |_| true));
    assert_eq!(h.resets(b), 1);
    assert_eq!(h.len(), 0);
}

#[test]
fn send_done_never_removes_exchange() {
    let mut h = H::new();
    let empty = h.open(BodyLen::Empty, 7);
    let known = h.open(BodyLen::Known(2), 7);
    let closed = h.open(BodyLen::Unknown, 7);
    assert_eq!(h.send(empty, b"x", false), SendOut::Done);
    assert_eq!(h.send(known, b"ab", false), SendOut::Accepted(2));
    assert_eq!(h.send(known, b"c", false), SendOut::Done);
    h.closed(
        closed,
        Some(Unread {
            headers: None,
            body: vec![],
        }),
    );
    assert_eq!(h.send(closed, b"x", true), SendOut::Done);
    assert!(h.contains(empty) && h.contains(known) && h.contains(closed));
    assert_eq!(h.len(), 3);
    assert_eq!(h.count(|c| matches!(c, Call::H3Reset(_))), 0);
}
