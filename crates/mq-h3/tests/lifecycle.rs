//! Request lifecycle: closure conditions, `h3_reset`, the connection-close fan-out with
//! client-side retention, and stale ids after close (adoption spec §4.3, §5.1, §5.2).

mod common;

use common::{Rig, aborts};
use h3wire::{FieldRef, H3Code, HeadersKind, StreamId as Q};
use mq_runtime::testing::Call;
use mq_transport_api::{
    CloseReason, ErrType, Error, Event, H3Header, H3ReqId, StreamError, StreamId, TransportOps,
};

fn f<'a>(n: &'a str, v: &'a str) -> FieldRef<'a> {
    FieldRef::new(n.as_bytes(), v.as_bytes())
}

fn h<'a>(n: &'a str, v: &'a str) -> H3Header<'a> {
    H3Header {
        name: n.as_bytes(),
        value: v.as_bytes(),
    }
}

fn request(method: &'static str) -> Vec<FieldRef<'static>> {
    vec![
        f(":method", method),
        f(":scheme", "https"),
        f(":authority", "example.com"),
        f(":path", "/x"),
    ]
}

fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

const CLOSE: CloseReason = CloseReason {
    err_type: ErrType::Application,
    code: 0x10c,
};

/// Server rig with SETTINGS exchanged and `NewConn` drained.
fn server() -> Rig {
    let mut r = Rig::server();
    r.pump();
    r.events();
    r
}

/// Client rig with SETTINGS exchanged.
fn client() -> Rig {
    let mut r = Rig::client();
    r.pump();
    r.events();
    r
}

/// The ids of the `H3Request`s in `ev`.
fn requests(ev: &[Event]) -> Vec<H3ReqId> {
    ev.iter()
        .filter_map(|e| match *e {
            Event::H3Request(_, id) => Some(id),
            _ => None,
        })
        .collect()
}

/// The single `H3Request` id, asserting `[H3Request, H3Readable]`.
fn started(r: &mut Rig) -> H3ReqId {
    let ev = r.events();
    let ids = requests(&ev);
    assert_eq!(ids.len(), 1, "{ev:?}");
    assert_eq!(
        ev,
        [Event::H3Request(r.conn, ids[0]), Event::H3Readable(ids[0])]
    );
    ids[0]
}

/// The `H3Closed` ids in `ev`, each asserting `unread: None`.
fn closed(ev: &[Event]) -> Vec<H3ReqId> {
    ev.iter()
        .filter_map(|e| match e {
            Event::H3Closed(id, c) => {
                assert_eq!(c.unread, None);
                Some(*id)
            }
            _ => None,
        })
        .collect()
}

fn recv_headers(r: &mut Rig, id: H3ReqId) -> Result<bool, StreamError> {
    r.w.h3_recv_headers(r.now, id, &mut |_, _| {})
}

/// `h3_recv_body` with a `cap`-byte buf until `fin` or an error: the bytes and the last
/// result.
fn pull(r: &mut Rig, id: H3ReqId, cap: usize) -> (Vec<u8>, Result<(usize, bool), StreamError>) {
    let mut all = Vec::new();
    let mut buf = vec![0u8; cap];
    loop {
        let res = r.w.h3_recv_body(r.now, id, &mut buf);
        if let Ok((n, _)) = res {
            all.extend_from_slice(&buf[..n]);
        }
        if !matches!(res, Ok((_, false))) {
            return (all, res);
        }
    }
}

/// Server request on `q` from the peer, HEADERS taken by the gateway (no FIN yet).
fn reading_request() -> (Rig, H3ReqId, StreamId) {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("GET"), false).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id), Ok(false));
    let s = r.peer_stream(Q(0));
    (r, id, s)
}

/// A client GET (FIN on HEADERS) whose HEADERS the peer received and released.
fn client_get(r: &mut Rig) -> (H3ReqId, Q) {
    let id = r.w.open_h3_request(r.now, r.conn).expect("open_h3_request");
    let hs = [
        h(":method", "GET"),
        h(":scheme", "https"),
        h(":authority", "example.com"),
        h(":path", "/"),
    ];
    r.w.h3_send_headers(r.now, id, &hs, true)
        .expect("send_headers");
    r.pump();
    let q = Q(r.w.h3_req_info(id).expect("h3_req_info").quic_id);
    let b = r
        .peer_events
        .iter()
        .find_map(|e| match *e {
            h3wire::Event::Headers {
                stream,
                block,
                kind: HeadersKind::Request,
            } if stream == q => Some(block),
            _ => None,
        })
        .expect("peer got the request");
    r.peer.release(b);
    (id, q)
}

/// A raw HEADERS frame over a static-only QPACK section of `fields`.
fn raw_headers(fields: &[FieldRef]) -> Vec<u8> {
    let mut p = Vec::new();
    h3wire::qpack::encoder::encode_field_section(fields, &mut p);
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x01, p.len() as u64, &mut out);
    out.extend_from_slice(&p);
    out
}

/// A raw DATA frame declaring `declared` bytes and carrying `payload`.
fn raw_data(declared: usize, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x00, declared as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// `stream_send` calls on `s`.
fn sends(r: &Rig, s: StreamId) -> usize {
    r.h.log()
        .iter()
        .filter(|c| matches!(c, Call::StreamSend { s: x, .. } if *x == s))
        .count()
}

/// Receive EOF is not closure: the response still goes out (adoption spec §4.3).
#[test]
fn server_finished_before_response_is_not_closure() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("GET"), true).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id), Ok(true), "Finished arrived first");
    r.pump();
    assert_eq!(closed(&r.events()), []);
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &[h(":status", "200")], false),
        Ok(())
    );
    assert_eq!(r.w.h3_send_body(r.now, id, b"hello", true), Ok(5));
    r.pump();
    assert_eq!(r.peer_body(Q(0)), b"hello");
    assert!(r.peer_events.contains(&h3wire::Event::Finished(Q(0))));
    assert_eq!(closed(&r.events()), []);
}

/// Condition 2: StreamClosed waits until the gateway has the receive end.
#[test]
fn closed_after_stream_closed_and_delivered() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("POST"), false).unwrap();
    let body = body_of(1000);
    r.peer_send_body(Q(0), &body, true);
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id), Ok(false));
    let s = r.peer_stream(Q(0));
    assert_eq!(r.h.recv_pending(s), 0, "the raw FIN sits in the carry");
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [], "the body is not delivered yet");
    let (got, last) = pull(&mut r, id, 4096);
    assert!(matches!(last, Ok((_, true))), "{last:?}");
    assert!(got == body, "body bytes differ");
    assert_eq!(closed(&r.events()), [id]);
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), []);
}

#[test]
fn aborted_closes_on_stream_closed() {
    let (mut r, id, s) = reading_request();
    r.peer.abort(Q(0), H3Code::REQUEST_CANCELLED).unwrap();
    r.pump();
    assert_eq!(closed(&r.events()), []);
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [id], "no read needed");
}

/// adoption spec §4.4: a StreamPeerReset after our abort is not passed to h3wire.
#[test]
fn late_peer_reset_after_abort_ignored() {
    let (mut r, id, s) = reading_request();
    r.w.h3_reset(r.now, id);
    let ours = [
        Call::StreamResetSend { s, code: 0x10c },
        Call::StreamStopSending { s, code: 0x10c },
    ];
    assert_eq!(aborts(&r, s), ours);
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    r.h.push_event(Event::StreamPeerReset(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(aborts(&r, s), ours, "no new action");
    assert_eq!(
        r.h.recv_pending(s),
        0,
        "the retirement probe read the reset"
    );
    assert_eq!(closed(&r.events()), []);
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [id]);
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), []);
}

#[test]
fn h3_reset_with_core() {
    let (mut r, id, s) = reading_request();
    r.w.h3_reset(r.now, id);
    assert_eq!(
        aborts(&r, s),
        [
            Call::StreamResetSend { s, code: 0x10c },
            Call::StreamStopSending { s, code: 0x10c }
        ]
    );
    r.w.h3_reset(r.now, id);
    assert_eq!(aborts(&r, s).len(), 2, "a second h3_reset adds nothing");
    assert_eq!(closed(&r.events()), []);
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [id]);
}

/// Review Focus 4 (adoption spec §6.4 "kept").
#[test]
fn early_response_then_drain_retires() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("POST"), false).unwrap();
    let upload = body_of(64 * 1024);
    r.peer_send_body(Q(0), &upload, true);
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id), Ok(false));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &[h(":status", "413")], false),
        Ok(())
    );
    assert_eq!(r.w.h3_send_body(r.now, id, b"done", true), Ok(4));
    r.pump();
    assert!(r.peer_events.contains(&h3wire::Event::Finished(Q(0))));
    let s = r.peer_stream(Q(0));
    assert!(r.h.recv_pending(s) > 0, "the upload is unread");
    assert_eq!(closed(&r.events()), []);
    let (got, last) = pull(&mut r, id, 16 * 1024);
    assert!(matches!(last, Ok((_, true))), "{last:?}");
    assert!(got == upload, "upload bytes differ");
    assert_eq!(
        r.h.recv_pending(s),
        0,
        "read to the FIN: the stream can retire"
    );
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [id]);
}

#[test]
fn conn_close_fans_out() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("GET"), false).unwrap();
    r.peer.send_headers(Q(4), &request("GET"), false).unwrap();
    r.pump();
    let mut ids = requests(&r.events());
    assert_eq!(ids.len(), 2);
    r.close_transport(CLOSE);
    r.w.drive(r.now);
    let ev = r.events();
    let mut got = closed(&ev);
    got.sort();
    ids.sort();
    assert_eq!(got, ids);
    assert_eq!(ev.last(), Some(&Event::ConnClosed(r.conn, CLOSE)), "{ev:?}");
    assert_eq!(ev.len(), 3, "{ev:?}");
    r.w.drive(r.now);
    assert_eq!(r.events(), []);
}

/// Review Focus 3.
#[test]
fn retained_download_survives_conn_close() {
    let mut r = client();
    let (id, q) = client_get(&mut r);
    let s = r.peer_stream(q);
    r.peer
        .send_headers(q, &[f(":status", "200")], false)
        .unwrap();
    let body = body_of(1000);
    r.peer_send_body(q, &body, true);
    r.pump();
    assert_eq!(r.events(), [Event::H3Readable(id)]);
    assert_eq!(r.h.recv_pending(s), 0, "the raw FIN sits in the carry");
    r.close_transport(CLOSE);
    r.w.drive(r.now);
    assert_eq!(r.events(), [Event::ConnClosed(r.conn, CLOSE)]);
    let n = sends(&r, s);
    assert_eq!(r.w.h3_send_body(r.now, id, b"late", false), Ok(4));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    assert_eq!(sends(&r, s), n, "accepted and discarded");
    assert_eq!(recv_headers(&mut r, id), Ok(false));
    assert_eq!(closed(&r.events()), []);
    let (got, last) = pull(&mut r, id, 256);
    assert!(matches!(last, Ok((_, true))), "{last:?}");
    assert!(got == body, "body bytes differ");
    assert_eq!(closed(&r.events()), [id]);
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), []);
    assert_eq!(r.w.h3_req_info(id), Err(Error::Stale));
}

/// adoption spec §4.3 step 4, §5.3 (1).
#[test]
fn retained_cut_frame_fans_out() {
    let mut r = client();
    let (a, qa) = client_get(&mut r);
    let (b, qb) = client_get(&mut r);
    let status = raw_headers(&[f(":status", "200")]);
    r.deliver(qa, &[&status[..], &raw_data(100, &[1; 10])].concat(), true);
    r.deliver(qb, &[&status[..], &raw_data(5, &[2; 5])].concat(), true);
    r.pump();
    let ev = r.events();
    assert!(ev.contains(&Event::H3Readable(a)) && ev.contains(&Event::H3Readable(b)));
    r.close_transport(CLOSE);
    r.w.drive(r.now);
    assert_eq!(
        r.events(),
        [Event::ConnClosed(r.conn, CLOSE)],
        "both retained"
    );
    assert_eq!(recv_headers(&mut r, a), Ok(false));
    let (_, last) = pull(&mut r, a, 4096);
    assert!(
        last.is_err(),
        "the cut frame is a connection error: {last:?}"
    );
    let mut got = closed(&r.events());
    got.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(got, want, "both closed at once");
    assert_eq!(recv_headers(&mut r, b), Err(StreamError::Stale));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), []);
}

/// adoption spec §4.3: retention is client-only.
#[test]
fn server_requests_not_retained() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("POST"), false).unwrap();
    r.peer_send_body(Q(0), &body_of(1000), true);
    r.pump();
    let id = started(&mut r);
    assert_eq!(
        r.h.recv_pending(r.peer_stream(Q(0))),
        0,
        "complete in the carry"
    );
    r.close_transport(CLOSE);
    r.w.drive(r.now);
    let ev = r.events();
    assert_eq!(closed(&ev), [id], "closed at once");
    assert_eq!(ev.len(), 2, "{ev:?}");
    assert_eq!(ev[1], Event::ConnClosed(r.conn, CLOSE));
    let mut buf = [0u8; 64];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Stale)
    );
}

#[test]
fn stale_after_close() {
    let mut r = server();
    r.peer.send_headers(Q(0), &request("GET"), true).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id), Ok(true));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &[h(":status", "204")], true),
        Ok(())
    );
    r.pump();
    let s = r.peer_stream(Q(0));
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    assert_eq!(closed(&r.events()), [id]);
    let now = r.now;
    let mut buf = [0u8; 64];
    assert_eq!(r.w.h3_recv_body(now, id, &mut buf), Err(StreamError::Stale));
    assert_eq!(recv_headers(&mut r, id), Err(StreamError::Stale));
    assert_eq!(
        r.w.h3_send_body(now, id, b"x", false),
        Err(StreamError::Stale)
    );
    assert_eq!(
        r.w.h3_send_headers(now, id, &[h(":status", "200")], false),
        Err(StreamError::Stale)
    );
    assert_eq!(r.w.h3_finish(now, id), Err(StreamError::Stale));
    assert_eq!(r.w.h3_req_info(id), Err(Error::Stale));
    let calls = r.h.log().len();
    r.w.h3_reset(now, id);
    let after: Vec<_> = r.h.log()[calls..]
        .iter()
        .filter(|c| !matches!(c, Call::Drive(_)))
        .cloned()
        .collect();
    assert_eq!(after, [], "h3_reset on a stale id is a no-op");
    r.w.drive(now);
    assert_eq!(closed(&r.events()), []);
}
