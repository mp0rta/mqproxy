//! Request send: client start, DATA framing with partial writes, the finish latch, the
//! pending FIN, `SendStopped` per role and GOAWAY (adoption spec §4.3 "Start", §4.4, §4.5).

mod common;

use common::{Rig, aborts, recvs};
use h3wire::{FieldRef, HeaderBlockId, HeadersKind, StreamId as Q};
use mq_runtime::testing::Call;
use mq_transport_api::{Event, H3Header, H3ReqId, StreamError, StreamId, TransportOps};

fn h<'a>(n: &'a str, v: &'a str) -> H3Header<'a> {
    H3Header {
        name: n.as_bytes(),
        value: v.as_bytes(),
    }
}

fn f<'a>(n: &'a str, v: &'a str) -> FieldRef<'a> {
    FieldRef::new(n.as_bytes(), v.as_bytes())
}

fn request(method: &'static str) -> [H3Header<'static>; 4] {
    [
        h(":method", method),
        h(":scheme", "https"),
        h(":authority", "example.com"),
        h(":path", "/"),
    ]
}

fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// A DATA frame prefix for `len` payload bytes.
fn prefix(len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    h3wire::frame::encode_header(0x00, len as u64, &mut p);
    p
}

/// Client rig with SETTINGS exchanged.
fn client() -> Rig {
    let mut r = Rig::client();
    r.pump();
    r.events();
    r
}

/// Server rig with SETTINGS exchanged and `NewConn` drained.
fn server() -> Rig {
    let mut r = Rig::server();
    r.pump();
    r.events();
    r
}

/// `open_h3_request`: the id and its request stream.
fn open(r: &mut Rig) -> (H3ReqId, StreamId) {
    let id = r.w.open_h3_request(r.now, r.conn).expect("open_h3_request");
    let q = r.w.h3_req_info(id).expect("h3_req_info").quic_id;
    (id, r.peer_stream(Q(q)))
}

/// A client POST whose HEADERS (no FIN) reached the peer; the wire length after them.
fn posting() -> (Rig, H3ReqId, StreamId, usize) {
    let mut r = client();
    let (id, s) = open(&mut r);
    r.w.h3_send_headers(r.now, id, &request("POST"), false)
        .expect("send_headers");
    r.pump();
    r.events();
    let head = r.h.sent_bytes(s).len();
    (r, id, s, head)
}

/// The peer's events on request stream `q`.
fn peer_events_on(r: &Rig, q: Q) -> Vec<h3wire::Event> {
    r.peer_events
        .iter()
        .filter(|e| match **e {
            h3wire::Event::Headers { stream, .. }
            | h3wire::Event::Finished(stream)
            | h3wire::Event::StreamAborted { stream, .. } => stream == q,
            _ => false,
        })
        .copied()
        .collect()
}

fn peer_block(r: &Rig, q: Q) -> HeaderBlockId {
    r.peer_events
        .iter()
        .rev()
        .find_map(|e| match *e {
            h3wire::Event::Headers { stream, block, .. } if stream == q => Some(block),
            _ => None,
        })
        .expect("peer got a block")
}

/// The peer request on `q` got its HEADERS (kind Request) and then `Finished`.
fn assert_peer_finished(r: &Rig, q: Q) {
    let ev = peer_events_on(r, q);
    assert!(
        matches!(
            ev[..],
            [
                h3wire::Event::Headers {
                    kind: HeadersKind::Request,
                    ..
                },
                h3wire::Event::Finished(_)
            ]
        ),
        "{ev:?}"
    );
}

/// The peer answers request `q` with 200, `body` and FIN.
fn respond(r: &mut Rig, q: Q, body: &[u8]) {
    let b = peer_block(r, q);
    r.peer.release(b);
    r.peer
        .send_headers(q, &[f(":status", "200")], false)
        .expect("peer response");
    r.peer_send_body(q, body, true);
    r.pump();
}

/// `h3_recv_headers` (asserting a bare 200) + `h3_recv_body` to `fin`: the body.
fn read_response(r: &mut Rig, id: H3ReqId) -> Vec<u8> {
    let mut head = Vec::new();
    let res =
        r.w.h3_recv_headers(r.now, id, &mut |n, v| head.push((n.to_vec(), v.to_vec())));
    assert_eq!(res, Ok(false));
    assert_eq!(head, [(b":status".to_vec(), b"200".to_vec())]);
    let mut body = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let (n, fin) = r.w.h3_recv_body(r.now, id, &mut buf).expect("body");
        body.extend_from_slice(&buf[..n]);
        if fin {
            return body;
        }
    }
}

/// `stream_send` calls on `s` (`fin`-only filter when `fin_only`).
fn sends(r: &Rig, s: StreamId, fin_only: bool) -> usize {
    r.h.log()
        .iter()
        .filter(
            |c| matches!(c, Call::StreamSend { s: x, fin, .. } if *x == s && (*fin || !fin_only)),
        )
        .count()
}

#[test]
fn client_request_round_trip() {
    let mut r = client();
    let calls = r.h.log().len();
    let (id, s) = open(&mut r);
    assert!(r.h.log()[calls..].contains(&Call::OpenStream(r.conn)));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &request("GET"), true),
        Ok(())
    );
    r.pump();
    assert_peer_finished(&r, Q(0));
    assert_eq!(r.fins(s), 1);
    respond(&mut r, Q(0), b"hello");
    assert!(r.events().contains(&Event::H3Readable(id)));
    let body = read_response(&mut r, id);
    assert_eq!(body, b"hello");
}

#[test]
fn send_body_partial_payload() {
    let (mut r, id, s, head) = posting();
    let body = body_of(1000);
    r.limit(s, None); // the prefix
    r.limit(s, Some(10)); // the payload
    // `fin` rides the frame: committed only by the call that completes it.
    assert_eq!(r.w.h3_send_body(r.now, id, &body, true), Ok(10));
    assert_eq!(r.fins(s), 0);
    assert_eq!(r.w.h3_send_body(r.now, id, &body[10..], true), Ok(990));
    r.pump();
    let want = [prefix(1000), body.clone()].concat();
    assert!(r.h.sent_bytes(s)[head..] == want[..], "one DATA frame");
    assert!(r.peer_body(Q(0)) == body);
    assert_eq!(r.fins(s), 1);
    assert_peer_finished(&r, Q(0));
}

#[test]
fn send_body_partial_prefix() {
    let (mut r, id, s, head) = posting();
    let body = body_of(1000);
    r.limit(s, Some(1));
    assert_eq!(
        r.w.h3_send_body(r.now, id, &body, false),
        Err(StreamError::Blocked)
    );
    assert_eq!(r.h.sent_bytes(s)[head..], prefix(1000)[..1]);
    assert_eq!(sends(&r, s, false), 2, "HEADERS, then one prefix byte only");
    r.h.push_event(Event::StreamWritable(s));
    r.w.drive(r.now);
    assert!(r.events().contains(&Event::H3Writable(id)));
    assert_eq!(r.w.h3_send_body(r.now, id, &body, true), Ok(1000));
    r.pump();
    let want = [prefix(1000), body.clone()].concat();
    assert!(
        r.h.sent_bytes(s)[head..] == want[..],
        "one well-formed frame"
    );
    assert!(r.peer_body(Q(0)) == body);
    assert_peer_finished(&r, Q(0));
}

#[test]
fn send_body_blocked_returns_blocked() {
    let mut r = client();
    let (id, s) = open(&mut r);
    r.limit(s, Some(0));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &request("POST"), false),
        Ok(())
    );
    r.limit(s, Some(0)); // the HEADERS stay unwritten through the next call, too
    assert_eq!(
        r.w.h3_send_body(r.now, id, b"abc", false),
        Err(StreamError::Blocked)
    );
    assert!(r.h.sent_bytes(s).is_empty());
    assert!(!r.events().contains(&Event::H3Writable(id)));
    r.h.push_event(Event::StreamWritable(s));
    r.w.drive(r.now);
    assert!(!r.h.sent_bytes(s).is_empty(), "the HEADERS drained");
    assert!(r.events().contains(&Event::H3Writable(id)));
    assert_eq!(r.w.h3_send_body(r.now, id, b"abc", false), Ok(3));
}

/// `H3Writable` also follows a drain on a bare call, with no `StreamWritable`.
#[test]
fn writable_after_drain_without_stream_writable() {
    let mut r = client();
    let (id, s) = open(&mut r);
    r.limit(s, Some(0));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &request("POST"), false),
        Ok(())
    );
    r.limit(s, Some(0));
    assert_eq!(
        r.w.h3_send_body(r.now, id, b"abc", false),
        Err(StreamError::Blocked)
    );
    assert_eq!(r.events(), []);
    r.w.drive(r.now);
    assert_eq!(r.events(), [Event::H3Writable(id)]);
}

/// Review Focus 5.
#[test]
fn fin_while_frame_in_flight() {
    let (mut r, id, s, head) = posting();
    let body = body_of(1500);
    r.limit(s, None); // the prefix
    r.limit(s, Some(400)); // the payload
    assert_eq!(r.w.h3_send_body(r.now, id, &body[..1000], false), Ok(400));
    assert_eq!(r.w.h3_send_body(r.now, id, &body[400..], true), Ok(1100));
    r.pump();
    let want = [
        prefix(1000),
        body[..1000].to_vec(),
        prefix(500),
        body[1000..].to_vec(),
    ]
    .concat();
    assert!(
        r.h.sent_bytes(s)[head..] == want[..],
        "the frame completes, then a new one; no prefix re-sent"
    );
    assert!(r.peer_body(Q(0)) == body);
    assert_eq!(r.fins(s), 1);
    assert_peer_finished(&r, Q(0));
}

#[test]
fn finish_latched_behind_headers() {
    let mut r = client();
    let (id, s) = open(&mut r);
    r.limit(s, Some(0));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &request("POST"), false),
        Ok(())
    );
    r.limit(s, Some(0));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    assert!(r.h.sent_bytes(s).is_empty());
    assert_eq!(r.fins(s), 0);
    r.pump();
    assert_peer_finished(&r, Q(0));
    assert_eq!(r.fins(s), 1);
}

#[test]
fn pending_fin_retried() {
    let (mut r, id, s, _) = posting();
    r.limit(s, Some(0));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    assert_eq!(sends(&r, s, true), 1);
    assert_eq!(r.fins(s), 0, "the FIN-only send was Blocked");
    r.h.push_event(Event::StreamWritable(s));
    r.w.drive(r.now);
    assert_eq!(r.fins(s), 1);
    r.pump();
    r.w.drive(r.now);
    assert_eq!(sends(&r, s, true), 2, "one retry");
    assert_eq!(r.fins(s), 1, "exactly one accepted FIN");
    assert_peer_finished(&r, Q(0));
}

/// adoption spec §3, §4.5: a late peer RESET does not drop our pending FIN.
#[test]
fn pending_fin_survives_peer_reset() {
    let (mut r, id, s, _) = posting();
    r.limit(s, Some(0));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    assert_eq!(r.fins(s), 0);
    r.limit(s, Some(0)); // still Blocked at the next call's sweep
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    r.h.push_event(Event::StreamPeerReset(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(r.fins(s), 1, "the FIN is still sent");
    assert_eq!(r.h.recv_pending(s), 0, "the probe read the reset");
    let log = r.h.log();
    let probe = log
        .iter()
        .position(|c| matches!(c, Call::StreamRecv { s: x, .. } if *x == s))
        .expect("retirement probe");
    let fin = log
        .iter()
        .rposition(|c| matches!(c, Call::StreamSend { s: x, fin: true, .. } if *x == s))
        .expect("FIN");
    assert!(probe < fin, "the FIN went out after the reset");
    assert_eq!(aborts(&r, s), [], "no reset of our finished send side");
    let mut buf = [0u8; 64];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Reset)
    );
}

#[test]
fn send_stopped_client_discards() {
    let (mut r, id, s, _) = posting();
    r.h.push_event(Event::StreamStopSending(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10c }]);
    assert_eq!(
        r.events(),
        [Event::H3Writable(id)],
        "a blocked pump learns of it"
    );
    let n = sends(&r, s, false);
    assert_eq!(r.w.h3_send_body(r.now, id, &[7u8; 4096], false), Ok(4096));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    r.w.drive(r.now);
    assert_eq!(sends(&r, s, false), n, "nothing written");
    respond(&mut r, Q(0), b"still here");
    let body = read_response(&mut r, id);
    assert_eq!(body, b"still here");
}

#[test]
fn send_stopped_server_resets() {
    let mut r = server();
    let get = [
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "example.com"),
        f(":path", "/"),
    ];
    r.peer.send_headers(Q(0), &get, false).unwrap();
    r.pump();
    let id = r
        .events()
        .iter()
        .find_map(|e| match *e {
            Event::H3Request(_, id) => Some(id),
            _ => None,
        })
        .expect("H3Request");
    assert_eq!(r.w.h3_recv_headers(r.now, id, &mut |_, _| {}), Ok(false));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &[h(":status", "200")], false),
        Ok(())
    );
    r.pump();
    let s = r.peer_stream(Q(0));
    r.h.push_event(Event::StreamStopSending(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(
        r.w.h3_send_body(r.now, id, &[7u8; 4096], false),
        Err(StreamError::Reset)
    );
    assert_eq!(r.w.h3_finish(r.now, id), Err(StreamError::Reset));
}

/// Client requests on quic ids 0 and 4; the peer processed only 0 when it sends GOAWAY(4).
fn goaway() -> (Rig, H3ReqId, H3ReqId, StreamId) {
    let mut r = client();
    let (id0, _) = open(&mut r);
    r.w.h3_send_headers(r.now, id0, &request("GET"), true)
        .unwrap();
    r.pump();
    let (id4, s4) = open(&mut r);
    r.limit(s4, Some(0)); // the HEADERS of 4 wait in h3wire
    r.w.h3_send_headers(r.now, id4, &request("POST"), false)
        .unwrap();
    r.peer.finish_shutdown().unwrap(); // GOAWAY(4)
    r.limit(s4, Some(0)); // and through the pump's first round: GOAWAY reaches w first
    r.pump();
    (r, id0, id4, s4)
}

#[test]
fn goaway_cutoff_aborts_existing() {
    let (mut r, id0, id4, s4) = goaway();
    assert_eq!(
        aborts(&r, s4),
        [
            Call::StreamResetSend { s: s4, code: 0x10c },
            Call::StreamStopSending { s: s4, code: 0x10c }
        ]
    );
    // h3wire reports REQUEST_REJECTED to the application; the wire says REQUEST_CANCELLED.
    #[cfg(feature = "test-support")]
    assert_eq!(
        r.w.debug_abort(id4),
        Some((
            h3wire::H3Code::REQUEST_REJECTED,
            h3wire::AbortSource::GoAway
        ))
    );
    // One retirement read at the GOAWAY abort, one probe at the peer's own reject.
    assert_eq!(recvs(&r, s4), 2);
    assert_eq!(r.h.recv_pending(s4), 0);
    assert!(r.events().contains(&Event::H3Readable(id4)));
    let mut buf = [0u8; 64];
    assert_eq!(
        r.w.h3_recv_body(r.now, id4, &mut buf),
        Err(StreamError::Reset)
    );
    // Request 0 completes normally.
    respond(&mut r, Q(0), b"zero");
    let body = read_response(&mut r, id0);
    assert_eq!(body, b"zero");
    assert_eq!(aborts(&r, r.peer_stream(Q(0))), []);
}

#[test]
fn going_away_maps_to_conn() {
    let (mut r, ..) = goaway();
    let (id, s) = open(&mut r);
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &request("GET"), true),
        Err(StreamError::Conn)
    );
    let calls = r.h.log().len();
    r.w.h3_reset(r.now, id);
    assert!(
        r.h.log()[calls..].contains(&Call::StreamReset(s)),
        "no h3wire state: the raw stream is reset (adoption spec §4.3)"
    );
    r.w.h3_reset(r.now, id);
    assert_eq!(
        aborts(&r, s),
        [Call::StreamReset(s)],
        "h3_reset is idempotent"
    );
    r.events();
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let ev = r.events();
    assert!(
        matches!(ev[..], [Event::H3Closed(x, _)] if x == id),
        "closure follows StreamClosed: {ev:?}"
    );
}

#[test]
fn invalid_field_maps_to_reset() {
    let mut r = client();
    let (id, s) = open(&mut r);
    let mut hs = request("GET").to_vec();
    hs.push(h("X-Upper", "1"));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &hs, true),
        Err(StreamError::Reset)
    );
    r.pump();
    assert!(r.h.sent_bytes(s).is_empty());
}

/// A peer RESET_STREAM after the request's FIN (xqc_h3 sends one on any cancel): h3wire
/// resets our send side but emits no `StreamAborted` after `Finished`, so it ends the send
/// side as `SendStopped` does, here with a DATA frame in flight.
#[test]
fn peer_reset_after_finished_ends_send() {
    let mut r = server();
    let get = [
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "example.com"),
        f(":path", "/"),
    ];
    r.peer.send_headers(Q(0), &get, true).unwrap();
    r.pump();
    let id = r
        .events()
        .iter()
        .find_map(|e| match *e {
            Event::H3Request(_, id) => Some(id),
            _ => None,
        })
        .expect("H3Request");
    assert_eq!(r.w.h3_recv_headers(r.now, id, &mut |_, _| {}), Ok(true));
    assert_eq!(
        r.w.h3_send_headers(r.now, id, &[h(":status", "200")], false),
        Ok(())
    );
    r.pump();
    let s = r.peer_stream(Q(0));
    r.limit(s, Some(0));
    assert_eq!(
        r.w.h3_send_body(r.now, id, b"x", false),
        Err(StreamError::Blocked),
        "the frame is in flight"
    );
    r.events();
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    r.h.push_event(Event::StreamPeerReset(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10c }]);
    assert_eq!(
        r.events(),
        [Event::H3Writable(id)],
        "a blocked pump learns of it"
    );
    let n = sends(&r, s, false);
    assert_eq!(
        r.w.h3_send_body(r.now, id, b"x", false),
        Err(StreamError::Reset)
    );
    assert_eq!(r.w.h3_finish(r.now, id), Err(StreamError::Reset));
    assert_eq!(sends(&r, s, false), n, "nothing written after the reset");
}

/// Client role of `peer_reset_after_finished_ends_send` (adoption spec §4.5 "A peer RESET
/// after Finished"): the upload is accepted and discarded and the response still ends
/// clean.
#[test]
fn peer_reset_after_finished_client_discards() {
    let (mut r, id, s, _) = posting();
    let b = peer_block(&r, Q(0));
    r.peer.release(b);
    r.peer
        .send_headers(Q(0), &[f(":status", "200")], true)
        .expect("peer response");
    r.pump();
    r.events();
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    r.h.push_event(Event::StreamPeerReset(s, 0x10c));
    r.w.drive(r.now);
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10c }]);
    assert_eq!(r.events(), [Event::H3Writable(id)]);
    let n = sends(&r, s, false);
    assert_eq!(r.w.h3_send_body(r.now, id, &[7u8; 4096], false), Ok(4096));
    assert_eq!(r.w.h3_finish(r.now, id), Ok(()));
    assert_eq!(sends(&r, s, false), n, "nothing written");
    assert_eq!(r.w.h3_recv_headers(r.now, id, &mut |_, _| {}), Ok(true));
    let mut buf = [0u8; 64];
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((0, true)));
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let ev = r.events();
    assert!(
        matches!(ev[..], [Event::H3Closed(x, _)] if x == id),
        "one H3Closed: {ev:?}"
    );
}

/// The gateway answers a request the peer already reset: `Err(Reset)` as for the body, not
/// `Stale` for a request still held. Before `Finished` the request is aborted; after it the
/// send side is stopped (found by the property test).
#[test]
fn send_headers_after_peer_reset_resets() {
    for fin in [false, true] {
        let mut r = server();
        let get = [
            f(":method", "GET"),
            f(":scheme", "https"),
            f(":authority", "example.com"),
            f(":path", "/"),
        ];
        r.peer.send_headers(Q(0), &get, fin).unwrap();
        r.pump();
        let id = r
            .events()
            .iter()
            .find_map(|e| match *e {
                Event::H3Request(_, id) => Some(id),
                _ => None,
            })
            .expect("H3Request");
        assert_eq!(r.w.h3_recv_headers(r.now, id, &mut |_, _| {}), Ok(fin));
        let s = r.peer_stream(Q(0));
        r.h.expect_stream_recv(s, Err(StreamError::Reset));
        r.h.push_event(Event::StreamPeerReset(s, 0x10c));
        r.w.drive(r.now);
        assert_eq!(
            r.w.h3_send_headers(r.now, id, &[h(":status", "200")], false),
            Err(StreamError::Reset),
            "fin = {fin}"
        );
    }
}
