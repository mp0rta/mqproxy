//! Request receive: HEADERS bootstrap, `h3_recv_headers`, body pull, carry and
//! "reset, code pending" (adoption spec §4.3 "Start", §4.4, §5.3 (2), (3), (6)).

mod common;

use common::{Rig, aborts, recvs};
use h3wire::{FieldRef, HeaderBlockId, HeadersKind, StreamId as Q};
use mq_runtime::testing::Call;
use mq_transport_api::{
    Error, Event, H3Header, H3ReqId, H3ReqInfo, StreamError, StreamId, TransportOps,
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

fn get_request() -> Vec<FieldRef<'static>> {
    vec![
        f(":method", "GET"),
        f(":scheme", "https"),
        f(":authority", "example.com"),
        f(":path", "/x"),
        f("user-agent", "t"),
        f("accept", "*/*"),
    ]
}

/// Server rig with SETTINGS exchanged and `NewConn` drained.
fn server() -> Rig {
    let mut r = Rig::server();
    r.pump();
    r.events();
    r
}

/// Client rig with SETTINGS exchanged and a request on quic id 0 whose HEADERS reached
/// the peer (`fin`: the request ends with them).
fn client_request(fin: bool) -> (Rig, H3ReqId) {
    let mut r = Rig::client();
    r.pump();
    r.events();
    let id = r.w.open_h3_request(r.now, r.conn).expect("open_h3_request");
    let hs = [
        h(":method", "GET"),
        h(":scheme", "https"),
        h(":authority", "example.com"),
        h(":path", "/"),
    ];
    r.w.h3_send_headers(r.now, id, &hs, fin)
        .expect("send_headers");
    r.pump();
    let b = peer_block(&r, HeadersKind::Request);
    r.peer.release(b);
    (r, id)
}

/// The peer's last received header block of `kind`.
fn peer_block(r: &Rig, kind: HeadersKind) -> HeaderBlockId {
    r.peer_events
        .iter()
        .rev()
        .find_map(|e| match *e {
            h3wire::Event::Headers { block, kind: k, .. } if k == kind => Some(block),
            _ => None,
        })
        .expect("peer got the block")
}

/// The id from the single `H3Request`, asserting `[H3Request, H3Readable]`.
fn started(r: &mut Rig) -> H3ReqId {
    let ev = r.events();
    let Some(&Event::H3Request(c, id)) = ev.first() else {
        panic!("no H3Request: {ev:?}");
    };
    assert_eq!(c, r.conn);
    assert_eq!(ev, [Event::H3Request(c, id), Event::H3Readable(id)]);
    id
}

fn recv_headers(r: &mut Rig, id: H3ReqId) -> (Result<bool, StreamError>, Vec<(String, String)>) {
    let mut got = Vec::new();
    let res = r.w.h3_recv_headers(r.now, id, &mut |n, v| {
        got.push((
            String::from_utf8(n.to_vec()).unwrap(),
            String::from_utf8(v.to_vec()).unwrap(),
        ))
    });
    (res, got)
}

/// `h3_recv_body` with a `cap`-byte buf until `fin`, an error or `Blocked`; every result.
fn pull(r: &mut Rig, id: H3ReqId, cap: usize) -> Vec<Result<(Vec<u8>, bool), StreamError>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; cap];
    loop {
        let res = r.w.h3_recv_body(r.now, id, &mut buf);
        let done = !matches!(res, Ok((_, false)));
        out.push(res.map(|(n, fin)| (buf[..n].to_vec(), fin)));
        if done {
            return out;
        }
    }
}

/// Asserts the pulled results deliver `body` exactly, with `fin` only on the call that
/// returns its last byte, and each slice ≤ `cap`.
fn assert_body(got: &[Result<(Vec<u8>, bool), StreamError>], body: &[u8], cap: usize) {
    let mut all = Vec::new();
    for (i, g) in got.iter().enumerate() {
        let (bytes, fin) = g.as_ref().expect("no error");
        assert!(bytes.len() <= cap, "slice {i} is {} > {cap}", bytes.len());
        assert!(
            !bytes.is_empty(),
            "an empty result at call {i} (fin comes with the last byte)"
        );
        all.extend_from_slice(bytes);
        assert_eq!(*fin, i == got.len() - 1, "fin only on the last call");
    }
    assert_eq!(all.len(), body.len());
    assert!(all == body, "body bytes differ");
}

fn close_codes(r: &Rig) -> Vec<u64> {
    r.h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::CloseConnWith { code, .. } => Some(code),
            _ => None,
        })
        .collect()
}

fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

/// A raw HEADERS frame over a static-only QPACK section of `fields` (no validation).
fn raw_headers(fields: &[FieldRef]) -> Vec<u8> {
    let mut p = Vec::new();
    h3wire::qpack::encoder::encode_field_section(fields, &mut p);
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x01, p.len() as u64, &mut out);
    out.extend_from_slice(&p);
    out
}

#[test]
fn request_headers_only() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), true).unwrap();
    r.pump();
    let id = started(&mut r);
    let (res, got) = recv_headers(&mut r, id);
    assert_eq!(res, Ok(true));
    let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            ":method",
            ":scheme",
            ":authority",
            ":path",
            "user-agent",
            "accept"
        ]
    );
    assert_eq!(got[0].1, "GET");
    assert_eq!(got[2].1, "example.com");
    assert_eq!(got[3].1, "/x");
    assert_eq!(
        r.w.h3_req_info(id),
        Ok(H3ReqInfo {
            conn: r.conn,
            quic_id: 0
        })
    );
}

#[test]
fn request_with_body() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    let mut buf = [0u8; 16 * 1024];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Blocked),
        "nothing arrived since the last pump"
    );
    let body = body_of(100 * 1024);
    r.peer_send_body(Q(0), &body, true);
    r.pump();
    let got = pull(&mut r, id, 16 * 1024);
    assert_body(&got, &body, 16 * 1024);
}

/// Review Focus 1.
#[test]
fn carry_fed_to_smaller_buf() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    let body = body_of(3000);
    r.peer_send_body(Q(0), &body, true);
    r.pump();
    let s = r.peer_stream(Q(0));
    assert_eq!(
        r.h.recv_pending(s),
        0,
        "one delivery, read whole by the bootstrap"
    );
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    let reads = recvs(&r, s);
    let got = pull(&mut r, id, 1024);
    assert_body(&got, &body, 1024);
    assert_eq!(recvs(&r, s), reads, "fed from the carry only");
}

#[test]
fn framing_only_read_continues() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    let payload = body_of(500);
    let frame = r.peer.send_data(Q(0), payload.len() as u64, false).unwrap();
    let prefix = frame.prefix().to_vec();
    r.deliver(Q(0), &prefix, false);
    r.pump(); // chunk 1: the DATA prefix only
    r.deliver(Q(0), &payload, false);
    r.peer
        .data_written(Q(0), prefix.len() + payload.len())
        .unwrap();
    r.pump(); // chunk 2: the payload
    let mut buf = [0u8; 4096];
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((500, false)));
    assert!(buf[..500] == payload[..]);
}

#[test]
fn trailers_discarded() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    let body = body_of(6000);
    r.peer_send_body(Q(0), &body, false);
    r.peer
        .send_headers(Q(0), &[f("x-checksum", "abc")], true)
        .unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    let got = pull(&mut r, id, 16 * 1024);
    assert_eq!(got.last(), Some(&Ok((vec![], true))), "fin after the body");
    let all: Vec<u8> = got
        .iter()
        .flat_map(|g| g.as_ref().unwrap().0.clone())
        .collect();
    assert!(all == body);
    assert_eq!(recv_headers(&mut r, id).0, Err(StreamError::Blocked));
    assert!(!r.events().iter().any(|e| matches!(e, Event::H3Readable(_))));
}

/// Review Focus 2.
#[test]
fn informational_at_read_boundary() {
    let (mut r, id) = client_request(true);
    r.events();
    r.peer
        .send_headers(Q(0), &[f(":status", "103"), f("link", "</a>")], false)
        .unwrap();
    r.peer
        .send_headers(Q(0), &[f(":status", "200"), f("server", "p")], false)
        .unwrap();
    r.pump();
    let s = r.peer_stream(Q(0));
    assert_eq!(recvs(&r, s), 1, "both blocks in one transport read");
    let ev = r.events();
    assert_eq!(ev, [Event::H3Readable(id)]);
    let (res, got) = recv_headers(&mut r, id);
    assert_eq!(res, Ok(false));
    assert_eq!(
        got,
        [
            (":status".to_string(), "200".to_string()),
            ("server".to_string(), "p".to_string())
        ]
    );
}

#[test]
fn headers_blocked_when_none() {
    // Server: the request block was taken; no further block.
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    assert_eq!(recv_headers(&mut r, id).0, Err(StreamError::Blocked));
    // Client: no response block yet.
    let (mut r, id) = client_request(true);
    assert_eq!(recv_headers(&mut r, id).0, Err(StreamError::Blocked));
}

#[test]
fn paused_until_release() {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    r.peer_send_body(Q(0), b"0123456789", false);
    r.peer.send_headers(Q(0), &[f("x-t", "1")], true).unwrap();
    r.pump();
    let id = started(&mut r);
    // The request block is still unreleased: the body flows, the trailers wait.
    let mut buf = [0u8; 1024];
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((10, false)));
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Blocked)
    );
    assert_eq!(r.events(), []);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    assert_eq!(r.events(), [Event::H3Readable(id)], "carry and FIN remain");
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((0, true)));
}

/// Server request with HEADERS read; returns (rig, id, stream).
fn reading_request() -> (Rig, H3ReqId, StreamId) {
    let mut r = server();
    r.peer.send_headers(Q(0), &get_request(), false).unwrap();
    r.pump();
    let id = started(&mut r);
    assert_eq!(recv_headers(&mut r, id).0, Ok(false));
    let s = r.peer_stream(Q(0));
    (r, id, s)
}

#[test]
fn reset_code_pending() {
    let (mut r, id, s) = reading_request();
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    let mut buf = [0u8; 1024];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Reset)
    );
    let reads = recvs(&r, s);
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Reset)
    );
    assert_eq!(recvs(&r, s), reads, "nothing more is read or fed");
    assert_eq!(aborts(&r, s), [], "the code is not known yet");
    r.h.push_event(Event::StreamPeerReset(s, 0x10c));
    r.w.drive(r.now);
    // stream_reset_received ran once: h3wire reset our send side with the peer's code.
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10c }]);
}

#[test]
fn reset_code_pending_then_stream_closed() {
    let (mut r, id, s) = reading_request();
    r.h.expect_stream_recv(s, Err(StreamError::Reset));
    let mut buf = [0u8; 1024];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Reset)
    );
    // The transport dropped the StreamPeerReset: only StreamClosed arrives.
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let ev = r.events();
    let closed: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e, Event::H3Closed(..)))
        .collect();
    assert_eq!(closed.len(), 1, "{ev:?}");
    let Event::H3Closed(cid, close) = closed[0] else {
        unreachable!()
    };
    assert_eq!(*cid, id);
    assert_eq!(close.unread, None);
    assert_eq!(aborts(&r, s), [], "actions on the gone stream are dropped");
    // The id is stale from now on.
    let now = r.now;
    assert_eq!(recv_headers(&mut r, id).0, Err(StreamError::Stale));
    assert_eq!(r.w.h3_recv_body(now, id, &mut buf), Err(StreamError::Stale));
    assert_eq!(
        r.w.h3_send_headers(now, id, &[h(":status", "200")], false),
        Err(StreamError::Stale)
    );
    assert_eq!(
        r.w.h3_send_body(now, id, b"x", false),
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
    assert!(!r.events().iter().any(|e| matches!(e, Event::H3Closed(..))));
}

/// adoption spec §5.3 (6).
#[test]
fn malformed_headers_never_reach_gateway() {
    let mut r = server();
    let mut fields = get_request();
    fields.push(f("X-Upper", "1"));
    r.deliver(Q(0), &raw_headers(&fields), false);
    r.pump();
    assert_eq!(r.events(), []);
    let s = r.peer_stream(Q(0));
    assert_eq!(
        aborts(&r, s),
        [
            Call::StreamResetSend { s, code: 0x10e },
            Call::StreamStopSending { s, code: 0x10e }
        ]
    );
}

/// A stream h3wire aborts during a feed is read to its FIN, so it can retire
/// (adoption spec §3, §4.4).
#[test]
fn abort_in_feed_retires() {
    let mut r = server();
    let mut fields = get_request();
    fields.push(f("X-Upper", "1"));
    let mut bytes = raw_headers(&fields);
    let mut data = Vec::new();
    h3wire::frame::encode_header(0x00, 10_000, &mut data);
    bytes.extend_from_slice(&data);
    bytes.extend_from_slice(&body_of(10_000));
    assert!(bytes.len() > 4096);
    r.deliver(Q(0), &bytes, true);
    r.pump();
    assert_eq!(r.events(), []);
    let s = r.peer_stream(Q(0));
    assert_eq!(r.h.recv_pending(s), 0, "read to the FIN");
    assert_eq!(
        aborts(&r, s),
        [
            Call::StreamResetSend { s, code: 0x10e },
            Call::StreamStopSending { s, code: 0x10e }
        ]
    );
}

/// The xqc_h3 backend's order (`reserve_local`): role, then conn, then protocol.
#[test]
fn open_h3_request_errors() {
    let mut r = Rig::client();
    r.pump();
    let unknown = r.h.new_conn_id();
    assert_eq!(r.w.open_h3_request(r.now, unknown), Err(Error::Stale));
    let raw = r.h.new_conn_id();
    r.h.set_conn_stats(raw, Default::default());
    assert_eq!(r.w.open_h3_request(r.now, raw), Err(Error::Other));
    let mut r = server();
    assert_eq!(r.w.open_h3_request(r.now, r.conn), Err(Error::Role));
    let unknown = r.h.new_conn_id();
    assert_eq!(r.w.open_h3_request(r.now, unknown), Err(Error::Role));
    assert!(!r.h.log().iter().any(|c| matches!(c, Call::OpenStream(_))));
}

/// adoption spec §5.3 (2), server.
#[test]
fn fin_without_headers() {
    let mut r = server();
    r.deliver(Q(0), &[], true);
    r.pump();
    assert_eq!(r.events(), []);
    let s = r.peer_stream(Q(0));
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10d }]);
}

/// adoption spec §5.3 (2), client.
#[test]
fn no_final_response() {
    let (mut r, id) = client_request(false);
    r.events();
    r.peer
        .send_headers(Q(0), &[f(":status", "103")], false)
        .unwrap();
    r.deliver(Q(0), &[], true); // raw FIN: h3wire cannot end a stream without a response
    r.pump();
    assert_eq!(r.events(), [Event::H3Readable(id)]);
    assert_eq!(recv_headers(&mut r, id).0, Err(StreamError::Reset));
    let mut buf = [0u8; 64];
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut buf),
        Err(StreamError::Reset)
    );
    let s = r.peer_stream(Q(0));
    assert_eq!(aborts(&r, s), [Call::StreamResetSend { s, code: 0x10e }]);
}

/// adoption spec §5.3 (3).
#[test]
fn oversized_headers_closes() {
    let mut r = server();
    let mut bytes = Vec::new();
    h3wire::frame::encode_header(0x01, 65537, &mut bytes);
    bytes.extend_from_slice(&body_of(10_000)); // payload follows the frame header
    r.deliver(Q(0), &bytes, false);
    r.pump();
    assert_eq!(close_codes(&r), [0x107]);
    // Closed at the frame header: the first read is dropped and nothing more is read.
    let s = r.peer_stream(Q(0));
    assert_eq!(recvs(&r, s), 1);
    assert_eq!(
        r.h.recv_pending(s),
        1,
        "the rest of the payload is never read"
    );
    assert!(
        !r.events()
            .iter()
            .any(|e| matches!(e, Event::H3Request(..) | Event::H3Readable(_)))
    );
}

/// The MITM's terminal probe `h3_recv_body(id, &mut [])` (mq-proxy `client/mitm/stream.rs`)
/// answers as on xqc_h3: `Blocked` while payload or nothing is left, `(0, true)` once only
/// the FIN is. The FIN comes alone here: the probe reads it into the empty carry and feeds
/// it as a bare carried FIN (a carried FIN never outlives a feed otherwise: a slice passes it
/// with the whole carry).
#[test]
fn empty_probe_bare_fin() {
    let (mut r, id, _) = reading_request();
    let body = body_of(100);
    r.peer_send_body(Q(0), &body, false);
    r.pump();
    let probe = |r: &mut Rig| r.w.h3_recv_body(r.now, id, &mut []);
    assert_eq!(probe(&mut r), Err(StreamError::Blocked), "payload left");
    assert_eq!(
        pull(&mut r, id, 4096),
        [Ok((body, false)), Err(StreamError::Blocked)]
    );
    assert_eq!(probe(&mut r), Err(StreamError::Blocked), "nothing left");
    r.peer_send_body(Q(0), &[], true);
    r.pump();
    assert_eq!(probe(&mut r), Ok((0, true)), "only the FIN left");
}

/// Framing alone (an empty DATA frame) left before the FIN: the probe feeds no byte (slices
/// of at most `buf.len()`, adoption spec §4.4) and stays `Blocked`, where xqc_h3, which parsed
/// the frame on arrival, answers `(0, true)`. Open against the spec (final-fix report, I3);
/// the next read with a buffer ends the body.
#[test]
fn empty_probe_framing_before_fin() {
    let (mut r, id, _) = reading_request();
    let mut bytes = Vec::new();
    h3wire::frame::encode_header(0x00, 3, &mut bytes);
    bytes.extend_from_slice(b"abc");
    h3wire::frame::encode_header(0x00, 0, &mut bytes);
    r.deliver(Q(0), &bytes, true);
    r.pump();
    let mut buf = [0u8; 64];
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((3, false)));
    assert_eq!(
        r.w.h3_recv_body(r.now, id, &mut []),
        Err(StreamError::Blocked)
    );
    assert_eq!(r.w.h3_recv_body(r.now, id, &mut buf), Ok((0, true)));
}
