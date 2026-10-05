//! SP3 spec §5.3: the fetch upload (local TCP → H3) — 16 KiB chunks with the
//! FIN on the last byte, H3 backpressure, the EOF rule, bytes beyond
//! `Content-Length`, and the abort paths (§5.5).

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::Call;
use mq_runtime::{IoRequest, IoResult, TcpId};
use mq_transport_api::{ConnId, Event, H3Close, H3ReqId, H3ReqStats, StreamError, Unread};
use std::io;

/// A gateway-only client whose tunnel is established.
fn up() -> (H, ConnId) {
    let mut h = H::new(ClientConfig {
        gateway: Some(addr(8080)),
        has_tcp_ingress: false,
        ..cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    (h, gw)
}

/// An open fetch request with `Content-Length: cl` whose head read carried `body`.
fn open(cl: usize, body: &[u8], script: &[Result<usize, StreamError>]) -> (H, TcpId, H3ReqId) {
    let (mut h, gw) = up();
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(gw, Ok(r));
    for v in script {
        h.t.expect_h3_send_body(r, *v);
    }
    let tcp = h.accept(h.fetch, meta(None));
    h.rx(tcp, &fetch_req(&format!("Content-Length: {cl}\r\n"), body));
    (h, tcp, r)
}

/// `(bytes offered, fin)` of every `h3_send_body` call on `r`.
fn send_calls(h: &H, r: H3ReqId) -> Vec<(Vec<u8>, bool)> {
    h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::H3SendBody { r: x, bytes, fin } if x == r => Some((bytes, fin)),
            _ => None,
        })
        .collect()
}

fn resets(h: &H, r: H3ReqId) -> usize {
    h.count(|c| *c == Call::H3Reset(r))
}

/// `Some(abort)` when the socket was closed.
fn close_of(h: &mut H, tcp: TcpId) -> Option<bool> {
    h.reqs().into_iter().find_map(|q| match q {
        IoRequest::TcpClose { tcp: t, abort } if t == tcp => Some(abort),
        _ => None,
    })
}

fn rx_room(h: &mut H, tcp: TcpId) -> usize {
    h.sh.tcp_rx_buf(tcp).len()
}

#[test]
fn upload_streams_in_16k_chunks_with_fin_on_last() {
    const CL: usize = 8 << 20;
    let body: Vec<u8> = (0..CL).map(|i| (i % 251) as u8).collect();
    let (mut h, tcp, r) = open(CL, b"", &[]);
    for piece in body.chunks(64 * 1024) {
        h.rx(tcp, piece);
    }
    let calls = send_calls(&h, r);
    assert_eq!(calls.len(), CL / 16_384);
    assert!(calls.iter().all(|(b, _)| b.len() == 16_384));
    let fins: Vec<usize> = (0..calls.len()).filter(|&i| calls[i].1).collect();
    assert_eq!(fins, [calls.len() - 1], "FIN only on the last byte");
    assert_eq!(h.t.h3_sends(r).concat(), body);
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn upload_blocked_consumes_nothing_then_resumes() {
    let (mut h, tcp, r) = open(5, b"hello", &[Err(StreamError::Blocked)]);
    assert!(h.t.h3_sends(r).is_empty());
    assert_eq!(rx_room(&mut h, tcp), 64 * 1024 - 5, "tcp_rx untouched");
    h.event(Event::H3Writable(r));
    assert_eq!(h.t.h3_sends(r), [b"hello".to_vec()]);
    assert!(send_calls(&h, r).last().unwrap().1, "FIN on the last byte");
    assert_eq!(rx_room(&mut h, tcp), 64 * 1024);
}

#[test]
fn upload_partial_final_chunk_resent_with_fin() {
    let body = b"0123456789abcdef";
    let (h, _, r) = open(16, body, &[Ok(10)]);
    assert_eq!(
        send_calls(&h, r),
        [(body.to_vec(), true), (body[10..].to_vec(), true)]
    );
    assert_eq!(h.t.h3_sends(r), [body[..10].to_vec(), body[10..].to_vec()]);
}

#[test]
fn upload_eof_while_blocked_completes() {
    let (mut h, tcp, r) = open(5, b"hello", &[Err(StreamError::Blocked)]);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert_eq!(resets(&h, r), 0);
    assert_eq!(close_of(&mut h, tcp), None);
    h.event(Event::H3Writable(r));
    assert_eq!(h.t.h3_sends(r), [b"hello".to_vec()]);
    assert!(send_calls(&h, r).last().unwrap().1, "FIN on the last byte");
    assert_eq!(resets(&h, r), 0);
    assert_eq!(close_of(&mut h, tcp), None);
}

#[test]
fn upload_eof_short_resets_and_aborts() {
    // Five of ten bytes sent, then EOF: `tcp_rx.len() (0) < remaining (5)`.
    let (mut h, tcp, r) = open(10, b"hello", &[]);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert_eq!(resets(&h, r), 1);
    assert_eq!(close_of(&mut h, tcp), Some(true));
    // A blocked tail shorter than the remainder is a truncation too.
    let (mut h, tcp, r) = open(10, b"hello", &[Err(StreamError::Blocked)]);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert_eq!(resets(&h, r), 1);
    assert_eq!(close_of(&mut h, tcp), Some(true));
    assert!(h.t.h3_sends(r).is_empty(), "never a fake FIN");
}

#[test]
fn bytes_beyond_cl_discarded() {
    let (mut h, tcp, r) = open(5, b"helloEXTRA", &[]);
    assert_eq!(h.t.h3_sends(r), [b"hello".to_vec()]);
    assert_eq!(rx_room(&mut h, tcp), 64 * 1024);
    h.rx(tcp, b"more");
    assert_eq!(rx_room(&mut h, tcp), 64 * 1024);
    assert_eq!(send_calls(&h, r).len(), 1);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Eof);
    assert_eq!(resets(&h, r), 0);
    assert_eq!(close_of(&mut h, tcp), None);
}

#[test]
fn tcp_error_resets() {
    let (mut h, tcp, r) = open(10, b"hello", &[]);
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Error(io::ErrorKind::ConnectionReset));
    assert_eq!(resets(&h, r), 1);
    // Removed: a later `H3Writable` sends nothing.
    h.event(Event::H3Writable(r));
    assert_eq!(send_calls(&h, r).len(), 1);
}

const UPSTREAM_RESET: &[u8] =
    b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// SP4 spec §4.3: a send error resets the request and fails the response;
/// before the head that is the synthesised 502 (§6.2, §13.20).
#[test]
fn send_body_conn_error_aborts() {
    for e in [StreamError::Conn, StreamError::Reset] {
        let (mut h, tcp, r) = open(5, b"hello", &[Err(e)]);
        assert_eq!(h.tx_all(tcp), UPSTREAM_RESET, "{e:?}");
        assert_eq!(close_of(&mut h, tcp), Some(false), "{e:?}");
        assert_eq!(resets(&h, r), 1, "{e:?}");
        // Removed: neither `H3Writable` nor more data sends again.
        h.event(Event::H3Writable(r));
        assert_eq!(send_calls(&h, r).len(), 1, "{e:?}");
    }
}

/// SP4 spec §4.3 / §13.20: a `Stale` send is `Blocked` — the request's
/// `H3Closed` is queued; its rescue completes the request (SP3 aborted).
#[test]
fn send_stale_waits_for_h3closed_then_rescues() {
    let (mut h, tcp, r) = open(5, b"hello", &[Err(StreamError::Stale)]);
    assert_eq!(close_of(&mut h, tcp), None, "no abort");
    assert_eq!(resets(&h, r), 0);
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
    let unread = Unread {
        headers: Some(vec![(b":status".to_vec(), b"200".to_vec())]),
        body: b"ok".to_vec(),
    };
    h.t.close_h3(
        r,
        H3Close {
            stats,
            unread: Some(unread),
        },
    );
    h.drive();
    assert_eq!(
        h.tx_all(tcp),
        b"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n"
    );
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
    assert_eq!(send_calls(&h, r).len(), 1, "never resent");
}
