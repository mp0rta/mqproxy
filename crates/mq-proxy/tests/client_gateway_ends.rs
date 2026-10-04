//! SP3 spec §5.5 the fetch request's ends (finish with the rescued leftovers
//! of §3.7 (2), `H3Closed`, the incomplete-upload reset, abort), §5.9
//! shutdown, and §5.7 the metrics tick's two blocks.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{IoRequest, IoResult, TcpId};
use mq_transport_api::{
    CloseReason, ConnId, ConnStats, ErrType, Event, H3Close, H3ReqId, H3ReqStats, PathStats, Unread,
};
use std::io;
use std::time::Duration;

fn gw_only() -> ClientConfig {
    ClientConfig {
        gateway: Some(addr(8080)),
        has_tcp_ingress: false,
        ..cfg()
    }
}

/// A gateway-only client with an open fetch request carrying `extra` header
/// lines and `body`.
fn open_with(extra: &str, body: &[u8]) -> (H, TcpId, H3ReqId) {
    let mut h = H::new(gw_only());
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(gw, Ok(r));
    let tcp = h.accept(h.fetch, meta(None));
    h.rx(tcp, &fetch_req(extra, body));
    (h, tcp, r)
}

fn open() -> (H, TcpId, H3ReqId) {
    open_with("", b"")
}

fn hs(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

fn respond(h: &mut H, r: H3ReqId, head: &[(&str, &str)], fin: bool) {
    h.t.inject_h3_headers(r, hs(head), fin);
    h.drive();
}

fn body(h: &mut H, r: H3ReqId, bytes: &[u8], fin: bool) {
    h.t.inject_h3_body(r, bytes.to_vec(), fin);
    h.drive();
}

/// `H3Closed` for `r` with `unread`, then let the client run.
fn closed(h: &mut H, r: H3ReqId, unread: Option<Unread>) {
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
    h.t.close_h3(r, H3Close { stats, unread });
    h.drive();
}

fn unread(headers: Option<&[(&str, &str)]>, body: &[u8]) -> Option<Unread> {
    Some(Unread {
        headers: headers.map(hs),
        body: body.to_vec(),
    })
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

fn owned(h: &H, tcp: TcpId) -> bool {
    h.sh.app().gateway().unwrap().owns_tcp(tcp)
}

fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i + seed) % 251) as u8).collect()
}

fn chunked(b: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    for c in b.chunks(16_384) {
        o.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        o.extend_from_slice(c);
        o.extend_from_slice(b"\r\n");
    }
    o
}

const HEAD_CHUNKED: &[u8] =
    b"HTTP/1.1 200 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
const UPSTREAM_RESET: &[u8] =
    b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[test]
fn finish_write_order_pending_src_terminator_close() {
    // Review Focus 2: a consumer > 3 PTO behind a completed download.
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    let first = pattern(4 * 16_384, 0);
    body(&mut h, r, &first, false); // the fourth frame is stuck (`SendBufFull`)
    let rescued = pattern(100 * 1024, 7);
    closed(&mut h, r, unread(None, &rescued));
    let mut want = HEAD_CHUNKED.to_vec();
    want.extend(chunked(&first));
    want.extend(chunked(&rescued));
    want.extend_from_slice(b"0\r\n\r\n");
    let mut out = Vec::new();
    for _ in 0..16 {
        out.extend(h.tx_all(tcp)); // each drain → `on_tcp_writable`
        if let Some(abort) = close_of(&mut h, tcp) {
            assert!(!abort);
            out.extend(h.tx_all(tcp));
            break;
        }
    }
    assert_eq!(out.len(), want.len());
    assert!(out == want, "pending, then rescued frames, then terminator");
    assert!(!owned(&h, tcp));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn finish_from_unread_src() {
    let (mut h, tcp, r) = open();
    closed(&mut h, r, unread(Some(&[(":status", "200")]), b"hello"));
    let mut want = HEAD_CHUNKED.to_vec();
    want.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    assert_eq!(h.tx_all(tcp), want);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert!(!owned(&h, tcp));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn h3closed_without_unread_before_head_502_upstream_reset() {
    let (mut h, tcp, r) = open();
    closed(&mut h, r, None);
    assert_eq!(h.tx_all(tcp), UPSTREAM_RESET);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert!(!owned(&h, tcp));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn unread_body_without_headers_before_head_is_502() {
    let (mut h, tcp, r) = open();
    closed(&mut h, r, unread(None, b"abc"));
    assert_eq!(h.tx_all(tcp), UPSTREAM_RESET);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert!(!owned(&h, tcp));
}

#[test]
fn h3closed_after_head_aborts() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, b"abc", false);
    closed(&mut h, r, None);
    assert_eq!(close_of(&mut h, tcp), Some(true));
    assert!(!owned(&h, tcp));
    assert_eq!(resets(&h, r), 0, "the H3 side is gone");
}

#[test]
fn h3closed_after_tunnel_closed_still_ends_request() {
    // spec §3.5: `H3Closed` may follow `ConnClosed`; it is the one terminal event.
    for started in [false, true] {
        let (mut h, tcp, r) = open();
        if started {
            respond(&mut h, r, &[(":status", "200")], false);
        }
        let gw = h.gw_conn.unwrap();
        h.event(Event::ConnClosed(
            gw,
            CloseReason {
                err_type: ErrType::Transport,
                code: 0,
            },
        ));
        assert!(owned(&h, tcp), "ConnClosed alone does not end it");
        closed(&mut h, r, None);
        if started {
            assert_eq!(close_of(&mut h, tcp), Some(true));
        } else {
            assert_eq!(h.tx_all(tcp), UPSTREAM_RESET);
            assert_eq!(close_of(&mut h, tcp), Some(false));
        }
        assert!(!owned(&h, tcp), "started={started}");
    }
}

#[test]
fn finish_with_upload_remaining_resets() {
    // An early 403 while 90 of 100 body bytes are still to come.
    let (mut h, tcp, r) = open_with("Content-Length: 100\r\n", &[b'x'; 10]);
    respond(&mut h, r, &[(":status", "403")], true);
    assert_eq!(resets(&h, r), 1);
    assert_eq!(
        h.tx_all(tcp),
        b"HTTP/1.1 403 \r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
    );
    assert_eq!(close_of(&mut h, tcp), Some(false));
    // A complete upload is not reset.
    let (mut h, tcp, r) = open_with("Content-Length: 10\r\n", &[b'x'; 10]);
    respond(&mut h, r, &[(":status", "200")], true);
    h.tx_all(tcp);
    assert_eq!(close_of(&mut h, tcp), Some(false));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn unread_short_cl_aborts() {
    // The body check counts delivered plus rescued bytes: 10 + 50 < 100
    // aborts, 10 + 90 finishes.
    for (rescued, abort) in [(50, true), (90, false)] {
        let (mut h, tcp, r) = open();
        respond(
            &mut h,
            r,
            &[(":status", "200"), ("content-length", "100")],
            false,
        );
        body(&mut h, r, &[b'x'; 10], false);
        closed(&mut h, r, unread(None, &vec![b'y'; rescued]));
        if !abort {
            let out = h.tx_all(tcp);
            assert!(out.ends_with(&[&[b'x'; 10][..], &[b'y'; 90]].concat()));
        }
        assert_eq!(close_of(&mut h, tcp), Some(abort), "rescued={rescued}");
        assert!(!owned(&h, tcp));
        assert_eq!(resets(&h, r), 0);
    }
}

#[test]
fn tcp_error_while_finishing_removes() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    body(&mut h, r, &pattern(4 * 16_384, 0), true); // finishing, a frame stuck
    assert!(owned(&h, tcp));
    h.sh.tcp_rx_commit(h.now, tcp, IoResult::Error(io::ErrorKind::ConnectionReset));
    assert!(!owned(&h, tcp));
    assert_eq!(resets(&h, r), 0);
}

#[test]
fn shutdown_aborts_live_fetch_requests() {
    let (mut h, tcp, r) = open();
    respond(&mut h, r, &[(":status", "200")], false);
    let waiting = h.accept(h.fetch, meta(None)); // still in `Head`
    h.reqs();
    h.t.hold_conn_closed(true);
    h.sh.on_shutdown_signal(h.now);
    let reqs = h.reqs();
    for t in [tcp, waiting] {
        assert!(
            reqs.contains(&IoRequest::TcpClose {
                tcp: t,
                abort: true
            }),
            "{reqs:?}"
        );
        assert!(!owned(&h, t));
    }
    assert_eq!(resets(&h, r), 1);
    closed(&mut h, r, None); // the reset's own close: ignored
    assert_eq!(resets(&h, r), 1);
}

fn stats(id: u64) -> ConnStats {
    ConnStats {
        mp_state: 1,
        app_bytes: 0,
        standby_bytes: 0,
        paths: vec![PathStats {
            id,
            state: 1,
            srtt_us: 1,
            est_bw: 1,
            sent_bytes: 1,
            recv_bytes: 1,
            lost_count: 0,
            min_rtt_us: 1,
            cwnd: 1,
            bytes_in_flight: 0,
        }],
    }
}

fn path_ids(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| l.strip_prefix("INFO mq.path id="))
        .map(|l| l.split(' ').next().unwrap().to_owned())
        .collect()
}

#[test]
fn shutdown_dumps_tunnel_stats_then_closes() {
    log_capture::install();
    let mut h = H::new(gw_only());
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.t.set_conn_stats(gw, stats(5));
    h.t.hold_conn_closed(true);
    log_capture::take();
    h.sh.on_shutdown_signal(h.now);
    let lines = log_capture::take();
    assert!(
        lines.iter().any(|l| l.starts_with("INFO mq.conn ")),
        "{lines:?}"
    );
    assert_eq!(path_ids(&lines), ["5"]);
    assert_eq!(h.close_conn_count(gw), 1);
}

fn metrics_tick(cfg: ClientConfig) -> (Vec<String>, H) {
    log_capture::install();
    let mut h = H::new(ClientConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..cfg
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.t.set_conn_stats(gw, stats(7));
    let raw: ConnId = h.conn;
    h.t.set_conn_stats(raw, stats(3));
    log_capture::take();
    h.advance(Duration::from_secs(1));
    (log_capture::take(), h)
}

#[test]
fn metrics_tick_prints_raw_then_gateway_block() {
    let (lines, _h) = metrics_tick(ClientConfig {
        gateway: Some(addr(8080)),
        ..cfg()
    });
    assert_eq!(path_ids(&lines), ["3", "7"], "{lines:?}");
    let conns = lines
        .iter()
        .filter(|l| l.starts_with("INFO mq.conn "))
        .count();
    assert_eq!(conns, 2);
}

#[test]
fn gateway_only_metrics_tick_prints_gateway_block_only() {
    // spec §5.7: no raw tunnel is a permanent, silent state.
    let (lines, _h) = metrics_tick(gw_only());
    assert_eq!(path_ids(&lines), ["7"], "{lines:?}");
    assert!(!lines.iter().any(|l| l.starts_with("WARN")), "{lines:?}");
}
