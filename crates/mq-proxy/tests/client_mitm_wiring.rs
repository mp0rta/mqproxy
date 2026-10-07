// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §2.2 / §7.9 / §7.10: the MITM front inside `Client` — the shared
//! H3 tunnel, routing by owner, the opaque hand-off to the raw tunnel, the
//! `mq.mitm` line and shutdown.

mod common;
mod mitm_harness;

use common::*;
use mitm_harness::{Browser, GOAWAY};
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{IoRequest, TcpId};
use mq_transport_api::{
    CloseReason, ConnConfig, ConnId, ConnProto, ConnStats, ErrType, Event, H3ReqId, PathStats,
};
use std::time::Duration;

fn mitm(c: ClientConfig) -> ClientConfig {
    ClientConfig {
        mitm: Some(mitm_harness::cfg("ca-p256")),
        ..c
    }
}

/// A MITM client (raw + H3 tunnel) whose H3 tunnel is established.
fn up(c: ClientConfig) -> (H, ConnId) {
    let mut h = H::new(mitm(c));
    let gw = h.gw_conn.expect("an H3 tunnel");
    h.event(Event::ConnEstablished(gw));
    (h, gw)
}

fn connect_cfgs(h: &H) -> Vec<ConnConfig> {
    (h.log().into_iter())
        .filter_map(|c| match c {
            Call::Connect(cc) => Some(cc),
            _ => None,
        })
        .collect()
}

fn closed_ev(c: ConnId) -> Event {
    Event::ConnClosed(
        c,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

/// Bytes both ways until neither side has anything to send.
fn relay(h: &mut H, b: &mut Browser, tcp: TcpId) {
    for _ in 0..100 {
        h.drive();
        let from = h.tx_all(tcp);
        let to = b.exchange(&from);
        if !to.is_empty() {
            h.rx(tcp, &to);
        }
        if from.is_empty() && to.is_empty() {
            return;
        }
    }
    panic!("relay did not settle");
}

/// A browser captured by `TRANSPARENT` (original dst 127.0.0.1:443), TLS
/// and h2 handshaken.
fn browse(h: &mut H, b: &mut Browser) -> TcpId {
    let tcp = h.accept(h.tproxy, meta(Some(addr(443))));
    relay(h, b, tcp);
    tcp
}

fn next_req(h: &H, gw: ConnId) -> H3ReqId {
    let r = h.t.new_h3_req_id();
    h.t.expect_open_h3_request(gw, Ok(r));
    r
}

fn header<'a>(h: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    h.iter()
        .find(|(n, _)| n == name.as_bytes())
        .map(|(_, v)| &v[..])
}

fn h3_opens(h: &H, gw: ConnId) -> usize {
    h.count(|c| *c == Call::OpenH3Request(gw))
}

fn stats() -> ConnStats {
    ConnStats {
        mp_state: 1,
        app_bytes: 0,
        standby_bytes: 0,
        paths: vec![PathStats {
            id: 0,
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

// ---- tunnels ----

#[test]
fn mitm_only_client_creates_h3_and_raw_tunnels() {
    let h = H::new(mitm(cfg()));
    let cs = connect_cfgs(&h);
    let protos: Vec<ConnProto> = cs.iter().map(|c| c.proto).collect();
    assert_eq!(protos, [ConnProto::Raw, ConnProto::H3]);
    assert_eq!(cs[1].sni, "mqproxy");
    assert!(h.sh.app().gateway().is_none(), "no fetch front");
}

#[test]
fn mitm_request_opens_h3_on_tunnel() {
    let (mut h, gw) = up(ClientConfig {
        token: "tok-xyz".into(),
        ..cfg()
    });
    let mut b = Browser::new("example.com");
    let tcp = browse(&mut h, &mut b);
    let r = next_req(&h, gw);
    let s = b.request("GET", "/x", &[], b"");
    relay(&mut h, &mut b, tcp);
    assert_eq!(h3_opens(&h, gw), 1);
    let sent = h.t.h3_headers_sent(r);
    let (hs, _) = &sent[0];
    assert_eq!(header(hs, ":authority"), Some(&b"example.com"[..]));
    assert_eq!(header(hs, "x-mq-auth"), Some(&b"Bearer tok-xyz"[..]));
    // The H3 events of the exchange reach the MITM front (Owner::Mitm).
    h.t.inject_h3_headers(r, vec![(b":status".to_vec(), b"204".to_vec())], true);
    relay(&mut h, &mut b, tcp);
    let (head, body) = b.response(&s).expect("complete");
    assert_eq!(head.status, 204);
    assert!(body.is_empty());
}

#[test]
fn fetch_and_mitm_share_one_tunnel() {
    let (mut h, gw) = up(ClientConfig {
        gateway: Some(addr(8080)),
        ..cfg()
    });
    let protos: Vec<ConnProto> = connect_cfgs(&h).iter().map(|c| c.proto).collect();
    assert_eq!(protos, [ConnProto::Raw, ConnProto::H3], "one H3 tunnel");
    next_req(&h, gw);
    let f = h.accept(h.fetch, meta(None));
    h.rx(f, &fetch_req("", b""));
    h.drive();
    assert_eq!(h3_opens(&h, gw), 1, "the fetch front");
    let mut b = Browser::new("example.com");
    let tcp = browse(&mut h, &mut b);
    next_req(&h, gw);
    b.request("GET", "/x", &[], b"");
    relay(&mut h, &mut b, tcp);
    assert_eq!(h3_opens(&h, gw), 2, "the MITM front, same conn");
}

// ---- opaque relay ----

#[test]
fn opaque_handoff_relays_peeked_bytes_first() {
    let mut h = H::new(mitm(cfg()));
    h.serving();
    let s = h.next_stream(h.conn);
    let mut b = Browser::new("example.com").alpn(&[b"http/1.1"]);
    let hello = b.exchange(&[]);
    let tcp = h.accept(h.tproxy, meta(Some(addr(443))));
    h.rx(tcp, &hello);
    h.drive();
    let req = h.t.sent_bytes(s);
    assert_eq!(req.first(), Some(&0x01), "CONNECT_TCP on the raw tunnel");
    assert!(!req.ends_with(&hello), "nothing before the response");
    h.t.expect_stream_recv(s, Ok((connect_resp(0, 0), false)));
    h.event(Event::StreamReadable(s));
    h.drive();
    let mut want = req;
    want.extend_from_slice(&hello);
    assert!(h.t.sent_bytes(s) == want, "the ClientHello, first");
    assert_eq!(
        h.tx_all(tcp),
        b"",
        "no ingress reply on a transparent socket"
    );
}

// ---- metrics ----

#[test]
fn metrics_tick_prints_mq_mitm_after_tunnel_block() {
    log_capture::install();
    let (mut h, gw) = up(ClientConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..cfg()
    });
    h.t.set_conn_stats(gw, stats());
    log_capture::take();
    h.advance(Duration::from_secs(1));
    let lines = log_capture::take();
    assert!(lines.iter().any(|l| l.contains("mq.path")), "{lines:?}");
    assert!(
        !lines.iter().any(|l| l.contains("mq.mitm")),
        "nothing while all-zero: {lines:?}"
    );
    let mut b = Browser::new("example.com");
    browse(&mut h, &mut b);
    log_capture::take();
    h.advance(Duration::from_secs(1));
    let want = "INFO mq.mitm conns=1 streams=0 mitm=1 opaque_not_tls=0 opaque_no_sni=0 \
                opaque_bad_sni=0 opaque_no_h2=0 opaque_ignored=0 opaque_ca_scope=0 \
                opaque_tls_incompat=0 opaque_timeout=0 opaque_too_large=0 opaque_eof=0 \
                opaque_capacity=0 tls_fail=0 h2_fail=0 dead=0 leaf_hit=0 leaf_miss=1 \
                reqs=0 rejects=0";
    let tick = |lines: &[String]| {
        let at = lines.iter().position(|l| l == want);
        let at = at.unwrap_or_else(|| panic!("{lines:?}"));
        let last_path = lines.iter().rposition(|l| l.contains("mq.path"));
        assert!(last_path.is_some_and(|p| p < at), "{lines:?}");
    };
    tick(&log_capture::take());
    // Once more at shutdown, after the tunnel's block.
    h.t.hold_conn_closed(true);
    h.sh.on_shutdown_signal(h.now);
    tick(&log_capture::take());
}

// ---- shutdown ----

#[test]
fn shutdown_closes_peek_and_live_conns() {
    let (mut h, gw) = up(cfg());
    let peek = h.accept(h.tproxy, meta(Some(addr(443))));
    let mut b = Browser::new("example.com");
    let live = browse(&mut h, &mut b);
    h.reqs();
    h.t.hold_conn_closed(true);
    h.sh.on_shutdown_signal(h.now);
    let reqs = h.reqs();
    assert!(H::closed(&reqs, peek), "{reqs:?}");
    assert!(!H::closed(&reqs, live), "Closing drains first");
    let from = h.tx_all(live);
    b.exchange(&from);
    assert!(b.frames().iter().any(|f| f.ty == GOAWAY), "GOAWAY");
    assert!(b.close_notify, "close_notify");
    // §7.9: exit waits for the tunnels, not for the Closing conn.
    h.event(closed_ev(h.conn));
    h.event(closed_ev(gw));
    assert_eq!(h.sh.exit_status(), Some(0));
    assert!(
        !reqs
            .iter()
            .any(|r| matches!(r, IoRequest::TcpClose { tcp, abort: true } if *tcp == live)),
        "not aborted before exit"
    );
}

// ---- logging ----

#[test]
fn no_header_values_logged() {
    log_capture::install();
    let (mut h, gw) = up(cfg());
    log_capture::take();
    let mut b = Browser::new("example.com");
    let tcp = browse(&mut h, &mut b);
    let r = next_req(&h, gw);
    let s = b.request(
        "GET",
        "/x",
        &[
            ("cookie", "sid=SEKRIT-COOKIE"),
            ("authorization", "Basic SEKRIT-AUTH"),
        ],
        b"",
    );
    relay(&mut h, &mut b, tcp);
    let resp = vec![
        (b":status".to_vec(), b"200".to_vec()),
        (b"set-cookie".to_vec(), b"sid=SEKRIT-SET".to_vec()),
    ];
    h.t.inject_h3_headers(r, resp, false);
    h.t.inject_h3_body(r, b"SEKRIT-BODY".to_vec(), true);
    relay(&mut h, &mut b, tcp);
    assert!(b.response(&s).is_some(), "complete");
    h.sh.on_shutdown_signal(h.now);
    let lines = log_capture::take();
    assert!(!lines.is_empty());
    assert!(
        !lines.iter().any(|l| l.contains("SEKRIT")),
        "a header or body value was logged: {lines:?}"
    );
}
