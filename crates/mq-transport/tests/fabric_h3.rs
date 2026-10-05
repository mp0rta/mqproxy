//! spec §3.2, §3.3: H3 connections share the raw connections' slot table, admission,
//! provisional expiry and close reporting; H3 requests (spec §3.1, §3.4).
mod common;

use common::initial::{client_hello_fragment, initial};
use common::lockstep::{Peer, cfg, exchange_many, server_role};
use common::pair::{MS, Opts, Pair, T0, cli_addr, conn_cfg, srv_addr, stream_count};
use mq_transport_api::{
    ConnId, ConnProto, Event, H3Close, H3Header, H3ReqId, Role, StreamError, Time, TransportConfig,
    TransportOps,
};
use std::net::SocketAddr;
use std::time::Duration;

fn h3_cfg(role: Role) -> TransportConfig {
    TransportConfig {
        h3: true,
        ..cfg(role)
    }
}

fn h3_opts(proto: ConnProto) -> Opts {
    Opts {
        server: h3_cfg(server_role()),
        client: h3_cfg(Role::Client),
        proto,
        ..Opts::default()
    }
}

fn new_conns(ev: &[Event]) -> Vec<(ConnId, ConnProto)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::NewConn(c, p) => Some((*c, *p)),
            _ => None,
        })
        .collect()
}

#[test]
fn h3_connect_established_both_sides() {
    let p = Pair::with(h3_opts(ConnProto::H3)); // asserts ConnEstablished on both sides
    assert_eq!(new_conns(&p.sev), vec![(p.srv_conn, ConnProto::H3)]);
}

#[test]
fn raw_and_h3_on_one_engine() {
    let mut p = Pair::with(h3_opts(ConnProto::Raw));
    assert_eq!(new_conns(&p.sev), vec![(p.srv_conn, ConnProto::Raw)]);
    let mut cc = conn_cfg(None);
    cc.proto = ConnProto::H3;
    let c2 = p
        .client
        .call(p.now, move |t, now| t.connect(now, &cc))
        .expect("connect h3");
    p.exchange();
    assert!(p.cev.contains(&Event::ConnEstablished(c2)), "{:?}", p.cev);
    let news = new_conns(&p.sev);
    assert_eq!(news.len(), 2, "{news:?}");
    assert_eq!(news[1].1, ConnProto::H3);
    assert!(p.sev.contains(&Event::ConnEstablished(news[1].0)));
    assert_eq!(p.server.call(p.now, |t, _| t.conn_count()), 2);
}

#[test]
fn h3_conn_counts_toward_max_conns() {
    let mut scfg = h3_cfg(server_role());
    scfg.max_conns = 1;
    let server = Peer::spawn(scfg, vec![srv_addr()]);
    let mut now = T0;
    let client = |k: usize, now: Time| {
        let c = Peer::spawn(h3_cfg(Role::Client), vec![cli_addr(k)]);
        let mut cc = conn_cfg(None);
        cc.proto = ConnProto::H3;
        let id = c.call(now, move |t, now| t.connect(now, &cc)).unwrap();
        (c, id)
    };
    let run = |peers: &[&Peer], now: &mut Time, steps: usize| {
        for _ in 0..steps {
            *now = *now + MS;
            for p in peers {
                p.drive(*now);
            }
            exchange_many(*now, peers);
        }
    };
    let count = |s: &Peer| s.call(T0, |t, _| (t.conn_count(), t.n_provisional()));

    let (c0, id0) = client(3, now);
    run(&[&c0, &server], &mut now, 5);
    assert!(c0.drain_events().contains(&Event::ConnEstablished(id0)));
    let news = new_conns(&server.drain_events());
    assert!(matches!(news[..], [(_, ConnProto::H3)]), "{news:?}");
    assert_eq!(count(&server), (1, 0));

    // spec §4.7: an unauthenticated H3 conn (no request yet) is evicted by a newcomer.
    let (c1, id1) = client(0, now);
    let (mut sev, mut c0ev) = (Vec::new(), Vec::new());
    for _ in 0..1000 {
        run(&[&c0, &c1, &server], &mut now, 10);
        sev.extend(server.drain_events());
        c0ev.extend(c0.drain_events());
        if c0ev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(c1.drain_events().contains(&Event::ConnEstablished(id1)));
    assert!(
        c0ev.iter()
            .any(|e| matches!(e, Event::ConnClosed(c, r) if *c == id0 && r.code == 0x1002)),
        "{c0ev:?}"
    );
    let news = new_conns(&sev);
    assert!(matches!(news[..], [(_, ConnProto::H3)]), "{news:?}");
    assert_eq!(count(&server), (1, 0));
    let s1 = news[0].0;
    server.call(now, move |t, _| t.mark_conn_authed(s1));

    // The second H3 client is refused at the shared cap, before any slot: s1 is authed.
    let (c2, id2) = client(1, now);
    run(&[&c1, &c2, &server], &mut now, 50);
    assert!(!c2.drain_events().contains(&Event::ConnEstablished(id2)));
    assert!(new_conns(&server.drain_events()).is_empty());
    assert_eq!(count(&server), (1, 0));

    // Closing the first H3 connection releases its unit.
    c1.call(now, move |t, now| t.close_conn(now, id1));
    let mut sev = Vec::new();
    for _ in 0..1000 {
        run(&[&c1, &c2, &server], &mut now, 10);
        sev.extend(server.drain_events());
        if sev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(
        sev.iter().any(|e| matches!(e, Event::ConnClosed(..))),
        "{sev:?}"
    );
    assert_eq!(count(&server), (0, 0));
}

/// The canned ClientHello carries no ALPN: this only pins that an `h3: true` engine still
/// expires provisionals (the provisional path is ALPN-agnostic, `fabric_provisional.rs`).
#[test]
fn h3_conn_provisional_expiry() {
    let server = Peer::spawn(h3_cfg(server_role()), vec![srv_addr()]);
    let from: SocketAddr = "10.2.0.1:40000".parse().unwrap();
    let pkt = initial(
        &[0xd0, 0, 1, 1, 2, 3, 4, 5],
        &[0x5c, 0, 1, 5, 4, 3, 2, 1],
        0,
        0,
        &client_hello_fragment(0, 300),
    );
    server.deliver(T0, srv_addr(), from, pkt);
    server.drive(T0);
    server.pump_out(T0);
    let n_prov = |s: &Peer| s.call(Time::ZERO, |t, _| t.n_provisional());
    assert_eq!(n_prov(&server), 1);
    let mut now = T0;
    while n_prov(&server) > 0 {
        let d = server.next_timeout().expect("provisional deadline");
        now = now.max(d);
        server.drive(now);
        server.pump_out(now);
        assert!(now < T0 + Duration::from_secs(60), "never released");
    }
    assert!(
        now >= T0 + Duration::from_secs(10),
        "not before the 10 s deadline"
    );
    assert_eq!(server.call(now, |t, _| t.conn_count()), 0);
    assert_eq!(server.drain_events(), vec![], "never admitted: no events");
}

#[test]
fn h3_conn_close_reported() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let c = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, c));
    assert!(p.pump_until(10 * MS, 1000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    assert_eq!(p.server.call(p.now, |t, _| t.conn_count()), 0);
}

// ── requests (spec §3.1 contracts, §3.3 request rows, §3.4) ─────────────

const REQ: &[(&str, &str)] = &[
    (":method", "POST"),
    (":scheme", "https"),
    (":authority", "x"),
    (":path", "/"),
];
const RESP: &[(&str, &str)] = &[(":status", "200")];

fn owned(hs: &[(&str, &str)]) -> Vec<(String, String)> {
    hs.iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn open_req(p: &Pair) -> H3ReqId {
    let c = p.conn;
    p.client
        .call(p.now, move |t, now| t.open_h3_request(now, c))
        .expect("open_h3_request")
}

fn send_headers(
    peer: &Peer,
    now: Time,
    r: H3ReqId,
    hs: &'static [(&'static str, &'static str)],
    fin: bool,
) -> Result<(), StreamError> {
    peer.call(now, move |t, now| {
        let v: Vec<H3Header<'_>> = hs
            .iter()
            .map(|(n, v)| H3Header {
                name: n.as_bytes(),
                value: v.as_bytes(),
            })
            .collect();
        t.h3_send_headers(now, r, &v, fin)
    })
}

fn send_body(
    peer: &Peer,
    now: Time,
    r: H3ReqId,
    data: &'static [u8],
    fin: bool,
) -> Result<usize, StreamError> {
    peer.call(now, move |t, now| t.h3_send_body(now, r, data, fin))
}

/// One `h3_recv_headers` call.
fn recv_headers(
    peer: &Peer,
    now: Time,
    r: H3ReqId,
) -> Result<(Vec<(String, String)>, bool), StreamError> {
    peer.call(now, move |t, now| {
        let mut out = Vec::new();
        let mut each = |n: &[u8], v: &[u8]| {
            out.push((
                String::from_utf8_lossy(n).into_owned(),
                String::from_utf8_lossy(v).into_owned(),
            ))
        };
        t.h3_recv_headers(now, r, &mut each).map(|fin| (out, fin))
    })
}

/// One `h3_recv_body` call into a 64 KiB buffer.
fn recv_body(peer: &Peer, now: Time, r: H3ReqId) -> Result<(Vec<u8>, bool), StreamError> {
    peer.call(now, move |t, now| {
        let mut buf = vec![0u8; 64 * 1024];
        t.h3_recv_body(now, r, &mut buf)
            .map(|(n, fin)| (buf[..n].to_vec(), fin))
    })
}

fn h3_requests(ev: &[Event]) -> Vec<(ConnId, H3ReqId)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::H3Request(c, r) => Some((*c, *r)),
            _ => None,
        })
        .collect()
}

fn h3_closed(ev: &[Event], r: H3ReqId) -> Option<H3Close> {
    ev.iter().find_map(|e| match e {
        Event::H3Closed(x, c) if *x == r => Some((**c).clone()),
        _ => None,
    })
}

fn readables(ev: &[Event], r: H3ReqId) -> usize {
    ev.iter().filter(|e| **e == Event::H3Readable(r)).count()
}

/// The server's one request.
fn server_req(p: &Pair) -> H3ReqId {
    match h3_requests(&p.sev)[..] {
        [(c, r)] => {
            assert_eq!(c, p.srv_conn);
            r
        }
        ref other => panic!("expected one H3Request, got {other:?}"),
    }
}

/// Follows timeouts until both requests reported `H3Closed`.
fn wait_closed(p: &mut Pair, cr: H3ReqId, sr: H3ReqId) -> (H3Close, H3Close) {
    for _ in 0..500 {
        if let (Some(c), Some(s)) = (h3_closed(&p.cev, cr), h3_closed(&p.sev, sr)) {
            return (c, s);
        }
        if !p.follow_timeout() {
            p.tick(10 * MS);
        }
    }
    panic!("H3Closed never arrived: {:?} / {:?}", p.cev, p.sev);
}

/// POST "hello" → 200 "hello", every byte read on both sides (`h3_request_echo`).
// Body writes defer their flush to the next drive (`defer_send_flush`, SP2 spec §3.3), so the
// tests move packets with `tick(ZERO)` (drive both, then exchange), as the runtime drives.
fn echo(p: &mut Pair) -> (H3ReqId, H3ReqId) {
    let cr = open_req(p);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    assert_eq!(send_body(&p.client, p.now, cr, b"hello", true), Ok(5));
    p.tick(Duration::ZERO);
    let sr = server_req(p);
    assert!(p.sev.contains(&Event::H3Readable(sr)), "{:?}", p.sev);
    assert_eq!(recv_headers(&p.server, p.now, sr), Ok((owned(REQ), false)));
    assert_eq!(
        recv_body(&p.server, p.now, sr),
        Ok((b"hello".to_vec(), true))
    );
    send_headers(&p.server, p.now, sr, RESP, false).unwrap();
    assert_eq!(send_body(&p.server, p.now, sr, b"hello", true), Ok(5));
    p.tick(Duration::ZERO);
    assert!(p.cev.contains(&Event::H3Readable(cr)), "{:?}", p.cev);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    assert_eq!(
        recv_body(&p.client, p.now, cr),
        Ok((b"hello".to_vec(), true))
    );
    (cr, sr)
}

#[test]
fn h3_request_echo() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, sr) = echo(&mut p);
    let info = p.client.call(p.now, move |t, _| t.h3_req_info(cr)).unwrap();
    assert_eq!(info.conn, p.conn);
    let sinfo = p.server.call(p.now, move |t, _| t.h3_req_info(sr)).unwrap();
    assert_eq!((sinfo.conn, sinfo.quic_id), (p.srv_conn, info.quic_id));
    let (c, s) = wait_closed(&mut p, cr, sr);
    for x in [&c, &s] {
        assert_eq!(x.stats.stream_err, 0, "{x:?}");
        assert_eq!((x.stats.send_body, x.stats.recv_body), (5, 5), "{x:?}");
        assert_eq!(x.unread, None);
    }
    assert_eq!(stream_count(&p.client, p.conn), 0);
    assert_eq!(stream_count(&p.server, p.srv_conn), 0);
}

#[test]
fn h3_stats_monotone() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    p.tick(MS);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    p.tick(MS);
    assert_eq!(send_body(&p.client, p.now, cr, b"x", true), Ok(1));
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    recv_headers(&p.server, p.now, sr).unwrap();
    recv_body(&p.server, p.now, sr).unwrap();
    send_headers(&p.server, p.now, sr, RESP, true).unwrap();
    p.tick(Duration::ZERO);
    recv_headers(&p.client, p.now, cr).unwrap();
    let (c, _) = wait_closed(&mut p, cr, sr);
    let s = &c.stats;
    assert!(s.begin_us > 0, "{s:?}");
    assert!(s.begin_us < s.header_send_us, "{s:?}");
    assert!(s.header_send_us < s.fin_send_us, "{s:?}");
    assert!(s.fin_send_us <= s.fin_ack_us, "{s:?}");
}

#[test]
fn h3_server_reset_reaches_client() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    p.server.call(p.now, move |t, now| t.h3_reset(now, sr));
    let (c, s) = wait_closed(&mut p, cr, sr);
    assert_ne!(c.stats.stream_err, 0, "{c:?}");
    assert_eq!(c.stats.close_msg.as_deref(), Some("remote reset"));
    assert_eq!(c.unread, None);
    assert_eq!(s.stats.close_msg.as_deref(), Some("local reset"));
    assert_eq!(stream_count(&p.client, p.conn), 0);
    assert_eq!(stream_count(&p.server, p.srv_conn), 0);
}

#[test]
fn h3_readable_coalesces() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    recv_headers(&p.server, p.now, sr).unwrap();
    // Two body injections reach the server before anyone polls it.
    for chunk in [&b"a"[..], &b"b"[..]] {
        assert_eq!(send_body(&p.client, p.now, cr, chunk, false), Ok(1));
        p.client.drive(p.now);
        let out = p.client.pump_out(p.now);
        assert!(!out.is_empty());
        for d in out {
            p.server.deliver(p.now, d.to, d.from, d.data);
        }
        p.server.drive(p.now);
    }
    let ev = p.server.drain_events();
    assert_eq!(readables(&ev, sr), 1, "{ev:?}");
    assert_eq!(recv_body(&p.server, p.now, sr), Ok((b"ab".to_vec(), false)));
    assert_eq!(recv_body(&p.server, p.now, sr), Err(StreamError::Blocked));
}

#[test]
fn h3_trailer_drained_inside_transport() {
    // (a) The trailer arrives before the app read the header section: drained right after it.
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, true).unwrap();
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    send_headers(&p.server, p.now, sr, RESP, false).unwrap();
    assert_eq!(send_body(&p.server, p.now, sr, b"body", false), Ok(4));
    send_headers(&p.server, p.now, sr, &[("x-trailer", "v")], true).unwrap();
    p.tick(Duration::ZERO);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    assert_eq!(
        recv_headers(&p.client, p.now, cr),
        Err(StreamError::Blocked)
    );
    assert_eq!(
        recv_body(&p.client, p.now, cr),
        Ok((b"body".to_vec(), true))
    );

    // (b) The trailer arrives after the header section was read: drained in the notification.
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, true).unwrap();
    p.sev.clear();
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    send_headers(&p.server, p.now, sr, RESP, false).unwrap();
    p.tick(Duration::ZERO);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    assert_eq!(send_body(&p.server, p.now, sr, b"body", false), Ok(4));
    send_headers(&p.server, p.now, sr, &[("x-trailer", "v")], true).unwrap();
    p.tick(Duration::ZERO);
    assert_eq!(
        recv_headers(&p.client, p.now, cr),
        Err(StreamError::Blocked)
    );
    assert_eq!(
        recv_body(&p.client, p.now, cr),
        Ok((b"body".to_vec(), true))
    );
}

#[test]
fn h3_ops_stale_after_close() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, sr) = echo(&mut p);
    wait_closed(&mut p, cr, sr);
    for (peer, r) in [(&p.client, cr), (&p.server, sr)] {
        let now = p.now;
        assert_eq!(
            send_headers(peer, now, r, RESP, false),
            Err(StreamError::Stale)
        );
        assert_eq!(send_body(peer, now, r, b"x", true), Err(StreamError::Stale));
        assert_eq!(
            peer.call(now, move |t, now| t.h3_finish(now, r)),
            Err(StreamError::Stale)
        );
        assert_eq!(recv_headers(peer, now, r), Err(StreamError::Stale));
        assert_eq!(recv_body(peer, now, r), Err(StreamError::Stale));
        assert_eq!(
            peer.call(now, move |t, _| t.h3_req_info(r)),
            Err(mq_transport_api::Error::Stale)
        );
        peer.call(now, move |t, now| t.h3_reset(now, r)); // a no-op
    }
}

#[test]
fn h3_empty_fin_is_zero_true() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, true).unwrap();
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    send_headers(&p.server, p.now, sr, RESP, false).unwrap();
    p.tick(Duration::ZERO);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    let before = p.cev.len();
    assert_eq!(
        p.server.call(p.now, move |t, now| t.h3_finish(now, sr)),
        Ok(())
    );
    p.tick(Duration::ZERO);
    assert_eq!(readables(&p.cev[before..], cr), 1, "{:?}", p.cev);
    assert_eq!(recv_body(&p.client, p.now, cr), Ok((Vec::new(), true)));
}

// ── H3Closed stats and the client-side unread rescue (spec §3.3 close row, §3.5, §3.7) ──

/// The server's response `RESP` + `body` (+ fin), the client reading nothing.
fn respond(p: &mut Pair, body: &'static [u8], fin: bool) -> (H3ReqId, H3ReqId) {
    let cr = open_req(p);
    send_headers(&p.client, p.now, cr, REQ, true).unwrap();
    p.tick(Duration::ZERO);
    let sr = server_req(p);
    recv_headers(&p.server, p.now, sr).unwrap();
    send_headers(&p.server, p.now, sr, RESP, body.is_empty() && fin).unwrap();
    if !body.is_empty() {
        assert_eq!(send_body(&p.server, p.now, sr, body, fin), Ok(body.len()));
    }
    p.tick(Duration::ZERO);
    (cr, sr)
}

/// Follows timeouts until `side`'s events hold `r`'s `H3Closed`.
fn wait_one(p: &mut Pair, client: bool, r: H3ReqId) -> H3Close {
    for _ in 0..2000 {
        if let Some(c) = h3_closed(if client { &p.cev } else { &p.sev }, r) {
            return c;
        }
        if !p.follow_timeout() {
            p.tick(10 * MS);
        }
    }
    panic!("H3Closed never arrived: {:?} / {:?}", p.cev, p.sev);
}

#[test]
fn h3_closed_carries_stats_before_drain() {
    const BODY: &[u8] = &[7u8; 100];
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, sr) = respond(&mut p, BODY, true);
    let (c, _) = wait_closed(&mut p, cr, sr); // past the 3 × PTO close timer
    assert_eq!(c.stats.recv_body, 0, "stats read before the drain: {c:?}");
    assert_eq!(c.stats.stream_err, 0);
    let u = c.unread.expect("a complete unread response is rescued");
    assert_eq!(u.body, BODY);
    let hs: Vec<_> = u
        .headers
        .expect("never read")
        .into_iter()
        .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
        .collect();
    assert_eq!(hs, owned(RESP));
}

#[test]
fn h3_unread_none_on_reset() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, sr) = respond(&mut p, b"partial", false);
    p.server.call(p.now, move |t, now| t.h3_reset(now, sr));
    let c = wait_one(&mut p, true, cr);
    assert_eq!(c.unread, None, "{c:?}");
    assert_ne!(c.stats.stream_err, 0, "{c:?}");
}

#[test]
fn h3_unread_none_on_conn_close_code_0() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, _) = respond(&mut p, b"partial", false);
    let sc = p.srv_conn;
    p.server.call(p.now, move |t, now| t.close_conn(now, sc));
    let c = wait_one(&mut p, true, cr);
    assert_eq!(c.unread, None, "{c:?}");
}

#[test]
fn h3_unread_headers_when_never_read() {
    // (a) A header-only response (fin on HEADERS) the client never read.
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, _) = respond(&mut p, b"", true);
    let u = wait_one(&mut p, true, cr).unread.expect("rescued");
    assert_eq!(u.headers.map(|h| h.len()), Some(RESP.len()));
    assert!(u.body.is_empty());

    // (b) Headers read, body not: only the body is rescued.
    p.sev.clear();
    let (cr, _) = respond(&mut p, b"tail", true);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    let u = wait_one(&mut p, true, cr).unread.expect("rescued");
    assert_eq!(u.headers, None);
    assert_eq!(u.body, b"tail");
}

/// An empty `buf` reads nothing and reports the fin only once no body is
/// buffered (the MITM terminal probe, SP4 R1); a separate empty FIN that is
/// never read is rescued as an empty body, not `None`.
#[test]
fn h3_empty_buf_probe_and_unread_empty_fin_rescued() {
    let probe = |p: &Pair, r| {
        p.client
            .call(p.now, move |t, now| t.h3_recv_body(now, r, &mut []))
    };
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, sr) = respond(&mut p, b"", false);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    assert_eq!(probe(&p, cr), Err(StreamError::Blocked));
    assert_eq!(send_body(&p.server, p.now, sr, b"ab", false), Ok(2));
    p.tick(Duration::ZERO);
    assert_eq!(probe(&p, cr), Err(StreamError::Blocked), "bytes buffered");
    assert_eq!(recv_body(&p.client, p.now, cr), Ok((b"ab".to_vec(), false)));
    let fin = p.server.call(p.now, move |t, now| t.h3_finish(now, sr));
    assert_eq!(fin, Ok(()));
    p.tick(Duration::ZERO);
    assert_eq!(probe(&p, cr), Ok((0, true)));

    // The same empty FIN, never read: `H3Closed` rescues an empty body.
    p.sev.clear();
    let (cr, sr) = respond(&mut p, b"", false);
    assert_eq!(recv_headers(&p.client, p.now, cr), Ok((owned(RESP), false)));
    let fin = p.server.call(p.now, move |t, now| t.h3_finish(now, sr));
    assert_eq!(fin, Ok(()));
    p.tick(Duration::ZERO);
    let u = wait_one(&mut p, true, cr).unread.expect("rescued");
    assert_eq!(u.headers, None);
    assert!(u.body.is_empty());
}

#[test]
fn h3_server_never_rescues() {
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    assert_eq!(send_body(&p.client, p.now, cr, b"unread", true), Ok(6));
    p.tick(Duration::ZERO);
    let sr = server_req(&p);
    // The server answers without reading anything of the request.
    send_headers(&p.server, p.now, sr, RESP, true).unwrap();
    p.tick(Duration::ZERO);
    let (_, s) = wait_closed(&mut p, cr, sr);
    assert_eq!(s.unread, None, "{s:?}");
    assert_eq!(s.stats.stream_err, 0, "{s:?}");
}

#[test]
fn h3_idle_timeout_mid_response_aborts() {
    let idle = Duration::from_secs(30);
    let mut p = Pair::with(Opts {
        idle: Some(idle),
        ..h3_opts(ConnProto::H3)
    });
    let (cr, _) = respond(&mut p, b"partial", false);
    p.lose = true; // the server goes silent mid-response
    let start = p.now;
    let c = wait_one(&mut p, true, cr);
    assert!(p.client_closed().is_some(), "closed by the idle timeout");
    assert!(p.now - start <= 2 * idle, "after {:?}", p.now - start);
    assert_eq!(c.unread, None, "{c:?}");
}

#[test]
fn h3_drop_transport_with_live_requests_is_clean() {
    // (a) A local close with a request holding unread data: its `H3Closed` precedes
    // `ConnClosed` and rescues nothing (no fin).
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    let (cr, _) = respond(&mut p, b"partial", false);
    let c = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, c));
    assert!(p.pump_until(10 * MS, 1000, |p| p.client_closed().is_some()));
    let at = |e: &dyn Fn(&Event) -> bool| p.cev.iter().position(e);
    let closed = at(&|e| matches!(e, Event::H3Closed(r, _) if *r == cr)).expect("H3Closed");
    let conn = at(&|e| matches!(e, Event::ConnClosed(x, _) if *x == c)).expect("ConnClosed");
    assert!(closed < conn, "{:?}", p.cev);
    assert_eq!(h3_closed(&p.cev, cr).unwrap().unread, None);

    // (b) Both transports dropped with open requests on both sides (one holding unread body):
    // the close notifications fire inside the engine teardown, without a panic.
    let mut p = Pair::with(h3_opts(ConnProto::H3));
    respond(&mut p, b"partial", false);
    let cr = open_req(&p);
    send_headers(&p.client, p.now, cr, REQ, false).unwrap();
    p.tick(Duration::ZERO);
    drop(p);
}
