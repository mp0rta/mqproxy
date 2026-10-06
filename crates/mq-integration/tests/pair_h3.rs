//! spec §10.3 (H3 pair, §3.7): the H3 test apps on two production drivers over loopback UDP,
//! real xquic on both sides.
#![forbid(unsafe_code)]

use mq_integration::h3_apps::{EchoMode, H3Client, H3EchoServer, H3Handle, H3Script};
use mq_integration::loopback::{LoopbackPair, cert, h3_transport, raw_h3_transport};
use mq_integration::raw_h3::{RawH3Handle, RawH3Peer, RawH3Script, field, headers_frame};
use mq_runtime::Shard;
use mq_runtime::testing::{RecordHandle, Recorded, RecordingApp};
use mq_transport_api::{ConnConfig, ConnProto, Event, H3Header, Role, StreamError};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn post(body: Vec<u8>) -> H3Script {
    H3Script {
        headers: [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "x"),
            (":path", "/"),
        ]
        .map(|(n, v)| (n.into(), v.into()))
        .to_vec(),
        body,
    }
}

/// Polls `h` until `cond` holds (at most 10 s).
fn wait(h: &H3Handle, cond: impl Fn(&mq_integration::h3_apps::H3Recorded) -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !cond(&h.lock()) {
        assert!(Instant::now() < end, "timed out: {:?}", h.lock());
        thread::sleep(Duration::from_millis(5));
    }
}

/// `n` fields of `len` bytes (`x-<i>`).
fn fields(n: usize, len: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|i| (format!("x-{i}"), "a".repeat(len)))
        .collect()
}

/// RFC 9114 §4.2.2 size: Σ name + value + 32.
fn section(hs: &[(Vec<u8>, Vec<u8>)]) -> usize {
    hs.iter().map(|(n, v)| n.len() + v.len() + 32).sum()
}

/// `hs` as the apps record a header list.
fn bytes(hs: &[(String, String)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let b = |s: &String| s.as_bytes().to_vec();
    hs.iter().map(|(n, v)| (b(n), b(v))).collect()
}

// SP4 spec §5: both engines accept a 40 KiB field section (xquic's default limit was 32 KiB;
// `H3_FIELD_SECTION_MAX` is 64 KiB): a request section reaches the server and a response
// section comes back, each exactly as sent (adoption spec §6.2).
#[test]
fn h3_40k_section_both_ways() {
    let mut script = post(Vec::new());
    script.headers.extend(fields(6, 7000));
    let want_req = bytes(&script.headers);
    let mut want_resp = vec![(b":status".to_vec(), b"200".to_vec())];
    want_resp.extend(bytes(&fields(6, 7000)));
    let lo = Ipv4Addr::LOCALHOST.into();
    let p = LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let (app, h) = H3EchoServer::new(EchoMode::Echo);
            let app = app.with_response_headers(fields(6, 7000));
            (Shard::new(h3_transport(server_role()), app, local, 1), h)
        },
        move |local, server| {
            let (app, h) = H3Client::new(server, script);
            (Shard::new(h3_transport(Role::Client), app, local, 2), h)
        },
    );
    wait(&p.client.handle, |r| r.fin);
    {
        let s = p.server.handle.lock();
        assert!(section(&want_req) >= 40 * 1024, "{}", section(&want_req));
        assert!(s.request_headers == want_req, "request headers differ");
    }
    {
        let c = p.client.handle.lock();
        assert!(section(&want_resp) >= 40 * 1024, "{}", section(&want_resp));
        assert!(c.headers == want_resp, "response headers differ");
    }
    p.join_both();
}

fn server_role() -> Role {
    Role::Server {
        cert: cert("test.crt"),
        key: cert("test.key"),
    }
}

/// adoption spec §6.2: an `H3Client` and an `H3EchoServer`, both on h3wire over real xquic; a
/// 1 MiB POST is echoed.
#[test]
fn wire_pair_smoke() {
    let body: Vec<u8> = (0..1u32 << 20).map(|k| (k % 251) as u8).collect();
    let lo = Ipv4Addr::LOCALHOST.into();
    let script = post(body.clone());
    let p = LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let (app, h) = H3EchoServer::new(EchoMode::Echo);
            let t = h3_transport(server_role());
            (Shard::new(t, app, local, 1), h)
        },
        move |local, server| {
            let (app, h) = H3Client::new(server, script);
            let t = h3_transport(Role::Client);
            (Shard::new(t, app, local, 2), h)
        },
    );
    wait(&p.client.handle, |r| r.fin && !r.closed.is_empty());
    {
        let c = p.client.handle.lock();
        assert_eq!(c.headers[0], (b":status".to_vec(), b"200".to_vec()));
        assert!(c.body == body, "echo differs: {} bytes", c.body.len());
        assert_eq!(c.closed[0].0.stats.stream_err, 0, "{:?}", c.closed[0].0);
    }
    p.join_both();
}

/// adoption spec §6.2: the raw-H3 peer's valid GET (fixed bytes) gets a 200 from an
/// `H3EchoServer` over H3Wire.
#[test]
fn raw_peer_smoke() {
    let get = headers_frame(&[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/"),
    ]);
    let lo = Ipv4Addr::LOCALHOST.into();
    let p: LoopbackPair<H3Handle, RawH3Handle> = LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let (app, h) = H3EchoServer::new(EchoMode::Echo);
            (Shard::new(h3_transport(server_role()), app, local, 1), h)
        },
        move |local, server| {
            let s = RawH3Script {
                stream: get,
                fin: true,
            };
            let (app, h) = RawH3Peer::client(server, s);
            (Shard::new(raw_h3_transport(Role::Client), app, local, 2), h)
        },
    );
    let end = Instant::now() + Duration::from_secs(10);
    while !p.client.handle.lock().fin {
        assert!(
            Instant::now() < end,
            "timed out: {:?}",
            p.client.handle.lock()
        );
        thread::sleep(Duration::from_millis(5));
    }
    {
        let seen = p.client.handle.lock();
        assert_eq!(
            field(&seen.read, b":status").as_deref(),
            Some(&b"200"[..]),
            "{seen:?}"
        );
        assert!(seen.resets.is_empty() && seen.closed.is_empty(), "{seen:?}");
    }
    assert_eq!(p.server.handle.lock().requests, 1);
    p.join_both();
}

/// Two live H3Wire requests: an unread partial response and an unfinished request.
fn live_wire_pair(
    idle: Option<Duration>,
    close_on_response: bool,
) -> (LoopbackPair<RecordHandle, RecordHandle>, mpsc::Receiver<()>) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let lo = Ipv4Addr::LOCALHOST.into();
    let p = LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let (app, rec) = RecordingApp::new();
            rec.on(|r, cx| match r {
                Recorded::TransportEvent(Event::H3Readable(req)) => {
                    let fin = cx.h3_recv_headers(*req, &mut |_, _| {});
                    if fin == Ok(true) {
                        let headers = [H3Header {
                            name: b":status",
                            value: b"200",
                        }];
                        assert_eq!(cx.h3_send_headers(*req, &headers, false), Ok(()));
                        assert_eq!(cx.h3_send_body(*req, b"partial", false), Ok(7));
                    }
                }
                Recorded::Shutdown => cx.request_exit(0),
                _ => {}
            });
            (Shard::new(h3_transport(server_role()), app, local, 1), rec)
        },
        move |local, server| {
            let (app, rec) = RecordingApp::new();
            let mut prefix_read = false;
            rec.on(move |r, cx| match r {
                Recorded::Start => {
                    cx.connect(&ConnConfig {
                        peer: server,
                        sni: "mqproxy",
                        idle_timeout: idle,
                        proto: ConnProto::H3,
                    })
                    .expect("connect");
                }
                Recorded::TransportEvent(Event::ConnEstablished(conn)) => {
                    let headers = [
                        H3Header {
                            name: b":method",
                            value: b"POST",
                        },
                        H3Header {
                            name: b":scheme",
                            value: b"https",
                        },
                        H3Header {
                            name: b":authority",
                            value: b"x",
                        },
                        H3Header {
                            name: b":path",
                            value: b"/",
                        },
                    ];
                    for fin in [true, false] {
                        let req = cx.open_h3_request(*conn).expect("open request");
                        assert_eq!(cx.h3_send_headers(req, &headers, fin), Ok(()));
                    }
                }
                Recorded::TransportEvent(Event::H3Readable(req)) if !prefix_read => {
                    let _ = cx.h3_recv_headers(*req, &mut |_, _| {});
                    let mut prefix = [0; 1];
                    match cx.h3_recv_body(*req, &mut prefix) {
                        Ok((n, fin)) => {
                            assert_eq!((n, fin), (1, false), "positive body prefix, no FIN");
                            assert_eq!(&prefix, b"p");
                            // Only one of the seven sent bytes is consumed; six stay unread.
                            prefix_read = true;
                            ready_tx.send(()).expect("test awaiting body prefix");
                            if close_on_response {
                                let conn = cx.h3_req_info(*req).expect("live request").conn;
                                cx.close_conn(conn);
                            }
                        }
                        Err(StreamError::Blocked) => {} // HEADERS may precede DATA.
                        Err(e) => panic!("body prefix: {e:?}"),
                    }
                }
                Recorded::Shutdown => cx.request_exit(0),
                _ => {}
            });
            (Shard::new(h3_transport(Role::Client), app, local, 2), rec)
        },
    );
    (p, ready_rx)
}

fn wait_records(rec: &RecordHandle, pred: impl Fn(&[Recorded]) -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !pred(&rec.records()) {
        assert!(Instant::now() < end, "timed out: {:?}", rec.records());
        thread::sleep(Duration::from_millis(2));
    }
}

/// The peer disappears mid-response: the real engine's idle timeout closes live requests.
#[test]
fn wire_idle_timeout_mid_response_aborts() {
    let idle = Duration::from_secs(1);
    let (mut p, ready) = live_wire_pair(Some(idle), false);
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("unfinished body prefix received");
    let start = Instant::now();
    // The server exits without sending CONNECTION_CLOSE, so only idle expiry can close it.
    p.server.shutdown.trigger();
    assert_eq!(p.server.join_timeout(Duration::from_secs(10)), Some(0));
    wait_records(&p.client.handle, |records| {
        records
            .iter()
            .any(|r| matches!(r, Recorded::TransportEvent(Event::ConnClosed(..))))
    });
    assert!(start.elapsed() <= 2 * idle, "after {:?}", start.elapsed());
    let records = p.client.handle.records();
    let closed: Vec<_> = records
        .iter()
        .filter_map(|r| match r {
            Recorded::TransportEvent(Event::H3Closed(_, close)) => Some(close),
            _ => None,
        })
        .collect();
    assert_eq!(closed.len(), 2, "{records:?}");
    p.client.shutdown.trigger();
    assert_eq!(p.client.join(), 0);
}

/// Local close reports every live request before ConnClosed.
#[test]
fn wire_local_close_with_live_requests_is_clean() {
    let (p, ready) = live_wire_pair(None, true);
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("unfinished body prefix received before local close");
    wait_records(&p.client.handle, |records| {
        records
            .iter()
            .any(|r| matches!(r, Recorded::TransportEvent(Event::ConnClosed(..))))
    });
    let records = p.client.handle.records();
    let conn = records
        .iter()
        .position(|r| matches!(r, Recorded::TransportEvent(Event::ConnClosed(..))))
        .expect("ConnClosed");
    let closed: Vec<_> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r {
            Recorded::TransportEvent(Event::H3Closed(_, close)) => Some((i, close)),
            _ => None,
        })
        .collect();
    assert_eq!(closed.len(), 2, "{records:?}");
    for (i, _) in closed {
        assert!(i < conn, "{records:?}");
    }
    assert_eq!(p.join_both(), (0, 0));
}

/// Engine teardown with open requests on both sides, including an unread partial response.
#[test]
fn wire_drop_transport_with_live_requests_is_clean() {
    let (p, ready) = live_wire_pair(None, false);
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("unfinished body prefix received");
    wait_records(&p.server.handle, |records| {
        records
            .iter()
            .filter(|r| matches!(r, Recorded::TransportEvent(Event::H3Request(..))))
            .count()
            == 2
    });
    let server = p.server.handle.records();
    assert_eq!(
        server
            .iter()
            .filter(|r| matches!(r, Recorded::TransportEvent(Event::H3Request(..))))
            .count(),
        2,
        "{server:?}"
    );
    for rec in [&p.client.handle, &p.server.handle] {
        assert!(
            !rec.records().iter().any(|r| matches!(
                r,
                Recorded::TransportEvent(Event::H3Closed(..) | Event::ConnClosed(..))
            )),
            "requests still live"
        );
    }
    assert_eq!(p.join_both(), (0, 0));
}
