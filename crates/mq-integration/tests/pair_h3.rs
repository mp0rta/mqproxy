//! spec §10.3 (H3 pair, §3.7): the H3 test apps on two production drivers over loopback UDP,
//! real xquic on both sides.
#![forbid(unsafe_code)]

use mq_integration::h3_apps::{EchoMode, H3Client, H3EchoServer, H3Handle, H3Script};
use mq_integration::loopback::{
    Backend, LoopbackPair, cert, h3_transport, raw_h3_transport, transport,
};
use mq_integration::matrix;
use mq_integration::raw_h3::{RawH3Handle, RawH3Peer, RawH3Script, headers_frame};
use mq_runtime::Shard;
use mq_transport_api::Role;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

/// Bare xqc_h3 on both sides (the rescue tests).
fn pair(mode: EchoMode, script: H3Script) -> LoopbackPair<H3Handle, H3Handle> {
    let lo = Ipv4Addr::LOCALHOST.into();
    LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let t = transport(
                Role::Server {
                    cert: cert("test.crt"),
                    key: cert("test.key"),
                },
                true,
            );
            let (app, h) = H3EchoServer::new(mode);
            (Shard::new(t, app, local, 1), h)
        },
        move |local, server| {
            let (app, h) = H3Client::new(server, script);
            (Shard::new(transport(Role::Client, true), app, local, 2), h)
        },
    )
}

fn post(body: Vec<u8>, pause_reads: Option<Duration>) -> H3Script {
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
        pause_reads,
        truncate_after_partial: false,
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

// The rescue tests below read `H3Closed.unread`, which only xqc_h3 fills: they stay on the
// xqc_h3 backend, outside the differential matrix (adoption spec §6.2).

/// spec §3.7 (2): the client stops reading for longer than 3 PTO after the server's FIN; every
/// byte still arrives, through `H3Closed.unread`.
#[test]
fn h3_unread_rescued_after_close_timer() {
    let body: Vec<u8> = (0..200_000u32).map(|k| k as u8).collect();
    let p = pair(
        EchoMode::Echo,
        post(body.clone(), Some(Duration::from_secs(1))),
    );
    wait(&p.client.handle, |r| !r.closed.is_empty());
    {
        let r = p.client.handle.lock();
        let (close, _) = &r.closed[0];
        assert_eq!(close.stats.stream_err, 0, "{close:?}");
        let u = close.unread.as_ref().expect("rescued");
        assert_eq!(u.body, body);
        assert_eq!(
            u.headers.as_ref().map(|h| h[0].0.as_slice()),
            Some(&b":status"[..])
        );
        assert!(r.body.is_empty() && !r.fin, "the app read nothing itself");
    }
    p.join_both();
}

/// spec §3.7, §10.3: a server reset before its FIN while the client holds unread body gives
/// `H3Closed` with `stream_err != 0` and no `unread` within 1 RTT + 3 PTO (plus margin).
#[test]
fn h3_reset_with_unread_body_within_margin() {
    let p = pair(
        EchoMode::ResetBeforeFin,
        post(vec![9; 50_000], Some(Duration::from_secs(5))),
    );
    wait(&p.client.handle, |r| !r.closed.is_empty());
    let (cut_at, srtt) = {
        let s = p.server.handle.lock();
        (
            s.cut_at.expect("server reset"),
            Duration::from_micros(s.srtt_us),
        )
    };
    {
        let r = p.client.handle.lock();
        let (close, at) = &r.closed[0];
        assert_ne!(close.stats.stream_err, 0, "{close:?}");
        assert_eq!(close.unread, None);
        // PTO ≤ srtt + 4 × rttvar + max_ack_delay (25 ms), with rttvar ≤ srtt.
        let pto = 5 * srtt + Duration::from_millis(25);
        let margin = srtt + 3 * pto + Duration::from_millis(500);
        assert!(*at - cut_at <= margin, "{:?} > {margin:?}", *at - cut_at);
    }
    p.join_both();
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

// SP4 spec §5: both engines accept a 40 KiB field section (xquic's default limit was 32 KiB;
// `H3_FIELD_SECTION_MAX` is 64 KiB): a request section reaches the server and a response
// section comes back. Matrixed over (client, server) backends (adoption spec §6.2).
matrix!(
    h3_40k_section_both_ways,
    |cells: (Backend, Backend), _tag: &str| {
        let mut script = post(Vec::new(), None);
        script.headers.extend(fields(6, 7000));
        let lo = Ipv4Addr::LOCALHOST.into();
        let p = LoopbackPair::spawn(
            (lo, lo),
            Vec::new(),
            move |local| {
                let (app, h) = H3EchoServer::new(EchoMode::Echo);
                let app = app.with_response_headers(fields(6, 7000));
                (
                    Shard::new(h3_transport(server_role(), cells.1), app, local, 1),
                    h,
                )
            },
            move |local, server| {
                let (app, h) = H3Client::new(server, script);
                (
                    Shard::new(h3_transport(Role::Client, cells.0), app, local, 2),
                    h,
                )
            },
        );
        wait(&p.client.handle, |r| r.fin);
        {
            let s = p.server.handle.lock();
            assert!(
                section(&s.request_headers) >= 40 * 1024,
                "{}",
                section(&s.request_headers)
            );
        }
        {
            let c = p.client.handle.lock();
            assert_eq!(c.headers[0].0, b":status");
            assert!(section(&c.headers) >= 40 * 1024, "{}", section(&c.headers));
        }
        p.join_both();
    }
);

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
    let script = post(body.clone(), None);
    let p = LoopbackPair::spawn(
        (lo, lo),
        Vec::new(),
        move |local| {
            let (app, h) = H3EchoServer::new(EchoMode::Echo);
            let t = h3_transport(server_role(), Backend::Wire);
            (Shard::new(t, app, local, 1), h)
        },
        move |local, server| {
            let (app, h) = H3Client::new(server, script);
            let t = h3_transport(Role::Client, Backend::Wire);
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

/// The `:status` of the first HEADERS frame in `bytes` (a request stream as read raw).
fn status(bytes: &[u8]) -> Option<Vec<u8>> {
    use h3wire::qpack::decoder::{Span, decode_field_section};
    let mut b = bytes;
    while !b.is_empty() {
        let (ty, n) = h3wire::varint::decode(b)?;
        let (len, m) = h3wire::varint::decode(&b[n..])?;
        let payload = b.get(n + m..n + m + len as usize)?;
        b = &b[n + m + len as usize..];
        if ty != 0x01 {
            continue; // DATA or a reserved frame
        }
        let (mut arena, mut fields) = (Vec::new(), Vec::new());
        decode_field_section(payload, &mut arena, &mut fields).ok()?;
        let get = |s: Span| match s {
            Span::Static(v) => v.to_vec(),
            Span::Arena(a, z) => arena[a as usize..z as usize].to_vec(),
        };
        return fields
            .iter()
            .find(|f| get(f.name) == b":status")
            .map(|f| get(f.value));
    }
    None
}

/// adoption spec §6.2: the raw-H3 peer's valid GET (fixed bytes) gets a 200 from an
/// `H3EchoServer` on each backend.
#[test]
fn raw_peer_smoke() {
    for b in [Backend::XqcH3, Backend::Wire] {
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
                (Shard::new(h3_transport(server_role(), b), app, local, 1), h)
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
                "{b:?}: timed out: {:?}",
                p.client.handle.lock()
            );
            thread::sleep(Duration::from_millis(5));
        }
        {
            let seen = p.client.handle.lock();
            assert_eq!(
                status(&seen.read).as_deref(),
                Some(&b"200"[..]),
                "{b:?}: {seen:?}"
            );
            assert!(
                seen.resets.is_empty() && seen.closed.is_empty(),
                "{b:?}: {seen:?}"
            );
        }
        assert_eq!(p.server.handle.lock().requests, 1, "{b:?}");
        p.join_both();
    }
}
