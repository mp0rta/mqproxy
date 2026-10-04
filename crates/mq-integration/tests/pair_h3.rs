//! spec §10.3 (H3 pair, §3.7): the H3 test apps on two production drivers over loopback UDP,
//! real xquic on both sides.
#![forbid(unsafe_code)]

use mq_integration::h3_apps::{EchoMode, H3Client, H3EchoServer, H3Handle, H3Script};
use mq_integration::loopback::{LoopbackPair, cert, transport};
use mq_runtime::Shard;
use mq_transport_api::Role;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

fn pair(mode: EchoMode, script: H3Script) -> LoopbackPair<H3Handle, H3Handle> {
    pair_with(mode, Vec::new(), script)
}

fn pair_with(
    mode: EchoMode,
    resp_headers: Vec<(String, String)>,
    script: H3Script,
) -> LoopbackPair<H3Handle, H3Handle> {
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
            let app = app.with_response_headers(resp_headers.clone());
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

/// SP4 spec §5: both engines accept a 40 KiB field section (xquic's default limit was 32 KiB;
/// `H3_FIELD_SECTION_MAX` is 64 KiB): a request section reaches the server and a response
/// section comes back.
#[test]
fn h3_40k_section_both_ways() {
    let mut script = post(Vec::new(), None);
    script.headers.extend(fields(6, 7000));
    let p = pair_with(EchoMode::Echo, fields(6, 7000), script);
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
