//! Shard-pair tests (spec §8.1 "Shard pair", §8.4): the real `Client` and
//! `Server` relaying end to end below the syscall layer, on one and two paths.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::{Client, SOCKS5};
use mq_proxy::config::ClientConfig;
use mq_proxy::server::Server;
use mq_runtime::testing::Op;
use mq_transport_api::{ConnId, PathId, TransportOps};

/// spec §8.1: authentication, then a SOCKS5 request relayed to an echo origin.
#[test]
fn pair_auth_and_relay() {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(client_cfg()));
    p.origin(OriginMode::Echo);
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    let app = p.with_client(|n| {
        let s = n.accept(SOCKS5, None);
        let mut b = socks5_connect(origin_addr());
        b.extend_from_slice(b"hello");
        n.io_mut().tcp_feed(s, &b);
        s
    });
    let mut want = SOCKS5_OK.to_vec();
    want.extend_from_slice(b"hello");
    let w = want.clone();
    assert!(
        p.run_until(5 * SEC, move |p| p.app_written(app) == w),
        "{:?}",
        p.app_written(app)
    );
}

const ACTIVE: u32 = 2; // XQC_PATH_STATE_ACTIVE

/// A client with a second `--path`, authenticated, both paths active.
fn two_paths() -> (Pair<Server, Client>, ConnId) {
    let cfg = ClientConfig {
        paths: vec![client_addr().ip(), CLIENT_IP2],
        ..client_cfg()
    };
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(cfg));
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    let c = p.client_conns()[0];
    let up = move |p: &mut Pair<Server, Client>| {
        let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
        st.paths.len() == 2 && st.paths.iter().all(|x| x.state == ACTIVE)
    };
    assert!(p.run_until(5 * SEC, up), "second path never came up");
    let socks = p.with_client(|n| n.udp_socks());
    assert_eq!(socks.len(), 2);
    assert_eq!(socks[1].1.ip(), CLIENT_IP2);
    (p, c)
}

/// spec §8.1 / §6.2 "Paths": the second `--path` comes up on its own UDP
/// socket and both paths carry the relayed bytes.
#[test]
fn pair_two_paths_carry_traffic() {
    let (mut p, c) = two_paths();
    const N: usize = 1 << 20;
    p.origin(OriginMode::Send(bulk(N)));
    let s = p.socks_open(origin_addr(), b"");
    let done = move |p: &mut Pair<Server, Client>| {
        p.with_client(move |n| n.io().ops().contains(&Op::ShutdownWrite(s)))
    };
    assert!(p.run_until(20 * SEC, done));
    assert_eq!(p.app_written(s)[12..], bulk(N)[..]);
    let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
    for path in &st.paths {
        assert!(path.recv_bytes > 64 * 1024, "path {} idle: {st:?}", path.id);
    }
}

/// spec §8.4 "One path's socket blocked": the blocked path's queue stops at
/// its quota; the other path keeps sending; when the socket unblocks the
/// connection resumes and the transfer completes without loss.
#[test]
fn pair_blocked_path_quota_and_resume() {
    const QUOTA: usize = 256 * 1024; // spec §4.4
    const N: usize = 2 << 20;
    let (mut p, c) = two_paths();
    p.origin(OriginMode::Sink);
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    let o = p.origin_socks()[0];
    let blocked = p.with_client(|n| n.udp_socks()[1].0);
    let sent0 = move |p: &Pair<Server, Client>| {
        let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
        st.paths.iter().find(|x| x.id == 0).unwrap().sent_bytes
    };
    let before = sent0(&p);
    p.with_client(move |n| n.io_mut().mark_udp_unwritable(blocked, true));
    p.app_send(s, &bulk(N));

    let key = (Some(c), PathId(1));
    let at_origin =
        move |p: &Pair<Server, Client>| p.with_server(move |n| n.io().tcp_written(o).len());
    let mut peak = 0;
    p.run_until(5 * SEC, |p| {
        let q = p.with_client(move |n| n.transport().queued_bytes(key));
        assert!(q <= QUOTA, "path 1 queue {q} over its quota");
        peak = peak.max(q);
        false
    });
    let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
    assert!(
        peak > 0,
        "nothing was scheduled on the blocked path: {st:?}"
    );
    assert!(
        sent0(&p) - before > N as u64 / 2,
        "path 0 stopped too: {st:?}"
    );
    assert!(at_origin(&p) < N, "the blocked path held nothing back");

    p.with_client(move |n| n.io_mut().mark_udp_unwritable(blocked, false));
    assert!(
        p.run_until(30 * SEC, |p| at_origin(p) == N),
        "{} of {N}",
        at_origin(&p)
    );
    assert_eq!(p.with_server(move |n| n.io().tcp_written(o)), bulk(N));
    assert_eq!(p.with_client(move |n| n.transport().queued_bytes(key)), 0);
}
