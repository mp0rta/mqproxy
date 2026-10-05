//! Shard-pair tests (spec §8.1 "Shard pair", §8.4): the real `Client` and
//! `Server` relaying end to end below the syscall layer, on one and two paths.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::{Client, SOCKS5};
use mq_proxy::config::ClientConfig;
use mq_proxy::server::Server;
use mq_runtime::testing::Op;
use mq_transport_api::fabric::Rule;
use mq_transport_api::{CongestionControl, ConnId, PathId, Time, TransportOps};

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
fn two_paths(cc: CongestionControl) -> (Pair<Server, Client>, ConnId) {
    let cfg = ClientConfig {
        paths: vec![client_addr().ip(), CLIENT_IP2],
        ..client_cfg()
    };
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client_cc(cfg, cc));
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
    let (mut p, c) = two_paths(CongestionControl::Bbr);
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

/// spec §8.4 "One path's socket blocked": the blocked path's queue fills to
/// its quota and stops there; the other path keeps sending; when the socket
/// unblocks the connection resumes and the transfer completes without loss.
/// A warm-up upload over both paths first grows path 1's congestion window
/// past the quota (as `fabric_txq` does), or the window, not the queue,
/// would stop the sender; the fabric adds a 5 ms one-way delay so the
/// window has a bandwidth-delay product to grow into.
#[test]
fn pair_blocked_path_quota_and_resume() {
    const QUOTA: usize = 1024 * 1024; // spec §4.4
    const WARM: usize = 8 << 20;
    const N: usize = 8 << 20;
    // Cubic: in the fabric BBR's window on path 1 settles below one queue quota.
    let (mut p, c) = two_paths(CongestionControl::Cubic);
    p.fabric.add_rule(Rule::DelayRange {
        min: 5 * MS,
        max: 5 * MS,
        seed: 1,
    });
    p.origin(OriginMode::Sink);
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    let o = p.origin_socks()[0];
    // `tcp_written` copies: poll it when the clock moved or every 64 steps.
    let at_origin =
        move |p: &Pair<Server, Client>| p.with_server(move |n| n.io().tcp_written(o).len());
    let poll = |k: &mut (u32, Time), now: Time| {
        k.0 += 1;
        let moved = k.1 != now;
        k.1 = now;
        moved || k.0.is_multiple_of(64)
    };

    // Warm-up over both paths.
    p.app_send(s, &bulk(WARM));
    let mut k = (0, p.now);
    assert!(p.run_until(60 * SEC, |p| poll(&mut k, p.now) && at_origin(p) == WARM));

    // Block path 1's socket and keep sending.
    let blocked = p.with_client(|n| n.udp_socks()[1].0);
    let sent0 = move |p: &Pair<Server, Client>| {
        let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
        st.paths.iter().find(|x| x.id == 0).unwrap().sent_bytes
    };
    p.with_client(move |n| n.io_mut().mark_udp_unwritable(blocked, true));
    p.app_send(s, &bulk(N));
    let key = (Some(c), PathId(1));
    let queued =
        move |p: &Pair<Server, Client>| p.with_client(move |n| n.transport().queued_bytes(key));
    let refused = |p: &Pair<Server, Client>| p.with_client(|n| n.transport().blocked_conns());
    let mut peak = 0;
    assert!(
        p.run_until(5 * SEC, |p| {
            let q = queued(p);
            assert!(q <= QUOTA, "path 1 queue {q} over its quota");
            peak = peak.max(q);
            refused(p) == [c]
        }),
        "the quota never refused the connection (peak {peak})"
    );
    assert!(peak > QUOTA - 1500, "peak {peak}");
    // Saturated: the queue stays at its quota while path 0 keeps sending.
    let sent_at_full = sent0(&p);
    p.run_until(5 * SEC, |p| {
        let q = queued(p);
        assert!(
            q > QUOTA - 1500 && q <= QUOTA,
            "the blocked queue left its quota: {q}"
        );
        false
    });
    let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
    assert!(
        sent0(&p) - sent_at_full > 1 << 20,
        "path 0 stopped too: {st:?}"
    );
    assert!(
        at_origin(&p) < WARM + N,
        "the blocked path held nothing back"
    );

    p.with_client(move |n| n.io_mut().mark_udp_unwritable(blocked, false));
    let mut k = (0, p.now);
    assert!(
        p.run_until(60 * SEC, |p| poll(&mut k, p.now)
            && at_origin(p) == WARM + N),
        "{} of {}",
        at_origin(&p),
        WARM + N
    );
    let mut want = bulk(WARM);
    want.extend(bulk(N));
    assert_eq!(p.with_server(move |n| n.io().tcp_written(o)), want);
    assert_eq!(queued(&p), 0);
}

/// A black-holed path is removed by xquic after the idle timeout (30 s) while the
/// connection lives on the other path; once the black hole lifts the client re-adds a
/// path from the same address (a fresh socket for an extra path, the primary socket for
/// the primary) and both paths are active again.
fn blackhole_one_path_then_recover(ip: std::net::IpAddr, dead: u64) {
    const CLOSED: u32 = 4; // XQC_PATH_STATE_CLOSED
    let (mut p, c) = two_paths(CongestionControl::Bbr);
    let paths = move |p: &Pair<Server, Client>| {
        let st = p.with_client(move |n| n.transport().conn_stats(c)).unwrap();
        st.paths.iter().map(|x| (x.id, x.state)).collect::<Vec<_>>()
    };
    let active = move |p: &Pair<Server, Client>| paths(p).iter().filter(|x| x.1 == ACTIVE).count();
    let live = |p: &Pair<Server, Client>| {
        p.with_client(|n| {
            let io = n.io();
            n.udp_socks()
                .into_iter()
                .filter(|s| !io.udp_closed(s.0))
                .collect::<Vec<_>>()
        })
    };
    let before = live(&p);
    p.blackhole_ip = Some(ip);
    assert!(
        p.run_until(45 * SEC, |p| paths(p).contains(&(dead, CLOSED))),
        "the dead path was never removed: {:?}",
        paths(&p)
    );
    assert_eq!(active(&p), 1);
    assert_eq!(p.client_conns(), [c], "the connection survives");
    p.blackhole_ip = None;
    assert!(
        p.run_until(10 * SEC, |p| active(p) == 2),
        "no path re-added: {:?}",
        paths(&p)
    );
    assert_eq!(p.client_conns(), [c]);
    // One live socket per address: the dead extra path's socket was replaced, the
    // primary's reused.
    let after = live(&p);
    assert_eq!(after.len(), 2, "{after:?}");
    assert!(after.iter().any(|s| s.1.ip() == CLIENT_IP2));
    assert_eq!(after[0], before[0], "the primary socket is kept");
    if dead != 0 {
        assert_ne!(after[1], before[1], "the extra path got a fresh socket");
    }
}

#[test]
fn pair_blackholed_extra_path_is_readded() {
    blackhole_one_path_then_recover(CLIENT_IP2, 1);
}

#[test]
fn pair_blackholed_primary_path_is_readded() {
    blackhole_one_path_then_recover(client_addr().ip(), 0);
}
