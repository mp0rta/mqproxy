//! Shard-pair failure injection (spec §8.4, the "shard pair" rows; §6.3
//! server streams and auth; §5.6 relay ends).
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::Client;
use mq_proxy::server::Server;
use mq_runtime::testing::Op;
use mq_transport_api::{ConnId, Event};
use std::io::ErrorKind;
use std::time::Duration;

fn authed_real() -> (Pair<Server, Client>, ConnId, ConnId) {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(client_cfg()));
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    p.run_for(10 * MS); // the AUTH_RESPONSE is read and the control stream drained
    let (s, c) = (p.server_conns()[0], p.client_conns()[0]);
    (p, s, c)
}

fn authed_raw() -> (Pair<Server, RawClient>, ConnId, ConnId) {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_raw(false));
    let c = p.raw_connect(true);
    let s = p.server_conns()[0];
    (p, s, c)
}

/// Runs until both sides are back to one stream slot (the control stream)
/// and keep no dead relay stream.
fn back_to_baseline<C: mq_runtime::App + 'static>(p: &mut Pair<Server, C>, s: ConnId, c: ConnId) {
    let ok = p.run_until(5 * SEC, move |p| {
        p.stream_counts(s, c) == (1, 1)
            && p.with_server(|n| n.shard().dead_stream_count()) == 0
            && p.with_client(|n| n.shard().dead_stream_count()) == 0
    });
    assert!(
        ok,
        "stream slots (server, client): {:?}",
        p.stream_counts(s, c)
    );
}

fn op_of(p: &Pair<Server, impl mq_runtime::App + 'static>, f: fn(&Op) -> bool) -> Option<Op> {
    p.with_server(move |n| n.io().ops().iter().find(|o| f(o)).cloned())
}

/// spec §8.4 "Auth timeout, server": a client that never authenticates;
/// the server starts closing at 10 s; after draining the slot is released
/// exactly once.
#[test]
fn pair_server_auth_timeout_slot_released_once() {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_raw(true));
    assert!(p.run_until(5 * SEC, |p| !p.server_conns().is_empty()));
    let c = p.server_conns()[0];
    let accepted = p.with_server(move |n| {
        (n.tap().events.iter())
            .find(|(_, e)| *e == Event::NewConn(c))
            .map(|(t, _)| *t)
            .expect("NewConn")
    });
    assert!(p.run_until(SEC, |p| p.with_server(|n| n.transport().conn_count()) == 1));

    // Just before the deadline nothing has started closing.
    let before = accepted + Duration::from_millis(9_990);
    p.run_for(before - p.now);
    assert_eq!(p.with_server(move |n| n.tap().closed(c)), 0);
    assert!(p.with_client(|n| n.app().conns.values().all(|k| !k.closed)));

    // At 10 s the server closes: its first datagram after the quiet period
    // (the CONNECTION_CLOSE) leaves at 10 s; the client then closes too.
    p.wire = Some(Vec::new());
    assert!(p.run_until(SEC, |p| {
        p.with_client(|n| n.app().conns.values().all(|k| k.closed))
    }));
    let first = (p.wire.take().unwrap().iter())
        .find(|(_, d)| d.from == server_addr())
        .map(|(t, _)| *t - accepted)
        .expect("the server sent nothing");
    assert!(first >= 10 * SEC && first < 10 * SEC + MS, "{first:?}");

    // After draining: released once, and stays released.
    let srv = |p: &Pair<Server, RawClient>| {
        p.with_server(move |n| {
            let t = n.transport();
            (n.tap().closed(c), t.conn_count(), t.n_provisional())
        })
    };
    assert!(
        p.run_until(10 * SEC, |p| srv(p) == (1, 0, 0)),
        "{:?}",
        srv(&p)
    );
    p.run_for(30 * SEC);
    assert_eq!(srv(&p), (1, 0, 0));
    assert_eq!(p.with_server(|n| n.app().active_conn()), None);
}

/// spec §8.4 "Peer reset after FIN with the TCP side idle": the origin
/// half-closes, so the server relay sends FIN; the client's local app stays
/// idle; the origin then errors, so the server relay resets; the client relay
/// aborts its TCP socket and both stream slots are released.
#[test]
fn pair_peer_reset_after_fin_with_idle_tcp() {
    let (mut p, sc, cc) = authed_real();
    p.origin(OriginMode::Sink);
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    let o = p.origin_socks()[0];
    assert_eq!(p.stream_counts(sc, cc), (2, 2));

    p.with_server(move |n| n.io_mut().tcp_eof(o));
    let fin = move |p: &mut Pair<Server, Client>| {
        p.with_client(move |n| n.io().ops().contains(&Op::ShutdownWrite(s)))
    };
    assert!(p.run_until(5 * SEC, fin), "FIN never reached the local app");
    assert_eq!(p.app_closed(s), None);

    p.with_server(move |n| n.io_mut().fail_socket(o, ErrorKind::ConnectionReset));
    assert!(
        p.run_until(5 * SEC, |p| p.app_closed(s).is_some()),
        "client relay kept its socket"
    );
    assert_eq!(p.app_closed(s), Some(true), "aborted");
    assert_eq!(p.with_server(move |n| n.io().tcp_closed(o)), Some(true));
    back_to_baseline(&mut p, sc, cc);
}

/// spec §8.4 "Peer reset while the server is dialling": the resolver is
/// held; the client resets the stream; the server's `stream_recv` sees
/// `Reset` and cancels the dial; the late resolver answer starts no connect;
/// both stream slots are released.
#[test]
fn pair_peer_reset_while_server_dialling() {
    let (mut p, sc, cc) = authed_raw();
    let s = p.raw_open(cc, &connect_request_domain("origin.test", 80), false);
    let resolving = |o: &Op| matches!(o, Op::StartResolve(..));
    assert!(p.run_until(5 * SEC, |p| op_of(p, resolving).is_some()));
    let Some(Op::StartResolve(op, host, 80)) = op_of(&p, resolving) else {
        unreachable!()
    };
    assert_eq!(host, "origin.test");
    assert_eq!(p.stream_counts(sc, cc), (2, 2));

    p.with_client(move |n| n.with_app(|r, cx| r.reset(cx, s)));
    back_to_baseline(&mut p, sc, cc);
    assert_eq!(
        p.with_server(|n| n.core().resolver().running()),
        1,
        "slot held"
    );

    p.with_server(move |n| n.io_mut().resolve(op, Ok(vec![origin_addr()])));
    p.run_for(SEC);
    assert_eq!(p.server_connects(), 0, "the late answer started a connect");
    assert_eq!(p.with_server(|n| n.core().resolver().running()), 0);
    back_to_baseline(&mut p, sc, cc);
}

/// spec §8.4 "Peer reset before FIN with a full buffer and blocked TCP
/// writes": the server relay's buffer is full and its origin socket never
/// takes a byte; a probe answered with `Blocked` leaves the socket alone;
/// the client resets the stream; the zero-capacity probe sees `Reset`,
/// the relay aborts the origin socket, and the slots are released.
#[test]
fn pair_reset_before_fin_full_buffer_blocked_tcp() {
    let (mut p, sc, cc) = authed_raw();
    let s = p.raw_open(cc, &connect_request(origin_addr()), false);
    let connecting = |o: &Op| matches!(o, Op::StartConnect(..));
    assert!(p.run_until(5 * SEC, |p| op_of(p, connecting).is_some()));
    let Some(Op::StartConnect(op, _)) = op_of(&p, connecting) else {
        unreachable!()
    };
    let o = p.with_server(move |n| {
        let o = n.io_mut().connect_ok(op);
        n.io_mut().would_block_after(o, 0);
        o
    });
    assert_eq!(p.raw_response(s).0, 0);

    // 256 KiB, no FIN: more than the relay buffer and the stream window.
    p.raw_send(s, &bulk(256 * 1024), false);
    p.run_for(2 * SEC);
    let writes = move |p: &Pair<Server, RawClient>| {
        p.with_server(move |n| {
            (n.io().ops().iter())
                .filter(|x| matches!(x, Op::Write(t, _) if *t == o))
                .count()
        })
    };
    assert!(writes(&p) > 0, "the relay never tried the origin");
    assert_eq!(p.with_server(move |n| n.io().tcp_written(o)), b"");
    assert_eq!(p.with_server(move |n| n.io().tcp_closed(o)), None);
    let rx = p.raw_stream(s).rx;
    assert_eq!(
        connect_response(&rx).unwrap().2,
        rx.len(),
        "only the response came back"
    );

    p.with_client(move |n| n.with_app(|r, cx| r.reset(cx, s)));
    assert!(p.run_until(5 * SEC, |p| {
        p.with_server(move |n| n.io().tcp_closed(o)).is_some()
    }));
    assert_eq!(
        p.with_server(move |n| n.io().tcp_closed(o)),
        Some(true),
        "aborted"
    );
    back_to_baseline(&mut p, sc, cc);
}

/// spec §8.4 "Repeated failed opens": 100 dials to a refusing origin; the
/// client resets each stream; the server's stream budget and both sides'
/// stream counts return to baseline.
#[test]
fn pair_repeated_failed_opens_return_budget_to_baseline() {
    let (mut p, sc, cc) = authed_real();
    p.origin(OriginMode::Refuse);
    assert_eq!(p.stream_counts(sc, cc), (1, 1));
    let refused = [5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
    for _ in 0..10 {
        let socks: Vec<_> = (0..10).map(|_| p.socks_open(origin_addr(), b"")).collect();
        let all = socks.clone();
        assert!(p.run_until(5 * SEC, move |p| {
            all.iter().all(|s| p.app_closed(*s).is_some())
        }));
        for s in socks {
            assert_eq!(p.app_written(s), refused);
        }
    }
    assert_eq!(p.server_connects(), 100);
    back_to_baseline(&mut p, sc, cc);
    // The budget is back: the server still serves new streams.
    p.origin(OriginMode::Echo);
    let s = p.socks_open(origin_addr(), b"ping");
    let mut want = SOCKS5_OK.to_vec();
    want.extend_from_slice(b"ping");
    assert!(p.run_until(5 * SEC, move |p| p.app_written(s) == want));
}

/// spec §8.4 "Control-stream reset after authentication": the client resets
/// its control stream; the server consumes the reset and closes the connection.
#[test]
fn pair_control_stream_reset_after_auth_closes_conn() {
    let (mut p, sc, cc) = authed_raw();
    let ctrl = p.with_client(move |n| n.app().conns[&cc].ctrl.unwrap());
    p.with_client(move |n| n.with_app(|r, cx| r.reset(cx, ctrl)));
    assert!(
        p.run_until(5 * SEC, move |p| p.with_server(move |n| n.tap().closed(sc))
            == 1)
    );
    assert!(p.run_until(5 * SEC, move |p| {
        p.with_client(move |n| n.app().conns[&cc].closed)
    }));
    assert_eq!(p.with_server(|n| n.app().active_conn()), None);
}
