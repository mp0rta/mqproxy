//! Client↔server cases on the shard pair (spec §8.1 "Shard pair"):
//!
//! | case | test | client side |
//! |---|---|---|
//! | A | `pair_cs_auth_wrong_token` | real `Client` |
//! | B | `pair_cs_auth_matching_token` | `RawClient` |
//! | C | `pair_cs_data_stream_echo` | `RawClient` |
//! | D | `pair_cs_data_stream_refused` | `RawClient` |
//! | E | `pair_cs_data_stream_preauth_reset` | `RawClient` |
//! | F | `pair_cs_data_stream_teardown` | `RawClient` |
//! | G | `pair_cs_data_stream_download_completion` | `RawClient` |
//! | H | `pair_cs_data_stream_halfclose_nospin` | `RawClient` |
//! | M | `pair_cs_data_stream_coalesced_payload` | `RawClient` |
//! | I | `pair_cs_client_open_echo` | real `Client` |
//! | J | `pair_cs_client_open_download` | real `Client` |
//! | K | `pair_cs_client_open_preauth_queue` | real `Client` |
//! | L | `pair_cs_client_open_refused` | real `Client` |
//!
//! The origins are the server side's `Origin` (echo / bulk-then-close /
//! refusing); a client open is a SOCKS5 request from a scripted local socket,
//! whose SOCKS5 reply stands for the open callback (`ok` = success reply,
//! `err` = the reply code). Reconnect is off.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::Client;
use mq_proxy::config::ClientConfig;
use mq_proxy::server::Server;
use mq_runtime::driver::Wait;
use mq_runtime::testing::Op;
use mq_transport_api::Event;

const N: usize = 200_000;

fn raw() -> Pair<Server, RawClient> {
    Pair::new(spawn_server(server_cfg(), 0), spawn_raw(false))
}

fn real(cfg: ClientConfig) -> Pair<Server, Client> {
    Pair::new(spawn_server(server_cfg(), 0), spawn_client(cfg))
}

fn authed(p: &mut Pair<Server, Client>) {
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
}

/// Case A: wrong token → the server refuses (one auth attempt) and the
/// client's connection closes; with reconnect off nothing re-dials.
#[test]
fn pair_cs_auth_wrong_token() {
    let mut p = real(ClientConfig {
        token: "wrong".into(),
        ..client_cfg()
    });
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    let closed = |p: &mut Pair<Server, Client>| {
        p.with_client(|n| n.tap().count(|e| matches!(e, Event::ConnClosed(..))))
    };
    assert!(p.run_until(5 * SEC, |p| closed(p) == 1));
    p.run_for(5 * SEC);
    assert_eq!(p.with_client(|n| n.tap().established().len()), 1);
    assert_eq!(p.auth_attempts(), 1);
    // An open after the refusal is refused at once (the client is closed).
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(SEC, |p| p.app_closed(s).is_some()));
    assert_eq!(&p.app_written(s)[2..4], [5, 5], "CONN_REFUSED");
}

/// Case B: matching token → OK; a second stream afterwards is not
/// authenticated again (exactly one auth attempt).
#[test]
fn pair_cs_auth_matching_token() {
    let mut p = raw();
    let c = p.raw_connect(true);
    p.raw_open(c, b"data\0", false);
    p.run_for(800 * MS);
    assert_eq!(p.auth_attempts(), 1);
}

/// Case C: an authenticated data stream dials the echo origin: OK, then "ping" echoes.
#[test]
fn pair_cs_data_stream_echo() {
    let mut p = raw();
    p.origin(OriginMode::Echo);
    let c = p.raw_connect(true);
    let s = p.raw_open(c, &connect_request(origin_addr()), false);
    let (st, code, _) = p.raw_response(s);
    assert_eq!((st, code), (0, 0));
    p.raw_send(s, b"ping", false);
    assert!(p.run_until(5 * SEC, |p| p.raw_stream(s).rx.ends_with(b"ping")));
}

/// Case D: a closed origin port → ERROR(CONN_REFUSED).
#[test]
fn pair_cs_data_stream_refused() {
    let mut p = raw();
    p.origin(OriginMode::Refuse);
    let c = p.raw_connect(true);
    let s = p.raw_open(c, &connect_request(origin_addr()), false);
    let (st, code, _) = p.raw_response(s);
    assert_eq!((st, code), (1, 2));
}

/// Case E: a data stream before auth completes is reset without a dial.
#[test]
fn pair_cs_data_stream_preauth_reset() {
    let mut p = raw();
    p.origin(OriginMode::Echo);
    let c = p.raw_connect(false);
    assert!(p.run_until(5 * SEC, |p| !p.client_conns().is_empty()));
    let s = p.raw_open(c, &connect_request(origin_addr()), false);
    p.run_for(2500 * MS);
    assert_eq!(p.server_connects(), 0, "dialled before auth");
    let rx = p.raw_stream(s);
    assert!(
        !matches!(connect_response(&rx.rx), Some((0, ..))),
        "OK before auth"
    );
    assert!(rx.reset, "not reset: {rx:?}");
}

/// Case F: dropping the connection mid-transfer reaps the relay: the origin
/// socket is closed once and the server keeps no dead stream.
#[test]
fn pair_cs_data_stream_teardown() {
    let mut p = raw();
    p.origin(OriginMode::Echo);
    let c = p.raw_connect(true);
    let s = p.raw_open(c, &connect_request(origin_addr()), false);
    assert_eq!(p.raw_response(s).0, 0);
    let srv_conn = p.server_conns()[0];
    p.with_client(move |n| n.with_app(|r, cx| r.close_conn(cx, c)));
    p.run_for(1500 * MS);
    let o = p.origin_socks()[0];
    assert!(p.with_server(move |n| n.io().tcp_closed(o)).is_some());
    let closes = p.with_server(move |n| {
        (n.io().ops().iter())
            .filter(|x| matches!(x, Op::CloseTcp(t, _) if *t == o))
            .count()
    });
    assert_eq!(closes, 1);
    assert_eq!(p.with_server(|n| n.shard().dead_stream_count()), 0);
    assert_eq!(p.with_server(move |n| n.tap().closed(srv_conn)), 1);
}

/// Bulk origin: N bytes then close; the stream gets every byte and a clean FIN.
fn download(n: usize) -> Pair<Server, RawClient> {
    let mut p = raw();
    p.origin(OriginMode::Send(bulk(n)));
    let c = p.raw_connect(true);
    let s = p.raw_open(c, &connect_request(origin_addr()), false);
    assert_eq!(p.raw_response(s).0, 0);
    assert!(p.run_until(10 * SEC, |p| p.raw_stream(s).fin));
    let rx = p.raw_stream(s);
    let (_, _, used) = connect_response(&rx.rx).unwrap();
    assert!(!rx.reset);
    assert_eq!(rx.rx[used..], bulk(n)[..], "every byte, in order");
    p
}

/// Case G: download to completion — all N bytes and a clean FIN, no reset.
#[test]
fn pair_cs_data_stream_download_completion() {
    download(N);
}

/// Case H: the origin half-closes after a tiny reply → the reply and a clean
/// FIN arrive, and the server's loop can sleep afterwards (no spin).
#[test]
fn pair_cs_data_stream_halfclose_nospin() {
    let mut p = download(64);
    p.run_for(100 * MS);
    let w = p.with_server(|n| n.core().next_wait());
    assert_ne!(w, Wait::Yield, "server loop still runnable");
}

/// Case M: request and payload in one stream write: the payload reaches the
/// origin and echoes back.
#[test]
fn pair_cs_data_stream_coalesced_payload() {
    let mut p = raw();
    p.origin(OriginMode::Echo);
    let c = p.raw_connect(true);
    let mut b = connect_request(origin_addr());
    b.extend_from_slice(b"ping");
    let s = p.raw_open(c, &b, false);
    assert_eq!(p.raw_response(s).0, 0);
    assert!(p.run_until(5 * SEC, |p| p.raw_stream(s).rx.ends_with(b"ping")));
}

/// Case I: the client's open echoes "ping" end to end.
#[test]
fn pair_cs_client_open_echo() {
    let mut p = real(client_cfg());
    p.origin(OriginMode::Echo);
    authed(&mut p);
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    p.app_send(s, b"ping");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s)[12..] == *b"ping"));
}

/// Case J: client-side download — all N bytes reach the local socket, then
/// its write side is shut down (the stream FIN), no truncation.
#[test]
fn pair_cs_client_open_download() {
    let mut p = real(client_cfg());
    p.origin(OriginMode::Send(bulk(N)));
    authed(&mut p);
    let s = p.socks_open(origin_addr(), b"");
    let shut = move |p: &mut Pair<Server, Client>| {
        p.with_client(move |n| n.io().ops().contains(&Op::ShutdownWrite(s)))
    };
    assert!(p.run_until(10 * SEC, shut));
    let w = p.app_written(s);
    assert_eq!(w[..12], SOCKS5_OK);
    assert_eq!(w[12..], bulk(N)[..]);
}

/// Case K: an open before auth is queued, then served after auth.
#[test]
fn pair_cs_client_open_preauth_queue() {
    let mut p = real(client_cfg());
    p.origin(OriginMode::Echo);
    let s = p.socks_open(origin_addr(), b"");
    p.step();
    assert_eq!(p.auth_attempts(), 0);
    assert_eq!(p.app_written(s), [5, 0], "only the greeting reply: queued");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s) == SOCKS5_OK));
    assert_eq!(p.auth_attempts(), 1);
    p.app_send(s, b"ping");
    assert!(p.run_until(5 * SEC, |p| p.app_written(s)[12..] == *b"ping"));
}

/// Case L: an open to a closed port fails with CONN_REFUSED.
#[test]
fn pair_cs_client_open_refused() {
    let mut p = real(client_cfg());
    p.origin(OriginMode::Refuse);
    authed(&mut p);
    let s = p.socks_open(origin_addr(), b"");
    assert!(p.run_until(5 * SEC, |p| p.app_closed(s).is_some()));
    assert_eq!(p.app_written(s), [5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
}
