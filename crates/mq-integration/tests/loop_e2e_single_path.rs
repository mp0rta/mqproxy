//! Single-path cases on the loopback harness (spec §8.1 "Loopback"): the real `Server` and `Client` on real transports,
//! each on its own production driver thread, over loopback UDP. The test
//! thread plays the origin (`TcpListener`) and the application (`TcpStream`
//! through the client's SOCKS5 / HTTP CONNECT listener).
//!
//! | test                        | sizes / patterns |
//! |-----------------------------|------------------|
//! | `socks5_download`           | 200000 B, `i & 0xff`, then EOF |
//! | `socks5_echo`               | 4096 B, `i*31+7` |
//! | `http_echo`                 | 4096 B, `i*17+3` |
//! | `socks5_pipelined_payload`  | `EARLY-PIPELINED-BYTES` in the request write |
//! | `http_pipelined_payload`    | `EARLY-HTTP-BYTES` in the head write |
//! | `concurrent_ingress`        | 1 SOCKS5 + 1 HTTP, 4096 B each, `i*31+7` / `(i*17+3)^0xa5` |
//! | `socks5_refused`            | dead port → REP 0x05, then close |
//! | `http_refused`              | dead port → `HTTP/1.1 502`, then close |
//!
//! `socks5_echo_ipv6_path` runs the tunnel over `::1` with IPv4 ingress;
//! `socks5_echo_v6_wildcard_path_to_v4_server` runs it from a dual-stack
//! `[::]` client path (`--path ::`) to a `127.0.0.1` server.
//!
//! Each test ends with both drivers stopped through their handles, exit (0, 0).
#![forbid(unsafe_code)]

use mq_integration::loopback::LoopbackProxy;
use mq_proxy::config::{ClientConfig, ServerConfig};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const T: Duration = Duration::from_secs(8);

fn proxy() -> LoopbackProxy {
    let token = "secret".to_owned();
    LoopbackProxy::spawn_proxy(
        ServerConfig {
            token: token.clone(),
            ..ServerConfig::default()
        },
        ClientConfig {
            token,
            client_id: "client-1".into(),
            ..ClientConfig::default()
        },
    )
}

fn dial(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).expect("dial listener");
    c.set_read_timeout(Some(T)).unwrap();
    c.set_write_timeout(Some(T)).unwrap();
    c
}

fn read_n(c: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    c.read_exact(&mut v).expect("bytes within the timeout");
    v
}

fn read_to_eof(c: &mut TcpStream) -> Vec<u8> {
    let mut v = Vec::new();
    c.read_to_end(&mut v).expect("EOF within the timeout");
    v
}

/// An origin that accepts one connection and runs `serve` on it.
fn origin(serve: impl FnOnce(TcpStream) + Send + 'static) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(T)).unwrap();
        s.set_write_timeout(Some(T)).unwrap();
        serve(s);
    });
    port
}

/// Echoes every byte until EOF (or the read timeout).
fn echo_origin() -> u16 {
    origin(|mut s| {
        let mut buf = [0u8; 8192];
        while let Ok(n @ 1..) = s.read(&mut buf) {
            if s.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    })
}

/// A loopback port with nothing listening.
fn dead_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn socks5_request(port: u16) -> Vec<u8> {
    let mut r = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    r.extend_from_slice(&port.to_be_bytes());
    r
}

fn socks5_greet(c: &mut TcpStream) {
    c.write_all(&[0x05, 0x01, 0x00]).unwrap();
    assert_eq!(read_n(c, 2), [0x05, 0x00]);
}

/// Greeting + CONNECT + success reply.
fn socks5_open(addr: SocketAddr, port: u16) -> TcpStream {
    let mut c = dial(addr);
    socks5_greet(&mut c);
    c.write_all(&socks5_request(port)).unwrap();
    let r = read_n(&mut c, 10);
    assert_eq!(r[..4], [0x05, 0x00, 0x00, 0x01], "{r:?}");
    c
}

fn http_head(port: u16) -> Vec<u8> {
    format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes()
}

/// Reads the response head up to the blank line, byte by byte so no tunnel
/// byte is consumed.
fn read_http_head(c: &mut TcpStream) -> Vec<u8> {
    let mut h = Vec::new();
    while !h.ends_with(b"\r\n\r\n") {
        assert!(h.len() < 256, "head too long: {h:?}");
        h.extend(read_n(c, 1));
    }
    h
}

/// CONNECT head + `early`, then the 200 head.
fn http_open(addr: SocketAddr, port: u16, early: &[u8]) -> TcpStream {
    let mut c = dial(addr);
    let mut w = http_head(port);
    w.extend_from_slice(early);
    c.write_all(&w).unwrap();
    let h = read_http_head(&mut c);
    assert!(
        h.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&h)
    );
    c
}

fn pattern(m: usize, f: impl Fn(usize) -> usize) -> Vec<u8> {
    (0..m).map(|i| (f(i) & 0xff) as u8).collect()
}

fn echo_round_trip(c: &mut TcpStream, payload: &[u8]) {
    c.write_all(payload).unwrap();
    assert!(read_n(c, payload.len()) == payload, "echo mismatch");
}

#[test]
fn socks5_download() {
    const N: usize = 200_000;
    let p = proxy();
    let port = origin(|mut s| {
        s.write_all(&pattern(N, |i| i)).unwrap();
        // Dropping the socket closes it: the download's EOF.
    });
    let mut c = socks5_open(p.socks5_addr(), port);
    let got = read_to_eof(&mut c);
    assert_eq!(got.len(), N);
    assert!(got == pattern(N, |i| i), "download bytes differ");
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn socks5_echo() {
    let p = proxy();
    let mut c = socks5_open(p.socks5_addr(), echo_origin());
    echo_round_trip(&mut c, &pattern(4096, |i| i * 31 + 7));
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn socks5_echo_ipv6_path() {
    let token = "secret".to_owned();
    let p = LoopbackProxy::spawn_proxy_on(
        (Ipv6Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()),
        ServerConfig {
            token: token.clone(),
            ..ServerConfig::default()
        },
        ClientConfig {
            token,
            client_id: "client-1".into(),
            paths: vec![Ipv6Addr::LOCALHOST.into()],
            ..ClientConfig::default()
        },
    );
    assert!(p.server.udp_addr.is_ipv6() && p.client.udp_addr.is_ipv6());
    assert!(p.socks5_addr().is_ipv4(), "ingress stays IPv4");
    let mut c = socks5_open(p.socks5_addr(), echo_origin());
    // 64 KiB each way: GSO batches on the IPv6 socket.
    echo_round_trip(&mut c, &pattern(65536, |i| i * 31 + 7));
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn socks5_echo_v6_wildcard_path_to_v4_server() {
    let token = "secret".to_owned();
    let p = LoopbackProxy::spawn_proxy_on(
        (Ipv4Addr::LOCALHOST.into(), Ipv6Addr::UNSPECIFIED.into()),
        ServerConfig {
            token: token.clone(),
            ..ServerConfig::default()
        },
        ClientConfig {
            token,
            client_id: "client-1".into(),
            paths: vec![Ipv6Addr::UNSPECIFIED.into()],
            ..ClientConfig::default()
        },
    );
    assert!(p.server.udp_addr.is_ipv4() && p.client.udp_addr.is_ipv6());
    let mut c = socks5_open(p.socks5_addr(), echo_origin());
    // 64 KiB each way: GSO batches from the dual-stack socket.
    echo_round_trip(&mut c, &pattern(65536, |i| i * 31 + 7));
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn http_echo() {
    let p = proxy();
    let mut c = http_open(p.http_addr(), echo_origin(), b"");
    echo_round_trip(&mut c, &pattern(4096, |i| i * 17 + 3));
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn socks5_pipelined_payload() {
    const EARLY: &[u8] = b"EARLY-PIPELINED-BYTES";
    let p = proxy();
    let port = echo_origin();
    let mut c = dial(p.socks5_addr());
    socks5_greet(&mut c);
    let mut w = socks5_request(port);
    w.extend_from_slice(EARLY);
    c.write_all(&w).unwrap(); // request + payload in one write
    let r = read_n(&mut c, 10);
    assert_eq!(r[..2], [0x05, 0x00], "{r:?}");
    assert_eq!(read_n(&mut c, EARLY.len()), EARLY);
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn http_pipelined_payload() {
    const EARLY: &[u8] = b"EARLY-HTTP-BYTES";
    let p = proxy();
    let mut c = http_open(p.http_addr(), echo_origin(), EARLY);
    assert_eq!(read_n(&mut c, EARLY.len()), EARLY);
    drop(c);
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn concurrent_ingress() {
    let p = proxy();
    // One origin per ingress: a mis-attributed flow echoes the other's bytes.
    let (pa, pb) = (echo_origin(), echo_origin());
    let (socks, http) = (p.socks5_addr(), p.http_addr());
    let a = thread::spawn(move || {
        let mut c = socks5_open(socks, pa);
        echo_round_trip(&mut c, &pattern(4096, |i| i * 31 + 7));
    });
    let b = thread::spawn(move || {
        let mut c = http_open(http, pb, b"");
        echo_round_trip(&mut c, &pattern(4096, |i| (i * 17 + 3) ^ 0xa5));
    });
    a.join().expect("SOCKS5 flow");
    b.join().expect("HTTP CONNECT flow");
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn socks5_refused() {
    let p = proxy();
    let mut c = dial(p.socks5_addr());
    socks5_greet(&mut c);
    c.write_all(&socks5_request(dead_port())).unwrap();
    let r = read_to_eof(&mut c);
    assert_eq!(r.len(), 10, "{r:?}");
    assert_eq!(r[..2], [0x05, 0x05], "connection refused: {r:?}");
    assert_eq!(p.join_both(), (0, 0));
}

#[test]
fn http_refused() {
    let p = proxy();
    let mut c = dial(p.http_addr());
    c.write_all(&http_head(dead_port())).unwrap();
    let r = read_to_eof(&mut c);
    assert!(
        r.starts_with(b"HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&r)
    );
    assert_eq!(p.join_both(), (0, 0));
}
