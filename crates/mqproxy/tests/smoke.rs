//! spec §6.4 smoke: server + client binaries on loopback; an in-test SOCKS5
//! client fetches 1 MiB from an in-test origin through the client; bytes equal;
//! both processes exit 0 on SIGTERM.

mod common;
use common::{Proc, cert, free_tcp, free_udp};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

const SIZE: usize = 1 << 20;

fn payload() -> Vec<u8> {
    (0..SIZE).map(|i| (i * 7 + i / 251) as u8).collect()
}

/// Serves `payload()` to every connection, then closes it.
fn origin() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            std::thread::spawn(move || {
                let _ = s.write_all(&payload());
            });
        }
    });
    port
}

/// SOCKS5 no-auth CONNECT to 127.0.0.1:`port`, then everything until EOF.
fn socks5_fetch(proxy: &str, port: u16) -> Vec<u8> {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(common::T)).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).unwrap();
    assert_eq!(m, [5, 0]);
    let p = port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]])
        .unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep[..2], [5, 0], "SOCKS5 reply {rep:?}");
    let mut body = Vec::new();
    s.read_to_end(&mut body).unwrap();
    body
}

#[test]
fn smoke_socks5_1mib_through_both_binaries() {
    let listen = format!("127.0.0.1:{}", free_udp());
    let (c, k) = (cert("test.crt"), cert("test.key"));
    let mut srv = Proc::spawn(&[
        "server", "--listen", &listen, "--token", "s3cret", "--cert", &c, "--key", &k,
    ]);
    srv.wait_line("[INFO] mqproxy server listening on");

    let socks = format!("127.0.0.1:{}", free_tcp());
    let mut cli = Proc::spawn(&[
        "client", "--server", &listen, "--token", "s3cret", "--socks5", &socks,
    ]);
    cli.wait_line("[INFO] mqproxy client: server=");

    let body = socks5_fetch(&socks, origin());
    assert_eq!(body.len(), SIZE);
    assert!(body == payload(), "payload differs");

    assert_eq!(cli.term(), 0, "client {:#?}", cli.lines);
    assert_eq!(srv.term(), 0, "server {:#?}", srv.lines);
}
