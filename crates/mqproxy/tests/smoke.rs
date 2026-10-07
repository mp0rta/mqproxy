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
    let (c, k, ca) = (cert("test.crt"), cert("test.key"), cert("origin-ca.crt"));
    let mut srv = Proc::spawn(&[
        "server",
        "--listen",
        &listen,
        "--token",
        "s3cret",
        "--cert",
        &c,
        "--key",
        &k,
        "--origin-ca",
        &ca,
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

fn server(listen: &str, extra: &[&str]) -> Proc {
    let (c, k) = (cert("test.crt"), cert("test.key"));
    let base = [
        "server", "--listen", listen, "--token", "t", "--cert", &c, "--key", &k,
    ];
    Proc::spawn(&[&base[..], extra].concat())
}

/// spec §7.8, §12.7: an unreadable `--origin-ca` is a startup error.
#[test]
fn origin_ca_unreadable_exits_1_with_message() {
    let listen = format!("127.0.0.1:{}", free_udp());
    let mut p = server(&listen, &["--origin-ca", "/nonexistent/origin-ca.pem"]);
    assert_eq!(p.wait_exit(), 1, "{:#?}", p.lines);
    assert_eq!(
        own(&p.lines),
        vec![
            "[ERROR] failed to create HTTP gateway server \
             (origin_ca=/nonexistent/origin-ca.pem, connect_timeout=10s) \
             (cannot read origin CA /nonexistent/origin-ca.pem)"
        ]
    );
}

/// The tproxy listener is bound before the fetch listener.
#[test]
fn client_binds_tproxy_before_fetch_listener() {
    let (tp, gw) = (
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    );
    let (tp, gw) = (
        tp.local_addr().unwrap().to_string(),
        gw.local_addr().unwrap().to_string(),
    );
    let server = format!("127.0.0.1:{}", free_udp());
    let mut p = Proc::spawn(&[
        "client",
        "--server",
        &server,
        "--token",
        "t",
        "--gateway",
        &gw,
        "--tproxy",
        &tp,
    ]);
    assert_eq!(p.wait_exit(), 1, "{:#?}", p.lines);
    let err = own(&p.lines);
    assert_eq!(err.len(), 1, "{err:#?}");
    assert!(
        err[0].starts_with(&format!("[ERROR] failed to bind tproxy listener on {tp} (")),
        "{err:#?}"
    );
}

/// The binary's own lines (xquic's engine warnings left out).
fn own(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|l| !l.contains("[xquic]"))
        .cloned()
        .collect()
}

/// The binary's own lines up to and including the one containing `last`.
fn lines_until(p: &mut Proc, last: &str) -> Vec<String> {
    p.wait_line(last);
    let n = p.lines.iter().position(|l| l.contains(last)).unwrap();
    own(&p.lines[..=n])
}

/// spec §8: the server line's real `gateway=on|off`, the `mq_origin:` line
/// only with the gateway on, the client's `gateway=ip:port` in ingress order.
#[test]
fn startup_lines_golden() {
    let listen = format!("127.0.0.1:{}", free_udp());
    let mut p = server(&listen, &["--no-gateway"]);
    assert_eq!(
        lines_until(&mut p, "listening on"),
        vec![format!(
            "[INFO] mqproxy server listening on {listen} \
             (cc=bbr, sched=minrtt, gateway=off, udp=on, udp-idle=60s)"
        )]
    );
    assert_eq!(p.term(), 0, "{:#?}", p.lines);

    let ca = cert("origin-ca.crt");
    let mut p = server(&listen, &["--origin-ca", &ca]);
    assert_eq!(
        lines_until(&mut p, "listening on"),
        vec![
            "[INFO] mq_origin: hyper 1.10 + rustls (HTTP3=no)".to_string(),
            format!(
                "[INFO] mqproxy server listening on {listen} \
                 (cc=bbr, sched=minrtt, gateway=on, udp=on, udp-idle=60s)"
            ),
        ]
    );

    let (socks, gw, tp) = (free_tcp(), free_tcp(), free_tcp());
    let (socks, gw, tp) = (
        format!("127.0.0.1:{socks}"),
        format!("127.0.0.1:{gw}"),
        format!("127.0.0.1:{tp}"),
    );
    let mut cli = Proc::spawn(&[
        "client",
        "--server",
        &listen,
        "--token",
        "t",
        "--tproxy",
        &tp,
        "--gateway",
        &gw,
        "--socks5",
        &socks,
    ]);
    assert_eq!(
        lines_until(&mut cli, "mqproxy client:"),
        vec![format!(
            "[INFO] mqproxy client: server={listen} socks5={socks} gateway={gw} \
             tproxy={tp}(redirect) (bind 0.0.0.0, cc=bbr, sched=minrtt)"
        )]
    );
    // The fetch listener is bound.
    assert!(TcpStream::connect(&gw).is_ok());
    assert_eq!(cli.term(), 0, "client {:#?}", cli.lines);
    assert_eq!(p.term(), 0, "server {:#?}", p.lines);
}
