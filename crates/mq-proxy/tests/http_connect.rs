//! spec §6.1: HTTP CONNECT ingress parser.

use mq_proxy::ingress::{
    HttpConnectParser, INGRESS_CAP, Progress, http_error_reply, http_success_reply,
};
use mq_runtime::{Host, Target};
use mq_wire::frames::TcpErr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const REQ_DOMAIN: &[u8] = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
const REQ_IPV6: &[u8] = b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n";
const REQ_IPV4: &[u8] = b"CONNECT 93.184.216.34:80 HTTP/1.1\r\n\r\n";
const REQ_NOTERM: &[u8] = b"CONNECT example.com:443 HTTP/1.1\r\n";
const REQ_GET: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
const REQ_NOPORT: &[u8] = b"CONNECT example.com HTTP/1.1\r\n\r\n";

const R405: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";
const R400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";

fn parse(buf: &[u8]) -> Progress<'static> {
    HttpConnectParser.feed(buf)
}

fn done(consumed: usize, host: Host, port: u16) -> Progress<'static> {
    Progress::Done {
        consumed,
        target: Target { host, port },
    }
}

fn bad() -> Progress<'static> {
    Progress::Reply {
        consumed: 0,
        bytes: R400,
        close: true,
    }
}

#[test]
fn domain() {
    assert_eq!(
        parse(REQ_DOMAIN),
        done(REQ_DOMAIN.len(), Host::Domain("example.com".into()), 443)
    );
}

#[test]
fn ipv6() {
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(
        parse(REQ_IPV6),
        done(REQ_IPV6.len(), Host::Ip(IpAddr::V6(ip)), 443)
    );
}

#[test]
fn ipv4() {
    assert_eq!(
        parse(REQ_IPV4),
        done(
            REQ_IPV4.len(),
            Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            80
        )
    );
}

#[test]
fn fragmented() {
    let mut p = HttpConnectParser;
    assert_eq!(p.feed(REQ_NOTERM), Progress::Need);
    assert_eq!(
        p.feed(REQ_DOMAIN),
        done(REQ_DOMAIN.len(), Host::Domain("example.com".into()), 443)
    );
}

#[test]
fn unsupported() {
    assert_eq!(
        parse(REQ_GET),
        Progress::Reply {
            consumed: 0,
            bytes: R405,
            close: true
        }
    );
}

#[test]
fn missing_port() {
    assert_eq!(parse(REQ_NOPORT), bad());
}

#[test]
fn unclosed_bracket() {
    assert_eq!(parse(b"CONNECT [::1:443 HTTP/1.1\r\n\r\n"), bad());
}

#[test]
fn overlong_domain() {
    let host = "a".repeat(256);
    assert_eq!(
        parse(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes()),
        bad()
    );
    // 255 is still accepted.
    let host = "a".repeat(255);
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n");
    assert_eq!(
        parse(req.as_bytes()),
        done(req.len(), Host::Domain(host), 443)
    );
}

#[test]
fn port_boundaries() {
    let ok = |req: &[u8], port| {
        assert_eq!(
            parse(req),
            done(req.len(), Host::Domain("example.com".into()), port)
        )
    };
    ok(b"CONNECT example.com:1 HTTP/1.1\r\n\r\n", 1);
    ok(b"CONNECT example.com:65535 HTTP/1.1\r\n\r\n", 65535);
    assert_eq!(parse(b"CONNECT example.com:65536 HTTP/1.1\r\n\r\n"), bad());
    assert_eq!(parse(b"CONNECT example.com: HTTP/1.1\r\n\r\n"), bad());
    assert_eq!(parse(b"CONNECT example.com:0 HTTP/1.1\r\n\r\n"), bad());
    assert_eq!(parse(b"CONNECT example.com:+80 HTTP/1.1\r\n\r\n"), bad());
}

#[test]
fn malformed_request_lines() {
    for req in [
        &b"\r\n\r\n"[..],
        b"CONNECT\r\n\r\n",
        b"CONNECT example.com:443\r\n\r\n",
        b"CONNECT  HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:443 FTP/1.1\r\n\r\n",
        b"CONNECT :443 HTTP/1.1\r\n\r\n",
        b"CONNECT []:443 HTTP/1.1\r\n\r\n",
        b"CONNECT [1.2.3.4]:443 HTTP/1.1\r\n\r\n",
        b"CONNECT \xff\xfe:443 HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(parse(req), bad(), "{:?}", String::from_utf8_lossy(req));
    }
}

#[test]
fn build_200() {
    assert_eq!(
        http_success_reply(),
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
}

#[test]
fn status_line() {
    assert_eq!(
        http_error_reply(TcpErr::Timeout),
        b"HTTP/1.1 504 Gateway Timeout\r\n\r\n"
    );
    assert_eq!(
        http_error_reply(TcpErr::PolicyDenied),
        b"HTTP/1.1 403 Forbidden\r\n\r\n"
    );
    assert_eq!(
        http_error_reply(TcpErr::ConnRefused),
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
    );
    assert_eq!(
        http_error_reply(TcpErr::Ok),
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
    );
}

#[test]
fn status_line_dns_failed() {
    assert_eq!(
        http_error_reply(TcpErr::DnsFailed),
        b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
    );
}

// ---- Rust-side additions ----

#[test]
fn pipelined_bytes_left_unconsumed() {
    let mut buf = REQ_IPV4.to_vec();
    buf.extend_from_slice(b"\x16\x03\x01 tls hello\r\n\r\n");
    assert_eq!(
        parse(&buf),
        done(
            REQ_IPV4.len(),
            Host::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            80
        )
    );
}

#[test]
fn cap_8k_closes_without_reply() {
    // A full 8 KiB buffer with no complete head → close, no reply.
    let mut buf = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
    buf.resize(INGRESS_CAP - 1, b'x');
    assert_eq!(parse(&buf), Progress::Need);
    buf.push(b'x');
    assert_eq!(parse(&buf), Progress::Close);
    // A terminator past the cap is never seen.
    buf.extend_from_slice(b"\r\n\r\n");
    assert_eq!(parse(&buf), Progress::Close);
    // A head ending exactly at the cap still parses.
    let mut head = b"CONNECT example.com:443 HTTP/1.1\r\nX: ".to_vec();
    head.resize(INGRESS_CAP - 4, b'y');
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(
        parse(&head),
        done(INGRESS_CAP, Host::Domain("example.com".into()), 443)
    );
}
