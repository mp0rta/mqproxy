//! spec §6.1: HTTP CONNECT (authority-form) — port of `src/ingress/mq_http_connect.c`
//! plus the parse-error replies of `mq_listener.c:drive_http`.

use super::Progress;
use super::request::capped;
use mq_runtime::{Host, Target};
use mq_wire::frames::TcpErr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_HOST: usize = 255; // MQ_MAX_HOST

const R405: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\n\r\n";
const R400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";

/// spec §6.1: stateless; each `feed` re-parses the buffered head.
#[derive(Debug, Default)]
pub struct HttpConnectParser;

impl HttpConnectParser {
    /// spec §6.1: `Need` until `\r\n\r\n`; `Done` consumes the head only.
    pub fn feed(&mut self, buf: &[u8]) -> Progress<'static> {
        capped(buf, parse)
    }
}

fn bad() -> Progress<'static> {
    Progress::Reply {
        consumed: 0,
        bytes: R400,
        close: true,
    }
}

fn parse(buf: &[u8]) -> Progress<'static> {
    let Some(hend) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Progress::Need;
    };
    let hend = hend + 4;
    // The head contains a CRLF, so the request line ends inside it.
    let line_end = buf.windows(2).position(|w| w == b"\r\n").unwrap_or(0);
    let mut parts = buf[..line_end].splitn(3, |&c| c == b' ');
    let method = parts.next().unwrap_or_default();
    let Some(target) = parts.next() else {
        return bad(); // no target
    };
    if method.is_empty() {
        return bad();
    }
    if method != b"CONNECT" {
        return Progress::Reply {
            consumed: 0,
            bytes: R405,
            close: true,
        };
    }
    let Some(version) = parts.next() else {
        return bad(); // no version field
    };
    if target.is_empty() || !version.starts_with(b"HTTP/") {
        return bad();
    }
    // host:port, split on the last colon.
    let Some(colon) = target.iter().rposition(|&c| c == b':') else {
        return bad();
    };
    let (host, port) = (&target[..colon], &target[colon + 1..]);
    let Some(port) = parse_port(port) else {
        return bad();
    };
    let Some(host) = parse_host(host) else {
        return bad();
    };
    Progress::Done {
        consumed: hend,
        target: Target { host, port },
    }
}

/// 1–5 decimal digits, 1..=65535.
fn parse_port(t: &[u8]) -> Option<u16> {
    if t.is_empty() || t.len() > 5 || !t.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v: u32 = t.iter().fold(0, |v, &c| v * 10 + u32::from(c - b'0'));
    u16::try_from(v).ok().filter(|&p| p != 0)
}

pub(crate) fn parse_host(h: &[u8]) -> Option<Host> {
    let s = std::str::from_utf8(h).ok()?;
    if let Some(inner) = s.strip_prefix('[') {
        // A bracket must close and hold an IPv6 literal.
        let ip: Ipv6Addr = inner.strip_suffix(']')?.parse().ok()?;
        return Some(Host::Ip(IpAddr::V6(ip)));
    }
    if s.is_empty() || s.len() > MAX_HOST {
        return None;
    }
    Some(match s.parse::<Ipv4Addr>() {
        Ok(ip) => Host::Ip(IpAddr::V4(ip)),
        Err(_) => Host::Domain(s.to_owned()),
    })
}

/// spec §6.1: CONNECT succeeded.
pub fn http_success_reply() -> &'static [u8] {
    b"HTTP/1.1 200 Connection Established\r\n\r\n"
}

/// spec §6.1: CONNECT failed (`mq_http_status_line`).
pub fn http_error_reply(e: TcpErr) -> &'static [u8] {
    match e {
        TcpErr::Timeout => b"HTTP/1.1 504 Gateway Timeout\r\n\r\n",
        TcpErr::PolicyDenied => b"HTTP/1.1 403 Forbidden\r\n\r\n",
        TcpErr::DnsFailed | TcpErr::ConnRefused | TcpErr::Ok => b"HTTP/1.1 502 Bad Gateway\r\n\r\n",
    }
}
