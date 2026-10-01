//! spec §6.1: SOCKS5 (RFC 1928, no-auth, CONNECT only) — port of `src/ingress/mq_socks5.c`
//! plus the reply choices of `mq_listener.c:drive_socks5`.

use super::Progress;
use super::request::capped;
use mq_runtime::{Host, Target};
use mq_wire::frames::TcpErr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_ASSOCIATE: u8 = 0x03;
const METHOD_NOAUTH: u8 = 0x00;

static METHOD_OK: [u8; 2] = [VER, 0x00];
static METHOD_NONE: [u8; 2] = [VER, 0xFF];
static REP_CMD_UNSUPPORTED: [u8; 10] = reply(0x07);
static REP_ATYP_UNSUPPORTED: [u8; 10] = reply(0x08);

/// VER REP RSV ATYP=1 BND.ADDR=0.0.0.0 BND.PORT=0 (`build_reply10` with a zero bind).
const fn reply(rep: u8) -> [u8; 10] {
    [VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// spec §6.1: greeting, then one request.
#[derive(Debug, Default)]
pub struct Socks5Parser {
    greeted: bool,
}

impl Socks5Parser {
    /// spec §6.1: `buf` is everything buffered since the last `consumed`.
    pub fn feed(&mut self, buf: &[u8]) -> Progress<'_> {
        let greeted = &mut self.greeted;
        capped(buf, |b| {
            if *greeted {
                request(b)
            } else {
                greeting(b, greeted)
            }
        })
    }
}

/// VER | NMETHODS | METHODS.
fn greeting(b: &[u8], greeted: &mut bool) -> Progress<'static> {
    if b.len() < 2 {
        return Progress::Need;
    }
    if b[0] != VER {
        return Progress::Close; // mq_socks5.c:25 → MQ_DRIVE_CLOSE, no reply
    }
    let total = 2 + b[1] as usize;
    if b.len() < total {
        return Progress::Need;
    }
    if !b[2..total].contains(&METHOD_NOAUTH) {
        return Progress::Reply {
            consumed: 0,
            bytes: &METHOD_NONE,
            close: true,
        };
    }
    *greeted = true;
    Progress::Reply {
        consumed: total,
        bytes: &METHOD_OK,
        close: false,
    }
}

fn refuse(bytes: &'static [u8]) -> Progress<'static> {
    Progress::Reply {
        consumed: 0,
        bytes,
        close: true,
    }
}

/// VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT.
fn request(b: &[u8]) -> Progress<'static> {
    if b.len() < 4 {
        return Progress::Need;
    }
    if b[0] != VER {
        return Progress::Close; // mq_socks5.c:52 → MQ_DRIVE_CLOSE, no reply
    }
    let cmd = b[1];
    if cmd != CMD_CONNECT && cmd != CMD_ASSOCIATE {
        return refuse(&REP_CMD_UNSUPPORTED); // BIND and unknown commands
    }
    // b[2] RSV ignored, as in C.
    let atyp = b[3];
    let (off, len) = match atyp {
        0x01 => (4, 4),
        0x04 => (4, 16),
        0x03 => match b.get(4) {
            Some(&n) => (5, n as usize),
            None => return Progress::Need,
        },
        _ => return refuse(&REP_ATYP_UNSUPPORTED),
    };
    let total = off + len + 2;
    if b.len() < total {
        return Progress::Need;
    }
    if cmd == CMD_ASSOCIATE {
        // spec §6.1: UDP ASSOCIATE is refused with REP 0x07 in SP1 (parsed in full, as C).
        return Progress::Reply {
            consumed: total,
            bytes: &REP_CMD_UNSUPPORTED,
            close: true,
        };
    }
    let addr = &b[off..off + len];
    let host = match atyp {
        0x01 => Host::Ip(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(addr).unwrap(),
        ))),
        0x04 => Host::Ip(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(addr).unwrap(),
        ))),
        // `Host::Domain` is a `String`: a non-UTF-8 name is refused as an unsupported address.
        _ => match std::str::from_utf8(addr) {
            Ok(s) => Host::Domain(s.to_owned()),
            Err(_) => return refuse(&REP_ATYP_UNSUPPORTED),
        },
    };
    let port = u16::from_be_bytes([b[total - 2], b[total - 1]]);
    Progress::Done {
        consumed: total,
        target: Target { host, port },
    }
}

/// spec §6.1: CONNECT succeeded (REP 0x00).
pub fn socks5_success_reply() -> [u8; 10] {
    reply(0x00)
}

/// spec §6.1: CONNECT failed; REP from `mq_socks5_reply_code`, with `Ok` as general failure.
pub fn socks5_error_reply(e: TcpErr) -> [u8; 10] {
    reply(match e {
        TcpErr::DnsFailed => 0x04,
        TcpErr::ConnRefused => 0x05,
        TcpErr::Timeout => 0x06,
        TcpErr::PolicyDenied => 0x02,
        TcpErr::Ok => 0x01,
    })
}
