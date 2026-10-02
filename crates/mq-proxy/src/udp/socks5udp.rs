//! spec §5: SOCKS5 UDP encapsulation header (RFC 1928 §7) — `mq_socks5_parse_udp_hdr`.

use mq_runtime::{Host, Target};
use mq_wire::frames::AddrType;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DST.ADDR as it sits on the wire: for a domain, the name without its length byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dst<'a> {
    pub atype: AddrType,
    pub addr: &'a [u8],
    pub port: u16,
}

/// `RSV u16 | FRAG u8 | ATYP | DST.ADDR | DST.PORT`; returns the payload offset.
/// `None`: short, `RSV != 0`, `FRAG != 0` (C: -2, dropped alike), unknown ATYP.
pub fn parse(buf: &[u8]) -> Option<(Dst<'_>, usize)> {
    let [0, 0, 0, atyp, rest @ ..] = buf else {
        return None;
    };
    let atype = AddrType::from_raw(*atyp)?;
    let (off, len) = match atype {
        AddrType::Ipv4 => (4, 4),
        AddrType::Ipv6 => (4, 16),
        AddrType::Domain => (5, *rest.first()? as usize),
    };
    let addr = buf.get(off..off + len)?;
    let port = buf.get(off + len..off + len + 2)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    Some((Dst { atype, addr, port }, off + len + 2))
}

/// `RSV = 0, FRAG = 0`, then DST verbatim; returns the bytes appended.
pub fn build(out: &mut Vec<u8>, dst: &Dst<'_>) -> usize {
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, dst.atype as u8]);
    if dst.atype == AddrType::Domain {
        debug_assert!(dst.addr.len() <= 255, "`Dst` comes from `parse`");
        out.push(dst.addr.len() as u8);
    }
    out.extend_from_slice(dst.addr);
    out.extend_from_slice(&dst.port.to_be_bytes());
    out.len() - start
}

/// `None` for an empty or non-UTF-8 domain (spec §5: the datagram is dropped silently).
pub fn target_of(dst: &Dst<'_>) -> Option<Target> {
    let host = match dst.atype {
        AddrType::Ipv4 => Host::Ip(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(dst.addr).ok()?,
        ))),
        AddrType::Ipv6 => Host::Ip(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(dst.addr).ok()?,
        ))),
        AddrType::Domain => match std::str::from_utf8(dst.addr) {
            Ok(s) if !s.is_empty() => Host::Domain(s.to_owned()),
            _ => return None,
        },
    };
    Some(Target {
        host,
        port: dst.port,
    })
}
