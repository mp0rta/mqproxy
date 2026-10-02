//! An app-owned UDP socket's send ring (SP2 spec §4.1): one record per
//! datagram, `dst || u16 len || bytes`, in a `RingBuf`.

use super::ringbuf::RingBuf;
use crate::app::SendBufFull;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

/// SP2 spec §5: `TxRing` 256 KiB.
pub(crate) const TX_RING: usize = 256 * 1024;

/// family (4 | 6), 4/16 address bytes, u16 port, u32 scope_id, u16 len.
const MAX_HDR: usize = 1 + 16 + 2 + 4 + 2;

#[derive(Debug)]
pub(crate) struct TxRing(RingBuf);

impl TxRing {
    pub(crate) fn new() -> TxRing {
        TxRing(RingBuf::new(TX_RING))
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Appends one record; `SendBufFull`, with the ring untouched, when
    /// `bytes` is over 65 535 or the record does not fit.
    pub(crate) fn push(&mut self, dst: SocketAddr, bytes: &[u8]) -> Result<(), SendBufFull> {
        let len = u16::try_from(bytes.len()).map_err(|_| SendBufFull)?;
        let mut hdr = [0u8; MAX_HDR];
        let (at, scope) = match dst {
            SocketAddr::V4(a) => {
                hdr[0] = 4;
                hdr[1..5].copy_from_slice(&a.ip().octets());
                (5, 0)
            }
            SocketAddr::V6(a) => {
                hdr[0] = 6;
                hdr[1..17].copy_from_slice(&a.ip().octets());
                (17, a.scope_id())
            }
        };
        hdr[at..at + 2].copy_from_slice(&dst.port().to_le_bytes());
        hdr[at + 2..at + 6].copy_from_slice(&scope.to_le_bytes());
        hdr[at + 6..at + 8].copy_from_slice(&len.to_le_bytes());
        let (hdr, n) = (&hdr[..at + 8], at + 8 + bytes.len());
        if self.0.space() < n {
            return Err(SendBufFull);
        }
        let w = self.0.write_slice();
        w[..hdr.len()].copy_from_slice(hdr);
        w[hdr.len()..n].copy_from_slice(bytes);
        self.0.commit(n);
        Ok(())
    }

    /// The oldest record.
    pub(crate) fn peek(&self) -> Option<(SocketAddr, &[u8])> {
        let (dst, at, len) = self.head()?;
        Some((dst, &self.0.read_slice()[at..at + len]))
    }

    /// Drops the oldest record, if any.
    pub(crate) fn pop(&mut self) {
        if let Some((_, at, len)) = self.head() {
            self.0.consume(at + len);
        }
    }

    /// The oldest record's destination, payload offset and length.
    fn head(&self) -> Option<(SocketAddr, usize, usize)> {
        let r = self.0.read_slice();
        let (ip, at): (IpAddr, usize) = match *r.first()? {
            4 => (arr::<4>(&r[1..5]).into(), 5),
            _ => (arr::<16>(&r[1..17]).into(), 17),
        };
        let port = u16::from_le_bytes(arr(&r[at..at + 2]));
        let scope = u32::from_le_bytes(arr(&r[at + 2..at + 6]));
        let len = usize::from(u16::from_le_bytes(arr(&r[at + 6..at + 8])));
        let dst = match ip {
            IpAddr::V4(ip) => SocketAddr::from((ip, port)),
            IpAddr::V6(ip) => SocketAddrV6::new(ip, port, 0, scope).into(),
        };
        Some((dst, at + 8, len))
    }
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().expect("N bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    #[test]
    fn records_round_trip_v4_v6_scope() {
        let v4 = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 53));
        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            9,
            0,
            7,
        ));
        let mut r = TxRing::new();
        assert!(r.is_empty() && r.peek().is_none());
        for (dst, b) in [(v4, &b"four"[..]), (v6, b"six"), (scoped, b"")] {
            r.push(dst, b).unwrap();
        }
        r.push(v4, &[1; 65_535]).unwrap();
        assert_eq!(r.peek(), Some((v4, &b"four"[..])));
        r.pop();
        assert_eq!(r.peek(), Some((v6, &b"six"[..])));
        r.pop();
        assert_eq!(r.peek(), Some((scoped, &b""[..])));
        r.pop();
        assert_eq!(r.peek(), Some((v4, &[1; 65_535][..])));
        r.pop();
        assert!(r.is_empty() && r.peek().is_none());
        r.pop(); // a no-op once empty
    }

    #[test]
    fn oversized_or_full_push_leaves_ring_untouched() {
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let mut r = TxRing::new();
        assert_eq!(r.push(v4, &[0; 65_536]), Err(SendBufFull));
        assert!(r.is_empty());
        while r.push(v4, &[2; 60_000]).is_ok() {}
        // 13-byte v4 header (family, address, port, scope, len): four fit in 256 KiB.
        assert_eq!(r.0.len(), 4 * (13 + 60_000));
        assert_eq!(r.push(v4, &[2; 60_000]), Err(SendBufFull));
        assert_eq!(r.0.len(), 4 * (13 + 60_000));
    }
}
