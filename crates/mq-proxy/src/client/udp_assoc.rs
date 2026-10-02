//! spec §6.1/§6.3: a UDP association — its app UDP socket, the source lock,
//! and the table of DSTs it has sent to.

use crate::udp::{MAX_DST_PER_ASSOC, NEG_CACHE};
use mq_runtime::{Cx, SocketOpId, Target, UdpSocketId};
use mq_transport_api::Time;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// spec §6.3: a session of the client, by its sid.
pub(super) type SessionKey = u32;

/// spec §6.3: one DST of an association: its live session and its negative cache.
pub(super) struct DstEntry {
    pub(super) session: Option<SessionKey>,
    /// `socks5udp::build` of the `Dst` as the client sent it: every reply
    /// starts with it (spec §5).
    pub(super) dst_bytes: Vec<u8>,
    /// The last RESP error (spec §6.4).
    pub(super) failed_at: Option<Time>,
}

/// spec §6.3: one UDP ASSOCIATE, keyed by its control socket.
pub(super) struct Assoc {
    pub(super) sock: Option<UdpSocketId>,
    /// The socket open still in flight.
    pub(super) open_op: Option<SocketOpId>,
    /// The control connection's peer IP, unmapped (spec §6.1).
    peer_ip: IpAddr,
    /// spec §6.3: the first-packet source lock.
    pub(super) learned: Option<SocketAddr>,
    pub(super) dsts: HashMap<Target, DstEntry>,
}

impl Assoc {
    pub(super) fn new(open_op: SocketOpId, peer_ip: IpAddr) -> Assoc {
        Assoc {
            sock: None,
            open_op: Some(open_op),
            peer_ip,
            learned: None,
            dsts: HashMap::new(),
        }
    }

    /// spec §6.3 source learning: the first datagram from the peer's IP locks
    /// its source; before that other IPs are dropped, after it all but the lock.
    pub(super) fn accept_source(&mut self, from: SocketAddr) -> bool {
        match self.learned {
            Some(l) => l == from,
            None if from.ip() == self.peer_ip => {
                self.learned = Some(from);
                true
            }
            None => false,
        }
    }

    /// spec §6.3: the entry of a DST not in the table. When the table is full an
    /// entry without a session and outside the negative cache is reclaimed;
    /// `None` when there is none (the datagram is dropped).
    pub(super) fn insert_dst(
        &mut self,
        target: Target,
        dst_bytes: Vec<u8>,
        now: Time,
    ) -> Option<&mut DstEntry> {
        if self.dsts.len() >= MAX_DST_PER_ASSOC {
            // C `dst_alloc`: `failed_at == 0 || now - failed_at >= NEGCACHE`.
            let free = self.dsts.iter().find(|(_, e)| {
                e.session.is_none() && e.failed_at.is_none_or(|f| now - f >= NEG_CACHE)
            });
            let key = free?.0.clone();
            self.dsts.remove(&key);
        }
        let e = DstEntry {
            session: None,
            dst_bytes,
            failed_at: None,
        };
        Some(self.dsts.entry(target).insert_entry(e).into_mut())
    }

    /// spec §6.1: give up the UDP socket, or cancel its open.
    pub(super) fn release(&self, cx: &mut Cx<'_>) {
        if let Some(op) = self.open_op {
            cx.cancel_udp_socket(op);
        }
        if let Some(sock) = self.sock {
            cx.close_udp_socket(sock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_runtime::Host;
    use std::time::Duration;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn assoc(peer_ip: &str) -> Assoc {
        Assoc {
            sock: None,
            open_op: None,
            peer_ip: peer_ip.parse().unwrap(),
            learned: None,
            dsts: HashMap::new(),
        }
    }

    #[test]
    fn source_learning_locks_first_peer_ip_match() {
        let mut a = assoc("10.0.0.7");
        assert!(
            !a.accept_source(sa("10.0.0.9:6000")),
            "other IP before the lock"
        );
        assert_eq!(a.learned, None);
        assert!(
            a.accept_source(sa("10.0.0.7:6000")),
            "first from the peer IP"
        );
        assert_eq!(a.learned, Some(sa("10.0.0.7:6000")));
        assert!(a.accept_source(sa("10.0.0.7:6000")));
        assert!(
            !a.accept_source(sa("10.0.0.7:6001")),
            "other port after the lock"
        );
        assert!(
            !a.accept_source(sa("10.0.0.9:6000")),
            "other IP after the lock"
        );
    }

    #[test]
    fn dst_table_cap_64_reclaims_expired_or_dead() {
        let now = Time::from_micros(10_000_000);
        let t = |port| Target {
            host: Host::Ip(IpAddr::from([10, 0, 0, 1])),
            port,
        };
        let mut a = assoc("10.0.0.7");
        for p in 0..64u16 {
            a.insert_dst(t(p), vec![], now).unwrap().session = Some(p.into());
        }
        assert!(a.insert_dst(t(64), vec![], now).is_none(), "all live");
        // No session, failed 1 s ago: still in the negative cache.
        let e = a.dsts.get_mut(&t(0)).unwrap();
        e.session = None;
        e.failed_at = Some(now - Duration::from_secs(1));
        assert!(a.insert_dst(t(64), vec![], now).is_none(), "fresh failure");
        // Failed 3 s ago: reclaimed for the 65th DST.
        a.dsts.get_mut(&t(0)).unwrap().failed_at = Some(now - Duration::from_secs(3));
        let e = a.insert_dst(t(64), b"dst".to_vec(), now).unwrap();
        e.session = Some(64);
        assert!(!a.dsts.contains_key(&t(0)));
        assert_eq!(a.dsts[&t(64)].dst_bytes, b"dst");
        assert_eq!(a.dsts.len(), 64);
        // No session and no failure (closed, never cached): reclaimed too.
        a.dsts.get_mut(&t(1)).unwrap().session = None;
        assert!(a.insert_dst(t(65), vec![], now).is_some());
        assert!(!a.dsts.contains_key(&t(1)));
    }
}
