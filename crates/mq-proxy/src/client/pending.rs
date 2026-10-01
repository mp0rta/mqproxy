//! spec §6.2 "Pending requests (before auth)": at most 256, kept across reconnects,
//! 8 KiB of preread each, 30 s deadline.

use crate::ingress::{http_error_reply, socks5_error_reply};
use mq_runtime::{Target, TcpId};
use mq_transport_api::Time;
use mq_wire::frames::TcpErr;
use std::collections::VecDeque;
use std::time::Duration;

/// spec §6.2: C `MQ_CLIENT_QUEUE_MAX`.
pub const MAX_PENDING: usize = 256;
/// spec §6.2: preread held per pending request.
pub const PREREAD_CAP: usize = 8 * 1024;

/// spec §6.1: which ingress accepted the socket, i.e. which reply format it expects.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum IngressKind {
    Socks5,
    HttpConnect,
    /// No reply: the socket is just closed.
    Transparent,
}

impl IngressKind {
    /// spec §6.1: the ingress error reply for `e`, or `None` for transparent capture.
    pub fn error_reply(self, e: TcpErr) -> Option<Vec<u8>> {
        match self {
            IngressKind::Socks5 => Some(socks5_error_reply(e).to_vec()),
            IngressKind::HttpConnect => Some(http_error_reply(e).to_vec()),
            IngressKind::Transparent => None,
        }
    }
}

/// spec §6.2: one request waiting for auth. `K` is the socket key (`TcpId` in the client).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOpen<K = TcpId> {
    pub tcp: K,
    pub target: Target,
    /// Bytes read past the ingress request; forwarded after the OK response.
    pub preread: Vec<u8>,
    /// The socket reported `TcpEnd::ReadEof`; the request stays pending.
    pub read_eof: bool,
    pub kind: IngressKind,
    pub enqueued_at: Time,
}

/// spec §6.2: the queue is full; the caller replies `CONN_REFUSED` and closes.
#[derive(Debug, PartialEq, Eq)]
pub struct Full<K = TcpId>(pub PendingOpen<K>);

/// spec §6.2: the preread would exceed 8 KiB (or the socket is not pending).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapExceeded;

/// spec §6.2: the pending queue, in arrival order. Owned by the client, not the
/// connection, so a tunnel loss leaves it untouched.
#[derive(Debug)]
pub struct Pending<K = TcpId> {
    q: VecDeque<PendingOpen<K>>,
    deadline: Duration,
}

impl<K: PartialEq> Pending<K> {
    /// spec §6.2: `deadline` is `ClientConfig::pending_deadline` (30 s).
    pub fn new(deadline: Duration) -> Self {
        Pending {
            q: VecDeque::new(),
            deadline,
        }
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// spec §6.2: enqueue; at 256 the request comes back in `Full`.
    pub fn push(&mut self, open: PendingOpen<K>) -> Result<(), Full<K>> {
        if self.q.len() >= MAX_PENDING {
            return Err(Full(open));
        }
        self.q.push_back(open);
        Ok(())
    }

    /// spec §6.2: append preread bytes, up to 8 KiB in total.
    pub fn push_preread(&mut self, tcp: &K, bytes: &[u8]) -> Result<(), CapExceeded> {
        let o = self.find(tcp).ok_or(CapExceeded)?;
        if o.preread.len() + bytes.len() > PREREAD_CAP {
            return Err(CapExceeded);
        }
        o.preread.extend_from_slice(bytes);
        Ok(())
    }

    /// spec §6.2: `TcpEnd::ReadEof` keeps the request pending; returns whether it was found.
    pub fn set_read_eof(&mut self, tcp: &K) -> bool {
        self.find(tcp).map(|o| o.read_eof = true).is_some()
    }

    /// spec §6.2: `TcpEnd::Error` drops the request at once (the shard already closed it).
    pub fn remove(&mut self, tcp: &K) -> Option<PendingOpen<K>> {
        let i = self.q.iter().position(|o| o.tcp == *tcp)?;
        self.q.remove(i)
    }

    /// spec §6.2: requests pending for 30 s or more; the caller replies `TcpErr::Timeout`
    /// (SOCKS5 REP 0x06 / HTTP 504) and closes them.
    pub fn expire(&mut self, now: Time) -> Vec<PendingOpen<K>> {
        let (gone, keep) = self
            .q
            .drain(..)
            .partition(|o| now - o.enqueued_at >= self.deadline);
        self.q = keep;
        gone.into()
    }

    /// spec §6.2: take every request, in arrival order (auth success, auth refused,
    /// `--no-reconnect` loss).
    pub fn drain(&mut self) -> Vec<PendingOpen<K>> {
        self.q.drain(..).collect()
    }

    fn find(&mut self, tcp: &K) -> Option<&mut PendingOpen<K>> {
        self.q.iter_mut().find(|o| o.tcp == *tcp)
    }
}
