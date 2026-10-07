//! spec §7.2: per-connection pre-OPEN datagram buffer.

use super::{PREOPEN_BYTES, PREOPEN_DGRAMS, PREOPEN_TTL};
use mq_transport_api::Time;
use std::collections::VecDeque;

/// Datagrams that arrived before their session was `Live`, oldest first. `bytes`
/// is the sum of the queued datagram lengths.
#[derive(Default)]
pub struct PreOpen {
    q: VecDeque<(u32, Time, Vec<u8>)>,
    bytes: usize,
}

impl PreOpen {
    /// Parks `datagram` for `sid`; returns the evictions it caused (the caller adds them
    /// to `preopen_evictions`). Entries past the TTL are swept first and not counted.
    pub fn push(&mut self, now: Time, sid: u32, datagram: &[u8]) -> u32 {
        // Pushes arrive in time order, so the expired entries are a prefix.
        while self.q.front().is_some_and(|e| now - e.1 > PREOPEN_TTL) {
            self.bytes -= self.q.pop_front().map_or(0, |e| e.2.len());
        }
        // Can never fit: drop it rather than empty the buffer for nothing.
        if datagram.len() > PREOPEN_BYTES {
            return 1;
        }
        let mut evictions = 0;
        while !self.q.is_empty()
            && (self.q.len() >= PREOPEN_DGRAMS || self.bytes + datagram.len() > PREOPEN_BYTES)
        {
            self.bytes -= self.q.pop_front().map_or(0, |e| e.2.len());
            evictions += 1;
        }
        self.bytes += datagram.len();
        self.q.push_back((sid, now, datagram.to_vec()));
        evictions
    }

    /// Removes and returns `sid`'s datagrams in arrival order; entries past the TTL at
    /// `now` are dropped uncounted. Other sids stay queued.
    pub fn take(&mut self, now: Time, sid: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for e in std::mem::take(&mut self.q) {
            if e.0 != sid {
                self.q.push_back(e);
                continue;
            }
            self.bytes -= e.2.len();
            if now - e.1 <= PREOPEN_TTL {
                out.push(e.2);
            }
        }
        out
    }

    /// Drops `sid`'s datagrams (the session ended before it went `Live`).
    pub fn discard(&mut self, sid: u32) {
        self.q.retain(|e| e.0 != sid);
        self.bytes = self.q.iter().map(|e| e.2.len()).sum();
    }
}
