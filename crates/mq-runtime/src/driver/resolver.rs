//! Resolver queue accounting (spec §5.3): at most 64 resolutions run; further
//! dials wait FIFO. A queued dial can be cancelled; a running resolution keeps
//! its slot until its result returns, and that result is then dropped.

use super::io::Io;
use crate::ids::DialOpId;
use std::collections::{HashSet, VecDeque};

/// spec §5.3: concurrent resolutions.
pub const RESOLVER_SLOTS: usize = 64;

#[derive(Default, Debug)]
pub struct ResolverQueue {
    /// Holding a slot, abandoned ones included.
    running: HashSet<DialOpId>,
    /// Running, but cancelled or past their deadline: the result is dropped.
    abandoned: HashSet<DialOpId>,
    waiting: VecDeque<(DialOpId, String, u16)>,
}

impl ResolverQueue {
    /// Starts the resolution now if a slot is free, else queues it.
    pub fn submit(&mut self, io: &mut impl Io, op: DialOpId, host: String, port: u16) {
        if self.running.len() < RESOLVER_SLOTS {
            self.running.insert(op);
            io.start_resolve(op, host, port);
        } else {
            self.waiting.push_back((op, host, port));
        }
    }
    /// A queued dial is removed; a running one is abandoned (keeps its slot).
    pub fn cancel(&mut self, op: DialOpId) {
        if self.running.contains(&op) {
            self.abandoned.insert(op);
        } else {
            self.waiting.retain(|w| w.0 != op);
        }
    }
    /// A result for `op` came back: frees its slot, starts the next waiting
    /// dial. True when the result is to be used (not abandoned, not unknown).
    pub fn finished(&mut self, io: &mut impl Io, op: DialOpId) -> bool {
        if !self.running.remove(&op) {
            return false;
        }
        if let Some((next, host, port)) = self.waiting.pop_front() {
            self.running.insert(next);
            io.start_resolve(next, host, port);
        }
        !self.abandoned.remove(&op)
    }
    /// Slots in use.
    pub fn running(&self) -> usize {
        self.running.len()
    }
    /// Dials waiting for a slot.
    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }
}
