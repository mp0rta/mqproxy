//! In-memory packet network between two transports: drop, delay, reorder (spec §8.1).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::Time;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum Rule {
    /// Drop every n-th pushed packet (the n-th, 2n-th, ...).
    DropEvery(u32),
    /// Delay delivery by a seeded-random amount in `[min, max]`.
    DelayRange {
        min: Duration,
        max: Duration,
        seed: u64,
    },
    /// Duplicate the next pushed packet once, then the rule is consumed.
    DuplicateNext,
}

#[derive(Default)]
pub struct Fabric {
    // Rule plus its RNG state (used by DelayRange only).
    rules: Vec<(Rule, u64)>,
    // Keyed by (delivery time, push seq): earliest first, FIFO among equal times.
    queue: BTreeMap<(Time, u64), Packet>,
    seq: u64,
    pushed: u64,
}

// xorshift64*; state must be non-zero.
fn next_rand(s: &mut u64) -> u64 {
    *s ^= *s >> 12;
    *s ^= *s << 25;
    *s ^= *s >> 27;
    s.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

impl Fabric {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, r: Rule) {
        let state = match r {
            Rule::DelayRange { seed, .. } => seed | 1,
            _ => 1,
        };
        self.rules.push((r, state));
    }

    pub fn push(&mut self, now: Time, p: Packet) {
        self.pushed += 1;
        let mut at = now;
        let mut dup = false;
        for (rule, rng) in self.rules.iter_mut() {
            match rule {
                Rule::DropEvery(n) => {
                    if *n != 0 && self.pushed.is_multiple_of(u64::from(*n)) {
                        return;
                    }
                }
                Rule::DelayRange { min, max, .. } => {
                    let (lo, hi) = (micros(*min), micros(*max));
                    let span = hi.saturating_sub(lo).saturating_add(1);
                    at = at + Duration::from_micros(lo.saturating_add(next_rand(rng) % span));
                }
                Rule::DuplicateNext => dup = true,
            }
        }
        if dup {
            // Consumed only once the packet survived the other rules.
            if let Some(i) = self
                .rules
                .iter()
                .position(|(r, _)| matches!(r, Rule::DuplicateNext))
            {
                self.rules.remove(i);
            }
            self.queue.insert((at, self.seq), p.clone());
            self.seq += 1;
        }
        self.queue.insert((at, self.seq), p);
        self.seq += 1;
    }

    pub fn pop_ready(&mut self, now: Time) -> Option<Packet> {
        let (&(t, _), _) = self.queue.first_key_value()?;
        if t > now {
            return None;
        }
        self.queue.pop_first().map(|(_, p)| p)
    }

    pub fn next_delivery(&self) -> Option<Time> {
        self.queue.first_key_value().map(|(&(t, _), _)| t)
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
