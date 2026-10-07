// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The driver's own deadline set (spec §5.3 "Driver deadlines"): dial
//! deadlines, the listener retry after `EMFILE`, and the shutdown cap.

use crate::ids::{DialOpId, ListenerId};
use mq_transport_api::Time;

/// One driver deadline; also what `expire` returns.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Expired {
    Dial(DialOpId),
    ListenerRetry(ListenerId),
    ShutdownCap,
}

/// spec §5.3: the driver deadline set.
#[derive(Default, Debug)]
pub struct Deadlines {
    // ponytail: O(n) scans; a heap when dials in flight get numerous.
    set: Vec<(Time, Expired)>,
}

impl Deadlines {
    /// Arms `d` at `at`, replacing an earlier arming of the same deadline.
    pub fn set(&mut self, d: Expired, at: Time) {
        self.cancel(d);
        self.set.push((at, d));
    }
    pub fn cancel(&mut self, d: Expired) {
        self.set.retain(|(_, x)| *x != d);
    }
    /// The earliest armed deadline.
    pub fn earliest(&self) -> Option<Time> {
        self.set.iter().map(|(t, _)| *t).min()
    }
    /// Removes and returns every deadline at or before `now`, earliest first.
    pub fn expire(&mut self, now: Time) -> Vec<Expired> {
        let mut due: Vec<(Time, Expired)> = Vec::new();
        self.set.retain(|e| {
            let hit = e.0 <= now;
            if hit {
                due.push(*e);
            }
            !hit
        });
        due.sort_by_key(|e| e.0);
        due.into_iter().map(|(_, d)| d).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_transport_api::SlotId;

    #[test]
    fn expire_returns_due_in_order_and_keeps_the_rest() {
        let op = |i| DialOpId::from_slot(SlotId::new(i, 1)).unwrap();
        let mut d = Deadlines::default();
        d.set(Expired::Dial(op(1)), Time(30));
        d.set(Expired::ShutdownCap, Time(10));
        d.set(Expired::Dial(op(2)), Time(50));
        d.set(Expired::Dial(op(1)), Time(20)); // re-armed
        assert_eq!(d.earliest(), Some(Time(10)));
        assert_eq!(
            d.expire(Time(30)),
            vec![Expired::ShutdownCap, Expired::Dial(op(1))]
        );
        assert_eq!(d.earliest(), Some(Time(50)));
        d.cancel(Expired::Dial(op(2)));
        assert_eq!(d.earliest(), None);
    }
}
