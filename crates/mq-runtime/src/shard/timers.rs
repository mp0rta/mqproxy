// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! App timers (spec §5.2 `drive` step 1, §5.4 `set_timer`/`cancel_timer`).

use super::{Shard, ShardState};
use crate::app::App;
use crate::ids::TimerId;
use mq_transport_api::{Time, TransportOps};

impl ShardState {
    pub(crate) fn set_timer(&mut self, at: Time) -> TimerId {
        let id = self.alloc(TimerId::from_slot);
        self.timers.insert(id, at);
        id
    }
    pub(crate) fn cancel_timer(&mut self, id: TimerId) {
        self.timers.remove(&id);
    }
    /// spec §5.2: the earliest app timer.
    pub fn next_timer(&self) -> Option<Time> {
        self.timers.values().min().copied()
    }
    /// spec §5.4: a live timer's deadline.
    pub fn timer_deadline(&self, id: TimerId) -> Option<Time> {
        self.timers.get(&id).copied()
    }
}

impl<T: TransportOps, A: App> Shard<T, A> {
    /// spec §5.2 step 1: timers due at `now`, ordered by (time, id). One set
    /// by a callback here fires in the next `drive`; one cancelled here does not fire.
    pub(super) fn fire_timers(&mut self, now: Time) {
        let mut due: Vec<(Time, TimerId)> = self
            .st
            .timers
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(id, at)| (*at, *id))
            .collect();
        due.sort();
        for (_, id) in due {
            if self.st.timers.remove(&id).is_some() {
                self.call_app(now, |a, cx| a.on_timer(cx, id));
            }
        }
    }
}
