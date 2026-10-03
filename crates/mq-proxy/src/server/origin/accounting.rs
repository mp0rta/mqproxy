//! SP3 spec §7.7: an origin conn's record accounting and the pure decisions
//! taken from it — the h2 pool-hit rule, `draining`, retirement and the idle
//! sweep's verdict. No hyper here; the settling feeds the counters.

use super::IDLE_MAX;
use mq_transport_api::Time;
use std::time::Duration;

/// One conn's counters, kept by the settling (§7.7 "Settling point").
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnAccounting {
    /// `Assigned` + `Ended`-unreleased records: `+= 1` at assignment, `-= 1`
    /// once when the record is dropped. Counted on every conn, consulted for
    /// h2 only (h1 has `busy`).
    pub active: u32,
    /// `Ended` records still waiting for `released`, as of the last settling.
    pub ended_unreleased: u32,
    /// The driver is `Completed`: the conn takes no new assignment.
    pub completed: bool,
}

/// The idle sweep's verdict on one conn (§7.7 "Idle sweep"). No `B`: an
/// empty `Completed` conn is removed at the settling, not by the sweep.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SweepClass {
    /// Idle ≥ `IDLE_MAX`: `tcp_close`.
    A,
    /// h2 retirement: `tcp_abort`.
    E,
    Keep,
}

impl ConnAccounting {
    pub fn assign(&mut self) {
        self.active += 1;
    }

    /// The settling's scan (§7.7 (a)), one `Ended` record: a `released`
    /// record is dropped — its one `active -= 1`; an unreleased one stays and
    /// counts toward `ended_unreleased`, which the settling zeroes before the
    /// scan.
    pub fn record_dropped(&mut self, released: bool) {
        if released {
            self.active -= 1;
        } else {
            self.ended_unreleased += 1;
        }
    }

    /// h2 (§7.7): an `Ended`-unreleased record or a `Completed` driver.
    #[allow(dead_code)] // Task 5.6c: the h2 pool hit
    pub fn draining(&self) -> bool {
        self.ended_unreleased > 0 || self.completed
    }

    /// §7.2 step 2: an h2 pool hit needs `!draining` and
    /// `active < current_max_send_streams()`.
    #[allow(dead_code)] // Task 5.6c: the h2 pool hit
    pub fn h2_hit_allowed(&self, max: usize) -> bool {
        !self.draining() && (self.active as usize) < max
    }

    /// §7.7 retirement: nothing `Assigned`, at least one `Ended`-unreleased
    /// record, and every one of them older than one sweep — the caller
    /// passes the newest `Ended.since`.
    pub fn retire_eligible(&self, now: Time, sweep: Duration, newest_ended: Option<Time>) -> bool {
        self.ended_unreleased > 0
            && self.active == self.ended_unreleased
            && newest_ended.is_some_and(|t| now - t >= sweep)
    }
}

/// The idle sweep's decision for one pooled conn: expiry (class A) when it
/// has been idle `IDLE_MAX`, else h2 retirement (class E), else keep.
/// `newest_ended` tells a young stuck record from an aged one, which the
/// counters alone cannot.
pub fn sweep_class(
    acct: &ConnAccounting,
    idle_since: Option<Time>,
    newest_ended: Option<Time>,
    now: Time,
    sweep: Duration,
) -> SweepClass {
    if idle_since.is_some_and(|t| now - t >= IDLE_MAX) {
        SweepClass::A
    } else if acct.retire_eligible(now, sweep, newest_ended) {
        SweepClass::E
    } else {
        SweepClass::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::super::SWEEP;
    use super::*;

    const T0: Time = Time(1_000_000_000);

    const SEC: Duration = Duration::from_secs(1);

    fn at(s: u64) -> Time {
        T0 + Duration::from_secs(s)
    }

    fn acct(active: u32, ended_unreleased: u32, completed: bool) -> ConnAccounting {
        ConnAccounting {
            active,
            ended_unreleased,
            completed,
        }
    }

    #[test]
    fn active_increments_at_assign_decrements_once_at_drop() {
        let mut a = ConnAccounting::default();
        a.assign();
        a.assign();
        assert_eq!(a.active, 2);
        // A settling sees one record Ended but unreleased: it stays counted.
        a.record_dropped(false);
        assert_eq!((a.active, a.ended_unreleased), (2, 1));
        // The next settling: zeroed, the record now released → dropped.
        a.ended_unreleased = 0;
        a.record_dropped(true);
        assert_eq!((a.active, a.ended_unreleased), (1, 0));
        a.record_dropped(true);
        assert_eq!(a.active, 0);
    }

    #[test]
    fn draining_derived_from_ended_unreleased_or_completed() {
        assert!(!acct(0, 0, false).draining());
        assert!(
            !acct(3, 0, false).draining(),
            "Assigned alone is not draining"
        );
        assert!(acct(1, 1, false).draining());
        assert!(acct(0, 0, true).draining());
        assert!(acct(2, 1, true).draining());
    }

    #[test]
    fn retire_eligible_requires_no_assigned_and_aged_records() {
        let aged = Some(at(0));
        let now = at(10);
        assert!(acct(1, 1, false).retire_eligible(now, SWEEP, aged));
        assert!(acct(1, 1, true).retire_eligible(now, SWEEP, aged));
        assert!(
            !acct(2, 1, false).retire_eligible(now, SWEEP, aged),
            "one record still Assigned"
        );
        assert!(
            !acct(1, 1, false).retire_eligible(at(9), SWEEP, aged),
            "younger than one sweep"
        );
        assert!(
            !acct(0, 0, true).retire_eligible(now, SWEEP, None),
            "an empty Completed conn is the settling's (B), not the sweep's"
        );
        assert!(!acct(0, 0, false).retire_eligible(now, SWEEP, None));
    }

    #[test]
    fn retire_eligible_mixed_ages_waits_for_the_newest() {
        // Two stuck records ended at 0 s and 7 s: the caller passes 7 s.
        let a = acct(2, 2, false);
        assert!(!a.retire_eligible(at(12), SWEEP, Some(at(7))));
        assert!(a.retire_eligible(at(17), SWEEP, Some(at(7))));
    }

    #[test]
    fn h2_hit_rule_requires_active_below_max() {
        let rows = [
            (acct(0, 0, false), 1, true),
            (acct(0, 0, false), 0, false),
            (acct(99, 0, false), 100, true),
            (acct(100, 0, false), 100, false),
            (acct(1, 1, false), 100, false), // draining: an Ended-unreleased record
            (acct(0, 0, true), 100, false),  // draining: Completed
        ];
        for (a, max, want) in rows {
            assert_eq!(a.h2_hit_allowed(max), want, "{a:?} max={max}");
        }
    }

    #[test]
    fn h2_sweep_classes_pure() {
        use SweepClass::*;
        let (young, expired) = (T0 + (IDLE_MAX - SEC), T0 + IDLE_MAX);
        let rows = [
            // (acct, idle_since, newest_ended, now, want)
            (acct(0, 0, false), None, None, at(500), Keep),
            (acct(0, 0, false), Some(at(0)), None, young, Keep),
            (acct(0, 0, false), Some(at(0)), None, expired, A),
            (acct(1, 0, false), None, None, at(500), Keep), // live exchange
            (acct(2, 1, false), None, Some(at(0)), at(500), Keep), // one Assigned left
            // Identical counters: a young stuck record keeps, an aged one retires.
            (acct(1, 1, false), None, Some(at(495)), at(500), Keep),
            (acct(1, 1, false), None, Some(at(490)), at(500), E),
            (acct(1, 1, true), None, Some(at(0)), at(500), E),
            (acct(0, 0, true), None, None, at(500), Keep), // empty Completed: no B
        ];
        for (a, idle, newest, now, want) in rows {
            assert_eq!(
                sweep_class(&a, idle, newest, now, SWEEP),
                want,
                "{a:?} idle={idle:?} newest={newest:?} now={now:?}"
            );
        }
    }
}
