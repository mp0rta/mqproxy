//! Caller-supplied monotonic time (spec §4.1, §4.3).

use std::ops::{Add, Sub};
use std::time::Duration;

/// Monotonic timestamp in microseconds, supplied by the caller.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct Time(pub u64);

impl Time {
    pub const ZERO: Time = Time(0);

    pub fn from_micros(us: u64) -> Time {
        Time(us)
    }
    pub fn as_micros(self) -> u64 {
        self.0
    }
}

// Durations are truncated to whole microseconds.
fn us(d: Duration) -> u64 {
    d.as_micros() as u64
}

impl Add<Duration> for Time {
    type Output = Time;
    fn add(self, d: Duration) -> Time {
        Time(self.0 + us(d))
    }
}

impl Sub<Duration> for Time {
    type Output = Time;
    fn sub(self, d: Duration) -> Time {
        Time(self.0 - us(d))
    }
}

impl Sub for Time {
    type Output = Duration;
    /// Saturates at zero.
    fn sub(self, rhs: Time) -> Duration {
        Duration::from_micros(self.0.saturating_sub(rhs.0))
    }
}
