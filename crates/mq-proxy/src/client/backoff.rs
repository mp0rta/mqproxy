//! spec §6.2 "Reconnect": exponential backoff, base 250 ms, multiplier 2, jitter into `[d/2, d]`.

use mq_transport_api::Time;
use std::time::Duration;

/// spec §6.2: the reconnect base delay.
pub const BASE_MS: u64 = 250;
/// spec §6.2: `--reconnect-max-backoff` is floored to this.
pub const MIN_CAP: Duration = Duration::from_secs(1);
/// spec §6.2: being `Serving` this long resets the attempt counter.
pub const SERVING_RESET: Duration = Duration::from_secs(10);

/// spec §6.2: `min(cap, base << min(attempt, 31))`.
pub fn backoff_ms(base_ms: u64, cap_ms: u64, attempt: u32) -> u64 {
    (base_ms << attempt.min(31)).min(cap_ms)
}

/// spec §6.2: the client's reconnect schedule.
#[derive(Clone, Debug)]
pub struct Backoff {
    cap_ms: u64,
    attempts: u32,
    serving_since: Option<Time>,
}

impl Backoff {
    /// spec §6.2: `max_backoff` is `--reconnect-max-backoff`, floored to 1 s.
    pub fn new(max_backoff: Duration) -> Backoff {
        let cap = u64::try_from(max_backoff.max(MIN_CAP).as_millis()).unwrap_or(u64::MAX);
        Backoff {
            cap_ms: cap,
            attempts: 0,
            serving_since: None,
        }
    }

    /// spec §6.2: the connection entered `Serving` at `now`.
    pub fn on_serving(&mut self, now: Time) {
        self.serving_since = Some(now);
    }

    /// spec §6.2: the delay before the next attempt, taken on leaving for `Backoff` at
    /// `now`; `rnd` is a random value (the shard's `Cx::rng()`). If the client had been
    /// `Serving` for 10 s the counter resets first; then it is incremented
    /// before the delay is computed (first retry: 250–500 ms).
    pub fn next_delay(&mut self, now: Time, rnd: u64) -> Duration {
        if let Some(since) = self.serving_since.take()
            && now - since >= SERVING_RESET
        {
            self.attempts = 0;
        }
        self.attempts = self.attempts.saturating_add(1);
        let d = backoff_ms(BASE_MS, self.cap_ms, self.attempts);
        Duration::from_millis(d / 2 + rnd % (d / 2 + 1))
    }

    /// spec §6.2: clear the attempt counter.
    pub fn reset(&mut self) {
        self.attempts = 0;
        self.serving_since = None;
    }

    /// spec §6.2: attempts since the last reset.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}
