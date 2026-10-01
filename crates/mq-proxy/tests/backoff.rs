//! spec §6.2: reconnect backoff — port of tests/test_backoff.c plus the Rust-side schedule cases.

use mq_proxy::client::backoff::{Backoff, backoff_ms};
use mq_runtime::Rng;
use mq_transport_api::Time;
use std::time::Duration;

const BASE: u64 = 250;
const CAP: u64 = 30_000;

// test_backoff.c: test_doubling_sequence
#[test]
fn doubling_sequence() {
    let got: Vec<u64> = (0..=6).map(|a| backoff_ms(BASE, CAP, a)).collect();
    assert_eq!(got, [250, 500, 1000, 2000, 4000, 8000, 16000]);
}

// test_backoff.c: test_saturates_at_cap
#[test]
fn saturates_at_cap() {
    for a in [7, 8, 10] {
        assert_eq!(backoff_ms(BASE, CAP, a), CAP);
    }
}

// test_backoff.c: test_no_overflow_large_attempts
#[test]
fn no_overflow_large_attempts() {
    assert_eq!(backoff_ms(BASE, CAP, 31), CAP);
    assert_eq!(backoff_ms(BASE, CAP, 64), CAP);
    assert_eq!(backoff_ms(BASE, CAP, u32::MAX), CAP);
}

// test_backoff.c: test_generic
#[test]
fn generic() {
    let got = [0, 1, 2, 3, 4, 31].map(|a| backoff_ms(1, 8, a));
    assert_eq!(got, [1, 2, 4, 8, 8, 8]);
    for a in [0, 5, 31] {
        assert_eq!(backoff_ms(100, 100, a), 100);
    }
}

#[test]
fn first_retry_between_250_and_500ms() {
    // The counter is incremented before the delay is computed: attempt 1 → d = 500.
    let lo = Backoff::new(Duration::from_secs(30)).next_delay(Time::ZERO, 0);
    let hi = Backoff::new(Duration::from_secs(30)).next_delay(Time::ZERO, 250);
    assert_eq!(lo, Duration::from_millis(250));
    assert_eq!(hi, Duration::from_millis(500));
}

#[test]
fn jitter_in_half_to_full_with_seeded_rng() {
    let mut rng = Rng::new(42);
    let mut b = Backoff::new(Duration::from_secs(30));
    let mut seen_below_d = false;
    for attempt in 1..=20u32 {
        let d = backoff_ms(BASE, CAP, attempt);
        let got = b.next_delay(Time::ZERO, rng.next_u64());
        let ms = u64::try_from(got.as_millis()).unwrap();
        assert!(
            (d / 2..=d).contains(&ms),
            "attempt {attempt}: {ms} not in [{}, {d}]",
            d / 2
        );
        seen_below_d |= ms < d;
    }
    assert!(seen_below_d, "jitter never moved below d");
}

#[test]
fn cap_floored_to_1s() {
    let mut b = Backoff::new(Duration::from_millis(100));
    for _ in 0..10 {
        b.next_delay(Time::ZERO, 0);
    }
    // d = 1000 (the floored cap); rnd 500 picks the top of [500, 1000].
    assert_eq!(b.next_delay(Time::ZERO, 500), Duration::from_millis(1000));
}

#[test]
fn reset_after_10s_serving() {
    let t0 = Time::ZERO;
    let mut b = Backoff::new(Duration::from_secs(30));
    for _ in 0..3 {
        b.next_delay(t0, 0);
    }
    assert_eq!(b.attempts(), 3);

    // Serving for under 10 s: the counter keeps climbing.
    b.on_serving(t0);
    b.next_delay(t0 + Duration::from_millis(9_999), 0);
    assert_eq!(b.attempts(), 4);

    // Serving for 10 s: the counter restarts, so the next retry is again 250–500 ms.
    let t1 = t0 + Duration::from_secs(20);
    b.on_serving(t1);
    let d = b.next_delay(t1 + Duration::from_secs(10), 0);
    assert_eq!(b.attempts(), 1);
    assert_eq!(d, Duration::from_millis(250));

    // A later loss without a new Serving does not reset again.
    b.next_delay(t1 + Duration::from_secs(60), 0);
    assert_eq!(b.attempts(), 2);

    b.reset();
    assert_eq!(b.attempts(), 0);
}
