//! spec §7.2: server pre-OPEN datagram buffer.

use mq_proxy::udp::preopen::PreOpen;
use mq_proxy::udp::{PREOPEN_BYTES, PREOPEN_DGRAMS, PREOPEN_TTL};
use mq_transport_api::Time;
use std::time::Duration;

const T0: Time = Time(1_000_000);

#[test]
fn push_evicts_expired_lazily() {
    let mut p = PreOpen::default();
    for i in 0..PREOPEN_DGRAMS {
        assert_eq!(p.push(T0, 1, &[i as u8]), 0);
    }
    // All 16 are past the TTL: the new entry sweeps them instead of evicting
    // the oldest, and a TTL sweep is not an eviction.
    let later = T0 + PREOPEN_TTL + Duration::from_millis(1);
    assert_eq!(p.push(later, 2, &[9]), 0);
    assert!(p.take(later, 1).is_empty());
    assert_eq!(p.take(later, 2), vec![vec![9]]);

    // Exactly the TTL old is not expired.
    p.push(later, 3, &[3]);
    p.push(later + PREOPEN_TTL, 4, &[4]);
    assert_eq!(p.take(later + PREOPEN_TTL, 3), vec![vec![3]]);
}

#[test]
fn push_overflow_count_evicts_oldest() {
    let mut p = PreOpen::default();
    for i in 0..PREOPEN_DGRAMS {
        assert_eq!(p.push(T0, 1, &[i as u8]), 0);
    }
    assert_eq!(p.push(T0, 1, &[16]), 1); // the 17th
    let got = p.take(T0, 1);
    assert_eq!(got.len(), PREOPEN_DGRAMS);
    assert_eq!(got[0], vec![1]); // [0] was evicted
    assert_eq!(got[PREOPEN_DGRAMS - 1], vec![16]);
}

#[test]
fn push_overflow_bytes_evicts() {
    let half = vec![0xAA; PREOPEN_BYTES / 2];
    let mut p = PreOpen::default();
    // Exactly the cap fits.
    assert_eq!(p.push(T0, 1, &half), 0);
    assert_eq!(p.push(T0, 1, &half), 0);
    // One more evicts the oldest only.
    assert_eq!(p.push(T0, 1, &[1]), 1);
    let got = p.take(T0, 1);
    assert_eq!(got.len(), 2);
    assert_eq!(got[1], vec![1]);

    // A cap-sized entry evicts every other entry (loop, not a single pop).
    assert_eq!(p.push(T0, 1, &half), 0);
    assert_eq!(p.push(T0, 1, &half), 0);
    assert_eq!(p.push(T0, 1, &vec![0xBB; PREOPEN_BYTES]), 2);
    let got = p.take(T0, 1);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].len(), PREOPEN_BYTES);
}

#[test]
fn oversize_single_entry_dropped_counted() {
    let mut p = PreOpen::default();
    assert_eq!(p.push(T0, 1, &[1]), 0);
    assert_eq!(p.push(T0, 1, &vec![0; PREOPEN_BYTES + 1]), 1);
    assert_eq!(p.take(T0, 1), vec![vec![1]]); // buffer unchanged
}

#[test]
fn take_fifo_for_sid_only() {
    let mut p = PreOpen::default();
    p.push(T0, 1, &[1]);
    p.push(T0, 2, &[2]);
    p.push(T0, 1, &[3]);
    assert_eq!(p.take(T0, 1), vec![vec![1], vec![3]]);
    assert_eq!(p.take(T0, 2), vec![vec![2]]);
    assert!(p.take(T0, 1).is_empty());

    // The byte total follows the takes: the cap is free again.
    let half = vec![0; PREOPEN_BYTES / 2];
    p.push(T0, 1, &half);
    p.push(T0, 1, &half);
    p.take(T0, 1);
    assert_eq!(p.push(T0, 3, &half), 0);
    assert_eq!(p.push(T0, 3, &half), 0);
}

#[test]
fn take_applies_ttl_without_intervening_push() {
    let mut p = PreOpen::default();
    p.push(T0, 1, &[1]);
    p.push(T0, 2, &[2]);
    // The TTL is inclusive.
    assert_eq!(p.take(T0 + PREOPEN_TTL, 1), vec![vec![1]]);
    let late = T0 + Duration::from_millis(300);
    assert!(p.take(late, 2).is_empty());
    // The expired entry was consumed by the take, not left behind.
    assert!(p.take(T0, 2).is_empty());
}

#[test]
fn discard_removes_sid() {
    let half = vec![0; PREOPEN_BYTES / 2];
    let mut p = PreOpen::default();
    p.push(T0, 1, &half);
    p.push(T0, 2, &[2]);
    p.push(T0, 1, &half);
    p.discard(1);
    assert!(p.take(T0, 1).is_empty());
    assert_eq!(p.take(T0, 2), vec![vec![2]]);

    // The byte total follows the discard.
    p.push(T0, 1, &half);
    p.push(T0, 1, &half);
    p.discard(1);
    assert_eq!(p.push(T0, 3, &half), 0);
    assert_eq!(p.push(T0, 3, &half), 0);
}
