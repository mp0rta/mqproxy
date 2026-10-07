// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
use mq_transport_api::{ConnId, SlotId, StreamId, Time};
use std::time::Duration;

#[test]
fn slot_id_none_is_zero_and_live_ids_never_zero() {
    assert_eq!(SlotId::NONE.as_raw(), 0);
    assert!(SlotId::NONE.is_none());
    assert!(ConnId::from_slot(SlotId::NONE).is_none());
    assert!(StreamId::from_slot(SlotId::NONE).is_none());
    // generation 0 is never live, whatever the index
    assert!(ConnId::from_slot(SlotId::new(7, 0)).is_none());
    assert!(StreamId::from_slot(SlotId::new(u32::MAX, 0)).is_none());
    // index 0 with generation 1 is live and its slot is non-zero
    let c = ConnId::from_slot(SlotId::new(0, 1)).unwrap();
    assert_ne!(c.slot().as_raw(), 0);
    assert!(!c.slot().is_none());
    let s = StreamId::from_slot(SlotId::new(0, 1)).unwrap();
    assert_ne!(s.slot(), SlotId::NONE);
}

#[test]
fn slot_id_roundtrip() {
    for (i, g) in [(0u32, 1u32), (5, 9), (u32::MAX, u32::MAX), (0x1234, 0xabcd)] {
        let s = SlotId::new(i, g);
        assert_eq!(s.index(), i);
        assert_eq!(s.generation(), g);
        assert_eq!(s.as_raw(), (u64::from(g) << 32) | u64::from(i));
        assert_eq!(SlotId::from_raw(s.as_raw()), s);
        let c = ConnId::from_slot(s).unwrap();
        assert_eq!(c.index(), i);
        assert_eq!(c.generation().get(), g);
        assert_eq!(c.slot(), s);
        assert_eq!(StreamId::from_slot(s).unwrap().slot(), s);
    }
    // distinct generations of the same index are distinct ids
    assert_ne!(
        ConnId::from_slot(SlotId::new(3, 1)),
        ConnId::from_slot(SlotId::new(3, 2))
    );
}

#[test]
fn time_arithmetic() {
    let t = Time::from_micros(1_000);
    assert_eq!(t.as_micros(), 1_000);
    assert_eq!(Time::ZERO.as_micros(), 0);
    assert_eq!((t + Duration::from_millis(2)).as_micros(), 3_000);
    assert_eq!((t - Duration::from_micros(400)).as_micros(), 600);
    assert_eq!(Time::from_micros(5_000) - t, Duration::from_micros(4_000));
    // Time - Time saturates at zero
    assert_eq!(t - Time::from_micros(5_000), Duration::ZERO);
    // Time ± Duration saturates too
    assert_eq!(t - Duration::from_secs(1), Time::ZERO);
    assert_eq!((t + Duration::MAX).as_micros(), u64::MAX);
    assert!(t < t + Duration::from_micros(1));
    // sub-microsecond parts of a Duration are truncated
    assert_eq!((t + Duration::from_nanos(1_999)).as_micros(), 1_001);
}
