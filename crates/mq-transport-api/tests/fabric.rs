//! In-memory fabric tests (spec §8.1).
use mq_transport_api::Time;
use mq_transport_api::fabric::{Fabric, Packet, Rule};
use std::time::Duration;

fn pkt(i: u8) -> Packet {
    Packet {
        from: "127.0.0.1:1".parse().unwrap(),
        to: "127.0.0.1:2".parse().unwrap(),
        data: vec![i],
    }
}

fn drain(f: &mut Fabric, now: Time) -> Vec<u8> {
    let mut v = vec![];
    while let Some(p) = f.pop_ready(now) {
        v.push(p.data[0]);
    }
    v
}

fn delivery_times(seed: u64) -> Vec<Time> {
    let mut f = Fabric::new();
    f.add_rule(Rule::DelayRange {
        min: Duration::from_millis(1),
        max: Duration::from_millis(500),
        seed,
    });
    for i in 0..16 {
        f.push(Time::ZERO, pkt(i));
    }
    let mut out = vec![];
    while let Some(t) = f.next_delivery() {
        f.pop_ready(t).unwrap();
        out.push(t);
    }
    out
}

#[test]
fn delivers_in_order_by_default() {
    let mut f = Fabric::new();
    let now = Time::from_micros(5);
    for i in 0..5 {
        f.push(now, pkt(i));
    }
    assert_eq!(f.len(), 5);
    assert_eq!(f.next_delivery(), Some(now));
    assert_eq!(drain(&mut f, now), vec![0, 1, 2, 3, 4]);
    assert!(f.is_empty());
    assert_eq!(f.next_delivery(), None);
}

#[test]
fn drop_rule_drops_nth_packet() {
    let mut f = Fabric::new();
    f.add_rule(Rule::DropEvery(3));
    for i in 1..=9 {
        f.push(Time::ZERO, pkt(i));
    }
    assert_eq!(drain(&mut f, Time::ZERO), vec![1, 2, 4, 5, 7, 8]);
}

#[test]
fn delay_rule_reorders() {
    let mut f = Fabric::new();
    f.add_rule(Rule::DelayRange {
        min: Duration::from_millis(1),
        max: Duration::from_millis(1000),
        seed: 7,
    });
    for i in 0..16 {
        f.push(Time::ZERO, pkt(i));
    }
    let first = f.next_delivery().unwrap();
    assert!(first >= Time::from_micros(1_000));
    assert!(
        f.pop_ready(Time::from_micros(first.as_micros() - 1))
            .is_none()
    );
    let order = drain(&mut f, Time::from_micros(2_000_000));
    assert_eq!(order.len(), 16);
    assert_ne!(order, (0..16).collect::<Vec<u8>>());
}

#[test]
fn deterministic_with_seed() {
    assert_eq!(delivery_times(1), delivery_times(1));
    assert_ne!(delivery_times(1), delivery_times(2));
}

#[test]
fn duplicate_next_delivers_twice_then_stops() {
    let mut f = Fabric::new();
    f.add_rule(Rule::DuplicateNext);
    f.push(Time::ZERO, pkt(1));
    f.push(Time::ZERO, pkt(2));
    assert_eq!(drain(&mut f, Time::ZERO), vec![1, 1, 2]);
}
