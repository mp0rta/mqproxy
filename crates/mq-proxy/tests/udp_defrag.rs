// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §2.3: 4-slot LRU datagram defragmenter.

use mq_proxy::udp::defrag::{Defrag, Feed};
use mq_wire::udp_msg::UdpMsgHdr;

fn feed(d: &mut Defrag, packet_id: u16, frag_id: u8, frag_count: u8, bytes: &[u8]) -> Feed {
    let h = UdpMsgHdr {
        session_id: 1,
        packet_id,
        flags: 0,
        frag_id,
        frag_count,
    };
    d.feed(&h, bytes)
}

#[test]
fn single_frag_complete() {
    let mut d = Defrag::new();
    assert_eq!(
        feed(&mut d, 10, 0, 1, &[1, 2, 3]),
        Feed::Complete(vec![1, 2, 3])
    );
}

#[test]
fn single_frag_zero_len_complete() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 300, 0, 1, &[]), Feed::Complete(vec![]));
}

#[test]
fn two_frags_in_order() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 20, 0, 2, &[0xAA, 0xBB]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 20, 1, 2, &[0xCC, 0xDD, 0xEE]),
        Feed::Complete(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
    );
}

#[test]
fn two_frags_reversed() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 30, 1, 2, &[0x33, 0x44]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 30, 0, 2, &[0x11, 0x22]),
        Feed::Complete(vec![0x11, 0x22, 0x33, 0x44])
    );
}

#[test]
fn interleaved_two_packets() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 40, 0, 2, &[0xA0]), Feed::Pending);
    assert_eq!(feed(&mut d, 41, 0, 2, &[0xB0]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 40, 1, 2, &[0xA1]),
        Feed::Complete(vec![0xA0, 0xA1])
    );
    assert_eq!(
        feed(&mut d, 41, 1, 2, &[0xB1]),
        Feed::Complete(vec![0xB0, 0xB1])
    );
}

#[test]
fn lru_evicts_oldest_of_four() {
    let mut d = Defrag::new();
    for id in 100u16..=103 {
        assert_eq!(feed(&mut d, id, 0, 2, &[id as u8, 0xF0]), Feed::Pending);
    }
    // A fifth packet_id evicts 100, the least recently used.
    assert_eq!(feed(&mut d, 104, 0, 2, &[104, 0xF1]), Feed::Pending);
    for id in 101u16..=103 {
        assert_eq!(
            feed(&mut d, id, 1, 2, &[0xA0, id as u8]),
            Feed::Complete(vec![id as u8, 0xF0, 0xA0, id as u8])
        );
    }
    // 100's slot is gone: its second fragment starts a fresh assembly.
    assert_eq!(feed(&mut d, 100, 1, 2, &[0xFF]), Feed::Pending);
}

#[test]
fn feed_copies_fragment_bytes() {
    let mut d = Defrag::new();
    let mut buf = [0x11, 0x22, 0x33];
    assert_eq!(feed(&mut d, 400, 0, 2, &buf), Feed::Pending);
    buf.fill(0xFF);
    let mut buf = [0x44, 0x55, 0x66];
    let r = feed(&mut d, 400, 1, 2, &buf);
    buf.fill(0xFF);
    assert_eq!(r, Feed::Complete(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
}

#[test]
fn duplicate_ignored_pending() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 50, 0, 3, &[0x55]), Feed::Pending);
    // The duplicate's bytes must not replace the stored fragment.
    assert_eq!(feed(&mut d, 50, 0, 3, &[0x99, 0x99]), Feed::Pending);
    assert_eq!(feed(&mut d, 50, 0, 3, &[0x55]), Feed::Pending);
    assert_eq!(feed(&mut d, 50, 1, 3, &[0x56]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 50, 2, 3, &[0x57]),
        Feed::Complete(vec![0x55, 0x56, 0x57])
    );
}

#[test]
fn count_mismatch_drops_slot() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 60, 0, 3, &[0x01]), Feed::Pending);
    assert_eq!(feed(&mut d, 60, 1, 2, &[0x02]), Feed::Rejected);
    // The old assembly is gone: a fresh one completes without its bytes.
    assert_eq!(feed(&mut d, 60, 0, 2, &[0x0A]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 60, 1, 2, &[0x0B]),
        Feed::Complete(vec![0x0A, 0x0B])
    );
}

#[test]
fn packet_id_reused_single_frag() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 200, 0, 1, &[0xAA]), Feed::Complete(vec![0xAA]));
    assert_eq!(feed(&mut d, 200, 0, 1, &[0xBB]), Feed::Complete(vec![0xBB]));
}

#[test]
fn completed_packet_id_reused_same_count() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 500, 0, 2, &[1, 2]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 500, 1, 2, &[3, 4]),
        Feed::Complete(vec![1, 2, 3, 4])
    );
    assert_eq!(feed(&mut d, 500, 0, 2, &[0xAA, 0xBB, 0xCC]), Feed::Pending);
    assert_eq!(
        feed(&mut d, 500, 1, 2, &[0xDD, 0xEE]),
        Feed::Complete(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
    );
}

#[test]
fn exactly_65535_accepted() {
    let mut d = Defrag::new();
    let (f0, f1) = (vec![0x5A; 32767], vec![0xA5; 32768]);
    assert_eq!(feed(&mut d, 600, 0, 2, &f0), Feed::Pending);
    let Feed::Complete(out) = feed(&mut d, 600, 1, 2, &f1) else {
        panic!("65535 bytes must be accepted");
    };
    assert_eq!(out.len(), 65535);
    assert_eq!(out[..32767], f0[..]);
    assert_eq!(out[32767..], f1[..]);
}

#[test]
fn over_65535_rejected_slot_dropped() {
    let mut d = Defrag::new();
    let big = vec![0xAB; 32768];
    assert_eq!(feed(&mut d, 90, 0, 2, &big), Feed::Pending);
    assert_eq!(feed(&mut d, 90, 1, 2, &big), Feed::Rejected);
    // Dropped: the same fragment now opens a fresh slot instead of being rejected again.
    assert_eq!(feed(&mut d, 90, 1, 2, &big), Feed::Pending);
}

#[test]
fn first_frag_over_65535_rejected() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 91, 0, 2, &vec![0; 65536]), Feed::Rejected);
    assert_eq!(feed(&mut d, 91, 0, 2, &[7]), Feed::Pending);
}

#[test]
fn zero_count_rejected_slots_intact() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 7, 0, 2, &[1]), Feed::Pending);
    assert_eq!(feed(&mut d, 7, 0, 0, &[9]), Feed::Rejected);
    assert_eq!(feed(&mut d, 7, 1, 2, &[2]), Feed::Complete(vec![1, 2]));
}

#[test]
fn frag_id_out_of_range_rejected_slots_intact() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 7, 0, 2, &[1]), Feed::Pending);
    assert_eq!(feed(&mut d, 7, 2, 2, &[9]), Feed::Rejected);
    assert_eq!(feed(&mut d, 7, 5, 2, &[9]), Feed::Rejected);
    // Validated before the single-fragment short-circuit.
    assert_eq!(feed(&mut d, 8, 1, 1, &[9]), Feed::Rejected);
    assert_eq!(feed(&mut d, 7, 1, 2, &[2]), Feed::Complete(vec![1, 2]));
}

#[test]
fn duplicate_near_cap_then_complete() {
    let mut d = Defrag::new();
    assert_eq!(feed(&mut d, 9, 0, 3, &vec![1; 64_000]), Feed::Pending);
    assert_eq!(feed(&mut d, 9, 1, 3, &vec![2; 1_000]), Feed::Pending);
    // 65 000 stored: the duplicate would break the cap if it counted, but must not drop the slot.
    assert_eq!(feed(&mut d, 9, 1, 3, &vec![2; 1_000]), Feed::Pending);
    let Feed::Complete(out) = feed(&mut d, 9, 2, 3, &[3; 500]) else {
        panic!("assembly must survive the duplicate");
    };
    assert_eq!(out.len(), 65_500);
    assert_eq!(out[64_000], 2);
    assert_eq!(out[65_499], 3);
}

#[test]
fn duplicate_refreshes_lru() {
    let mut d = Defrag::new();
    for id in 100u16..=103 {
        assert_eq!(feed(&mut d, id, 0, 2, &[id as u8]), Feed::Pending);
    }
    // A duplicate for the oldest refreshes it; the fifth id must evict 101 instead.
    assert_eq!(feed(&mut d, 100, 0, 2, &[100]), Feed::Pending);
    assert_eq!(feed(&mut d, 104, 0, 2, &[104]), Feed::Pending);
    for id in [100u16, 102, 103] {
        assert_eq!(
            feed(&mut d, id, 1, 2, &[0xEE]),
            Feed::Complete(vec![id as u8, 0xEE])
        );
    }
    assert_eq!(feed(&mut d, 101, 1, 2, &[0xEE]), Feed::Pending);
}
