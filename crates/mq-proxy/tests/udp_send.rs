//! spec §5: datagram MSS cache and the fragment send policy (`send_packet`).

mod common;

use common::{H, cfg};
use mq_proxy::udp::send::{MssCache, SendOutcome, send_packet};
use mq_proxy::udp::{Counters, MSS_REFRESH};
use mq_transport_api::DatagramError;
use mq_wire::udp_msg::{UDP_MSG_HDR, UdpMsgHdr};

const SID: u32 = 0x0102_0304;

/// Sends `payload` as packet `pid` of `SID` through the harness' connection.
fn send(h: &mut H, mss: &mut MssCache, pid: u16, payload: &[u8], c: &mut Counters) -> SendOutcome {
    let (now, conn) = (h.now, h.conn);
    h.sh.with_app(now, |_, cx| {
        send_packet(cx, conn, mss, SID, pid, payload, c)
    })
}

fn expect_sends(h: &H, results: &[Result<(), DatagramError>]) {
    for r in results {
        h.t.expect_datagram_send(h.conn, *r);
    }
}

fn hdr(pid: u16, frag_id: u8, frag_count: u8) -> Vec<u8> {
    let mut b = [0u8; UDP_MSG_HDR];
    UdpMsgHdr {
        session_id: SID,
        packet_id: pid,
        flags: 0,
        frag_id,
        frag_count,
    }
    .encode(&mut b);
    b.to_vec()
}

fn cat(a: Vec<u8>, b: &[u8]) -> Vec<u8> {
    [a, b.to_vec()].concat()
}

#[test]
fn mss_cached_64_successful_emits() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    for pid in 0..MSS_REFRESH {
        let o = send(&mut h, &mut mss, pid as u16, b"x", &mut c);
        assert_eq!((o.frags_ok, o.failed), (1, 0));
    }
    assert_eq!(h.t.datagram_mss_calls(h.conn), 1);
    send(&mut h, &mut mss, 64, b"x", &mut c);
    assert_eq!(h.t.datagram_mss_calls(h.conn), 2);
    assert_eq!(h.t.datagram_sends(h.conn).len(), 65);
    assert_eq!(c, Counters::default());
}

#[test]
fn failed_emit_does_not_count_down() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    expect_sends(&h, &[Err(DatagramError::Blocked)]);
    // One failure plus 64 successes: had the failure counted, the countdown would
    // have expired a packet earlier and the 65th would already have refreshed.
    for pid in 0..=MSS_REFRESH {
        send(&mut h, &mut mss, pid as u16, b"x", &mut c);
    }
    assert_eq!(h.t.datagram_mss_calls(h.conn), 1);
    assert_eq!(c.drops_send_fail, 1);
    send(&mut h, &mut mss, 65, b"x", &mut c);
    assert_eq!(h.t.datagram_mss_calls(h.conn), 2);
}

#[test]
fn invalidate_forces_refresh() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    send(&mut h, &mut mss, 0, b"x", &mut c);
    mss.invalidate();
    h.t.set_datagram_mss(h.conn, 100);
    send(&mut h, &mut mss, 1, &[7; 200], &mut c);
    assert_eq!(h.t.datagram_mss_calls(h.conn), 2);
    // 200 bytes at mss 100 → 91 payload bytes per fragment → 3 fragments
    assert_eq!(h.t.datagram_sends(h.conn).len(), 1 + 3);
}

#[test]
fn mss_zero_drops_send_fail() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, 0);
    let o = send(&mut h, &mut mss, 0, b"x", &mut c);
    assert_eq!((o.frags_ok, o.failed), (0, 0));
    assert_eq!((c.drops_send_fail, c.drops_oversize), (1, 0));
    assert!(h.t.datagram_sends(h.conn).is_empty());
    // A 0 is never cached: the next packet asks again and goes through.
    h.t.set_datagram_mss(h.conn, 1200);
    let o = send(&mut h, &mut mss, 0, b"x", &mut c);
    assert_eq!(o.frags_ok, 1);
    assert_eq!(h.t.datagram_mss_calls(h.conn), 2);
}

#[test]
fn mss_no_larger_than_header_drops_send_fail() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, UDP_MSG_HDR);
    let o = send(&mut h, &mut mss, 0, b"x", &mut c);
    assert_eq!((o.frags_ok, o.failed), (0, 0));
    assert_eq!((c.drops_send_fail, c.drops_oversize), (1, 0));
    assert!(h.t.datagram_sends(h.conn).is_empty());
}

#[test]
fn too_many_frags_counts_oversize() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, UDP_MSG_HDR + 1); // mss_payload = 1

    let o = send(&mut h, &mut mss, 0, &[0; 256], &mut c);
    assert_eq!((o.frags_ok, o.failed), (0, 0));
    assert_eq!(c.drops_oversize, 1);
    assert_eq!(c.drops_send_fail, 0);
    assert!(h.t.datagram_sends(h.conn).is_empty());

    let o = send(&mut h, &mut mss, 1, &[0; 255], &mut c);
    assert_eq!((o.frags_ok, o.failed), (255, 0));
    assert_eq!(h.t.datagram_sends(h.conn).len(), 255);
    assert_eq!(c.drops_oversize, 1);
    assert_eq!(c.frags_sent, 255);
}

#[test]
fn middle_frag_failure_continues() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, UDP_MSG_HDR + 10);
    expect_sends(&h, &[Ok(()), Err(DatagramError::Blocked), Ok(())]);

    let payload: Vec<u8> = (0..25).collect();
    let o = send(&mut h, &mut mss, 7, &payload, &mut c);

    assert_eq!((o.frags_ok, o.failed), (2, 1));
    assert_eq!(
        h.t.datagram_sends(h.conn),
        vec![
            cat(hdr(7, 0, 3), &payload[..10]),
            cat(hdr(7, 2, 3), &payload[20..]),
        ]
    );
    assert_eq!(c.drops_send_fail, 1);
    assert_eq!(c.frags_sent, 2);
}

#[test]
fn two_frags_one_failure_no_frags_sent() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, UDP_MSG_HDR + 10);
    expect_sends(&h, &[Ok(()), Err(DatagramError::Conn)]);

    let o = send(&mut h, &mut mss, 0, &[1; 15], &mut c);

    assert_eq!((o.frags_ok, o.failed), (1, 1));
    assert_eq!(c.frags_sent, 0);
    assert_eq!(c.drops_send_fail, 1);
}

#[test]
fn single_fragment_and_empty_payload() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    send(&mut h, &mut mss, 1, b"abc", &mut c);
    send(&mut h, &mut mss, 2, b"", &mut c);
    assert_eq!(
        h.t.datagram_sends(h.conn),
        vec![cat(hdr(1, 0, 1), b"abc"), hdr(2, 0, 1)]
    );
    // unfragmented packets never add to frags_sent
    assert_eq!(c, Counters::default());
}

#[test]
fn mss_beyond_the_stack_scratch() {
    let mut h = H::new(cfg());
    let (mut mss, mut c) = (MssCache::new(), Counters::default());
    h.t.set_datagram_mss(h.conn, 9000);
    let payload = vec![0xAB; 5000];
    let o = send(&mut h, &mut mss, 3, &payload, &mut c);
    assert_eq!((o.frags_ok, o.failed), (1, 0));
    assert_eq!(
        h.t.datagram_sends(h.conn),
        vec![cat(hdr(3, 0, 1), &payload)]
    );
}
