// spec §2.2
use mq_wire::udp_msg::*;

/// Collects (header, slice length) per fragment.
fn run(
    sid: u32,
    packet_id: u16,
    payload: &[u8],
    mss: usize,
) -> (Result<(), SplitError>, Vec<(UdpMsgHdr, usize)>) {
    let mut out = Vec::new();
    let r = split(sid, packet_id, payload, mss, |h, p| out.push((*h, p.len())));
    (r, out)
}

// ---- test_hdr_roundtrip / test_hdr_byte_order ----
#[test]
fn hdr_roundtrip_be() {
    let h = UdpMsgHdr {
        session_id: 0x2A,
        packet_id: 0x0102,
        flags: 0,
        frag_id: 3,
        frag_count: 4,
    };
    let wire = [0x00, 0x00, 0x00, 0x2A, 0x01, 0x02, 0x00, 0x03, 0x04];
    let mut out = [0u8; UDP_MSG_HDR];
    h.encode(&mut out);
    assert_eq!(out, wire);
    assert_eq!(UdpMsgHdr::decode(&wire), Some(h));
}

#[test]
fn hdr_all_fields_roundtrip() {
    let h = UdpMsgHdr {
        session_id: 0xDEAD_BEEF,
        packet_id: 0x1234,
        flags: 0xAB,
        frag_id: 7,
        frag_count: 12,
    };
    let mut out = [0u8; UDP_MSG_HDR];
    h.encode(&mut out);
    assert_eq!(UdpMsgHdr::decode(&out), Some(h));
}

// ---- test_hdr_decode_truncation ----
#[test]
fn hdr_decode_short_is_none() {
    let wire = [1u8; UDP_MSG_HDR];
    for k in 0..UDP_MSG_HDR {
        assert_eq!(UdpMsgHdr::decode(&wire[..k]), None, "len {k}");
    }
    assert!(UdpMsgHdr::decode(&wire).is_some());
}

#[test]
fn hdr_decode_ignores_trailing_payload() {
    let mut buf = [0u8; 20];
    buf[3] = 9;
    buf[8] = 1;
    assert_eq!(UdpMsgHdr::decode(&buf).unwrap().session_id, 9);
}

// ---- test_split_empty_payload ----
#[test]
fn split_empty_emits_one() {
    let mut calls = 0;
    let r = split(1, 0, &[], 1000, |h, p| {
        calls += 1;
        assert_eq!((h.frag_id, h.frag_count), (0, 1));
        assert!(p.is_empty());
    });
    assert_eq!((r, calls), (Ok(()), 1));
}

// ---- test_split_3frags ----
#[test]
fn split_headers_and_order() {
    let payload: Vec<u8> = (0..2500).map(|i| i as u8).collect();
    let mut got = Vec::new();
    let r = split(0xAABB_CCDD, 0x42, &payload, 1000, |h, p| {
        got.push((*h, p.to_vec()))
    });
    assert_eq!(r, Ok(()));
    assert_eq!(got.len(), 3);
    let mut joined = Vec::new();
    for (i, (h, p)) in got.iter().enumerate() {
        let want = UdpMsgHdr {
            session_id: 0xAABB_CCDD,
            packet_id: 0x42,
            flags: 0,
            frag_id: i as u8,
            frag_count: 3,
        };
        assert_eq!(*h, want);
        joined.extend_from_slice(p);
    }
    let lens: Vec<_> = got.iter().map(|(_, p)| p.len()).collect();
    assert_eq!(lens, [1000, 1000, 500]);
    assert_eq!(joined, payload);
}

// ---- test_split_1frag ----
#[test]
fn split_smaller_than_mss_is_one() {
    let (r, got) = run(1, 2, &[0u8; 64], 1000);
    assert_eq!(r, Ok(()));
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].0.frag_id, got[0].0.frag_count, got[0].1),
        (0, 1, 64)
    );
}

#[test]
fn split_exact_multiple() {
    let (r, got) = run(1, 0, &[0u8; 2400], 1200);
    assert_eq!(r, Ok(()));
    assert_eq!(got.iter().map(|f| f.1).collect::<Vec<_>>(), [1200, 1200]);
    assert!(got.iter().all(|f| f.0.frag_count == 2));
}

#[test]
fn split_last_shorter() {
    let (r, got) = run(1, 0, &[0u8; 2401], 1200);
    assert_eq!(r, Ok(()));
    assert_eq!(got.iter().map(|f| f.1).collect::<Vec<_>>(), [1200, 1200, 1]);
    let ids: Vec<_> = got.iter().map(|f| f.0.frag_id).collect();
    assert_eq!(ids, [0, 1, 2]);
}

// ---- test_split_255frags_ok / test_split_256frags_rejected ----
#[test]
fn split_255_limit() {
    let payload = vec![0u8; 255 * 100 + 1];

    let (r, got) = run(1, 0, &payload[..255 * 100], 100);
    assert_eq!(r, Ok(()));
    assert_eq!(got.len(), 255);
    assert_eq!(got[0].0.frag_count, 255);
    assert_eq!(got[254].0.frag_id, 254);

    let (r, got) = run(1, 0, &payload, 100);
    assert_eq!(r, Err(SplitError::TooManyFrags));
    assert!(got.is_empty());
}

// ---- test_split_mss_zero_rejected ----
#[test]
fn split_zero_mss() {
    for payload in [&[][..], &[0u8; 64][..]] {
        let (r, got) = run(1, 0, payload, 0);
        assert_eq!(r, Err(SplitError::ZeroMss));
        assert!(got.is_empty());
    }
}

// ---- test_split_len_size_max_rejected: the frag-count math must not wrap ----
#[test]
fn split_huge_mss_is_one() {
    let (r, got) = run(1, 0, &[0u8; 8], usize::MAX);
    assert_eq!(r, Ok(()));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, 8);
}

#[test]
fn split_slices_borrow_payload() {
    let payload = [0u8; 2500];
    let mut ptrs = Vec::new();
    split(1, 0, &payload, 1000, |_, p| ptrs.push(p.as_ptr())).unwrap();
    assert_eq!(ptrs[0], payload.as_ptr());
    assert_eq!(ptrs[1], payload[1000..].as_ptr());
    assert_eq!(ptrs[2], payload[2000..].as_ptr());
}
