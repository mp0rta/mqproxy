// spec §2.3; ports tests/test_varint.c
use mq_wire::varint::{Error, MAX, decode, encode, len};
use proptest::prelude::*;

fn roundtrip(v: u64, expect_len: usize) {
    let mut buf = [0u8; 8];
    let n = encode(&mut buf, v).unwrap();
    assert_eq!(n, expect_len);
    assert_eq!(decode(&buf[..n]), Ok((v, expect_len)));
}

#[test]
fn roundtrip_boundaries() {
    roundtrip(0, 1);
    roundtrip(63, 1);
    roundtrip(64, 2);
    roundtrip(16383, 2);
    roundtrip(16384, 4);
    roundtrip(1073741823, 4);
    roundtrip(1073741824, 8);
    roundtrip(MAX, 8);
}

#[test]
fn wire_vectors() {
    let mut buf = [0u8; 8];
    assert_eq!(encode(&mut buf, 37), Ok(1));
    assert_eq!(&buf[..1], &[0x25]);
    assert_eq!(encode(&mut buf, 15293), Ok(2));
    assert_eq!(&buf[..2], &[0x7B, 0xBD]);
    assert_eq!(encode(&mut buf, 494878333), Ok(4));
    assert_eq!(&buf[..4], &[0x9D, 0x7F, 0x3E, 0x7D]);
}

#[test]
fn len_boundaries() {
    assert_eq!(len(63), 1);
    assert_eq!(len(64), 2);
    assert_eq!(len(16384), 4);
    assert_eq!(len(1073741824), 8);
}

#[test]
fn short_buffers() {
    let mut buf = [0u8; 8];
    assert_eq!(encode(&mut buf[..0], 5), Err(Error::Short));
    assert_eq!(decode(&[]), Err(Error::Short));
    assert_eq!(decode(&[0x40]), Err(Error::Short));
}

#[test]
fn encode_rejects_value_above_62_bits() {
    let mut buf = [0u8; 8];
    assert_eq!(
        encode(&mut buf, 0x4000_0000_0000_0000),
        Err(Error::TooLarge)
    );
}

#[test]
fn decodes_non_minimal_encoding() {
    assert_eq!(decode(&[0x40, 0x05]), Ok((5, 2)));
}

#[test]
fn decode_rejects_truncated_prefix() {
    assert_eq!(decode(&[0x80, 0x00]), Err(Error::Short));
}

proptest! {
    #[test]
    fn proptest_roundtrip(v in 0..=MAX) {
        let mut buf = [0u8; 8];
        let n = encode(&mut buf, v).unwrap();
        prop_assert_eq!(n, len(v));
        prop_assert_eq!(decode(&buf[..n]), Ok((v, n)));
    }
}
