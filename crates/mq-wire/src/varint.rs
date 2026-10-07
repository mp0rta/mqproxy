// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
// spec §2.3
pub const MAX: u64 = 0x3FFF_FFFF_FFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Short,
}

pub fn len(v: u64) -> usize {
    if v <= 0x3F {
        1
    } else if v <= 0x3FFF {
        2
    } else if v <= 0x3FFF_FFFF {
        4
    } else {
        8
    }
}

pub fn encode(buf: &mut [u8], v: u64) -> Result<usize, Error> {
    if v > MAX {
        return Err(Error::TooLarge);
    }
    let n = len(v);
    if buf.len() < n {
        return Err(Error::Short);
    }
    let prefix = match n {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xC0,
    };
    buf[..n].copy_from_slice(&v.to_be_bytes()[8 - n..]);
    buf[0] = (buf[0] & 0x3F) | prefix;
    Ok(n)
}

pub fn decode(buf: &[u8]) -> Result<(u64, usize), Error> {
    let first = *buf.first().ok_or(Error::Short)?;
    let n = 1usize << (first >> 6);
    if buf.len() < n {
        return Err(Error::Short);
    }
    let mut v = u64::from(first & 0x3F);
    for b in &buf[1..n] {
        v = (v << 8) | u64::from(*b);
    }
    Ok((v, n))
}
