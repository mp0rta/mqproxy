// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The relay's byte buffer (SP0/SP1 spec §5.6), also the transport's datagram receive ring
//! (SP2 spec §3.2).
//!
//! Linear, not wrapping: `space()` is the tail room after the write cursor, and
//! both cursors return to 0 when everything written has been consumed.

#[derive(Debug)]
pub struct RingBuf {
    data: Box<[u8]>,
    r: usize,
    w: usize,
}

impl RingBuf {
    pub fn new(cap: usize) -> RingBuf {
        RingBuf {
            data: vec![0; cap].into_boxed_slice(),
            r: 0,
            w: 0,
        }
    }
    pub fn capacity(&self) -> usize {
        self.data.len()
    }
    pub fn len(&self) -> usize {
        self.w - self.r
    }
    pub fn is_empty(&self) -> bool {
        self.r == self.w
    }
    /// Tail room after the write cursor.
    pub fn space(&self) -> usize {
        self.data.len() - self.w
    }
    pub fn write_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.w..]
    }
    pub fn commit(&mut self, n: usize) {
        assert!(n <= self.space(), "commit past capacity");
        self.w += n;
    }
    pub fn read_slice(&self) -> &[u8] {
        &self.data[self.r..self.w]
    }
    /// Compacts (both cursors to 0) once everything is consumed.
    pub fn consume(&mut self, n: usize) {
        assert!(n <= self.len(), "consume past length");
        self.r += n;
        if self.r == self.w {
            self.r = 0;
            self.w = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: usize = 64 * 1024;

    fn src() -> Vec<u8> {
        (1..=100).collect()
    }
    fn written() -> RingBuf {
        let mut b = RingBuf::new(CAP);
        b.write_slice()[..100].copy_from_slice(&src());
        b.commit(100);
        b
    }

    #[test]
    fn fresh_buf() {
        let b = RingBuf::new(CAP);
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
        assert_eq!(b.space(), 65536);
        assert_eq!(b.capacity(), 65536);
    }

    #[test]
    fn write_and_read() {
        let b = written();
        assert_eq!(b.len(), 100);
        assert_eq!(b.space(), 65436);
        assert_eq!(b.read_slice(), &src()[..]);
    }

    #[test]
    fn consume_partial() {
        let mut b = written();
        b.consume(40);
        assert_eq!(b.len(), 60);
        assert_eq!(b.space(), 65436); // tail space, no compaction
        assert_eq!(b.read_slice(), &src()[40..]);
    }

    #[test]
    fn consume_all_compacts() {
        let mut b = written();
        b.consume(40);
        b.consume(60);
        assert_eq!(b.len(), 0);
        assert_eq!(b.space(), 65536);
    }

    #[test]
    fn fill_to_capacity() {
        let mut b = RingBuf::new(CAP);
        b.commit(65536);
        assert_eq!(b.len(), 65536);
        assert_eq!(b.space(), 0);
        assert!(b.write_slice().is_empty());
        b.consume(65536);
        assert_eq!(b.len(), 0);
        assert_eq!(b.space(), 65536);
    }
}
