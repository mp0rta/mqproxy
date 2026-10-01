//! A one-way client→server stream transfer stepped from `Pair::pump_until`.

use super::pair::{Pair, new_streams, read_all, send};
use mq_transport_api::StreamId;
use std::time::Duration;

pub fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 131 + 3) as u8).collect()
}

pub struct Xfer {
    pub cs: StreamId,
    pub ss: Option<StreamId>,
    pub data: Vec<u8>,
    /// Bytes accepted by the client's `stream_send`.
    pub off: usize,
    /// Bytes the server has read.
    pub got: Vec<u8>,
    pub fin: bool,
    /// Bytes offered per `step` (64 KiB by default).
    pub chunk: usize,
    /// Server streams announced before this transfer started.
    seen: usize,
}

impl Xfer {
    pub fn start(p: &Pair, len: usize) -> Xfer {
        Xfer {
            cs: p.open(),
            ss: None,
            data: pattern(len),
            off: 0,
            got: Vec::new(),
            fin: false,
            chunk: 64 * 1024,
            seen: new_streams(&p.sev).len(),
        }
    }

    /// Offers the next `chunk` bytes (FIN with the last byte) and reads what the server has.
    pub fn step(&mut self, p: &Pair) {
        if self.off < self.data.len() {
            let end = self.data.len().min(self.off + self.chunk);
            let chunk = self.data[self.off..end].to_vec();
            if let Ok(n) = send(&p.client, p.now, self.cs, chunk, end == self.data.len()) {
                self.off += n;
            }
        }
        if self.ss.is_none() {
            self.ss = new_streams(&p.sev).get(self.seen).map(|x| x.0);
        }
        if let (Some(s), false) = (self.ss, self.fin) {
            let (b, f) = read_all(&p.server, p.now, s).expect("server read");
            self.got.extend(b);
            self.fin = f;
        }
    }

    /// Runs to the server's FIN and asserts the bytes arrived exactly once, in order.
    pub fn finish(&mut self, p: &mut Pair, dt: Duration, max_steps: usize) {
        let ok = p.pump_until(dt, max_steps, |p| {
            self.step(p);
            self.fin
        });
        assert!(
            ok,
            "transfer stalled at {} of {} bytes",
            self.got.len(),
            self.data.len()
        );
        assert_eq!(self.got.len(), self.data.len());
        assert!(self.got == self.data, "bytes differ");
    }
}
