use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use mq_transport_api::{ConnId, Transmit, TxKey};

// spec §4.4. One drive can hand xquic's output for a path over 256 KiB at ~1 Gbps; each
// refusal below makes xquic retry on every wakeup, so the quota sits well above that.
// Queues grow on use, so an idle (conn, path) costs nothing.
pub const QUEUE_QUOTA: usize = 1024 * 1024;
pub const QUEUE_LOW: usize = 512 * 1024;
pub const TOTAL_HIGH: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    Quota,
    Total,
}

/// A conn may hold both reasons; it resumes when EITHER clears.
#[derive(Default)]
struct Blocked {
    quota_keys: Vec<TxKey>,
    total: bool,
}

struct Pkt {
    len: usize,
    dst: SocketAddr,
}

struct Queue {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    pkts: VecDeque<Pkt>,
    bytes: usize,
}

impl Queue {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            tail: 0,
            pkts: VecDeque::new(),
            bytes: 0,
        }
    }

    fn append(&mut self, dst: SocketAddr, pkt: &[u8]) {
        if self.tail + pkt.len() > self.buf.capacity() {
            self.compact(); // memmove only here; the extend below grows the buffer if still short
        }
        self.buf.truncate(self.tail);
        self.buf.extend_from_slice(pkt);
        self.tail += pkt.len();
        self.pkts.push_back(Pkt {
            len: pkt.len(),
            dst,
        });
        self.bytes += pkt.len();
    }

    fn compact(&mut self) {
        self.buf.copy_within(self.head..self.tail, 0);
        self.tail -= self.head;
        self.head = 0;
    }

    /// A run from the head: same dst and same len, at most 64 packets; a packet SHORTER than the first
    /// is included as the last one and ends the run; a LONGER one or another dst ends the run before it.
    fn peek(&self) -> Option<Transmit<'_>> {
        let first = self.pkts.front()?;
        let mut bytes = 0;
        for (i, p) in self.pkts.iter().enumerate() {
            if i == 64 || p.dst != first.dst || p.len > first.len {
                break;
            }
            bytes += p.len;
            if p.len < first.len {
                break;
            }
        }
        Some(Transmit {
            dst: first.dst,
            segment_size: first.len,
            payload: &self.buf[self.head..self.head + bytes],
        })
    }

    fn done(&mut self, datagrams: usize) -> usize {
        let mut freed = 0;
        for _ in 0..datagrams {
            let p = self.pkts.pop_front().unwrap();
            self.head += p.len;
            freed += p.len;
        }
        self.bytes -= freed;
        if self.pkts.is_empty() {
            self.head = 0;
            self.tail = 0;
        }
        freed
    }
}

#[derive(Default)]
pub struct TxQueues {
    queues: HashMap<TxKey, Queue>,
    total: usize,
    blocked: HashMap<ConnId, Blocked>,
    resumable: Vec<ConnId>,
}

impl TxQueues {
    pub fn push(&mut self, key: TxKey, dst: SocketAddr, pkt: &[u8]) -> Result<(), Refusal> {
        let q = self.queues.entry(key).or_insert_with(Queue::new);
        if q.bytes + pkt.len() > QUEUE_QUOTA {
            return Err(Refusal::Quota);
        }
        if self.total + pkt.len() > TOTAL_HIGH {
            return Err(Refusal::Total);
        }
        q.append(dst, pkt);
        self.total += pkt.len();
        Ok(())
    }

    pub fn push_or_drop(&mut self, key: TxKey, dst: SocketAddr, pkt: &[u8]) {
        let _ = self.push(key, dst, pkt);
    }

    pub fn record_blocked(&mut self, conn: ConnId, key: TxKey, why: Refusal) {
        let b = self.blocked.entry(conn).or_default();
        match why {
            Refusal::Quota => {
                if !b.quota_keys.contains(&key) {
                    b.quota_keys.push(key)
                }
            }
            Refusal::Total => b.total = true,
        }
    }

    pub fn keys(&self, out: &mut Vec<TxKey>) {
        out.extend(
            self.queues
                .iter()
                .filter(|(_, q)| q.bytes > 0)
                .map(|(k, _)| *k),
        );
    }

    pub fn peek(&self, key: TxKey) -> Option<Transmit<'_>> {
        self.queues.get(&key)?.peek()
    }

    pub fn done(&mut self, key: TxKey, datagrams: usize) {
        let freed = self
            .queues
            .get_mut(&key)
            .map(|q| q.done(datagrams))
            .unwrap_or(0);
        self.total -= freed;
        self.resumption_pass(Some(key));
    }

    pub fn drop_conn(&mut self, conn: ConnId) {
        let keys: Vec<TxKey> = self
            .queues
            .keys()
            .filter(|k| k.0 == Some(conn))
            .copied()
            .collect();
        for k in keys {
            let q = self.queues.remove(&k).unwrap();
            self.total -= q.bytes;
        }
        self.blocked.remove(&conn);
        self.resumable.retain(|c| *c != conn);
        self.resumption_pass(None);
    }

    /// Quota reason: the key's queue is below QUEUE_LOW. Total reason: total < TOTAL_HIGH. Either clears the whole entry.
    fn resumption_pass(&mut self, key: Option<TxKey>) {
        let mut ready = Vec::new();
        let (queues, total) = (&self.queues, self.total);
        for (conn, b) in &self.blocked {
            let quota_ok = key.is_some_and(|k| {
                b.quota_keys.contains(&k) && queues.get(&k).is_none_or(|q| q.bytes < QUEUE_LOW)
            });
            let total_ok = b.total && total < TOTAL_HIGH;
            if quota_ok || total_ok {
                ready.push(*conn);
            }
        }
        for c in ready {
            self.blocked.remove(&c);
            if !self.resumable.contains(&c) {
                self.resumable.push(c);
            }
        }
    }

    pub fn take_resumable(&mut self) -> Vec<ConnId> {
        std::mem::take(&mut self.resumable)
    }

    pub fn resume_pending(&self) -> bool {
        !self.resumable.is_empty()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn blocked_conns(&self) -> Vec<ConnId> {
        self.blocked.keys().copied().collect()
    }

    #[cfg(feature = "test-support")]
    pub fn queued_bytes(&self, key: TxKey) -> usize {
        self.queues.get(&key).map_or(0, |q| q.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_transport_api::{PathId, SlotId};

    fn conn(i: u32) -> ConnId {
        ConnId::from_slot(SlotId::new(i, 1)).unwrap()
    }
    fn key(i: u32) -> TxKey {
        (Some(conn(i)), PathId(0))
    }
    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 4433))
    }
    /// Keys that fill to exactly TOTAL_HIGH; key(N) is the next one.
    const N: u32 = (TOTAL_HIGH / QUEUE_QUOTA) as u32;
    /// 1024-byte packets to drain a full queue to exactly QUEUE_LOW.
    const TO_LOW: usize = (QUEUE_QUOTA - QUEUE_LOW) / 1024;

    /// Fill `k` to exactly QUEUE_QUOTA with 1024-byte packets.
    fn fill(t: &mut TxQueues, k: TxKey) {
        for _ in 0..QUEUE_QUOTA / 1024 {
            t.push(k, addr(1), &[0u8; 1024]).unwrap();
        }
    }

    #[test]
    fn peek_groups_equal_size_runs_and_includes_one_shorter_tail() {
        let mut t = TxQueues::default();
        let k = key(0);
        for len in [1200, 1200, 1200, 900, 1200] {
            t.push(k, addr(1), &vec![7u8; len]).unwrap();
        }
        let tx = t.peek(k).unwrap();
        assert_eq!((tx.segment_size, tx.payload.len()), (1200, 4500));
        t.done(k, 4);
        let tx = t.peek(k).unwrap();
        assert_eq!((tx.segment_size, tx.payload.len()), (1200, 1200));
    }

    #[test]
    fn peek_stops_at_dst_change() {
        let mut t = TxQueues::default();
        let k = key(0);
        t.push(k, addr(1), &[0; 1200]).unwrap();
        t.push(k, addr(2), &[0; 1200]).unwrap();
        t.push(k, addr(1), &[0; 1300]).unwrap();
        let tx = t.peek(k).unwrap();
        assert_eq!((tx.dst, tx.payload.len()), (addr(1), 1200));
    }

    #[test]
    fn peek_stops_before_longer_packet() {
        let mut t = TxQueues::default();
        let k = key(0);
        t.push(k, addr(1), &[0; 1200]).unwrap();
        t.push(k, addr(1), &[0; 1300]).unwrap();
        assert_eq!(t.peek(k).unwrap().payload.len(), 1200);
    }

    #[test]
    fn peek_stops_at_64() {
        let mut t = TxQueues::default();
        let k = key(0);
        for _ in 0..70 {
            t.push(k, addr(1), &[0; 100]).unwrap();
        }
        assert_eq!(t.peek(k).unwrap().payload.len(), 64 * 100);
    }

    #[test]
    fn done_advances_head_without_copy() {
        let mut t = TxQueues::default();
        let k = key(0);
        for _ in 0..3 {
            t.push(k, addr(1), &[1; 500]).unwrap();
        }
        let before = t.queues[&k].buf.as_ptr();
        t.done(k, 2);
        let q = &t.queues[&k];
        assert_eq!(q.buf.as_ptr(), before);
        assert_eq!((q.head, q.bytes, t.total), (1000, 500, 500));
        t.done(k, 1);
        let q = &t.queues[&k];
        assert_eq!((q.head, q.tail, q.bytes, t.total), (0, 0, 0, 0));
    }

    #[test]
    fn fresh_queue_reserves_nothing_and_grows_with_use() {
        let mut q = Queue::new();
        assert_eq!(q.buf.capacity(), 0);
        q.append(addr(1), &[0; 1200]);
        assert!((1200..QUEUE_QUOTA).contains(&q.buf.capacity()));
    }

    #[test]
    fn compaction_only_when_capacity_reached() {
        let mut q = Queue::new();
        q.buf.reserve_exact(64 * 1024);
        let cap = q.buf.capacity();
        let p = [9u8; 1000];
        while q.tail + 1000 * 2 <= cap {
            q.append(addr(1), &p);
        }
        q.done(1);
        assert_eq!(q.head, 1000);
        q.append(addr(1), &p); // still fits: no compaction
        assert_eq!(q.head, 1000);
        assert!(q.tail + 1000 > cap);
        q.append(addr(1), &p); // would overflow: compacts
        assert_eq!(q.head, 0);
        assert_eq!(q.buf.capacity(), cap);
        assert_eq!(q.tail, q.bytes);
    }

    #[test]
    fn quota_refuses_one_key_only() {
        let mut t = TxQueues::default();
        fill(&mut t, key(0));
        assert_eq!(t.push(key(0), addr(1), &[0; 1]), Err(Refusal::Quota));
        assert_eq!(t.push(key(1), addr(1), &[0; 1]), Ok(()));
        assert_eq!(t.push((Some(conn(0)), PathId(1)), addr(1), &[0; 1]), Ok(()));
    }

    #[test]
    fn quota_resumes_when_that_key_drains_below_low() {
        let mut t = TxQueues::default();
        let k = key(0);
        fill(&mut t, k);
        t.record_blocked(conn(0), k, Refusal::Quota);
        t.done(k, TO_LOW); // exactly at QUEUE_LOW: not below
        assert!(!t.resume_pending());
        t.done(k, 1);
        assert!(t.resume_pending());
        assert_eq!(t.take_resumable(), vec![conn(0)]);
        assert!(!t.resume_pending());
    }

    #[test]
    fn total_refuses_at_high_water() {
        let mut t = TxQueues::default();
        for i in 0..N {
            fill(&mut t, key(i));
        }
        assert_eq!(t.total, TOTAL_HIGH);
        assert_eq!(t.push(key(N), addr(1), &[0; 1]), Err(Refusal::Total));
    }

    #[test]
    fn total_resumes_on_any_commit_below_high_even_with_two_keys_at_quota() {
        let mut t = TxQueues::default();
        for i in 0..N {
            fill(&mut t, key(i));
        }
        t.record_blocked(conn(0), key(0), Refusal::Quota);
        t.record_blocked(conn(1), key(1), Refusal::Quota);
        t.record_blocked(conn(N), key(N), Refusal::Total);
        t.done(key(3), 1); // unrelated key; total now below high
        assert_eq!(t.take_resumable(), vec![conn(N)]);
        assert!(t.blocked.contains_key(&conn(0)) && t.blocked.contains_key(&conn(1)));
    }

    #[test]
    fn blocked_for_both_reasons_resumes_when_either_clears() {
        let mut t = TxQueues::default();
        fill(&mut t, key(0));
        fill(&mut t, key(1));
        // blocked on two quota keys: draining only A resumes it
        t.record_blocked(conn(0), key(0), Refusal::Quota);
        t.record_blocked(conn(0), key(1), Refusal::Quota);
        t.done(key(0), TO_LOW + 1);
        assert_eq!(t.take_resumable(), vec![conn(0)]);
        assert!(!t.blocked.contains_key(&conn(0)));
        // quota + total: a commit below high-water clears via total while the quota key stays full
        t.record_blocked(conn(1), key(1), Refusal::Quota);
        t.record_blocked(conn(1), key(1), Refusal::Total);
        t.done(key(0), 1);
        assert_eq!(t.take_resumable(), vec![conn(1)]);
        assert!(t.blocked.is_empty());
    }

    #[test]
    fn push_or_drop_never_fails() {
        let mut t = TxQueues::default();
        fill(&mut t, key(0));
        t.push_or_drop(key(0), addr(1), &[0; 1]);
        assert_eq!(t.queues[&key(0)].bytes, QUEUE_QUOTA);
        t.push_or_drop(key(1), addr(1), &[0; 10]);
        assert_eq!(t.queues[&key(1)].bytes, 10);
    }

    #[test]
    fn drop_conn_counts_as_commit_and_forgets_block() {
        let mut t = TxQueues::default();
        for i in 0..N {
            fill(&mut t, key(i));
        }
        t.push_or_drop((Some(conn(0)), PathId(1)), addr(1), &[0; 1]);
        t.record_blocked(conn(0), key(0), Refusal::Quota);
        t.record_blocked(conn(N), key(N), Refusal::Total);
        t.drop_conn(conn(0));
        assert_eq!(t.total, (N as usize - 1) * QUEUE_QUOTA);
        assert!(t.queues.keys().all(|k| k.0 != Some(conn(0))));
        assert!(!t.blocked.contains_key(&conn(0)));
        assert_eq!(t.take_resumable(), vec![conn(N)]);
    }

    #[test]
    fn resumable_dedup() {
        let mut t = TxQueues::default();
        let k = key(0);
        t.push(k, addr(1), &[0; 10]).unwrap();
        t.push(k, addr(1), &[0; 10]).unwrap();
        t.record_blocked(conn(0), k, Refusal::Total);
        t.done(k, 1);
        t.record_blocked(conn(0), k, Refusal::Total); // blocked again before drive() took it
        t.done(k, 1);
        assert_eq!(t.take_resumable(), vec![conn(0)]);
    }
}
