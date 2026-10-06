//! Generational slot tables (spec §4.8): ids handed across the FFI boundary are
//! `(index, generation)`; a stale id never resolves to a reused slot.

use mq_transport_api::ringbuf::RingBuf;
use mq_transport_api::{ConnProto, SlotId, StreamKind, Time};
use xquic_sys::{xqc_cid_t, xqc_connection_t, xqc_stream_t};

pub(crate) struct Slots<T> {
    entries: Vec<Entry<T>>,
    free: Vec<u32>,
}

struct Entry<T> {
    generation: u32, // starts at 1; 0 is never a live generation
    value: Option<T>,
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Slots<T> {
    pub fn insert(&mut self, v: T) -> SlotId {
        if let Some(i) = self.free.pop() {
            let e = &mut self.entries[i as usize];
            e.value = Some(v);
            return SlotId::new(i, e.generation);
        }
        self.entries.push(Entry {
            generation: 1,
            value: Some(v),
        });
        SlotId::new((self.entries.len() - 1) as u32, 1)
    }
    pub fn get(&self, id: SlotId) -> Option<&T> {
        self.entries
            .get(id.index() as usize)
            .filter(|e| e.generation == id.generation())
            .and_then(|e| e.value.as_ref())
    }
    pub fn get_mut(&mut self, id: SlotId) -> Option<&mut T> {
        self.entries
            .get_mut(id.index() as usize)
            .filter(|e| e.generation == id.generation())
            .and_then(|e| e.value.as_mut())
    }
    pub fn remove(&mut self, id: SlotId) -> Option<T> {
        let e = self.entries.get_mut(id.index() as usize)?;
        if e.generation != id.generation() {
            return None;
        }
        let v = e.value.take()?;
        e.generation = e.generation.wrapping_add(1);
        if e.generation == 0 {
            e.generation = 1;
        }
        self.free.push(id.index());
        Some(v)
    }
    pub fn is_live(&self, id: SlotId) -> bool {
        self.get(id).is_some()
    }
    pub fn iter_live(&self) -> impl Iterator<Item = (SlotId, &T)> {
        self.entries.iter().enumerate().filter_map(|(i, e)| {
            e.value
                .as_ref()
                .map(|v| (SlotId::new(i as u32, e.generation), v))
        })
    }
    #[cfg(test)]
    pub fn len_live(&self) -> usize {
        self.entries.len() - self.free.len()
    }
}

pub(crate) struct ConnSlot {
    pub xqc: *mut xqc_connection_t,
    pub cid: xqc_cid_t,
    pub counted: bool,
    pub server: bool,
    /// Set by the create notification (spec §3.2).
    pub proto: ConnProto,
    /// Counted in `n_provisional` while true; cleared only by a successful ALPN admission (spec §4.7).
    pub provisional: bool,
    /// Scheduling input for `next_timeout()`; cleared when the deadline closes the connection.
    pub provisional_deadline: Option<Time>,
    pub streams: u32,
    /// The app authenticated its peer (`mark_conn_authed`): never an eviction victim (spec §4.7).
    pub authed: bool,
    /// Picked as an eviction victim; still counted until its close notification (spec §4.7).
    pub evicting: bool,
    /// Admission order, for picking the oldest victim (spec §4.7).
    pub admitted: u64,
    pub pending_close: Option<u64>,
    /// We closed it before any peer CONNECTION_CLOSE arrived: its `ConnClosed` reports
    /// `ErrType::Unknown` even if the peer echoes a close back (spec §4.2).
    pub closed_locally: bool,
    pub mp_ready_queued: bool,
    /// Received datagrams, `u16 len (LE) || bytes` each; allocated on the first (SP2 spec §3.2).
    pub dgram_rx: Option<RingBuf>,
    pub dgram_readable_queued: bool,
    /// Datagrams dropped: ring full, or a `datagram_recv` buffer too short (SP2 spec §3.1).
    pub dgram_rx_dropped: u64,
}

impl ConnSlot {
    pub fn new(server: bool, xqc: *mut xqc_connection_t, cid: xqc_cid_t) -> Self {
        Self {
            xqc,
            cid,
            counted: false,
            server,
            proto: ConnProto::Raw,
            provisional: false,
            provisional_deadline: None,
            streams: 0,
            authed: false,
            evicting: false,
            admitted: 0,
            pending_close: None,
            closed_locally: false,
            mp_ready_queued: false,
            dgram_rx: None,
            dgram_readable_queued: false,
            dgram_rx_dropped: 0,
        }
    }
}

pub(crate) struct StreamSlot {
    pub xqc: *mut xqc_stream_t,
    pub conn: SlotId,
    pub quic_id: u64,
    pub kind: StreamKind,
    pub readable_queued: bool,
    pub writable_queued: bool,
    pub fin_seen: bool,
    pub abandoned: bool,
    /// `StreamPeerReset` / `StreamStopSending` already queued: xquic notifies on every
    /// (retransmitted) frame, the events are one-shot (adoption spec §3).
    pub peer_reset_reported: bool,
    pub stop_sending_reported: bool,
}

impl StreamSlot {
    pub fn new(conn: SlotId, xqc: *mut xqc_stream_t, quic_id: u64, kind: StreamKind) -> Self {
        Self {
            xqc,
            conn,
            quic_id,
            kind,
            readable_queued: false,
            writable_queued: false,
            fin_seen: false,
            abandoned: false,
            peer_reset_reported: false,
            stop_sending_reported: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_never_zero() {
        let mut s = Slots::default();
        let id = s.insert(1u8);
        assert_ne!(id.as_raw(), 0);
        assert_ne!(id.generation(), 0);
        // generation wrap skips 0
        let mut s = Slots::default();
        let id = s.insert(0u8);
        s.entries[id.index() as usize].generation = u32::MAX;
        let id = SlotId::new(id.index(), u32::MAX);
        assert_eq!(s.remove(id), Some(0));
        let id2 = s.insert(1u8);
        assert_eq!(id2.generation(), 1);
    }

    #[test]
    fn stale_after_remove() {
        let mut s = Slots::default();
        let id = s.insert("a");
        assert!(s.is_live(id));
        assert_eq!(s.remove(id), Some("a"));
        assert!(!s.is_live(id));
        assert!(s.get(id).is_none());
        assert!(s.get_mut(id).is_none());
    }

    #[test]
    fn reuse_bumps_generation() {
        let mut s = Slots::default();
        let a = s.insert(1);
        s.remove(a);
        let b = s.insert(2);
        assert_eq!(a.index(), b.index());
        assert_eq!(b.generation(), a.generation() + 1);
        assert!(s.get(a).is_none());
        assert_eq!(s.get(b), Some(&2));
    }

    #[test]
    fn remove_twice_is_none() {
        let mut s = Slots::default();
        let id = s.insert(1);
        assert_eq!(s.remove(id), Some(1));
        assert_eq!(s.remove(id), None);
    }

    #[test]
    fn get_with_wrong_generation_is_none() {
        let mut s = Slots::default();
        let id = s.insert(1);
        let bad = SlotId::new(id.index(), id.generation() + 1);
        assert!(s.get(bad).is_none());
        assert!(s.get_mut(bad).is_none());
        assert_eq!(s.remove(bad), None);
        assert_eq!(s.get(id), Some(&1));
        assert!(s.get(SlotId::NONE).is_none());
    }

    #[test]
    fn iter_live_skips_removed_in_index_order() {
        let mut s = Slots::default();
        let a = s.insert(10);
        let b = s.insert(20);
        let c = s.insert(30);
        s.remove(b);
        let got: Vec<_> = s.iter_live().map(|(i, v)| (i, *v)).collect();
        assert_eq!(got, vec![(a, 10), (c, 30)]);
    }
}
