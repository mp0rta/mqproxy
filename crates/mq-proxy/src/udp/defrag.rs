//! spec §2.3: 4-slot LRU datagram defragmenter.

use mq_wire::udp_msg::UdpMsgHdr;

const SLOTS: usize = 4;
/// Largest reassembled packet.
const MAX_TOTAL: usize = 65_535;

#[derive(PartialEq, Eq, Debug)]
pub enum Feed {
    Complete(Vec<u8>),
    Pending,
    Rejected,
}

struct Slot {
    packet_id: u16,
    /// One entry per expected fragment; `Some` once received.
    frags: Vec<Option<Vec<u8>>>,
    received: usize,
    total_len: usize,
    /// LRU recency: the `Defrag::seq` of the last feed that touched the slot.
    seq: u64,
}

/// `session_id` and `flags` of the header are ignored. Slots appear with the
/// first multi-fragment packet, so an unfragmented session never allocates.
#[derive(Default)]
pub struct Defrag {
    slots: Vec<Slot>,
    seq: u64,
}

impl Defrag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, h: &UdpMsgHdr, bytes: &[u8]) -> Feed {
        if h.frag_count == 0 || h.frag_id >= h.frag_count {
            return Feed::Rejected;
        }
        if h.frag_count == 1 {
            return Feed::Complete(bytes.to_vec());
        }

        self.seq += 1;
        let i = match self.slots.iter().position(|s| s.packet_id == h.packet_id) {
            Some(i) => {
                if self.slots[i].frags.len() != usize::from(h.frag_count) {
                    self.slots.swap_remove(i);
                    return Feed::Rejected;
                }
                self.slots[i].seq = self.seq;
                i
            }
            None => {
                let s = Slot {
                    packet_id: h.packet_id,
                    frags: vec![None; usize::from(h.frag_count)],
                    received: 0,
                    total_len: 0,
                    seq: self.seq,
                };
                if self.slots.len() < SLOTS {
                    self.slots.push(s);
                    self.slots.len() - 1
                } else {
                    let lru = (0..SLOTS).min_by_key(|&i| self.slots[i].seq).unwrap();
                    self.slots[lru] = s;
                    lru
                }
            }
        };
        let s = &mut self.slots[i];

        // Before the length check: a repeated fragment near the cap must not
        // destroy a valid assembly.
        if s.frags[usize::from(h.frag_id)].is_some() {
            return Feed::Pending;
        }
        if s.total_len + bytes.len() > MAX_TOTAL {
            self.slots.swap_remove(i);
            return Feed::Rejected;
        }

        s.frags[usize::from(h.frag_id)] = Some(bytes.to_vec());
        s.received += 1;
        s.total_len += bytes.len();
        if s.received < s.frags.len() {
            return Feed::Pending;
        }
        let s = self.slots.swap_remove(i);
        Feed::Complete(s.frags.into_iter().flatten().flatten().collect())
    }
}
