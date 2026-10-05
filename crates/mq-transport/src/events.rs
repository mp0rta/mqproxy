//! Coalescing event queue (spec §4.2 "Event coalescing").
//!
//! `StreamReadable`/`StreamWritable`/`MpReady`/`DatagramReadable`/`H3Readable`/`H3Writable` are
//! level flags: at most one is queued per object (tracked by the `*_queued` flag on the slot); lifecycle events never
//! coalesce.
//! Ids are invalidated inside notifications (spec §4.8), so a queued event may outlive its
//! slot; `pop` returns it as-is and the consumer drops stale ones.

use crate::slots::{ConnSlot, H3ReqSlot, Slots, StreamSlot};
use mq_transport_api::{ConnId, Event, H3ReqId, StreamId};
use std::collections::VecDeque;

#[derive(Default)]
pub(crate) struct Events {
    queue: VecDeque<Event>,
}

impl Events {
    /// spec §4.2: enqueue iff the slot is live, not abandoned and no readable is already queued.
    pub fn push_readable(&mut self, streams: &mut Slots<StreamSlot>, id: StreamId) {
        if let Some(s) = streams.get_mut(id.slot())
            && !s.abandoned
            && !s.readable_queued
        {
            s.readable_queued = true;
            self.queue.push_back(Event::StreamReadable(id));
        }
    }

    /// spec §4.2: as `push_readable`, with the writable flag.
    pub fn push_writable(&mut self, streams: &mut Slots<StreamSlot>, id: StreamId) {
        if let Some(s) = streams.get_mut(id.slot())
            && !s.abandoned
            && !s.writable_queued
        {
            s.writable_queued = true;
            self.queue.push_back(Event::StreamWritable(id));
        }
    }

    /// spec §4.2: enqueue iff the conn is live and no `MpReady` is already queued.
    pub fn push_mp_ready(&mut self, conns: &mut Slots<ConnSlot>, id: ConnId) {
        if let Some(c) = conns.get_mut(id.slot())
            && !c.mp_ready_queued
        {
            c.mp_ready_queued = true;
            self.queue.push_back(Event::MpReady(id));
        }
    }

    /// SP2 spec §3.1: as `push_mp_ready`, with the datagram-readable flag.
    pub fn push_datagram_readable(&mut self, conns: &mut Slots<ConnSlot>, id: ConnId) {
        if let Some(c) = conns.get_mut(id.slot())
            && !c.dgram_readable_queued
        {
            c.dgram_readable_queued = true;
            self.queue.push_back(Event::DatagramReadable(id));
        }
    }

    /// spec §3.4: enqueue iff the request is live and no `H3Readable` is already queued.
    pub fn push_h3_readable(&mut self, reqs: &mut Slots<H3ReqSlot>, id: H3ReqId) {
        if let Some(r) = reqs.get_mut(id.slot())
            && !r.readable_queued
        {
            r.readable_queued = true;
            self.queue.push_back(Event::H3Readable(id));
        }
    }

    /// spec §3.4: as `push_h3_readable`, with the writable flag.
    pub fn push_h3_writable(&mut self, reqs: &mut Slots<H3ReqSlot>, id: H3ReqId) {
        if let Some(r) = reqs.get_mut(id.slot())
            && !r.writable_queued
        {
            r.writable_queued = true;
            self.queue.push_back(Event::H3Writable(id));
        }
    }

    /// Lifecycle events: unconditional, never coalesced.
    pub fn push(&mut self, e: Event) {
        self.queue.push_back(e);
    }

    /// Clears the coalescing flag of the dequeued event (if its slot is still live). Events
    /// for released slots are returned as-is; the consumer drops stale ones (spec §4.8).
    pub fn pop(
        &mut self,
        streams: &mut Slots<StreamSlot>,
        conns: &mut Slots<ConnSlot>,
        reqs: &mut Slots<H3ReqSlot>,
    ) -> Option<Event> {
        let e = self.queue.pop_front()?;
        match &e {
            Event::StreamReadable(id) => {
                if let Some(s) = streams.get_mut(id.slot()) {
                    s.readable_queued = false;
                }
            }
            Event::StreamWritable(id) => {
                if let Some(s) = streams.get_mut(id.slot()) {
                    s.writable_queued = false;
                }
            }
            Event::MpReady(id) => {
                if let Some(c) = conns.get_mut(id.slot()) {
                    c.mp_ready_queued = false;
                }
            }
            Event::DatagramReadable(id) => {
                if let Some(c) = conns.get_mut(id.slot()) {
                    c.dgram_readable_queued = false;
                }
            }
            Event::H3Readable(id) => {
                if let Some(r) = reqs.get_mut(id.slot()) {
                    r.readable_queued = false;
                }
            }
            Event::H3Writable(id) => {
                if let Some(r) = reqs.get_mut(id.slot()) {
                    r.writable_queued = false;
                }
            }
            // Never coalesced. Listed, not wildcarded: a new level flag must clear here.
            Event::ConnEstablished(_)
            | Event::ConnClosed(..)
            | Event::NewConn(..)
            | Event::NewStream(..)
            | Event::StreamClosed(_)
            | Event::StreamPeerReset(..)
            | Event::StreamStopSending(..)
            | Event::PathRemoved(..)
            | Event::H3Request(..)
            | Event::H3Closed(..) => {}
        }
        Some(e)
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_transport_api::{CloseReason, ErrType, StreamKind};

    fn stream(abandoned: bool) -> StreamSlot {
        StreamSlot {
            xqc: std::ptr::null_mut(),
            conn: mq_transport_api::SlotId::new(0, 1),
            quic_id: 0,
            kind: StreamKind::Bidi,
            readable_queued: false,
            writable_queued: false,
            fin_seen: false,
            abandoned,
            peer_reset_reported: false,
            stop_sending_reported: false,
        }
    }

    fn conn() -> ConnSlot {
        // SAFETY: the cid is a POD C struct; all-zero is valid.
        ConnSlot::new(false, std::ptr::null_mut(), unsafe { std::mem::zeroed() })
    }

    fn sid(streams: &mut Slots<StreamSlot>, abandoned: bool) -> StreamId {
        StreamId::from_slot(streams.insert(stream(abandoned))).unwrap()
    }

    #[test]
    fn readable_coalesced_until_popped() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let id = sid(&mut st, false);
        ev.push_readable(&mut st, id);
        ev.push_readable(&mut st, id);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::StreamReadable(id))
        );
        assert!(ev.is_empty());
        ev.push_readable(&mut st, id);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn writable_coalesced() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let id = sid(&mut st, false);
        ev.push_writable(&mut st, id);
        ev.push_writable(&mut st, id);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::StreamWritable(id))
        );
        ev.push_writable(&mut st, id);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn mp_ready_coalesced() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let id = ConnId::from_slot(cs.insert(conn())).unwrap();
        ev.push_mp_ready(&mut cs, id);
        ev.push_mp_ready(&mut cs, id);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev.pop(&mut st, &mut cs, &mut rs), Some(Event::MpReady(id)));
        ev.push_mp_ready(&mut cs, id);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn datagram_readable_coalesced() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let id = ConnId::from_slot(cs.insert(conn())).unwrap();
        ev.push_datagram_readable(&mut cs, id);
        ev.push_datagram_readable(&mut cs, id);
        assert_eq!(ev.len(), 1);
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::DatagramReadable(id))
        );
        ev.push_datagram_readable(&mut cs, id);
        assert_eq!(ev.len(), 1);
    }

    #[test]
    fn h3_readable_and_writable_coalesced() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let c = mq_transport_api::SlotId::new(0, 1);
        let id = H3ReqId::from_slot(rs.insert(H3ReqSlot::new(c, std::ptr::null_mut(), 0))).unwrap();
        ev.push_h3_readable(&mut rs, id);
        ev.push_h3_writable(&mut rs, id);
        ev.push_h3_readable(&mut rs, id);
        ev.push_h3_writable(&mut rs, id);
        assert_eq!(ev.len(), 2);
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::H3Readable(id))
        );
        ev.push_h3_readable(&mut rs, id);
        ev.push_h3_writable(&mut rs, id);
        assert_eq!(ev.len(), 2, "readable re-queued, writable still pending");
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::H3Writable(id))
        );
        rs.remove(id.slot());
        ev.push_h3_writable(&mut rs, id);
        assert_eq!(ev.len(), 1, "nothing queued for a released request");
    }

    #[test]
    fn lifecycle_not_coalesced() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let c = ConnId::from_slot(cs.insert(conn())).unwrap();
        let r = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        ev.push(Event::ConnEstablished(c));
        ev.push(Event::ConnEstablished(c));
        ev.push(Event::ConnClosed(c, r));
        assert_eq!(ev.len(), 3);
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::ConnEstablished(c))
        );
    }

    #[test]
    fn abandoned_slot_gets_no_readable_or_writable() {
        let (mut st, mut ev) = (Slots::default(), Events::default());
        let id = sid(&mut st, true);
        ev.push_readable(&mut st, id);
        ev.push_writable(&mut st, id);
        assert!(ev.is_empty());
    }

    #[test]
    fn pop_after_slot_release_returns_owned_event() {
        let (mut st, mut cs, mut rs, mut ev) = (
            Slots::default(),
            Slots::default(),
            Slots::default(),
            Events::default(),
        );
        let id = sid(&mut st, false);
        ev.push_readable(&mut st, id);
        st.remove(id.slot());
        assert_eq!(
            ev.pop(&mut st, &mut cs, &mut rs),
            Some(Event::StreamReadable(id))
        );
    }
}
