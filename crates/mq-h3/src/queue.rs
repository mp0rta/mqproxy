// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Outer event queue (adoption spec §4.1): level events coalesce, stale ones drop on pop.

use mq_transport_api::{Event, SlotId};
use std::collections::{HashSet, VecDeque};
use std::mem::{Discriminant, discriminant};

#[derive(Default)]
pub(crate) struct OutQueue {
    q: VecDeque<Event>,
    /// The level events in `q`, as flags (the bare transport's slot flags).
    level: HashSet<(Discriminant<Event>, SlotId)>,
}

/// A level event's flag: its kind and object.
fn level(e: &Event) -> Option<(Discriminant<Event>, SlotId)> {
    let slot = match *e {
        Event::StreamReadable(s) | Event::StreamWritable(s) => s.slot(),
        Event::DatagramReadable(c) | Event::MpReady(c) => c.slot(),
        Event::H3Readable(r) | Event::H3Writable(r) => r.slot(),
        _ => return None,
    };
    Some((discriminant(e), slot))
}

/// Close events are the last word on an id and are never dropped (adoption spec §4.1).
fn is_close(e: &Event) -> bool {
    matches!(
        e,
        Event::StreamClosed(_)
            | Event::StreamCloseStats(..)
            | Event::H3Closed(..)
            | Event::ConnClosed(..)
    )
}

impl OutQueue {
    /// A level event already queued is not queued twice.
    pub(crate) fn push(&mut self, e: Event) {
        if let Some(f) = level(&e)
            && !self.level.insert(f)
        {
            return;
        }
        self.q.push_back(e);
    }

    /// The next event that is a close event or that `live` accepts.
    pub(crate) fn pop(&mut self, live: impl Fn(&Event) -> bool) -> Option<Event> {
        while let Some(e) = self.q.pop_front() {
            if let Some(f) = level(&e) {
                self.level.remove(&f);
            }
            if is_close(&e) || live(&e) {
                return Some(e);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_transport_api::{CloseReason, ConnId, ConnProto, ErrType, H3ReqId, SlotId, StreamId};

    fn s(i: u32) -> StreamId {
        StreamId::from_slot(SlotId::new(i, 1)).unwrap()
    }
    fn c(i: u32) -> ConnId {
        ConnId::from_slot(SlotId::new(i, 1)).unwrap()
    }

    #[test]
    fn level_events_coalesce() {
        let mut q = OutQueue::default();
        q.push(Event::StreamReadable(s(1)));
        q.push(Event::StreamReadable(s(1)));
        q.push(Event::StreamReadable(s(2)));
        assert_eq!(q.pop(|_| true), Some(Event::StreamReadable(s(1))));
        assert_eq!(q.pop(|_| true), Some(Event::StreamReadable(s(2))));
        assert_eq!(q.pop(|_| true), None);
        // After the pop the flag is clear again.
        q.push(Event::StreamReadable(s(1)));
        assert_eq!(q.pop(|_| true), Some(Event::StreamReadable(s(1))));
    }

    #[test]
    fn close_events_never_dropped() {
        let mut q = OutQueue::default();
        let r = H3ReqId::from_slot(SlotId::new(3, 1)).unwrap();
        let reason = CloseReason {
            err_type: ErrType::Unknown,
            code: 0,
        };
        q.push(Event::StreamClosed(s(1)));
        q.push(Event::ConnClosed(c(1), reason));
        q.push(Event::StreamReadable(s(1)));
        q.push(Event::StreamWritable(s(1)));
        q.push(Event::NewConn(c(2), ConnProto::H3));
        q.push(Event::H3Readable(r));
        assert_eq!(q.pop(|_| false), Some(Event::StreamClosed(s(1))));
        assert_eq!(q.pop(|_| false), Some(Event::ConnClosed(c(1), reason)));
        assert_eq!(q.pop(|_| false), None);
    }

    #[test]
    fn order_is_fifo_otherwise() {
        let mut q = OutQueue::default();
        q.push(Event::StreamWritable(s(2)));
        q.push(Event::StreamReadable(s(1)));
        q.push(Event::StreamClosed(s(3)));
        q.push(Event::StreamWritable(s(1)));
        let got: Vec<_> = std::iter::from_fn(|| q.pop(|_| true)).collect();
        assert_eq!(
            got,
            vec![
                Event::StreamWritable(s(2)),
                Event::StreamReadable(s(1)),
                Event::StreamClosed(s(3)),
                Event::StreamWritable(s(1)),
            ]
        );
    }
}
