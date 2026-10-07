// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Shard-allocated generational ids (spec §5.2 "Identities").
//!
//! Same shape as `mq_transport_api::ConnId`: `{ index, generation }` with a
//! never-zero generation, convertible to and from the api crate's packed
//! `SlotId`, so a generic slot table can hand them out.

use mq_transport_api::SlotId;
use std::num::NonZeroU32;

macro_rules! gen_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
        pub struct $name {
            index: u32,
            generation: NonZeroU32,
        }

        impl $name {
            /// spec §5.2: `None` when the slot's generation is 0 (never live).
            /// Only the shard allocates ids.
            #[allow(dead_code)] // not every id kind is allocated yet (Shard, task 6.4)
            pub(crate) fn from_slot(s: SlotId) -> Option<$name> {
                NonZeroU32::new(s.generation()).map(|generation| $name {
                    index: s.index(),
                    generation,
                })
            }
            /// spec §5.2: the packed slot handle.
            pub fn slot(self) -> SlotId {
                SlotId::new(self.index, self.generation.get())
            }
            /// spec §5.2: slot index.
            pub fn index(self) -> u32 {
                self.index
            }
            /// spec §5.2: slot generation (never zero).
            pub fn generation(self) -> NonZeroU32 {
                self.generation
            }
        }
    };
}

gen_id!(
    /// spec §5.2: a TCP listener, registered at startup.
    ListenerId
);
gen_id!(
    /// spec §5.2: a UDP socket; the primary one is registered at startup.
    UdpSocketId
);
gen_id!(
    /// spec §5.2: an accepted or dialled TCP socket.
    TcpId
);
gen_id!(
    /// spec §5.2: an in-flight dial.
    DialOpId
);
gen_id!(
    /// spec §5.2: an in-flight UDP socket open.
    SocketOpId
);
gen_id!(
    /// spec §5.2: an app timer.
    TimerId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_zero_is_never_an_id() {
        assert_eq!(TcpId::from_slot(SlotId::NONE), None);
        assert_eq!(TimerId::from_slot(SlotId::new(5, 0)), None);
    }

    #[test]
    fn slot_roundtrip() {
        let s = SlotId::new(17, 3);
        let id = DialOpId::from_slot(s).unwrap();
        assert_eq!(id.slot(), s);
        assert_eq!((id.index(), id.generation().get()), (17, 3));
    }

    #[test]
    fn generations_distinguish_reused_slots() {
        let a = UdpSocketId::from_slot(SlotId::new(1, 1)).unwrap();
        let b = UdpSocketId::from_slot(SlotId::new(1, 2)).unwrap();
        assert_ne!(a, b);
        assert!(a < b);
    }
}
