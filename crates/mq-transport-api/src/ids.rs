// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Generational facade ids (spec §4.1, §4.8).

use std::num::NonZeroU32;

/// Raw slot handle `(generation << 32) | index`, e.g. a value stored in xquic
/// user-data. Generation 0 never belongs to a live object, so `NONE == 0`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct SlotId(u64);

impl SlotId {
    /// The "no object" handle.
    pub const NONE: SlotId = SlotId(0);

    pub fn new(index: u32, generation: u32) -> SlotId {
        SlotId((u64::from(generation) << 32) | u64::from(index))
    }
    pub fn index(self) -> u32 {
        self.0 as u32
    }
    pub fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
    pub fn as_raw(self) -> u64 {
        self.0
    }
    pub fn from_raw(raw: u64) -> SlotId {
        SlotId(raw)
    }
    pub fn is_none(self) -> bool {
        self.0 == 0
    }
}

macro_rules! gen_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
        pub struct $name {
            index: u32,
            generation: NonZeroU32,
        }

        impl $name {
            /// `None` when the slot's generation is 0 (never a live object).
            pub fn from_slot(s: SlotId) -> Option<$name> {
                NonZeroU32::new(s.generation()).map(|generation| $name {
                    index: s.index(),
                    generation,
                })
            }
            pub fn slot(self) -> SlotId {
                SlotId::new(self.index, self.generation.get())
            }
            pub fn index(self) -> u32 {
                self.index
            }
            pub fn generation(self) -> NonZeroU32 {
                self.generation
            }
        }
    };
}

gen_id!(
    /// A connection, by facade slot (spec §4.1). Stale after the conn closes.
    ConnId
);
gen_id!(
    /// A stream, by facade slot (spec §4.1). Not the QUIC stream id; see `StreamInfo`.
    StreamId
);
gen_id!(
    /// An H3 request, by facade slot (spec §3.1). Stale after `H3Closed`.
    H3ReqId
);

/// xquic's path id; meaningful only together with a `ConnId` (spec §4.1).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub struct PathId(pub u64);

/// One transmit queue (spec §4.1).
pub type TxKey = (Option<ConnId>, PathId);
