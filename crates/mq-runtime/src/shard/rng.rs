// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The shard's seeded RNG (spec §5.2), reached by the app via `Cx::rng()`.

/// spec §5.2: xorshift64*; reproducible for a given seed.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// spec §5.2: seed 0 is remapped (xorshift's state must be non-zero).
    pub fn new(seed: u64) -> Rng {
        Rng(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// spec §5.2: next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}
