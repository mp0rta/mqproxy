// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §8.1
#![forbid(unsafe_code)]

#[cfg(feature = "harness")]
pub mod browser;
#[cfg(feature = "harness")]
pub mod driver_harness;
#[cfg(feature = "harness")]
pub mod h3_apps;
#[cfg(feature = "harness")]
pub mod log_tap;
#[cfg(feature = "harness")]
pub mod loopback;
#[cfg(feature = "harness")]
pub mod origin_loop;
#[cfg(feature = "harness")]
pub mod origin_server;
#[cfg(feature = "harness")]
pub mod raw_h3;
#[cfg(feature = "harness")]
pub mod shard_pair;
