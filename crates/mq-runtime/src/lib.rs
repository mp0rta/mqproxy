// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The shard runtime (spec §5).
#![forbid(unsafe_code)]

mod app;
pub mod driver;
mod ids;
mod shard;
#[cfg(feature = "test-support")]
pub mod testing;

pub use app::{
    AcceptMeta, App, Cx, DialError, Host, Interest, IoRequest, IoResult, KeepAlive, ListenKind,
    ListenerTag, PrereadTooLarge, SendBufFull, StreamPreread, Target, TcpEnd,
};
pub use ids::{DialOpId, ListenerId, SocketOpId, TcpId, TimerId, UdpSocketId};
pub use shard::{
    PumpOutcome, RELAY_BUDGET, RELAY_BUF, Relay, RelayEnd, RelayState, Rng, SOCKET_CAP, Shard,
    ShardState, TCP_BUF,
};
