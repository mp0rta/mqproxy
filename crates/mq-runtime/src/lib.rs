//! The shard runtime (spec §5).
#![forbid(unsafe_code)]

mod app;
mod ids;
mod shard;
#[cfg(feature = "test-support")]
pub mod testing;

pub use app::{
    AcceptMeta, App, Cx, DialError, Host, Interest, IoRequest, IoResult, ListenKind, ListenerTag,
    PrereadTooLarge, SendBufFull, StreamPreread, Target, TcpEnd,
};
pub use ids::{DialOpId, ListenerId, SocketOpId, TcpId, TimerId, UdpSocketId};
pub use shard::{
    PumpOutcome, RELAY_BUDGET, RELAY_BUF, Relay, RelayEnd, RelayState, Rng, SOCKET_CAP, Shard,
    ShardState, TCP_BUF,
};
