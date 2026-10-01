//! The shard runtime (spec §5).
#![forbid(unsafe_code)]

mod app;
mod ids;
mod shard;

pub use app::{
    AcceptMeta, App, Cx, DialError, Host, Interest, IoRequest, IoResult, ListenKind, ListenerTag,
    PrereadTooLarge, SendBufFull, StreamPreread, Target, TcpEnd,
};
pub use ids::{DialOpId, ListenerId, SocketOpId, TcpId, TimerId, UdpSocketId};
pub use shard::{Rng, ShardState, TCP_BUF};
