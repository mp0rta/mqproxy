//! The sans-I/O transport contract seen by the shard and apps (spec §4, §5.1).
#![forbid(unsafe_code)]

mod config;
mod error;
mod event;
mod ids;
mod ops;
pub mod ringbuf;
mod time;

pub use config::{
    CongestionControl, ConnConfig, ConnStats, PathStats, Role, Scheduler, TransportConfig,
};
pub use error::{ConnectError, DatagramError, Error, PathError, StreamError};
pub use event::{CloseReason, ErrType, Event, StreamInfo, StreamKind, Transmit};
pub use ids::{ConnId, PathId, SlotId, StreamId, TxKey};
pub use ops::TransportOps;
pub use time::Time;

#[cfg(feature = "test-support")]
pub mod fabric;
