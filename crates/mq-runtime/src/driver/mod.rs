//! The driver (spec §5.3): the loop core over an `Io` trait.

mod core;
mod deadlines;
mod io;
mod resolver;

pub use core::{Latch, LoopConfig, LoopCore, Next};
pub use deadlines::{Deadlines, Expired};
pub use io::{
    Io, IoEvent, ListenerKey, RecvBatch, RecvStop, Resolver, SockKey, StdResolver, TcpSock,
    UdpSock, Wait,
};
pub use resolver::{RESOLVER_SLOTS, ResolverQueue};
