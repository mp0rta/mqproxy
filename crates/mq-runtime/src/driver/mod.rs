//! The driver (spec §5.3): the loop core over an `Io` trait.

mod core;
mod deadlines;
#[allow(clippy::module_inception)]
mod driver;
mod io;
mod mio_io;
mod resolver;

pub use core::{Latch, LoopConfig, LoopCore, Next};
pub use deadlines::{Deadlines, Expired};
pub use driver::{AlreadyAttached, BoundListener, BoundUdp, Driver, DriverConfig};
pub use io::{
    Io, IoEvent, ListenerKey, RecvBatch, RecvStop, Resolver, SockKey, StdResolver, TcpSock,
    UdpSock, Wait,
};
pub use mio_io::{MioIo, ShutdownHandle, Stats};
pub use resolver::{RESOLVER_SLOTS, ResolverQueue};
