//! The `Io` trait (spec §5.3 "Loop core and `Io`"). Handles are opaque keys
//! owned by the `Io` implementation.

use crate::app::{AcceptMeta, IoResult};
use crate::ids::DialOpId;
use mq_transport_api::{Time, Transmit};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::ops::Range;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub struct SockKey(pub u64);
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct TcpSock(pub SockKey);
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct UdpSock(pub SockKey);
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ListenerKey(pub SockKey);

/// One received datagram: `range` indexes `RecvBatch::buf`. OS-neutral so
/// the `Io` surface carries no platform crate types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub local: SocketAddr,
    pub range: Range<usize>,
}

/// One allocation, reused; filled by `Io::recv_udp`.
#[derive(Default, Debug)]
pub struct RecvBatch {
    pub buf: Vec<u8>,
    pub metas: Vec<RecvMeta>,
}

/// spec §5.3: edges, completions and signals returned by `Io::wait`.
#[derive(Debug)]
pub enum IoEvent {
    Readable(SockKey),
    Writable(SockKey),
    Error(SockKey),
    Resolved {
        op: DialOpId,
        r: io::Result<Vec<SocketAddr>>,
    },
    Connected {
        op: DialOpId,
        r: io::Result<TcpSock>,
    },
    Timer,
    Shutdown,
}

/// spec §5.5 step 10. `Yield` = collect what is pending without sleeping.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Wait {
    Yield,
    Until(Time),
    Forever,
}

/// How a `recv_udp` call ended.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum RecvStop {
    /// Hit `WouldBlock`: clear the latch.
    Drained,
    /// More may be pending: keep it.
    Budget,
}

/// spec §5.3: the primitives the loop core runs on; all non-blocking except `wait`.
pub trait Io {
    fn now(&self) -> Time;
    /// Blocks until at least one event arrives or the deadline passes. `Yield` returns at once with whatever
    /// is pending (mio events, completions, signals); a blocking call never returns an empty Vec before its deadline.
    fn wait(&mut self, w: Wait) -> Vec<IoEvent>;
    /// True when the last `wait` stopped draining before the source was empty (the mio impl caps drains at 8).
    /// The loop core treats it as runnable work in step 10 and calls `wait(Wait::Yield)`; cleared by a drain that ends early.
    fn has_pending_work(&self) -> bool;
    fn accept(&mut self, l: ListenerKey) -> io::Result<(TcpSock, AcceptMeta)>;
    /// Never called with an empty buf (debug_assert).
    fn read(&mut self, s: TcpSock, buf: &mut [u8]) -> IoResult;
    fn write(&mut self, s: TcpSock, buf: &[u8]) -> IoResult;
    /// A partly filled batch is kept on Err.
    fn recv_udp(&mut self, s: UdpSock, out: &mut RecvBatch, budget: usize) -> io::Result<RecvStop>;
    /// Sends as much of `t` as the kernel takes, in ≤64-segment / ≤65507-byte GSO calls; owns the GSO-off fallback.
    /// Ok(n) = datagrams sent. `Ok(n < total)` occurs only on WouldBlock: the rest stays queued and the caller
    /// clears the writable latch. Err(WouldBlock) when none were sent. Any other Err (even after a sent
    /// prefix) means the whole transmit is finished: the loop core commits all of it (sent + dropped) and
    /// owns the send-error counter and its rate-limited log; the `Io` neither counts nor logs it.
    fn send_udp(&mut self, s: UdpSock, t: &Transmit<'_>) -> io::Result<usize>;
    fn start_resolve(&mut self, op: DialOpId, host: String, port: u16);
    /// A connect that fails synchronously (ECONNREFUSED on loopback, EMFILE from socket()) is reported as
    /// IoEvent::Connected { r: Err } through the completion channel, so the next wait of either mode returns it.
    fn start_connect(&mut self, op: DialOpId, addr: SocketAddr);
    /// At the dial deadline: closes a SYN-blackholed socket.
    fn cancel_connect(&mut self, op: DialOpId);
    fn open_udp(&mut self, local_ip: IpAddr) -> io::Result<(UdpSock, SocketAddr)>;
    fn shutdown_write(&mut self, s: TcpSock) -> io::Result<()>;
    /// abort: mq_linux::set_linger_zero then close → the peer sees ECONNRESET.
    fn close_tcp(&mut self, s: TcpSock, abort: bool);
    fn close_udp(&mut self, s: UdpSock);
    fn socket_error(&mut self, s: TcpSock) -> io::ErrorKind;
}

/// spec §5.3: name resolution, run off the loop thread.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// `(host, port).to_socket_addrs()`.
#[derive(Copy, Clone, Debug, Default)]
pub struct StdResolver;

impl Resolver for StdResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}
