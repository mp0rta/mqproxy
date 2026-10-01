//! The shard (spec §5.2). This module currently holds only `ShardState`, the
//! part of the shard that `Cx` acts on; `Shard<T, A>` is built around it.

mod rng;

pub use rng::Rng;

use crate::app::{IoRequest, PrereadTooLarge, SendBufFull, StreamPreread};
use crate::ids::{DialOpId, SocketOpId, TcpId, TimerId, UdpSocketId};
use mq_transport_api::{ConnId, PathId, SlotId, StreamId, Time};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

/// spec §5.4: the app-owned send buffer and the relay buffers are 64 KiB.
pub const TCP_BUF: usize = 64 * 1024;

/// spec §5.4: a TCP socket's app-visible state.
#[derive(Debug, Default)]
pub(crate) struct TcpEntry {
    pub(crate) rx: Vec<u8>,
    pub(crate) tx: Vec<u8>,
    pub(crate) read: bool,
    /// `tcp_close` seen; closes once `tx` drains.
    pub(crate) closing: bool,
    /// `start_relay` seen: the stream and the preread toward TCP.
    pub(crate) relay: Option<PendingRelay>,
}

/// spec §5.4: what `start_relay` hands to the relay.
#[derive(Debug)]
#[allow(dead_code)] // consumed when the Shard builds the relay (task 6.4)
pub(crate) struct PendingRelay {
    pub(crate) stream: StreamId,
    pub(crate) preread: Vec<u8>,
    pub(crate) fin: bool,
}

/// spec §5.2/§5.4: the shard state `Cx` reads and records onto.
#[derive(Debug)]
pub struct ShardState {
    primary_local: SocketAddr,
    primary_udp: UdpSocketId,
    rng: Rng,
    // ponytail: one monotonic index, generation 1; the shard's slot tables replace it.
    next_index: u32,
    requests: VecDeque<IoRequest>,
    // ponytail: O(n) min scan; a heap when timers get numerous.
    timers: HashMap<TimerId, Time>,
    pub(crate) tcp: HashMap<TcpId, TcpEntry>,
    paths: HashMap<(ConnId, PathId), UdpSocketId>,
    app_accepting: bool,
    exit_status: Option<i32>,
}

impl ShardState {
    /// spec §5.2: the state of a new shard; registers the primary UDP socket.
    pub fn new(primary_local: SocketAddr, rng_seed: u64) -> ShardState {
        ShardState {
            primary_local,
            primary_udp: UdpSocketId::from_slot(SlotId::new(0, 1)).expect("generation 1"),
            rng: Rng::new(rng_seed),
            next_index: 1, // index 0 is the primary UDP socket
            requests: VecDeque::new(),
            timers: HashMap::new(),
            tcp: HashMap::new(),
            paths: HashMap::new(),
            app_accepting: true,
            exit_status: None,
        }
    }

    fn alloc<I>(&mut self, f: fn(SlotId) -> Option<I>) -> I {
        let i = self.next_index;
        self.next_index += 1;
        f(SlotId::new(i, 1)).expect("generation 1 is live")
    }

    /// spec §5.2: the primary UDP socket.
    pub fn primary_udp(&self) -> UdpSocketId {
        self.primary_udp
    }
    /// spec §5.2: the primary UDP socket's local address.
    pub fn primary_local(&self) -> SocketAddr {
        self.primary_local
    }
    /// spec §5.2: the seeded RNG.
    pub fn rng(&mut self) -> &mut Rng {
        &mut self.rng
    }
    /// spec §5.2: the next I/O request for the driver, in order.
    pub fn poll_io_request(&mut self) -> Option<IoRequest> {
        self.requests.pop_front()
    }
    /// spec §5.2: set by `Cx::request_exit`.
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }
    /// spec §5.4: the app's `set_accepting` flag (the socket cap is applied by the shard).
    pub fn accepting(&self) -> bool {
        self.app_accepting
    }
    /// spec §5.2: the earliest app timer.
    pub fn next_timer(&self) -> Option<Time> {
        self.timers.values().min().copied()
    }
    /// spec §5.4: a live timer's deadline.
    pub fn timer_deadline(&self, id: TimerId) -> Option<Time> {
        self.timers.get(&id).copied()
    }
    /// spec §5.2 "UDP socket selection": the socket mapped to (conn, path), if any.
    pub fn path_socket(&self, conn: ConnId, path: PathId) -> Option<UdpSocketId> {
        self.paths.get(&(conn, path)).copied()
    }

    /// Registers an app-owned TCP socket (what an accept or dial will do).
    #[cfg(feature = "test-support")]
    pub fn insert_tcp(&mut self) -> TcpId {
        let id = self.alloc(TcpId::from_slot);
        self.tcp.insert(id, TcpEntry::default());
        id
    }

    pub(crate) fn push_request(&mut self, r: IoRequest) {
        self.requests.push_back(r);
    }
    pub(crate) fn new_dial(&mut self) -> DialOpId {
        self.alloc(DialOpId::from_slot)
    }
    pub(crate) fn new_socket_op(&mut self) -> SocketOpId {
        self.alloc(SocketOpId::from_slot)
    }
    pub(crate) fn set_timer(&mut self, at: Time) -> TimerId {
        let id = self.alloc(TimerId::from_slot);
        self.timers.insert(id, at);
        id
    }
    pub(crate) fn cancel_timer(&mut self, id: TimerId) {
        self.timers.remove(&id);
    }
    pub(crate) fn map_path(&mut self, conn: ConnId, path: PathId, sock: UdpSocketId) {
        self.paths.insert((conn, path), sock);
    }
    pub(crate) fn unmap_socket(&mut self, sock: UdpSocketId) {
        self.paths.retain(|_, s| *s != sock);
    }
    pub(crate) fn set_accepting(&mut self, on: bool) {
        self.app_accepting = on;
    }
    pub(crate) fn request_exit(&mut self, code: i32) {
        self.exit_status = Some(code);
    }

    /// App-owned and not closing: the only state in which the app may act on it.
    fn app_tcp(&mut self, tcp: TcpId) -> Option<&mut TcpEntry> {
        self.tcp
            .get_mut(&tcp)
            .filter(|e| !e.closing && e.relay.is_none())
    }
    pub(crate) fn tcp_rx(&self, tcp: TcpId) -> &[u8] {
        self.tcp.get(&tcp).map_or(&[], |e| &e.rx)
    }
    pub(crate) fn tcp_consume(&mut self, tcp: TcpId, n: usize) {
        if let Some(e) = self.tcp.get_mut(&tcp) {
            e.rx.drain(..n.min(e.rx.len()));
        }
    }
    pub(crate) fn tcp_write(&mut self, tcp: TcpId, bytes: &[u8]) -> Result<(), SendBufFull> {
        let e = self.app_tcp(tcp).ok_or(SendBufFull)?;
        if e.tx.len() + bytes.len() > TCP_BUF {
            return Err(SendBufFull);
        }
        e.tx.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn tcp_set_read(&mut self, tcp: TcpId, on: bool) {
        if let Some(e) = self.tcp.get_mut(&tcp) {
            e.read = on;
        }
    }
    /// Graceful: closes now if nothing is queued, else once `tx` drains.
    pub(crate) fn tcp_close(&mut self, tcp: TcpId) {
        match self.tcp.get_mut(&tcp) {
            Some(e) if e.tx.is_empty() => self.close_now(tcp, false),
            Some(e) => e.closing = true,
            None => {}
        }
    }
    pub(crate) fn tcp_abort(&mut self, tcp: TcpId) {
        if self.tcp.contains_key(&tcp) {
            self.close_now(tcp, true);
        }
    }
    fn close_now(&mut self, tcp: TcpId, abort: bool) {
        self.tcp.remove(&tcp);
        self.push_request(IoRequest::TcpClose { tcp, abort });
    }
    pub(crate) fn start_relay(
        &mut self,
        tcp: TcpId,
        stream: StreamId,
        preread: StreamPreread<'_>,
    ) -> Result<(), PrereadTooLarge> {
        let e = self.app_tcp(tcp).ok_or(PrereadTooLarge)?;
        if e.tx.len() + preread.bytes.len() > TCP_BUF {
            return Err(PrereadTooLarge);
        }
        e.relay = Some(PendingRelay {
            stream,
            preread: preread.bytes.to_vec(),
            fin: preread.fin,
        });
        Ok(())
    }
}
