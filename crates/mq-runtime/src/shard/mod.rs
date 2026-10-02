//! The shard (spec §5.2): a synchronous state machine that owns the transport,
//! the `App`, the TCP socket table, relays, app timers and the UDP socket map.
//! It performs no syscalls; a driver feeds it and carries out its requests.
//!
//! `ShardState` is the part `Cx` acts on (everything but the transport and the
//! app); `Shard<T, A>` wraps it with the transport and the app.

mod inputs;
pub(crate) mod relay;
pub(crate) use mq_transport_api::ringbuf;
mod rng;
mod routing;
mod tcp;
mod timers;

pub use relay::{PumpOutcome, RELAY_BUF, Relay, RelayEnd, RelayState};
pub use rng::Rng;

use crate::app::{App, Cx, DialError, Interest, IoRequest, ListenerTag, Target};
use crate::ids::{DialOpId, ListenerId, SocketOpId, TcpId, TimerId, UdpSocketId};
use mq_transport_api::{ConnId, PathId, SlotId, StreamId, Time, TransportOps, TxKey};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tcp::TcpEntry;

/// spec §5.4: the app-owned send buffer and the relay buffers are 64 KiB.
pub const TCP_BUF: usize = 64 * 1024;

/// spec §5.2: a shard holds at most this many TCP sockets (`TcpId`s plus dials in progress).
pub const SOCKET_CAP: usize = 4096;

/// spec §5.2 `drive` step 4: bytes per relay per direction per `drive`.
pub const RELAY_BUDGET: usize = 256 * 1024;

/// spec §5.2/§5.4: the shard state `Cx` reads and records onto.
#[derive(Debug)]
pub struct ShardState {
    primary_local: SocketAddr,
    primary_udp: UdpSocketId,
    rng: Rng,
    /// Id allocator: index = low 32 bits, generation = high 32 bits + 1, so an
    /// id is never reused (spec §5.2 "generational").
    next_id: u64,
    requests: VecDeque<IoRequest>,
    // ponytail: O(n) scans; a heap when timers get numerous.
    timers: HashMap<TimerId, Time>,
    tcp: HashMap<TcpId, TcpEntry>,
    /// Relay-owned streams (spec §5.4 "Event routing").
    streams: HashMap<StreamId, TcpId>,
    /// Streams whose relay has closed: their late events are dropped. Pruned
    /// by the stream's `StreamClosed` or its connection's `ConnClosed`.
    dead_streams: HashMap<StreamId, ConnId>,
    /// Dials handed to the driver and not yet completed or cancelled.
    dials: HashSet<DialOpId>,
    /// spec §5.2: dials refused at the cap, delivered as `DialError::Limit` in `drive` step 3.
    limited: Vec<DialOpId>,
    socket_ops: HashSet<SocketOpId>,
    /// Live UDP sockets (the primary included) and their local addresses.
    udp: HashMap<UdpSocketId, SocketAddr>,
    paths: HashMap<(ConnId, PathId), UdpSocketId>,
    /// spec §5.2 "UDP socket selection": the queue each socket served last.
    tx_cursor: HashMap<UdpSocketId, TxKey>,
    app_accepting: bool,
    exit_status: Option<i32>,
    /// Something called into the transport since the last `drive` step 2:
    /// events may be queued there (spec §5.2 step 5, `has_runnable_work`).
    touched: bool,
}

impl ShardState {
    /// spec §5.2: the state of a new shard; registers the primary UDP socket.
    pub fn new(primary_local: SocketAddr, rng_seed: u64) -> ShardState {
        let primary_udp = UdpSocketId::from_slot(SlotId::new(0, 1)).expect("generation 1");
        ShardState {
            primary_local,
            primary_udp,
            rng: Rng::new(rng_seed),
            next_id: 1, // 0 is the primary UDP socket
            requests: VecDeque::new(),
            timers: HashMap::new(),
            tcp: HashMap::new(),
            streams: HashMap::new(),
            dead_streams: HashMap::new(),
            dials: HashSet::new(),
            limited: Vec::new(),
            socket_ops: HashSet::new(),
            udp: HashMap::from([(primary_udp, primary_local)]),
            paths: HashMap::new(),
            tx_cursor: HashMap::new(),
            app_accepting: true,
            exit_status: None,
            touched: false,
        }
    }

    fn alloc<I>(&mut self, f: fn(SlotId) -> Option<I>) -> I {
        let n = self.next_id;
        self.next_id += 1;
        f(SlotId::new(n as u32, (n >> 32) as u32 + 1)).expect("generation is never 0")
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
    /// spec §5.2: the listeners' accept interest — the app's `set_accepting`
    /// flag, and below the socket cap.
    pub fn accepting(&self) -> bool {
        self.app_accepting && !self.at_cap()
    }

    /// spec §5.2 "Socket cap".
    fn at_cap(&self) -> bool {
        self.tcp.len() + self.dials.len() >= SOCKET_CAP
    }

    pub(crate) fn push_request(&mut self, r: IoRequest) {
        self.requests.push_back(r);
    }
    pub(crate) fn touch(&mut self) {
        self.touched = true;
    }

    /// spec §5.2/§5.4: at the cap the dial completes with `Limit` in the next
    /// `drive`, without reaching the driver.
    pub(crate) fn dial(&mut self, target: Target, deadline: Duration) -> DialOpId {
        let op = self.alloc(DialOpId::from_slot);
        if self.at_cap() {
            self.limited.push(op);
        } else {
            self.dials.insert(op);
            self.push_request(IoRequest::Dial {
                op,
                target,
                deadline,
            });
        }
        op
    }
    /// spec §5.4: its result, if any, is dropped (and the socket closed by the driver).
    pub(crate) fn cancel_dial(&mut self, op: DialOpId) {
        if self.dials.remove(&op) {
            self.push_request(IoRequest::CancelDial { op });
        } else {
            self.limited.retain(|o| *o != op);
        }
    }
    pub(crate) fn open_udp_socket(&mut self, local_ip: IpAddr) -> SocketOpId {
        let op = self.alloc(SocketOpId::from_slot);
        self.socket_ops.insert(op);
        self.push_request(IoRequest::OpenUdpSocket { op, local_ip });
        op
    }
    pub(crate) fn cancel_udp_socket(&mut self, op: SocketOpId) {
        if self.socket_ops.remove(&op) {
            self.push_request(IoRequest::CancelUdpSocket { op });
        }
    }
    pub(crate) fn set_accepting(&mut self, on: bool) {
        self.app_accepting = on;
    }
    pub(crate) fn request_exit(&mut self, code: i32) {
        self.exit_status = Some(code);
    }
}

/// spec §5.2: the shard.
pub struct Shard<T: TransportOps, A: App> {
    transport: T,
    app: A,
    st: ShardState,
    listeners: HashMap<ListenerId, ListenerTag>,
    /// Round-robin start for step 4.
    rr: usize,
}

impl<T: TransportOps, A: App> Shard<T, A> {
    /// spec §5.2: construction; registers the primary UDP socket.
    pub fn new(transport: T, app: A, primary_local: SocketAddr, rng_seed: u64) -> Shard<T, A> {
        Shard {
            transport,
            app,
            st: ShardState::new(primary_local, rng_seed),
            listeners: HashMap::new(),
            rr: 0,
        }
    }
    /// spec §5.2.
    pub fn primary_udp(&self) -> UdpSocketId {
        self.st.primary_udp
    }
    /// spec §5.2: registers a listener; the app sees `tag` with each accept.
    pub fn add_listener(&mut self, tag: ListenerTag) -> ListenerId {
        let id = self.st.alloc(ListenerId::from_slot);
        self.listeners.insert(id, tag);
        id
    }
    /// spec §5.2: calls `App::on_start`; the driver's first call.
    pub fn start(&mut self, now: Time) {
        self.call_app(now, |a, cx| a.on_start(cx));
    }
    /// spec §5.3: gives the transport back so the binary can close it.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Runs app code with a `Cx` built around the shard.
    fn call_app<R>(&mut self, now: Time, f: impl FnOnce(&mut A, &mut Cx<'_>) -> R) -> R {
        let mut cx = Cx::new(&mut self.transport, now, &mut self.st);
        f(&mut self.app, &mut cx)
    }

    /// spec §5.2 `drive`.
    pub fn drive(&mut self, now: Time) {
        // 1. Due app timers, in (time, id) order.
        self.fire_timers(now);
        // 2. The transport.
        self.transport.drive(now);
        self.st.touched = false;
        // 3. Transport events, then shard-raised completions.
        self.dispatch_events(now);
        for op in std::mem::take(&mut self.st.limited) {
            self.call_app(now, |a, cx| a.on_dial_result(cx, op, Err(DialError::Limit)));
        }
        // 4. Runnable relays.
        self.pump_relays(now);
        // 5. Once more if 3 or 4 called into the transport. `touched` stays
        // set: this drive may have queued events nobody has dispatched yet.
        if self.st.touched {
            self.transport.drive(now);
        }
    }

    /// spec §5.2 step 4: each runnable relay once, round-robin, budget per direction.
    fn pump_relays(&mut self, now: Time) {
        // ponytail: O(relays) scan per drive; a runnable list if relays get numerous.
        let mut ids: Vec<TcpId> = self.st.streams.values().copied().collect();
        if ids.is_empty() {
            return;
        }
        ids.sort();
        let start = self.rr % ids.len();
        ids.rotate_left(start);
        self.rr = self.rr.wrapping_add(1);
        for tcp in ids {
            if let Some(TcpEntry::Relay(r)) = self.st.tcp.get_mut(&tcp) {
                if r.is_runnable() {
                    r.pump(&mut self.transport, now, RELAY_BUDGET);
                    self.st.touched = true;
                }
            }
            self.settle_relay(now, tcp);
        }
    }

    /// spec §5.6: after every relay operation — an owed SHUT_WR becomes
    /// `TcpShutdownWrite` (done at once); an ended relay is removed:
    /// `Abort` resets the stream and aborts TCP, `Clean` closes TCP. The app
    /// gets no callback (spec §5.4: none once relaying).
    fn settle_relay(&mut self, now: Time, tcp: TcpId) {
        let Some(TcpEntry::Relay(r)) = self.st.tcp.get_mut(&tcp) else {
            return;
        };
        let shut = r.take_owed_shutdown();
        if shut {
            r.shutdown_done();
        }
        let (end, stream, conn, gone) = (r.end_reason(), r.stream, r.conn, r.stream_gone());
        if shut {
            self.st.push_request(IoRequest::TcpShutdownWrite { tcp });
        }
        let Some(end) = end else {
            return;
        };
        self.st.tcp.remove(&tcp);
        self.st.streams.remove(&stream);
        // Late events are dropped until the stream's `StreamClosed`; if that
        // was already consumed, none can follow and no entry is kept.
        if !gone {
            self.st.dead_streams.insert(stream, conn);
        }
        let abort = end == RelayEnd::Abort;
        if abort {
            self.transport.stream_reset(now, stream);
            self.st.touched = true;
        }
        self.st.push_request(IoRequest::TcpClose { tcp, abort });
    }

    // --- Outputs (spec §5.2) ---

    /// spec §5.2.
    pub fn poll_io_request(&mut self) -> Option<IoRequest> {
        self.st.poll_io_request()
    }
    /// spec §5.2 "Interest".
    pub fn tcp_interest(&self, tcp: TcpId) -> Interest {
        match self.st.tcp.get(&tcp) {
            Some(TcpEntry::App(e)) => e.interest(),
            Some(TcpEntry::Relay(r)) => r.tcp_interest(),
            None => Interest::default(),
        }
    }
    /// spec §5.2: the listeners' accept interest.
    pub fn accepting(&self) -> bool {
        self.st.accepting()
    }
    /// spec §5.2: a runnable relay, an undispatched event, a shard-raised
    /// completion, or `resume_pending`.
    pub fn has_runnable_work(&self) -> bool {
        self.st.touched
            || !self.st.limited.is_empty()
            || self.transport.resume_pending()
            || self
                .st
                .tcp
                .values()
                .any(|e| matches!(e, TcpEntry::Relay(r) if r.is_runnable()))
    }
    /// spec §5.5 step 7: the transport's `resume_pending`.
    pub fn resume_pending(&self) -> bool {
        self.transport.resume_pending()
    }
    /// spec §5.2: min(transport, app timers).
    pub fn next_timeout(&self) -> Option<Time> {
        [self.transport.next_timeout(), self.st.next_timer()]
            .into_iter()
            .flatten()
            .min()
    }
    /// spec §5.2.
    pub fn exit_status(&self) -> Option<i32> {
        self.st.exit_status()
    }

    // --- Test hooks (spec §8.1) ---

    /// Runs app code outside a callback — the only way to. Harnesses call it
    /// on the shard's thread between lockstep steps, then `drive`.
    #[cfg(feature = "test-support")]
    pub fn with_app<R>(&mut self, now: Time, f: impl FnOnce(&mut A, &mut Cx<'_>) -> R) -> R {
        self.call_app(now, f)
    }
    /// Closed relays' streams still awaiting their `StreamClosed`.
    #[cfg(feature = "test-support")]
    pub fn dead_stream_count(&self) -> usize {
        self.st.dead_streams.len()
    }
    #[cfg(feature = "test-support")]
    pub fn app(&self) -> &A {
        &self.app
    }
    #[cfg(feature = "test-support")]
    pub fn transport(&self) -> &T {
        &self.transport
    }
    #[cfg(feature = "test-support")]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn size_constant() {
        assert_eq!(super::TCP_BUF, 65536);
    }
}
