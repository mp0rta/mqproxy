//! The app interface (spec §5.4) and the shard's request/result types (spec §5.2, §5.3).

use crate::ids::{DialOpId, SocketOpId, TcpId, TimerId, UdpSocketId};
use crate::shard::{Rng, ShardState};
use mq_transport_api::{
    ConnConfig, ConnId, ConnStats, ConnectError, DatagramError, Error, Event, H3Header, H3ReqId,
    H3ReqInfo, PathError, PathId, StreamError, StreamId, StreamInfo, Time, TransportOps,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// spec §5.2: chosen by the binary; tells SOCKS5, HTTP CONNECT and transparent capture apart.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ListenerTag(pub u32);

/// spec §5.3: how the driver fills `AcceptMeta::original_dst`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ListenKind {
    /// No original destination.
    Plain,
    /// `SO_ORIGINAL_DST`.
    Redirect,
    /// `getsockname`.
    Tproxy,
    /// Tests: every accepted socket gets this original destination.
    #[cfg(feature = "test-support")]
    Fixed(SocketAddr),
}

/// SP4 spec §7.8: TCP keepalive for a long-lived app socket.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeepAlive {
    pub idle: Duration,
    pub interval: Duration,
    pub count: u32,
    pub user_timeout: Duration,
}

/// spec §5.2: what the driver knows about an accepted socket.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct AcceptMeta {
    pub peer: SocketAddr,
    /// The accepted socket's own address (`getsockname`); not unmapped (spec §4.3).
    pub local: SocketAddr,
    pub original_dst: Option<SocketAddr>,
}

/// spec §5.2: the outcome of one TCP read or write.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum IoResult {
    Bytes(usize),
    /// A read returned zero (spec §5.4: the only source of EOF).
    Eof,
    WouldBlock,
    Error(io::ErrorKind),
}

/// spec §5.2: why a dial failed.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum DialError {
    Dns,
    Refused,
    Timeout,
    /// The shard's socket cap; raised by the shard without reaching the driver.
    Limit,
    Other,
}

/// spec §5.2: a dial target's host.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// spec §5.2: a dial target.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

/// spec §5.2: work the driver carries out, in order, in the same iteration.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum IoRequest {
    /// Resolve, then connect, under one deadline.
    Dial {
        op: DialOpId,
        target: Target,
        deadline: Duration,
    },
    CancelDial {
        op: DialOpId,
    },
    /// SP2 spec §4.2: resolve to the first address under one deadline, no connect.
    /// Shares the dial op-id space; the shard completes `Host::Ip` targets itself.
    Resolve {
        op: DialOpId,
        target: Target,
        deadline: Duration,
    },
    CancelResolve {
        op: DialOpId,
    },
    /// Ephemeral port.
    OpenUdpSocket {
        op: SocketOpId,
        local_ip: IpAddr,
    },
    CancelUdpSocket {
        op: SocketOpId,
    },
    CloseUdpSocket {
        sock: UdpSocketId,
    },
    TcpShutdownWrite {
        tcp: TcpId,
    },
    /// `TCP_NODELAY` on the socket (SP3: the origin bridge, libcurl parity).
    TcpSetNodelay {
        tcp: TcpId,
    },
    /// `SO_KEEPALIVE` and friends (SP4 spec §7.8: the MITM client socket).
    TcpSetKeepalive {
        tcp: TcpId,
        ka: KeepAlive,
    },
    /// `abort`: `SO_LINGER` 0 then close, so the peer sees `ECONNRESET`.
    TcpClose {
        tcp: TcpId,
        abort: bool,
    },
}

/// spec §5.2: the driver's read/write interest for a TCP socket.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Default)]
pub struct Interest {
    pub read: bool,
    pub write: bool,
}

/// spec §5.4: end of an app-owned socket.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum TcpEnd {
    /// A read returned zero; the socket is still writable and may be relayed.
    ReadEof,
    /// Terminal: the shard has closed the socket and the id is dead.
    Error(io::ErrorKind),
}

/// spec §5.4: stream bytes the app read before `start_relay`, and whether FIN was seen.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct StreamPreread<'a> {
    pub bytes: &'a [u8],
    pub fin: bool,
}

/// spec §5.4: `start_relay` failure — the preread does not fit behind what is
/// already queued for TCP (or `tcp` is not a live app-owned socket, or the
/// stream is already relayed).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct PrereadTooLarge;

/// spec §5.4: `tcp_write` failure — the bytes do not fit in the 64 KiB send
/// buffer (or `tcp` is not a live app-owned socket); SP2 spec §4.1: also
/// `udp_send`'s.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct SendBufFull;

/// spec §5.4: the application driven by the shard. `Cx` is its only way to act.
pub trait App {
    /// spec §5.4: once, from `Shard::start`.
    fn on_start(&mut self, cx: &mut Cx<'_>);
    /// spec §5.4: every transport event not routed to a relay.
    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event);
    /// spec §5.4: a new app-owned socket from a listener.
    fn on_accepted(&mut self, cx: &mut Cx<'_>, l: ListenerTag, tcp: TcpId, meta: AcceptMeta);
    /// spec §5.4: bytes arrived in an app-owned socket's receive buffer.
    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId);
    /// spec §5.4: read EOF or error on an app-owned socket.
    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd);
    /// spec §4: once after a `tcp_write` failed with `SendBufFull`, when the
    /// send buffer has fully drained. Never for a relay or a closed socket.
    fn on_tcp_writable(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId) {}
    /// spec §5.4: a dial completed (never delivered once cancelled).
    fn on_dial_result(&mut self, cx: &mut Cx<'_>, op: DialOpId, r: Result<TcpId, DialError>);
    /// SP2 spec §4.2: a resolve-only request completed (never delivered once
    /// cancelled). `Dns` and `Timeout` are its only failures.
    fn on_resolve_result(
        &mut self,
        cx: &mut Cx<'_>,
        op: DialOpId,
        r: Result<SocketAddr, DialError>,
    );
    /// spec §5.4: a UDP socket open completed (never delivered once cancelled).
    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    );
    /// SP2 spec §4.1: a datagram on an app-owned UDP socket, borrowed from the
    /// driver's receive batch: handle or drop it here.
    fn on_udp_rx(&mut self, cx: &mut Cx<'_>, sock: UdpSocketId, peer: SocketAddr, data: &[u8]);
    /// spec §5.4: an app timer fired.
    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId);
    /// spec §5.4: a shutdown signal arrived.
    fn on_shutdown(&mut self, cx: &mut Cx<'_>);
}

/// spec §5.4: the app's handle on the shard for one callback. Carries `now`.
pub struct Cx<'a> {
    t: &'a mut dyn TransportOps,
    now: Time,
    st: &'a mut ShardState,
}

impl<'a> Cx<'a> {
    /// spec §5.1/§5.4: built by the shard around each callback.
    #[doc(hidden)] // apps get a `Cx` only from the shard; public for `tests/app.rs`
    pub fn new(t: &'a mut dyn TransportOps, now: Time, st: &'a mut ShardState) -> Cx<'a> {
        Cx { t, now, st }
    }

    /// spec §5.4: the current time.
    pub fn now(&self) -> Time {
        self.now
    }

    /// The transport, for a call that may queue events (spec §5.2 step 5).
    fn tm(&mut self) -> &mut (dyn TransportOps + 'a) {
        self.st.touch();
        self.t
    }

    // --- Transport (spec §5.4) ---

    /// spec §5.4.
    pub fn connect(&mut self, cfg: &ConnConfig) -> Result<ConnId, ConnectError> {
        let now = self.now;
        self.tm().connect(now, cfg)
    }
    /// spec §5.4.
    pub fn open_stream(&mut self, conn: ConnId) -> Result<StreamId, Error> {
        let now = self.now;
        self.tm().open_stream(now, conn)
    }
    /// spec §5.4.
    pub fn stream_send(
        &mut self,
        s: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        let now = self.now;
        self.tm().stream_send(now, s, data, fin)
    }
    /// spec §5.4. An empty `buf` is a reset probe.
    pub fn stream_recv(
        &mut self,
        s: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        let now = self.now;
        self.tm().stream_recv(now, s, buf)
    }
    /// spec §5.4.
    pub fn stream_reset(&mut self, s: StreamId) {
        let now = self.now;
        self.tm().stream_reset(now, s)
    }
    /// Tests only: a local unidirectional stream, for the raw-H3 peer's control stream
    /// (adoption spec §3, §6.2).
    #[cfg(feature = "test-support")]
    pub fn open_uni(&mut self, conn: ConnId) -> Result<StreamId, Error> {
        let now = self.now;
        self.tm().open_uni(now, conn)
    }
    /// spec §5.4.
    pub fn stream_info(&self, s: StreamId) -> Result<StreamInfo, Error> {
        self.t.stream_info(s)
    }
    /// spec §5.4.
    pub fn close_conn(&mut self, conn: ConnId) {
        let now = self.now;
        self.tm().close_conn(now, conn)
    }
    /// spec §4.7: exempts the conn from eviction at `max_conns`.
    pub fn mark_conn_authed(&mut self, conn: ConnId) {
        self.tm().mark_conn_authed(conn)
    }
    /// spec §5.4.
    pub fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error> {
        self.t.conn_stats(conn)
    }

    /// spec §3.1: every error means the datagram was dropped.
    pub fn datagram_send(&mut self, conn: ConnId, data: &[u8]) -> Result<(), DatagramError> {
        let now = self.now;
        self.tm().datagram_send(now, conn, data)
    }
    /// spec §3.1: 0 = unsupported/unknown. Callers cache it (spec §5 `MSS_REFRESH`).
    pub fn datagram_mss(&self, conn: ConnId) -> usize {
        self.t.datagram_mss(conn)
    }
    /// spec §3.1: `buf.len() >= 65535`; `None` = ring empty / stale.
    pub fn datagram_recv(&mut self, conn: ConnId, buf: &mut [u8]) -> Option<usize> {
        self.tm().datagram_recv(conn, buf)
    }

    // --- H3 requests (spec §3.1) ---

    /// spec §3.1: client only.
    pub fn open_h3_request(&mut self, conn: ConnId) -> Result<H3ReqId, Error> {
        let now = self.now;
        self.tm().open_h3_request(now, conn)
    }
    /// spec §3.1: all-or-error.
    pub fn h3_send_headers(
        &mut self,
        r: H3ReqId,
        hs: &[H3Header<'_>],
        fin: bool,
    ) -> Result<(), StreamError> {
        let now = self.now;
        self.tm().h3_send_headers(now, r, hs, fin)
    }
    /// spec §3.1: the `stream_send` contract.
    pub fn h3_send_body(
        &mut self,
        r: H3ReqId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        let now = self.now;
        self.tm().h3_send_body(now, r, data, fin)
    }
    /// spec §3.1: a bare FIN.
    pub fn h3_finish(&mut self, r: H3ReqId) -> Result<(), StreamError> {
        let now = self.now;
        self.tm().h3_finish(now, r)
    }
    /// spec §3.1: `Ok(fin)`.
    pub fn h3_recv_headers(
        &mut self,
        r: H3ReqId,
        each: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError> {
        let now = self.now;
        self.tm().h3_recv_headers(now, r, each)
    }
    /// spec §3.1: `(bytes, fin)`.
    pub fn h3_recv_body(
        &mut self,
        r: H3ReqId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        let now = self.now;
        self.tm().h3_recv_body(now, r, buf)
    }
    /// spec §3.1: a no-op on a stale id.
    pub fn h3_reset(&mut self, r: H3ReqId) {
        let now = self.now;
        self.tm().h3_reset(now, r)
    }
    /// spec §3.1.
    pub fn h3_req_info(&self, r: H3ReqId) -> Result<H3ReqInfo, Error> {
        self.t.h3_req_info(r)
    }

    // --- Paths (spec §5.4) ---

    /// spec §5.4: the primary UDP socket's local address.
    pub fn primary_local(&self) -> SocketAddr {
        self.st.primary_local()
    }
    /// The primary UDP socket, for re-adding a removed primary path.
    pub fn primary_udp(&self) -> UdpSocketId {
        self.st.primary_udp()
    }
    /// spec §5.4: request a UDP socket on an ephemeral port; completes in `on_udp_socket`.
    pub fn open_udp_socket(&mut self, local_ip: IpAddr) -> SocketOpId {
        self.st.open_udp_socket(local_ip)
    }
    /// SP2 spec §4.1: an app-owned UDP socket on an ephemeral port, read through
    /// `on_udp_rx` and written with `udp_send`; completes in `on_udp_socket`
    /// (`Err(Other)` at the socket cap, which it counts toward).
    pub fn open_app_udp_socket(&mut self, local_ip: IpAddr) -> SocketOpId {
        self.st.open_app_udp_socket(local_ip)
    }
    /// spec §5.4: the result, if any, is dropped and its socket closed.
    pub fn cancel_udp_socket(&mut self, op: SocketOpId) {
        self.st.cancel_udp_socket(op)
    }
    /// spec §5.4: also removes the socket's path mappings. The primary
    /// socket cannot be closed (ignored).
    pub fn close_udp_socket(&mut self, sock: UdpSocketId) {
        self.st.close_udp_socket(sock)
    }
    /// SP2 spec §4.1: queues one datagram to `dst` on an app socket's 256 KiB
    /// ring. Empty `bytes` are discarded; `SendBufFull` when `sock` is not a
    /// live app socket, `bytes` is over 65 535 or the ring is full.
    pub fn udp_send(
        &mut self,
        sock: UdpSocketId,
        dst: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), SendBufFull> {
        self.st.udp_send(sock, dst, bytes)
    }
    /// spec §5.4: creates the xquic path and maps it to `sock` in the same call.
    /// SP2 spec §4.1: `Stale` for an app socket.
    pub fn add_path(
        &mut self,
        conn: ConnId,
        sock: UdpSocketId,
        standby: bool,
    ) -> Result<PathId, PathError> {
        if !self.st.transport_udp_live(sock) {
            return Err(PathError::Stale); // no dangling mapping
        }
        let now = self.now;
        let path = self.tm().add_path(now, conn, standby)?;
        self.st.map_path(conn, path, sock);
        Ok(path)
    }

    // --- TCP, app-owned phase (spec §5.4) ---

    /// spec §5.4: unconsumed received bytes.
    pub fn tcp_rx(&self, tcp: TcpId) -> &[u8] {
        self.st.tcp_rx(tcp)
    }
    /// spec §5.4.
    pub fn tcp_consume(&mut self, tcp: TcpId, n: usize) {
        self.st.tcp_consume(tcp, n)
    }
    /// spec §5.4: queues into the 64 KiB send buffer; fails if it does not fit.
    pub fn tcp_write(&mut self, tcp: TcpId, bytes: &[u8]) -> Result<(), SendBufFull> {
        self.st.tcp_write(tcp, bytes)
    }
    /// spec §5.4: the app's read-interest flag.
    pub fn tcp_set_read(&mut self, tcp: TcpId, on: bool) {
        self.st.tcp_set_read(tcp, on)
    }
    /// spec §6.2: caps the bytes read ahead into the receive buffer (default
    /// and maximum 64 KiB); the rest stays in the kernel. `start_relay` lifts it.
    pub fn tcp_set_rx_limit(&mut self, tcp: TcpId, n: usize) {
        self.st.tcp_set_rx_limit(tcp, n)
    }
    /// spec §5.4: closes once the send buffer has drained.
    pub fn tcp_close(&mut self, tcp: TcpId) {
        self.st.tcp_close(tcp)
    }
    /// spec §5.4: resets the connection now.
    pub fn tcp_abort(&mut self, tcp: TcpId) {
        self.st.tcp_abort(tcp)
    }
    /// Disables Nagle (`TCP_NODELAY`) on an app-owned socket; a stale id is ignored.
    pub fn tcp_set_nodelay(&mut self, tcp: TcpId) {
        self.st.tcp_set_nodelay(tcp)
    }
    /// Enables TCP keepalive on an app-owned socket; a stale id is ignored.
    pub fn tcp_set_keepalive(&mut self, tcp: TcpId, ka: KeepAlive) {
        self.st.tcp_set_keepalive(tcp, ka)
    }

    // --- Relay (spec §5.4, §5.6) ---

    /// spec §5.4: hands `tcp` and `stream` to a relay.
    pub fn start_relay(
        &mut self,
        tcp: TcpId,
        stream: StreamId,
        preread: StreamPreread<'_>,
    ) -> Result<(), PrereadTooLarge> {
        // The relay needs the stream's connection (spec §5.4 `ConnClosed` sweep).
        let conn = self.t.stream_info(stream).ok().map(|i| i.conn);
        let r = self.st.start_relay(tcp, stream, conn, preread);
        if r.is_ok() && conn.is_none() {
            // Stale stream: the socket was aborted; reset what is left of it.
            let now = self.now;
            self.tm().stream_reset(now, stream);
        }
        r
    }

    // --- Dial (spec §5.4) ---

    /// spec §5.4: completes in `on_dial_result` (`DialError::Limit` at the socket cap).
    pub fn dial(&mut self, target: Target, deadline: Duration) -> DialOpId {
        self.st.dial(target, deadline)
    }
    /// spec §5.4: the result, if any, is dropped and its socket closed.
    pub fn cancel_dial(&mut self, op: DialOpId) {
        self.st.cancel_dial(op)
    }
    /// SP2 spec §4.2: resolves `target` to its first address without
    /// connecting; completes in `on_resolve_result`. No socket is allocated,
    /// so the cap does not apply.
    pub fn resolve(&mut self, target: Target, deadline: Duration) -> DialOpId {
        self.st.resolve(target, deadline)
    }
    /// SP2 spec §4.2: as `cancel_dial`: the result, if any, is dropped.
    pub fn cancel_resolve(&mut self, op: DialOpId) {
        self.st.cancel_resolve(op)
    }

    // --- Timers (spec §5.4) ---

    /// spec §5.4: fires `on_timer` at `now + after`.
    pub fn set_timer(&mut self, after: Duration) -> TimerId {
        self.st.set_timer(self.now + after)
    }
    /// spec §5.4.
    pub fn cancel_timer(&mut self, id: TimerId) {
        self.st.cancel_timer(id)
    }

    // --- Listeners, process (spec §5.4) ---

    /// spec §5.4: the listeners' accept interest (the socket cap still applies).
    pub fn set_accepting(&mut self, on: bool) {
        self.st.set_accepting(on)
    }
    /// spec §5.4: the driver stops with `code`.
    pub fn request_exit(&mut self, code: i32) {
        self.st.request_exit(code)
    }
    /// spec §5.2/§5.4: the shard's seeded RNG.
    pub fn rng(&mut self) -> &mut Rng {
        self.st.rng()
    }
}
