//! The transport seam (spec §5.1): §4.2 minus `new`/`close`.
//! Object-safe, so `Cx` can hold `&mut dyn TransportOps`.

use crate::config::{ConnConfig, ConnStats};
use crate::error::{ConnectError, DatagramError, Error, PathError, StreamError};
use crate::event::{Event, H3Header, H3ReqInfo, StreamInfo, Transmit};
use crate::ids::{ConnId, H3ReqId, PathId, StreamId, TxKey};
use crate::time::Time;
use std::net::SocketAddr;

/// Everything the shard and apps see of a transport (spec §4.2, §5.1).
/// After any `&mut self` call, drain events/transmits and re-read
/// `next_timeout` (spec §4.2, §4.3).
pub trait TransportOps {
    // input
    /// Feed one received datagram; xquic finds conn and path from the CID.
    fn recv_datagram(&mut self, now: Time, local: SocketAddr, peer: SocketAddr, data: &[u8]);
    /// Scheduled entry point: timers, deferred processing, resumption.
    fn drive(&mut self, now: Time);

    // output
    /// Append the keys that have queued data.
    fn pending_transmit(&self, out: &mut Vec<TxKey>);
    fn peek_transmit(&mut self, key: TxKey) -> Option<Transmit<'_>>;
    /// `datagrams` of the peeked transmit were sent.
    fn transmit_done(&mut self, key: TxKey, datagrams: usize);
    /// A blocked conn can be resumed by `drive`.
    fn resume_pending(&self) -> bool;
    fn poll_event(&mut self) -> Option<Event>;
    fn next_timeout(&self) -> Option<Time>;

    // operations
    fn connect(&mut self, now: Time, cfg: &ConnConfig) -> Result<ConnId, ConnectError>;
    /// Client only: a server-role transport returns `Error::Role`, a conn at
    /// the 8192-slot ceiling `Error::Ceiling` (spec §4.2).
    fn open_stream(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error>;
    /// `Ok(n)` accepted bytes; FIN committed only when `n == data.len()`.
    fn stream_send(
        &mut self,
        now: Time,
        s: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError>;
    /// `(bytes, fin)`. An empty `buf` is a reset probe (spec §4.2).
    fn stream_recv(
        &mut self,
        now: Time,
        s: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError>;
    fn stream_reset(&mut self, now: Time, s: StreamId);
    /// A local unidirectional stream, either role (adoption spec §3). `Err(Stale)` for a dead
    /// conn, `Err(Other)` on an xqc_h3 conn or when the peer's uni credit is exhausted,
    /// `Err(Ceiling)` at 8192 streams.
    fn open_uni(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error>;
    /// RESET_STREAM only; the receive side keeps reporting. Stale id: no-op (adoption spec §3).
    fn stream_reset_send(&mut self, now: Time, s: StreamId, code: u64);
    /// STOP_SENDING only; the receive side keeps reporting until FIN or reset is read.
    /// Stale id: no-op (adoption spec §3).
    fn stream_stop_sending(&mut self, now: Time, s: StreamId, code: u64);
    fn add_path(&mut self, now: Time, conn: ConnId, standby: bool) -> Result<PathId, PathError>;
    fn close_conn(&mut self, now: Time, conn: ConnId);
    /// The app authenticated the peer: at `max_conns` the server evicts only
    /// connections never marked (spec §4.7). A no-op on a stale id.
    fn mark_conn_authed(&mut self, conn: ConnId);
    fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error>;
    fn stream_info(&self, s: StreamId) -> Result<StreamInfo, Error>;

    // datagrams (spec §3.1)
    /// One QUIC DATAGRAM; every error means the datagram was dropped.
    fn datagram_send(&mut self, now: Time, conn: ConnId, data: &[u8]) -> Result<(), DatagramError>;
    /// Largest payload `datagram_send` takes now; 0 = unsupported/unknown.
    fn datagram_mss(&self, conn: ConnId) -> usize;
    /// Oldest received datagram into `buf` (`buf.len() >= 65535`); `None` = ring empty / stale.
    fn datagram_recv(&mut self, conn: ConnId, buf: &mut [u8]) -> Option<usize>;

    // H3 requests (spec §3.1)
    /// Client only: a server-role transport returns `Error::Role`.
    fn open_h3_request(&mut self, now: Time, conn: ConnId) -> Result<H3ReqId, Error>;
    /// All-or-error; `Blocked` cannot occur with the vendored xquic (spec §3.1).
    fn h3_send_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        hs: &[H3Header<'_>],
        fin: bool,
    ) -> Result<(), StreamError>;
    /// The `stream_send` contract: `Ok(n)` accepted, FIN only when `n == data.len()`.
    fn h3_send_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError>;
    /// A bare FIN (spec §3.1).
    fn h3_finish(&mut self, now: Time, r: H3ReqId) -> Result<(), StreamError>;
    /// Drains one header section; `Ok(fin)`. `Blocked` when none is pending.
    fn h3_recv_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        each: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError>;
    /// `(bytes, fin)`; `(0, false)` is `Blocked`.
    fn h3_recv_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError>;
    /// A no-op on a stale id.
    fn h3_reset(&mut self, now: Time, r: H3ReqId);
    fn h3_req_info(&self, r: H3ReqId) -> Result<H3ReqInfo, Error>;
}
