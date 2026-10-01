//! The transport seam (spec §5.1): §4.2 minus `new`/`close`/`enable_qlog`.
//! Object-safe, so `Cx` can hold `&mut dyn TransportOps`.

use crate::config::{ConnConfig, ConnStats};
use crate::error::{ConnectError, Error, PathError, StreamError};
use crate::event::{Event, StreamInfo, Transmit};
use crate::ids::{ConnId, PathId, StreamId, TxKey};
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
    fn add_path(&mut self, now: Time, conn: ConnId, standby: bool) -> Result<PathId, PathError>;
    fn close_conn(&mut self, now: Time, conn: ConnId);
    fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error>;
    fn stream_info(&self, s: StreamId) -> Result<StreamInfo, Error>;
}
