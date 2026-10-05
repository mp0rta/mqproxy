//! Events and transmit view (spec §4.2).

use crate::config::ConnProto;
use crate::ids::{ConnId, H3ReqId, PathId, StreamId};
use std::net::SocketAddr;

/// Transport output event (spec §4.2). `StreamReadable`, `StreamWritable`,
/// `MpReady` and `DatagramReadable` are coalesced level flags; the rest occur
/// once per object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    ConnEstablished(ConnId),
    /// `err_type` is `Unknown` for a locally initiated close.
    ConnClosed(ConnId, CloseReason),
    /// Server only.
    NewConn(ConnId, ConnProto),
    /// Peer-initiated, either role.
    NewStream(ConnId, StreamId, StreamInfo),
    StreamReadable(StreamId),
    StreamWritable(StreamId),
    StreamClosed(StreamId),
    /// The peer's RESET_STREAM code; once, raw-H3 conns only (adoption spec §3). A
    /// `StreamReadable` queued before it pops first, so a read can fail with
    /// `StreamError::Reset` before this arrives (adoption spec §4.4).
    StreamPeerReset(StreamId, u64),
    /// The peer's STOP_SENDING code; once, raw-H3 conns only (adoption spec §3).
    StreamStopSending(StreamId, u64),
    /// "A path can be created now"; may repeat.
    MpReady(ConnId),
    /// A datagram is in the connection's receive ring; drain with
    /// `datagram_recv` until `None` (spec §3.1).
    DatagramReadable(ConnId),
    /// xquic closed a path (peer abandon, path idle timeout, failed validation); the
    /// connection lives on. Re-adding a path is up to the app: no `MpReady` follows.
    PathRemoved(ConnId, PathId),
    /// Server: the peer opened a request (spec §3.1).
    H3Request(ConnId, H3ReqId),
    /// Level flags, coalesced.
    H3Readable(H3ReqId),
    H3Writable(H3ReqId),
    /// Lifecycle, once (spec §3.1).
    H3Closed(H3ReqId, Box<H3Close>),
}

/// One H3 header, borrowed (spec §3.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct H3Header<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

/// xquic request stats at close (spec §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H3ReqStats {
    pub send_body: u64,
    pub recv_body: u64,
    pub begin_us: u64,
    pub header_send_us: u64,
    pub fin_send_us: u64,
    pub fin_ack_us: u64,
    pub mp_state: i32,
    pub stream_err: i32,
    /// At most 64 bytes, copied verbatim (xquic's messages are static ASCII).
    pub close_msg: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H3Close {
    pub stats: H3ReqStats,
    /// Present iff the app had not yet consumed the request's fin AND the drain inside
    /// the close notification ended with xquic's `fin` set (a complete body); a partial
    /// body (idle timeout, CONNECTION_CLOSE, reset, local close) is never rescued (§3.7).
    pub unread: Option<Unread>,
}

/// What the close-time drain read; the fin is implied (spec §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    pub headers: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    pub body: Vec<u8>,
}

/// Facade request metadata (spec §3.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct H3ReqInfo {
    pub conn: ConnId,
    /// QUIC stream id.
    pub quic_id: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CloseReason {
    pub err_type: ErrType,
    pub code: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrType {
    Unknown,
    Transport,
    Application,
}

/// Facade stream metadata (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct StreamInfo {
    pub conn: ConnId,
    /// QUIC stream id.
    pub quic_id: u64,
    pub kind: StreamKind,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    Bidi,
    Uni,
}

/// One queued send (spec §4.2): one or more datagrams of `segment_size`
/// (the last may be shorter).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Transmit<'a> {
    pub dst: SocketAddr,
    pub segment_size: usize,
    pub payload: &'a [u8],
}
