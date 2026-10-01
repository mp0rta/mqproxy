//! Events and transmit view (spec §4.2).

use crate::ids::{ConnId, StreamId};
use std::net::SocketAddr;

/// Transport output event (spec §4.2). `StreamReadable`, `StreamWritable` and
/// `MpReady` are coalesced level flags; the rest occur once per object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    ConnEstablished(ConnId),
    /// `err_type` is `Unknown` for a locally initiated close.
    ConnClosed(ConnId, CloseReason),
    /// Server only.
    NewConn(ConnId),
    /// Peer-initiated, either role.
    NewStream(ConnId, StreamId, StreamInfo),
    StreamReadable(StreamId),
    StreamWritable(StreamId),
    StreamClosed(StreamId),
    /// "A path can be created now"; may repeat.
    MpReady(ConnId),
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
