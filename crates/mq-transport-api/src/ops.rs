// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
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
    /// conn, `Err(Other)` when the peer's uni credit is exhausted,
    /// `Err(Ceiling)` at 8192 streams.
    fn open_uni(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error>;
    /// RESET_STREAM only; the receive side keeps reporting. Stale id: no-op (adoption spec §3).
    fn stream_reset_send(&mut self, now: Time, s: StreamId, code: u64);
    /// STOP_SENDING only; the receive side keeps reporting until FIN or reset is read.
    /// Stale id: no-op (adoption spec §3).
    fn stream_stop_sending(&mut self, now: Time, s: StreamId, code: u64);
    fn add_path(&mut self, now: Time, conn: ConnId, standby: bool) -> Result<PathId, PathError>;
    fn close_conn(&mut self, now: Time, conn: ConnId);
    /// CONNECTION_CLOSE carrying the HTTP/3 application code `code` (>= 0x100; xquic frames a
    /// lower code as a transport error, xqc_packet_out.c:799). Stale id: no-op (adoption spec §3).
    fn close_conn_with(&mut self, now: Time, conn: ConnId, code: u64);
    /// The app authenticated the peer: at `max_conns` the server evicts only
    /// connections never marked (spec §4.7). A no-op on a stale id.
    fn mark_conn_authed(&mut self, conn: ConnId);
    fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error>;
    /// Whether `conn` is a live conn id: the cheap liveness probe (no stats collected).
    fn conn_live(&self, conn: ConnId) -> bool;
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
    fn open_h3_request(&mut self, _: Time, _: ConnId) -> Result<H3ReqId, Error> {
        Err(Error::Role)
    }
    /// All-or-error; `Blocked` cannot occur with the vendored xquic (spec §3.1).
    fn h3_send_headers(
        &mut self,
        _: Time,
        _: H3ReqId,
        _: &[H3Header<'_>],
        _: bool,
    ) -> Result<(), StreamError> {
        Err(StreamError::Conn)
    }
    /// The `stream_send` contract: `Ok(n)` accepted, FIN only when `n == data.len()`.
    fn h3_send_body(
        &mut self,
        _: Time,
        _: H3ReqId,
        _: &[u8],
        _: bool,
    ) -> Result<usize, StreamError> {
        Err(StreamError::Conn)
    }
    /// A bare FIN (spec §3.1).
    fn h3_finish(&mut self, _: Time, _: H3ReqId) -> Result<(), StreamError> {
        Err(StreamError::Conn)
    }
    /// Drains one header section; `Ok(fin)`. `Blocked` when none is pending.
    fn h3_recv_headers(
        &mut self,
        _: Time,
        _: H3ReqId,
        _: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError> {
        Err(StreamError::Conn)
    }
    /// `(bytes, fin)`; `(0, false)` is `Blocked`.
    fn h3_recv_body(
        &mut self,
        _: Time,
        _: H3ReqId,
        _: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        Err(StreamError::Conn)
    }
    /// A no-op on a stale id.
    fn h3_reset(&mut self, _: Time, _: H3ReqId) {}
    fn h3_req_info(&self, _: H3ReqId) -> Result<H3ReqInfo, Error> {
        Err(Error::Role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    struct RawOnly;

    impl TransportOps for RawOnly {
        fn recv_datagram(&mut self, _: Time, _: SocketAddr, _: SocketAddr, _: &[u8]) {}
        fn drive(&mut self, _: Time) {}
        fn pending_transmit(&self, _: &mut Vec<TxKey>) {}
        fn peek_transmit(&mut self, _: TxKey) -> Option<Transmit<'_>> {
            None
        }
        fn transmit_done(&mut self, _: TxKey, _: usize) {}
        fn resume_pending(&self) -> bool {
            false
        }
        fn poll_event(&mut self) -> Option<Event> {
            None
        }
        fn next_timeout(&self) -> Option<Time> {
            None
        }
        fn connect(&mut self, _: Time, _: &ConnConfig) -> Result<ConnId, ConnectError> {
            unimplemented!()
        }
        fn open_stream(&mut self, _: Time, _: ConnId) -> Result<StreamId, Error> {
            unimplemented!()
        }
        fn stream_send(
            &mut self,
            _: Time,
            _: StreamId,
            _: &[u8],
            _: bool,
        ) -> Result<usize, StreamError> {
            unimplemented!()
        }
        fn stream_recv(
            &mut self,
            _: Time,
            _: StreamId,
            _: &mut [u8],
        ) -> Result<(usize, bool), StreamError> {
            unimplemented!()
        }
        fn stream_reset(&mut self, _: Time, _: StreamId) {}
        fn open_uni(&mut self, _: Time, _: ConnId) -> Result<StreamId, Error> {
            unimplemented!()
        }
        fn stream_reset_send(&mut self, _: Time, _: StreamId, _: u64) {}
        fn stream_stop_sending(&mut self, _: Time, _: StreamId, _: u64) {}
        fn add_path(&mut self, _: Time, _: ConnId, _: bool) -> Result<PathId, PathError> {
            unimplemented!()
        }
        fn close_conn(&mut self, _: Time, _: ConnId) {}
        fn close_conn_with(&mut self, _: Time, _: ConnId, _: u64) {}
        fn mark_conn_authed(&mut self, _: ConnId) {}
        fn conn_stats(&self, _: ConnId) -> Result<ConnStats, Error> {
            unimplemented!()
        }
        fn conn_live(&self, _: ConnId) -> bool {
            false
        }
        fn stream_info(&self, _: StreamId) -> Result<StreamInfo, Error> {
            unimplemented!()
        }
        fn datagram_send(&mut self, _: Time, _: ConnId, _: &[u8]) -> Result<(), DatagramError> {
            unimplemented!()
        }
        fn datagram_mss(&self, _: ConnId) -> usize {
            0
        }
        fn datagram_recv(&mut self, _: ConnId, _: &mut [u8]) -> Option<usize> {
            None
        }
    }

    #[test]
    fn raw_transport_h3_defaults() {
        let mut transport = RawOnly;
        let request = H3ReqId::from_slot(crate::ids::SlotId::new(0, 1)).unwrap();
        let conn = ConnId::from_slot(crate::ids::SlotId::new(0, 1)).unwrap();
        assert_eq!(
            transport.open_h3_request(Time::ZERO, conn),
            Err(Error::Role)
        );
        assert_eq!(
            transport.h3_send_headers(Time::ZERO, request, &[], false),
            Err(StreamError::Conn)
        );
        assert_eq!(
            transport.h3_send_body(Time::ZERO, request, &[], false),
            Err(StreamError::Conn)
        );
        assert_eq!(
            transport.h3_finish(Time::ZERO, request),
            Err(StreamError::Conn)
        );
        assert_eq!(
            transport.h3_recv_headers(Time::ZERO, request, &mut |_, _| {}),
            Err(StreamError::Conn)
        );
        assert_eq!(
            transport.h3_recv_body(Time::ZERO, request, &mut []),
            Err(StreamError::Conn)
        );
        transport.h3_reset(Time::ZERO, request);
        assert_eq!(transport.h3_req_info(request), Err(Error::Role));
    }
}
