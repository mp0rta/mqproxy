// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The TCP socket table (spec §5.2, §5.4): app-owned sockets and relays.

use super::{RELAY_BUF, Relay, ShardState, TCP_BUF};
use crate::app::{Interest, IoRequest, KeepAlive, PrereadTooLarge, SendBufFull, StreamPreread};
use crate::ids::TcpId;
use mq_transport_api::{ConnId, StreamId};

/// spec §5.4 "Phases of a TCP socket".
#[derive(Debug)]
pub(crate) enum TcpEntry {
    App(AppTcp),
    Relay(Relay),
}

/// spec §5.4: an app-owned socket.
#[derive(Debug)]
pub(crate) struct AppTcp {
    /// Receive buffer, sized to `TCP_BUF` on first read; `rx[..rx_len]` is data.
    rx: Vec<u8>,
    rx_len: usize,
    /// `tcp_set_rx_limit`: at most this much is read ahead; `TCP_BUF` by default.
    rx_limit: usize,
    /// Send buffer, at most `TCP_BUF`.
    pub(crate) tx: Vec<u8>,
    /// The app's `tcp_set_read` flag; on for a new socket.
    read: bool,
    /// spec §5.4: a read returned zero. Survives `start_relay`.
    pub(crate) read_eof: bool,
    /// `tcp_close` seen; closes once `tx` drains. The app has let go.
    pub(crate) closing: bool,
    /// spec §4: a `tcp_write` hit `SendBufFull`; `on_tcp_writable` is owed
    /// when `tx` next drains empty.
    pub(crate) want_writable: bool,
}

impl AppTcp {
    fn new() -> AppTcp {
        AppTcp {
            rx: Vec::new(),
            rx_len: 0,
            rx_limit: TCP_BUF,
            tx: Vec::new(),
            read: true,
            read_eof: false,
            closing: false,
            want_writable: false,
        }
    }

    /// spec §5.2 "Interest" for an app-owned socket.
    pub(crate) fn interest(&self) -> Interest {
        Interest {
            read: self.read && !self.read_eof && !self.closing && self.rx_len < self.rx_limit,
            write: !self.tx.is_empty(),
        }
    }
    /// Where the driver reads into; empty only while read interest is off.
    pub(crate) fn rx_space(&mut self) -> &mut [u8] {
        if !self.interest().read {
            return &mut [];
        }
        self.rx.resize(TCP_BUF, 0);
        &mut self.rx[self.rx_len..self.rx_limit]
    }
    pub(crate) fn rx_commit(&mut self, n: usize) {
        assert!(
            self.rx_len + n <= self.rx.len(),
            "rx commit past the buffer"
        );
        self.rx_len += n;
    }
}

impl ShardState {
    /// A new app-owned socket (accepted or dialled).
    pub(crate) fn insert_app_tcp(&mut self) -> TcpId {
        let id = self.alloc(TcpId::from_slot);
        self.tcp.insert(id, TcpEntry::App(AppTcp::new()));
        id
    }
    /// Registers an app-owned TCP socket (what an accept or dial does).
    #[cfg(feature = "test-support")]
    pub fn insert_tcp(&mut self) -> TcpId {
        self.insert_app_tcp()
    }

    /// App-owned and not closing: the only state in which the app may act on
    /// it. A relaying, closing or stale id is ignored.
    fn app_tcp(&mut self, tcp: TcpId) -> Option<&mut AppTcp> {
        match self.tcp.get_mut(&tcp) {
            Some(TcpEntry::App(e)) if !e.closing => Some(e),
            _ => None,
        }
    }
    /// Removes the socket and asks the driver to close it.
    pub(crate) fn close_now(&mut self, tcp: TcpId, abort: bool) {
        self.tcp.remove(&tcp);
        self.push_request(IoRequest::TcpClose { tcp, abort });
    }

    // --- spec §5.4 "TCP, app-owned phase" ---

    pub(crate) fn tcp_rx(&self, tcp: TcpId) -> &[u8] {
        match self.tcp.get(&tcp) {
            Some(TcpEntry::App(e)) if !e.closing => &e.rx[..e.rx_len],
            _ => &[],
        }
    }
    pub(crate) fn tcp_consume(&mut self, tcp: TcpId, n: usize) {
        if let Some(e) = self.app_tcp(tcp) {
            let n = n.min(e.rx_len);
            e.rx.copy_within(n..e.rx_len, 0);
            e.rx_len -= n;
        }
    }
    pub(crate) fn tcp_write(&mut self, tcp: TcpId, bytes: &[u8]) -> Result<(), SendBufFull> {
        let e = self.app_tcp(tcp).ok_or(SendBufFull)?;
        if e.tx.len() + bytes.len() > TCP_BUF {
            // An empty `tx` has nothing to drain, so waiting cannot help.
            e.want_writable |= !e.tx.is_empty();
            return Err(SendBufFull);
        }
        e.tx.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn tcp_set_read(&mut self, tcp: TcpId, on: bool) {
        if let Some(e) = self.app_tcp(tcp) {
            e.read = on;
        }
    }
    /// Caps what is read ahead (at most `TCP_BUF`); a relay has its own buffers.
    pub(crate) fn tcp_set_rx_limit(&mut self, tcp: TcpId, n: usize) {
        if let Some(e) = self.app_tcp(tcp) {
            e.rx_limit = n.min(TCP_BUF);
        }
    }
    pub(crate) fn tcp_set_nodelay(&mut self, tcp: TcpId) {
        if self.app_tcp(tcp).is_some() {
            self.push_request(IoRequest::TcpSetNodelay { tcp });
        }
    }
    pub(crate) fn tcp_set_keepalive(&mut self, tcp: TcpId, ka: KeepAlive) {
        if self.app_tcp(tcp).is_some() {
            self.push_request(IoRequest::TcpSetKeepalive { tcp, ka });
        }
    }
    /// Graceful: closes now if nothing is queued, else once `tx` drains.
    pub(crate) fn tcp_close(&mut self, tcp: TcpId) {
        if let Some(e) = self.app_tcp(tcp) {
            if e.tx.is_empty() {
                self.close_now(tcp, false);
            } else {
                e.closing = true;
            }
        }
    }
    /// Resets now; also cuts short a pending graceful close.
    pub(crate) fn tcp_abort(&mut self, tcp: TcpId) {
        if let Some(TcpEntry::App(_)) = self.tcp.get(&tcp) {
            self.close_now(tcp, true);
        }
    }

    /// spec §5.4 `start_relay`: unconsumed rx becomes the prebuffer toward
    /// QUIC, the queued reply then `preread` the prebuffer toward TCP, and the
    /// read EOF carries over. `conn` is `None` when the stream is already
    /// stale: the relay would abort at its first stream call, so the socket is
    /// aborted at once (the caller resets the stream).
    pub(crate) fn start_relay(
        &mut self,
        tcp: TcpId,
        stream: StreamId,
        conn: Option<ConnId>,
        preread: StreamPreread<'_>,
    ) -> Result<(), PrereadTooLarge> {
        if self.streams.contains_key(&stream) {
            return Err(PrereadTooLarge); // already bound to another relay
        }
        let e = self.app_tcp(tcp).ok_or(PrereadTooLarge)?;
        if e.tx.len() + preread.bytes.len() > RELAY_BUF {
            return Err(PrereadTooLarge);
        }
        let Some(conn) = conn else {
            self.close_now(tcp, true);
            return Ok(());
        };
        let relay = Relay::start(
            conn,
            tcp,
            stream,
            &e.rx[..e.rx_len],
            e.read_eof,
            &e.tx,
            preread,
        )?;
        self.tcp.insert(tcp, TcpEntry::Relay(relay));
        self.streams.insert(stream, tcp);
        Ok(())
    }
}
