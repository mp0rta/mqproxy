//! Event routing (spec §5.2 `drive` step 3, §5.4 "Event routing") and UDP
//! socket selection (spec §5.2 "UDP socket selection").

use super::tcp::TcpEntry;
use super::{Shard, ShardState};
use crate::app::{App, IoRequest};
use crate::ids::{TcpId, UdpSocketId};
use mq_transport_api::{ConnId, Event, PathId, Time, Transmit, TransportOps, TxKey};
use std::collections::BTreeSet;

impl ShardState {
    /// spec §5.2 "UDP socket selection": the socket mapped to (conn, path), if any.
    pub fn path_socket(&self, conn: ConnId, path: PathId) -> Option<UdpSocketId> {
        self.paths.get(&(conn, path)).copied()
    }
    pub(crate) fn map_path(&mut self, conn: ConnId, path: PathId, sock: UdpSocketId) {
        self.paths.insert((conn, path), sock);
    }
    /// A queue with no mapping uses the primary socket.
    fn socket_for(&self, key: TxKey) -> UdpSocketId {
        key.0
            .and_then(|c| self.path_socket(c, key.1))
            .unwrap_or(self.primary_udp)
    }
    /// spec §5.4 `close_udp_socket`: drops the socket's mappings and asks the
    /// driver to close it. The primary socket and unknown ids are ignored.
    pub(crate) fn close_udp_socket(&mut self, sock: UdpSocketId) {
        if sock == self.primary_udp || self.udp.remove(&sock).is_none() {
            return;
        }
        self.paths.retain(|_, s| *s != sock);
        self.tx_cursor.remove(&sock);
        self.push_request(IoRequest::CloseUdpSocket { sock });
    }
    /// spec §5.2: on `ConnClosed`, remove the connection's mappings and close
    /// each mapped socket other than the primary.
    fn close_conn_sockets(&mut self, conn: ConnId) {
        let socks: BTreeSet<UdpSocketId> = self
            .paths
            .iter()
            .filter(|((c, _), _)| *c == conn)
            .map(|(_, s)| *s)
            .collect();
        self.paths.retain(|(c, _), _| *c != conn);
        for sock in socks {
            self.close_udp_socket(sock);
        }
    }
}

impl<T: TransportOps, A: App> Shard<T, A> {
    /// spec §5.2 step 3: stream events to the relay owning the stream, late
    /// events for a closed relay dropped, everything else to the app.
    /// `ConnClosed` first closes the connection's relays and sockets.
    pub(super) fn dispatch_events(&mut self, now: Time) {
        while let Some(ev) = self.transport.poll_event() {
            match &ev {
                Event::StreamReadable(s) | Event::StreamWritable(s) | Event::StreamClosed(s) => {
                    if let Some(&tcp) = self.st.streams.get(s) {
                        if let Some(TcpEntry::Relay(r)) = self.st.tcp.get_mut(&tcp) {
                            r.on_stream_event(&ev);
                        }
                        self.settle_relay(now, tcp);
                        continue;
                    }
                    if self.st.dead_streams.contains_key(s) {
                        if matches!(ev, Event::StreamClosed(_)) {
                            self.st.dead_streams.remove(s);
                        }
                        continue;
                    }
                }
                Event::ConnClosed(c, _) => {
                    let swept: Vec<TcpId> = self
                        .st
                        .tcp
                        .iter_mut()
                        .filter_map(|(id, e)| match e {
                            TcpEntry::Relay(r) if r.conn == *c => {
                                r.on_stream_event(&ev);
                                Some(*id)
                            }
                            _ => None,
                        })
                        .collect();
                    for tcp in swept {
                        self.settle_relay(now, tcp);
                    }
                    self.st.dead_streams.retain(|_, conn| conn != c);
                    self.st.close_conn_sockets(*c);
                }
                _ => {}
            }
            self.call_app(now, |a, cx| a.on_transport_event(cx, ev));
        }
    }

    fn tx_keys(&self) -> Vec<TxKey> {
        let mut keys = Vec::new();
        self.transport.pending_transmit(&mut keys);
        keys
    }

    /// spec §5.2: the sockets with something to send.
    pub fn pending_transmit(&self) -> impl Iterator<Item = UdpSocketId> + '_ {
        let socks: BTreeSet<UdpSocketId> = self
            .tx_keys()
            .into_iter()
            .map(|k| self.st.socket_for(k))
            .collect();
        socks.into_iter()
    }

    /// spec §5.2: the next transmit for `sock`, serving the queues mapped to
    /// it in turn.
    pub fn peek_transmit(&mut self, sock: UdpSocketId) -> Option<Transmit<'_>> {
        let mut keys: Vec<TxKey> = self
            .tx_keys()
            .into_iter()
            .filter(|k| self.st.socket_for(*k) == sock)
            .collect();
        keys.sort();
        let last = self.st.tx_cursor.get(&sock);
        let key = last
            .and_then(|l| keys.iter().find(|k| *k > l))
            .or(keys.first())
            .copied()?;
        self.st.tx_cursor.insert(sock, key);
        self.transport.peek_transmit(key)
    }

    /// spec §5.2: `datagrams` of the last peeked transmit of `sock` were sent.
    pub fn transmit_done(&mut self, sock: UdpSocketId, datagrams: usize) {
        if let Some(&key) = self.st.tx_cursor.get(&sock) {
            self.transport.transmit_done(key, datagrams);
        }
    }
}
