// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Event routing (spec §5.2 `drive` step 3, §5.4 "Event routing") and UDP
//! socket selection (spec §5.2 "UDP socket selection").

use super::tcp::TcpEntry;
use super::{Shard, ShardState, TxRing, UdpEntry, UdpOwner};
use crate::app::{App, IoRequest, SendBufFull};
use crate::ids::{TcpId, UdpSocketId};
use mq_transport_api::{ConnId, Event, PathId, Time, Transmit, TransportOps, TxKey};
use std::collections::BTreeSet;
use std::net::SocketAddr;

impl ShardState {
    /// spec §5.2 "UDP socket selection": the socket mapped to (conn, path), if any.
    pub fn path_socket(&self, conn: ConnId, path: PathId) -> Option<UdpSocketId> {
        self.paths.get(&(conn, path)).copied()
    }
    /// A live transport-owned UDP socket (the primary included).
    pub(crate) fn transport_udp_live(&self, sock: UdpSocketId) -> bool {
        matches!(
            self.udp.get(&sock),
            Some(UdpEntry {
                owner: UdpOwner::Transport,
                ..
            })
        )
    }
    fn app_ring(&mut self, sock: UdpSocketId) -> Option<&mut TxRing> {
        match self.udp.get_mut(&sock) {
            Some(UdpEntry {
                owner: UdpOwner::App(ring),
                ..
            }) => Some(ring),
            _ => None,
        }
    }
    /// SP2 spec §4.1: one record on an app socket's ring; `SendBufFull` (ring
    /// untouched) when `sock` is not a live app socket, `bytes` is over 65 535
    /// or the record does not fit.
    pub(crate) fn udp_send(
        &mut self,
        sock: UdpSocketId,
        dst: SocketAddr,
        bytes: &[u8],
    ) -> Result<(), SendBufFull> {
        let ring = self.app_ring(sock).ok_or(SendBufFull)?;
        if bytes.is_empty() {
            // `udp_tx` neither sends nor consumes a zero-length record.
            // ponytail: zero-length target send dropped; teach udp_tx a one-empty-datagram record if a user needs it
            return Ok(());
        }
        ring.push(dst, bytes)
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
    /// driver to close it; an app socket's ring goes with it (SP2 spec §4.1).
    /// The primary socket and unknown ids are ignored.
    pub(crate) fn close_udp_socket(&mut self, sock: UdpSocketId) {
        if sock == self.primary_udp || self.udp.remove(&sock).is_none() {
            return;
        }
        self.paths.retain(|_, s| *s != sock);
        self.tx_cursor.remove(&sock);
        self.push_request(IoRequest::CloseUdpSocket { sock });
    }
    /// On `PathRemoved`: drop the path's mapping and close its socket unless
    /// it is the primary.
    fn close_path_socket(&mut self, conn: ConnId, path: PathId) {
        if let Some(sock) = self.paths.remove(&(conn, path)) {
            self.close_udp_socket(sock);
        }
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
        // ponytail: a socket also mapped by another connection is closed too
        // (spec §5.2 says "each mapped socket"); refcount if sockets get shared.
        for sock in socks {
            self.close_udp_socket(sock);
        }
    }
}

impl<T: TransportOps, A: App> Shard<T, A> {
    /// spec §5.2 step 3: stream events to the relay owning the stream, late
    /// events for a closed relay dropped, everything else to the app.
    /// `ConnClosed` first closes the connection's relays and sockets.
    /// A dead stream's entry goes once its `StreamClosed` has been seen —
    /// at the end of this pass, so a stray event behind it in the same pass
    /// is still dropped.
    pub(super) fn dispatch_events(&mut self, now: Time) {
        let mut closed = Vec::new();
        while let Some(ev) = self.transport.poll_event() {
            match &ev {
                Event::StreamReadable(s) | Event::StreamWritable(s) | Event::StreamClosed(s) => {
                    if let Some(&tcp) = self.st.streams.get(s) {
                        if let Some(TcpEntry::Relay(r)) = self.st.tcp.get_mut(&tcp) {
                            r.on_stream_event(&ev);
                        }
                        self.settle_relay(now, tcp);
                    } else if !self.st.dead_streams.contains_key(s) {
                        self.call_app(now, |a, cx| a.on_transport_event(cx, ev));
                        continue;
                    }
                    // Relay-owned or late for a closed relay: never the app's.
                    if matches!(ev, Event::StreamClosed(_)) {
                        closed.push(*s);
                    }
                    continue;
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
                Event::PathRemoved(c, path) => self.st.close_path_socket(*c, *path),
                _ => {}
            }
            self.call_app(now, |a, cx| a.on_transport_event(cx, ev));
        }
        for s in closed {
            self.st.dead_streams.remove(&s);
        }
    }

    fn tx_keys(&self) -> Vec<TxKey> {
        let mut keys = Vec::new();
        self.transport.pending_transmit(&mut keys);
        keys
    }

    /// spec §5.2: the sockets with something to send; SP2 spec §4.1: app
    /// sockets whose ring is not empty.
    // ponytail: O(UDP sockets) per call, and the driver calls it twice per loop iteration; keep a dirty set of non-empty app rings if ~1k server sessions make it measurable.
    pub fn pending_transmit(&self) -> impl Iterator<Item = UdpSocketId> + '_ {
        let mut socks: BTreeSet<UdpSocketId> = self
            .tx_keys()
            .into_iter()
            .map(|k| self.st.socket_for(k))
            .collect();
        socks.extend(self.st.udp.iter().filter_map(|(s, e)| match &e.owner {
            UdpOwner::App(ring) if !ring.is_empty() => Some(*s),
            _ => None,
        }));
        socks.into_iter()
    }

    /// spec §5.2: the next transmit for `sock`, serving the queues mapped to
    /// it in turn. SP2 spec §4.1: an app socket's oldest record, as exactly one datagram.
    pub fn peek_transmit(&mut self, sock: UdpSocketId) -> Option<Transmit<'_>> {
        if let Some(UdpEntry {
            owner: UdpOwner::App(ring),
            ..
        }) = self.st.udp.get(&sock)
        {
            // ponytail: one record per peek; coalesce same-dst same-len runs (≤ MTU) into a GSO batch if the UDP bench shows the syscall rate matters
            return ring.peek().map(|(dst, payload)| Transmit {
                dst,
                segment_size: payload.len(),
                payload,
            });
        }
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

    /// spec §5.2: `datagrams` of the last peeked transmit of `sock` were sent
    /// (SP2 spec §4.1: 0 or 1 records of an app socket).
    pub fn transmit_done(&mut self, sock: UdpSocketId, datagrams: usize) {
        if let Some(ring) = self.st.app_ring(sock) {
            for _ in 0..datagrams {
                ring.pop();
            }
        } else if let Some(&key) = self.st.tx_cursor.get(&sock) {
            self.transport.transmit_done(key, datagrams);
        }
    }
}
