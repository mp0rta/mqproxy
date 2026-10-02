//! The shard's inputs, called by the driver (spec §5.2 "Inputs").

use super::tcp::TcpEntry;
use super::{Shard, TxRing, UdpEntry, UdpOwner};
use crate::app::{AcceptMeta, App, DialError, IoResult, TcpEnd};
use crate::ids::{DialOpId, ListenerId, SocketOpId, TcpId, UdpSocketId};
use mq_transport_api::{Time, TransportOps};
use std::io;
use std::net::SocketAddr;

impl<T: TransportOps, A: App> Shard<T, A> {
    /// spec §5.2: a datagram on `sock`, fed to the transport with that socket's
    /// local address; SP2 spec §4.1: an app socket's goes to `App::on_udp_rx`.
    pub fn on_udp_rx(&mut self, now: Time, sock: UdpSocketId, peer: SocketAddr, data: &[u8]) {
        match self.st.udp.get(&sock) {
            Some(UdpEntry {
                local,
                owner: UdpOwner::Transport,
            }) => {
                self.transport.recv_datagram(now, *local, peer, data);
                self.st.touch();
            }
            Some(_) => self.call_app(now, |a, cx| a.on_udp_rx(cx, sock, peer, data)),
            None => {}
        }
    }

    /// spec §5.2: `None` at the socket cap (or for an unknown listener); the
    /// driver closes the socket.
    pub fn on_accepted(&mut self, now: Time, l: ListenerId, meta: AcceptMeta) -> Option<TcpId> {
        let tag = *self.listeners.get(&l)?;
        if self.st.at_cap() {
            return None;
        }
        let tcp = self.st.insert_app_tcp();
        self.call_app(now, |a, cx| a.on_accepted(cx, tag, tcp, meta));
        Some(tcp)
    }

    /// spec §5.2: where the driver reads into. Empty only when read interest is off.
    pub fn tcp_rx_buf(&mut self, tcp: TcpId) -> &mut [u8] {
        match self.st.tcp.get_mut(&tcp) {
            Some(TcpEntry::App(e)) => e.rx_space(),
            Some(TcpEntry::Relay(r)) if r.tcp_interest().read => r.tcp_rx_space(),
            _ => &mut [],
        }
    }

    /// spec §5.2/§5.4: a relaying socket forwards toward the stream at once;
    /// an app-owned one is told through `on_tcp_data` / `on_tcp_end`. EOF
    /// comes only from `IoResult::Eof` (a zero read).
    pub fn tcp_rx_commit(&mut self, now: Time, tcp: TcpId, r: IoResult) {
        match self.st.tcp.get_mut(&tcp) {
            Some(TcpEntry::Relay(rel)) => {
                rel.tcp_rx_commit(r, &mut self.transport, now);
                self.st.touch();
                self.settle_relay(now, tcp);
            }
            Some(TcpEntry::App(e)) if !e.closing => match r {
                IoResult::Bytes(0) | IoResult::WouldBlock => {}
                IoResult::Bytes(n) => {
                    e.rx_commit(n);
                    self.call_app(now, |a, cx| a.on_tcp_data(cx, tcp));
                }
                IoResult::Eof => {
                    e.read_eof = true;
                    self.call_app(now, |a, cx| a.on_tcp_end(cx, tcp, TcpEnd::ReadEof));
                }
                IoResult::Error(kind) => self.on_tcp_error(now, tcp, kind),
            },
            _ => {}
        }
    }

    /// spec §5.2: what the driver writes from.
    pub fn tcp_tx_buf(&self, tcp: TcpId) -> &[u8] {
        match self.st.tcp.get(&tcp) {
            Some(TcpEntry::App(e)) => &e.tx,
            Some(TcpEntry::Relay(r)) => r.tcp_tx_data(),
            None => &[],
        }
    }

    /// spec §5.2: bytes written. A graceful close waiting on the send buffer
    /// completes when it drains.
    pub fn tcp_tx_commit(&mut self, now: Time, tcp: TcpId, r: IoResult) {
        match self.st.tcp.get_mut(&tcp) {
            Some(TcpEntry::Relay(rel)) => {
                rel.tcp_tx_commit(r);
                self.settle_relay(now, tcp);
            }
            Some(TcpEntry::App(e)) => match r {
                IoResult::Bytes(n) => {
                    e.tx.drain(..n.min(e.tx.len()));
                    if e.closing && e.tx.is_empty() {
                        self.st.close_now(tcp, false);
                    }
                }
                IoResult::WouldBlock => {}
                // A write cannot return EOF; treated as an error.
                IoResult::Eof => self.on_tcp_error(now, tcp, io::ErrorKind::WriteZero),
                IoResult::Error(kind) => self.on_tcp_error(now, tcp, kind),
            },
            None => {}
        }
    }

    /// spec §5.2: `EPOLLERR`. Terminal: the socket is closed (reset) and the
    /// id is dead. An app-owned socket's app is told unless it already let go
    /// (`tcp_close`); a relay resets its stream.
    pub fn on_tcp_error(&mut self, now: Time, tcp: TcpId, kind: io::ErrorKind) {
        match self.st.tcp.get_mut(&tcp) {
            Some(TcpEntry::Relay(rel)) => {
                rel.tcp_tx_commit(IoResult::Error(kind));
                self.settle_relay(now, tcp);
            }
            Some(TcpEntry::App(e)) => {
                let notify = !e.closing;
                self.st.close_now(tcp, true);
                if notify {
                    self.call_app(now, |a, cx| a.on_tcp_end(cx, tcp, TcpEnd::Error(kind)));
                }
            }
            None => {}
        }
    }

    /// spec §5.2: `None` when the dial had been cancelled (or failed); the
    /// driver then closes any socket.
    pub fn on_dial_result(
        &mut self,
        now: Time,
        op: DialOpId,
        r: Result<SocketAddr, DialError>,
    ) -> Option<TcpId> {
        if !self.st.dials.remove(&op) {
            return None;
        }
        match r {
            Ok(_) => {
                let tcp = self.st.insert_app_tcp();
                self.call_app(now, |a, cx| a.on_dial_result(cx, op, Ok(tcp)));
                Some(tcp)
            }
            Err(e) => {
                self.call_app(now, |a, cx| a.on_dial_result(cx, op, Err(e)));
                None
            }
        }
    }

    /// spec §5.2: `None` when the open had been cancelled (or failed). SP2
    /// spec §4.1: an app open's cap reservation becomes the socket or is released.
    pub fn on_udp_socket(
        &mut self,
        now: Time,
        op: SocketOpId,
        r: Result<SocketAddr, io::ErrorKind>,
    ) -> Option<UdpSocketId> {
        if !self.st.socket_ops.remove(&op) {
            return None;
        }
        let app = self.st.app_udp_ops.remove(&op);
        match r {
            Ok(local) => {
                let sock = self.st.alloc(UdpSocketId::from_slot);
                let owner = if app {
                    UdpOwner::App(TxRing::new())
                } else {
                    UdpOwner::Transport
                };
                self.st.udp.insert(sock, UdpEntry { local, owner });
                self.call_app(now, |a, cx| a.on_udp_socket(cx, op, Ok((sock, local))));
                Some(sock)
            }
            Err(k) => {
                self.call_app(now, |a, cx| a.on_udp_socket(cx, op, Err(k)));
                None
            }
        }
    }

    /// spec §5.2: SIGTERM/SIGINT; calls `App::on_shutdown`.
    pub fn on_shutdown_signal(&mut self, now: Time) {
        self.call_app(now, |a, cx| a.on_shutdown(cx));
    }
}
