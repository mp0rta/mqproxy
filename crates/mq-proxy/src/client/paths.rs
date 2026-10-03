//! spec §6.2 "Paths": the `--path` entries after the first, each brought up as an
//! extra multipath path on its own ephemeral UDP socket.

use crate::config::ClientConfig;
use mq_runtime::{Cx, SocketOpId, UdpSocketId};
use mq_transport_api::{ConnId, PathError, Scheduler};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// spec §6.2: at most 8 entries, so at most 7 candidates.
const MAX_CANDIDATES: usize = 7;

/// spec §6.2: a candidate's state for the current connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Cand {
    NotStarted,
    Opening(SocketOpId),
    SocketReady(UdpSocketId),
    Active,
    /// Given up for this connection.
    Failed,
}

pub(super) struct Paths {
    cands: Vec<(IpAddr, Cand)>,
    /// spec §6.2: under the `backup` scheduler paths are added as standby.
    standby: bool,
}

impl Paths {
    pub(super) fn new(cfg: &ClientConfig) -> Paths {
        Paths {
            cands: cfg
                .paths
                .iter()
                .skip(1)
                .take(MAX_CANDIDATES)
                .map(|ip| (*ip, Cand::NotStarted))
                .collect(),
            standby: cfg.scheduler == Scheduler::Backup,
        }
    }

    /// spec §6.2: start every candidate not started; retry every socket-ready one.
    pub(super) fn on_mp_ready(&mut self, cx: &mut Cx<'_>, conn: ConnId) {
        for i in 0..self.cands.len() {
            match self.cands[i].1 {
                Cand::NotStarted => {
                    self.cands[i].1 = Cand::Opening(cx.open_udp_socket(self.cands[i].0));
                }
                Cand::SocketReady(sock) => self.add(cx, conn, i, sock),
                _ => {}
            }
        }
    }

    /// spec §6.2: a socket opened (or failed to); `conn` is the live connection.
    pub(super) fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        conn: Option<ConnId>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        let Some(i) = self.cands.iter().position(|c| c.1 == Cand::Opening(op)) else {
            // Not ours any more: dispose of the socket.
            if let Ok((sock, _)) = r {
                cx.close_udp_socket(sock);
            }
            return;
        };
        let ip = self.cands[i].0;
        match (r, conn) {
            (Ok((sock, _)), Some(conn)) => self.add(cx, conn, i, sock),
            (Ok((sock, _)), None) => {
                cx.close_udp_socket(sock);
                self.cands[i].1 = Cand::NotStarted;
            }
            (Err(k), _) => {
                log::warn!("mq_client: cannot open a UDP socket on {ip} for an extra path: {k}");
                self.cands[i].1 = Cand::Failed;
            }
        }
    }

    /// SP3 spec §5.7: `op` opens one of this connection's candidate sockets.
    pub(super) fn owns(&self, op: SocketOpId) -> bool {
        self.cands.iter().any(|c| c.1 == Cand::Opening(op))
    }

    fn add(&mut self, cx: &mut Cx<'_>, conn: ConnId, i: usize, sock: UdpSocketId) {
        let ip = self.cands[i].0;
        self.cands[i].1 = match cx.add_path(conn, sock, self.standby) {
            Ok(p) => {
                log::info!("mq_client: extra path up: bind {ip} -> path_id {}", p.0);
                Cand::Active
            }
            // xquic raises MpReady again when an id is available.
            Err(PathError::NoPathId) => Cand::SocketReady(sock),
            Err(e) => {
                log::warn!("mq_client: failed to add extra path bind {ip} ({e})");
                cx.close_udp_socket(sock);
                Cand::Failed
            }
        };
    }

    /// spec §6.2: the shard closed the mapped sockets; close the unmapped ones,
    /// cancel opens in flight, and start every candidate again next time.
    pub(super) fn on_conn_closed(&mut self, cx: &mut Cx<'_>) {
        for (_, c) in &mut self.cands {
            match *c {
                Cand::Opening(op) => cx.cancel_udp_socket(op),
                Cand::SocketReady(sock) => cx.close_udp_socket(sock),
                _ => {}
            }
            *c = Cand::NotStarted;
        }
    }
}
