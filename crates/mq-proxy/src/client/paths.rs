// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.2 "Paths": the `--path` entries after the first, each brought up as an
//! extra multipath path on its own ephemeral UDP socket; and the primary path.
//!
//! xquic closes a dead path on its own (path idle timeout, failed validation, peer
//! abandon) while the connection lives on, and raises no `MpReady` after it. A removed
//! path is re-added after a backoff: an extra path on a fresh socket, the primary on the
//! primary socket.

use super::backoff::Backoff;
use crate::config::ClientConfig;
use mq_runtime::{Cx, SocketOpId, TimerId, UdpSocketId};
use mq_transport_api::{ConnId, PathError, PathId, Scheduler};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// spec §6.2: at most 8 entries: the primary and 7 extra paths.
const MAX_CANDIDATES: usize = 8;

/// spec §6.2: a candidate's state for the current connection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Cand {
    NotStarted,
    Opening(SocketOpId),
    SocketReady(UdpSocketId),
    Active(PathId),
    /// Removed or failed; started again when the timer fires.
    Retry(TimerId),
}

struct Slot {
    /// `None`: the primary path, on the primary socket.
    ip: Option<IpAddr>,
    st: Cand,
    backoff: Backoff,
}

pub(super) struct Paths {
    slots: Vec<Slot>,
    /// spec §6.2: under the `backup` scheduler paths are added as standby.
    standby: bool,
    /// The log prefix: `mq_client` (raw tunnel) or `mq_gw_client` (gateway
    /// tunnel); SP3 spec §5.7.
    log: &'static str,
}

/// A fresh connection: the primary path is up, the others not started.
fn initial(ip: Option<IpAddr>) -> Cand {
    match ip {
        None => Cand::Active(PathId(0)),
        Some(_) => Cand::NotStarted,
    }
}

impl Paths {
    pub(super) fn new(cfg: &ClientConfig, log: &'static str) -> Paths {
        let extra = cfg.paths.iter().skip(1).map(|ip| Some(*ip));
        Paths {
            slots: std::iter::once(None)
                .chain(extra)
                .take(MAX_CANDIDATES)
                .map(|ip| Slot {
                    ip,
                    st: initial(ip),
                    backoff: Backoff::new(cfg.reconnect_max_backoff),
                })
                .collect(),
            standby: cfg.scheduler == Scheduler::Backup,
            log,
        }
    }

    /// spec §6.2: start every candidate not started; retry every socket-ready one.
    pub(super) fn on_mp_ready(&mut self, cx: &mut Cx<'_>, conn: ConnId) {
        for i in 0..self.slots.len() {
            match self.slots[i].st {
                Cand::NotStarted => self.start(cx, conn, i),
                Cand::SocketReady(sock) => self.add(cx, conn, i, sock),
                _ => {}
            }
        }
    }

    fn start(&mut self, cx: &mut Cx<'_>, conn: ConnId, i: usize) {
        match self.slots[i].ip {
            Some(ip) => self.slots[i].st = Cand::Opening(cx.open_udp_socket(ip)),
            None => {
                let sock = cx.primary_udp();
                self.add(cx, conn, i, sock);
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
        let Some(i) = self.slots.iter().position(|s| s.st == Cand::Opening(op)) else {
            // Not ours any more: dispose of the socket.
            if let Ok((sock, _)) = r {
                cx.close_udp_socket(sock);
            }
            return;
        };
        match (r, conn) {
            (Ok((sock, _)), Some(conn)) => self.add(cx, conn, i, sock),
            (Ok((sock, _)), None) => {
                cx.close_udp_socket(sock);
                self.slots[i].st = Cand::NotStarted;
            }
            (Err(k), _) => {
                let ip = self.slots[i].ip;
                log::warn!(
                    "{}: cannot open a UDP socket on {ip:?} for an extra path: {k}",
                    self.log
                );
                self.retry(cx, i);
            }
        }
    }

    /// SP3 spec §5.7: `op` opens one of this connection's candidate sockets.
    pub(super) fn owns(&self, op: SocketOpId) -> bool {
        self.slots.iter().any(|s| s.st == Cand::Opening(op))
    }

    fn add(&mut self, cx: &mut Cx<'_>, conn: ConnId, i: usize, sock: UdpSocketId) {
        let at = match self.slots[i].ip {
            Some(ip) => ip.to_string(),
            None => "the primary socket".into(),
        };
        match cx.add_path(conn, sock, self.standby) {
            Ok(p) => {
                log::info!("{}: path up: bind {at} -> path_id {}", self.log, p.0);
                self.slots[i].backoff.on_serving(cx.now());
                self.slots[i].st = Cand::Active(p);
            }
            // xquic raises MpReady again when an id is available.
            Err(PathError::NoPathId) => self.slots[i].st = Cand::SocketReady(sock),
            Err(e) => {
                log::warn!("{}: failed to add a path on {at} ({e})", self.log);
                cx.close_udp_socket(sock); // the primary is never closed
                self.retry(cx, i);
            }
        }
    }

    fn retry(&mut self, cx: &mut Cx<'_>, i: usize) {
        let rnd = cx.rng().next_u64();
        let d = self.slots[i].backoff.next_delay(cx.now(), rnd);
        self.slots[i].st = Cand::Retry(cx.set_timer(d));
    }

    /// xquic closed `path`; the shard already closed its socket (not the primary).
    pub(super) fn on_path_removed(&mut self, cx: &mut Cx<'_>, path: PathId) {
        let Some(i) = self.slots.iter().position(|s| s.st == Cand::Active(path)) else {
            return;
        };
        log::warn!(
            "{}: path_id {} removed; re-adding after a backoff",
            self.log,
            path.0
        );
        self.retry(cx, i);
    }

    /// A timer the client does not own: start its candidate again if it is ours
    /// (`false` = not ours).
    pub(super) fn on_timer(&mut self, cx: &mut Cx<'_>, conn: Option<ConnId>, id: TimerId) -> bool {
        let Some(i) = self.slots.iter().position(|s| s.st == Cand::Retry(id)) else {
            return false;
        };
        self.slots[i].st = Cand::NotStarted;
        if let Some(conn) = conn {
            self.start(cx, conn, i);
        }
        true
    }

    /// spec §6.2: the shard closed the mapped sockets; close the unmapped ones,
    /// cancel opens in flight and retries, and start every candidate again next time.
    pub(super) fn on_conn_closed(&mut self, cx: &mut Cx<'_>) {
        for s in &mut self.slots {
            match s.st {
                Cand::Opening(op) => cx.cancel_udp_socket(op),
                Cand::SocketReady(sock) => cx.close_udp_socket(sock),
                Cand::Retry(t) => cx.cancel_timer(t),
                _ => {}
            }
            s.st = initial(s.ip);
            s.backoff.reset();
        }
    }
}
