//! SP4 spec §3 (layer ③): the H3 tunnel connection shared by the client's H3
//! fronts — connect, reconnect with backoff, extra paths, metrics, shutdown.
//! Extracted from SP3's gateway (SP3 spec §5.7); log lines are unchanged.

use super::backoff::Backoff;
use super::paths::Paths;
use super::{SNI, log_conn_metrics};
use crate::config::ClientConfig;
use mq_runtime::{Cx, SocketOpId, TimerId, UdpSocketId};
use mq_transport_api::{ConnConfig, ConnId, ConnProto, Event};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// SP3 spec §5.7: the H3 tunnel connection.
pub struct H3Tunnel {
    server: SocketAddr,
    keepalive_idle: Option<Duration>,
    reconnect_enabled: bool,
    conn: Option<ConnId>,
    up: bool,
    backoff: Backoff,
    paths: Paths,
    reconnect: Option<TimerId>,
    shutting_down: bool,
}

impl H3Tunnel {
    pub fn new(cfg: &ClientConfig) -> H3Tunnel {
        H3Tunnel {
            server: cfg.server,
            keepalive_idle: cfg.keepalive_idle,
            reconnect_enabled: cfg.reconnect,
            conn: None,
            up: false,
            backoff: Backoff::new(cfg.reconnect_max_backoff),
            paths: Paths::new(cfg, "mq_gw_client"),
            reconnect: None,
            shutting_down: false,
        }
    }

    /// SP3 spec §5.7: the one tunnel connection, when established (the seam for
    /// a future route/policy/pool, §1.2).
    pub fn pick_conn(&self) -> Option<ConnId> {
        self.conn.filter(|_| self.up)
    }

    /// SP3 spec §5.9: no tunnel connection and none coming (shut down or
    /// `--no-reconnect` terminal).
    pub fn gone(&self) -> bool {
        self.conn.is_none() && self.reconnect.is_none()
    }

    /// SP3 spec §5.7: connect the tunnel; `false` on a synchronous failure.
    fn connect(&mut self, cx: &mut Cx<'_>) -> bool {
        let cc = ConnConfig {
            peer: self.server,
            sni: SNI,
            idle_timeout: self.keepalive_idle,
            proto: ConnProto::H3,
        };
        match cx.connect(&cc) {
            Ok(c) => {
                self.conn = Some(c);
                true
            }
            Err(_) => {
                log::error!("mq_gw_client: tunnel connect failed");
                false
            }
        }
    }

    /// SP3 spec §5.7: the next attempt after the SP1 backoff.
    fn arm_reconnect(&mut self, cx: &mut Cx<'_>) {
        let rnd = cx.rng().next_u64();
        let d = self.backoff.next_delay(cx.now(), rnd);
        log::info!("mq_gw_client: reconnecting in {} ms", d.as_millis());
        self.reconnect = Some(cx.set_timer(d));
    }

    /// SP3 spec §5.7: eager; the first failure is fatal.
    pub fn on_start(&mut self, cx: &mut Cx<'_>) {
        if !self.connect(cx) {
            cx.request_exit(1);
        }
    }

    /// SP3 spec §5.8: `None` when the event was the tunnel's. The H3 request
    /// events pass through to the front that owns the request.
    pub fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) -> Option<Event> {
        let mine = self.conn;
        match ev {
            Event::ConnEstablished(c) if mine == Some(c) => {
                self.up = true;
                self.backoff.reset();
                if let Some(t) = self.reconnect.take() {
                    cx.cancel_timer(t);
                }
                log::info!("mq_gw_client: tunnel conn established");
            }
            Event::ConnClosed(c, _) if mine == Some(c) => {
                self.up = false;
                self.conn = None;
                self.paths.on_conn_closed(cx);
                log::info!("mq_gw_client: tunnel conn closed");
                // In-flight requests end at their own `H3Closed` (§5.5).
                if !self.shutting_down && self.reconnect_enabled {
                    self.arm_reconnect(cx);
                }
            }
            Event::MpReady(c) if mine == Some(c) => self.paths.on_mp_ready(cx, c),
            Event::PathRemoved(c, p) if mine == Some(c) => self.paths.on_path_removed(cx, p),
            ev => return Some(ev),
        }
        None
    }

    /// SP3 spec §5.7: a socket for one of the tunnel's extra paths; `false` = not mine.
    pub fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) -> bool {
        if !self.paths.owns(op) {
            return false;
        }
        // Not on a conn being closed at shutdown (as the raw tunnel's `closing`).
        let conn = self.conn.filter(|_| !self.shutting_down);
        self.paths.on_udp_socket(cx, conn, op, r);
        true
    }

    /// SP3 spec §5.8: `false` = not the tunnel's timer.
    pub fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) -> bool {
        if self.reconnect == Some(id) {
            self.reconnect = None;
            if !self.connect(cx) {
                self.arm_reconnect(cx);
            }
            return true;
        }
        // A path retry of the tunnel (§5.7: own backoff and paths).
        let conn = self.conn.filter(|_| !self.shutting_down);
        self.paths.on_timer(cx, conn, id)
    }

    /// SP3 spec §5.7: the tunnel's `mq.conn` / `mq.path` block.
    pub fn dump_metrics(&self, cx: &Cx<'_>) {
        log_conn_metrics(cx, self.conn);
    }

    /// SP3 spec §5.9: cancel the reconnect, dump the block, close the connection.
    pub fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        if let Some(t) = self.reconnect.take() {
            cx.cancel_timer(t);
        }
        self.dump_metrics(cx);
        if let Some(c) = self.conn {
            cx.close_conn(c);
        }
    }
}
