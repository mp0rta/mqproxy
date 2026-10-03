//! SP3 spec §5: the client gateway — the fetch listener's requests and their own
//! H3 tunnel connection (§5.7), composed into `Client` (§5.8).

use super::backoff::Backoff;
use super::paths::Paths;
use super::{SNI, log_conn_metrics};
use crate::config::ClientConfig;
use mq_http::h1::HEAD_MAX;
use mq_runtime::{AcceptMeta, Cx, SocketOpId, TcpEnd, TcpId, TimerId, UdpSocketId};
use mq_transport_api::{ConnConfig, ConnId, ConnProto, Event, H3ReqId};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// SP3 spec §5.8: the gateway's timers (`Tm::GwReconnect` / `Tm::GwHead`).
#[derive(Copy, Clone, Debug)]
pub enum GwTm {
    Reconnect,
    Head(TcpId),
}

/// SP3 spec §5.1–§5.5: one fetch request, by local socket.
enum GwReq {
    /// Waiting for the complete request head (§5.2).
    Head { timer: TimerId },
}

/// The settings the gateway reads.
struct GwCfg {
    server: SocketAddr,
    keepalive_idle: Option<Duration>,
    reconnect: bool,
    ingress_deadline: Duration,
}

/// SP3 spec §5.7: the H3 tunnel connection.
struct GwTunnel {
    conn: Option<ConnId>,
    up: bool,
    backoff: Backoff,
    paths: Paths,
    reconnect: Option<TimerId>,
}

/// SP3 spec §5: the client gateway.
pub struct Gateway {
    tunnel: GwTunnel,
    reqs: HashMap<TcpId, GwReq>,
    by_h3: HashMap<H3ReqId, TcpId>,
    timers: HashMap<TimerId, GwTm>,
    cfg: GwCfg,
    shutting_down: bool,
}

impl Gateway {
    pub fn new(cfg: &ClientConfig) -> Gateway {
        Gateway {
            tunnel: GwTunnel {
                conn: None,
                up: false,
                backoff: Backoff::new(cfg.reconnect_max_backoff),
                paths: Paths::new(cfg, "mq_gw_client"),
                reconnect: None,
            },
            reqs: HashMap::new(),
            by_h3: HashMap::new(),
            timers: HashMap::new(),
            cfg: GwCfg {
                server: cfg.server,
                keepalive_idle: cfg.keepalive_idle,
                reconnect: cfg.reconnect,
                ingress_deadline: cfg.ingress_deadline,
            },
            shutting_down: false,
        }
    }

    /// SP3 spec §5.7: the one tunnel connection, when established (the seam for
    /// a future route/policy/pool, §1.2).
    #[cfg_attr(
        not(feature = "test-support"),
        expect(dead_code, reason = "the head path (Task 4.2) calls it")
    )]
    fn pick_conn(&self) -> Option<ConnId> {
        self.tunnel.conn.filter(|_| self.tunnel.up)
    }

    /// Test support: `pick_conn()`.
    #[cfg(feature = "test-support")]
    pub fn tunnel_conn(&self) -> Option<ConnId> {
        self.pick_conn()
    }

    /// SP3 spec §5.9: no tunnel connection and none coming (shut down or
    /// `--no-reconnect` terminal).
    pub fn tunnel_gone(&self) -> bool {
        self.tunnel.conn.is_none() && self.tunnel.reconnect.is_none()
    }

    fn timer(&mut self, cx: &mut Cx<'_>, after: Duration, tm: GwTm) -> TimerId {
        let id = cx.set_timer(after);
        self.timers.insert(id, tm);
        id
    }

    fn cancel(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        cx.cancel_timer(id);
        self.timers.remove(&id);
    }

    /// SP3 spec §5.7: connect the tunnel; `false` on a synchronous failure.
    fn connect(&mut self, cx: &mut Cx<'_>) -> bool {
        let cc = ConnConfig {
            peer: self.cfg.server,
            sni: SNI,
            idle_timeout: self.cfg.keepalive_idle,
            proto: ConnProto::H3,
        };
        match cx.connect(&cc) {
            Ok(c) => {
                self.tunnel.conn = Some(c);
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
        let d = self.tunnel.backoff.next_delay(cx.now(), rnd);
        log::info!("mq_gw_client: reconnecting in {} ms", d.as_millis());
        self.tunnel.reconnect = Some(self.timer(cx, d, GwTm::Reconnect));
    }

    /// SP3 spec §5.7: eager, as C's constructor; the first failure is fatal.
    pub fn on_start(&mut self, cx: &mut Cx<'_>) {
        if !self.connect(cx) {
            cx.request_exit(1);
        }
    }

    /// SP3 spec §5.8: `None` when the event was the gateway's.
    pub fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) -> Option<Event> {
        let mine = self.tunnel.conn;
        match ev {
            Event::ConnEstablished(c) if mine == Some(c) => {
                self.tunnel.up = true;
                self.tunnel.backoff.reset();
                if let Some(t) = self.tunnel.reconnect.take() {
                    self.cancel(cx, t);
                }
                log::info!("mq_gw_client: tunnel conn established");
            }
            Event::ConnClosed(c, _) if mine == Some(c) => {
                self.tunnel.up = false;
                self.tunnel.conn = None;
                self.tunnel.paths.on_conn_closed(cx);
                log::info!("mq_gw_client: tunnel conn closed");
                // In-flight requests end at their own `H3Closed` (§5.5).
                if !self.shutting_down && self.cfg.reconnect {
                    self.arm_reconnect(cx);
                }
            }
            Event::MpReady(c) if mine == Some(c) => self.tunnel.paths.on_mp_ready(cx, c),
            Event::H3Closed(r, _) => {
                self.by_h3.remove(&r);
            }
            // Only the gateway holds H3 requests on the client (§5.8).
            Event::H3Readable(_) | Event::H3Writable(_) => {}
            ev => return Some(ev),
        }
        None
    }

    /// SP3 spec §5.1.
    pub fn on_accepted(&mut self, cx: &mut Cx<'_>, tcp: TcpId, _meta: AcceptMeta) {
        cx.tcp_set_rx_limit(tcp, HEAD_MAX);
        let timer = self.timer(cx, self.cfg.ingress_deadline, GwTm::Head(tcp));
        self.reqs.insert(tcp, GwReq::Head { timer });
    }

    pub fn owns_tcp(&self, tcp: TcpId) -> bool {
        self.reqs.contains_key(&tcp)
    }

    /// SP3 spec §5.2–§5.3 (head parsing and upload arrive with Tasks 4.2/4.3).
    pub fn on_tcp_data(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId) {}

    /// SP3 spec §5.2: an end before the head is complete closes silently.
    pub fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        if let Some(GwReq::Head { timer }) = self.reqs.remove(&tcp) {
            self.cancel(cx, timer);
            if end == TcpEnd::ReadEof {
                cx.tcp_close(tcp);
            }
        }
    }

    /// SP3 spec §5.4 (the download pump arrives with Task 4.4).
    pub fn on_tcp_writable(&mut self, _cx: &mut Cx<'_>, _tcp: TcpId) {}

    /// SP3 spec §5.7: a socket for one of the tunnel's extra paths; `false` = not mine.
    pub fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) -> bool {
        if !self.tunnel.paths.owns(op) {
            return false;
        }
        // Not on a conn being closed at shutdown (as the raw tunnel's `closing`).
        let conn = self.tunnel.conn.filter(|_| !self.shutting_down);
        self.tunnel.paths.on_udp_socket(cx, conn, op, r);
        true
    }

    /// SP3 spec §5.8: `false` = not the gateway's timer.
    pub fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) -> bool {
        let Some(tm) = self.timers.remove(&id) else {
            return false;
        };
        match tm {
            GwTm::Reconnect => {
                self.tunnel.reconnect = None;
                if !self.connect(cx) {
                    self.arm_reconnect(cx);
                }
            }
            GwTm::Head(tcp) => {
                // The 400 reply arrives with Task 4.2.
                if self.reqs.remove(&tcp).is_some() {
                    cx.tcp_close(tcp);
                }
            }
        }
        true
    }

    /// SP3 spec §5.9: dump the tunnel's block, close it; `Client` exits once
    /// both tunnels are gone.
    pub fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        if let Some(t) = self.tunnel.reconnect.take() {
            self.cancel(cx, t);
        }
        self.dump_metrics(cx);
        if let Some(c) = self.tunnel.conn {
            cx.close_conn(c);
        }
    }

    /// SP3 spec §5.7: the tunnel's `mq.conn` / `mq.path` block.
    pub fn dump_metrics(&self, cx: &Cx<'_>) {
        log_conn_metrics(cx, self.tunnel.conn);
    }
}
