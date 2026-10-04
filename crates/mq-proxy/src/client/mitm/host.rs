//! `MitmHost` (test-support): an `App` holding `Exchanges<Owner>` and a
//! `Mitm`, routing its sockets' TCP events, its timers and the H3 events of
//! its exchanges to the front, as `Client` will (Task 8.2). Every `Handoff`
//! is recorded instead of reaching the SP1 relay.

use super::{Handoff, Mitm};
use crate::client::exchange::Exchanges;
use crate::client::{Owner, TRANSPARENT};
use crate::config::MitmConfig;
use crate::ingress::target_from_original_dst;
use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, SocketOpId, TcpEnd, TcpId, TimerId,
    UdpSocketId,
};
use mq_transport_api::{ConnId, Event};
use std::io;
use std::net::SocketAddr;

pub struct MitmHost {
    ex: Exchanges<Owner>,
    mitm: Mitm,
    /// What `H3Tunnel::pick_conn` would return.
    pub tunnel: Option<ConnId>,
    handoffs: Vec<Handoff>,
}

impl MitmHost {
    pub fn new(cfg: &MitmConfig, token: &str) -> MitmHost {
        MitmHost {
            ex: Exchanges::new(),
            mitm: Mitm::new(cfg, token),
            tunnel: None,
            handoffs: Vec::new(),
        }
    }

    /// Every socket handed to the opaque relay so far.
    pub fn handoffs(&self) -> &[Handoff] {
        &self.handoffs
    }

    pub fn mitm_metrics_line(&self) -> Option<String> {
        self.mitm.metrics_line()
    }

    /// Conns in the front's table, every phase.
    pub fn conn_count(&self) -> usize {
        self.mitm.conns.len()
    }

    /// Lowers the pump's pass budget (`PUMP_CAP`): the in-memory TCP fills
    /// long before a download spends 16 passes.
    pub fn set_pump_budget(&mut self, passes: usize) {
        self.mitm.pump_cap = passes;
    }

    /// A live conn's `Dirty` flag is set: a waker fired since its last pass.
    pub fn dirty(&self, tcp: TcpId) -> bool {
        self.mitm.dirty(tcp)
    }

    /// The caller's half of `Handoff` (SP4 spec §7.3 "Opaque" step 2).
    fn handoff(&mut self, cx: &mut Cx<'_>, h: Option<Handoff>) {
        if let Some(h) = h {
            cx.tcp_set_read(h.tcp, false);
            self.handoffs.push(h);
        }
    }
}

impl App for MitmHost {
    fn on_start(&mut self, _: &mut Cx<'_>) {}

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, mut ev: Event) {
        if let Some((Owner::Mitm(key), _, r)) = self.ex.on_event(&mut ev) {
            self.mitm.on_ready(cx, &mut self.ex, self.tunnel, key, r);
        }
    }

    fn on_accepted(&mut self, cx: &mut Cx<'_>, l: ListenerTag, tcp: TcpId, meta: AcceptMeta) {
        match target_from_original_dst(&meta).filter(|_| l == TRANSPARENT) {
            Some(t) => {
                let h = self.mitm.on_accepted(cx, tcp, t);
                self.handoff(cx, h);
            }
            None => cx.tcp_close(tcp),
        }
    }

    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if self.mitm.owns_tcp(tcp) {
            let h = self.mitm.on_tcp_data(cx, &mut self.ex, self.tunnel, tcp);
            self.handoff(cx, h);
        }
    }

    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        if self.mitm.owns_tcp(tcp) {
            let h = self
                .mitm
                .on_tcp_end(cx, &mut self.ex, self.tunnel, tcp, end);
            self.handoff(cx, h);
        }
    }

    fn on_tcp_writable(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if self.mitm.owns_tcp(tcp) {
            self.mitm
                .on_tcp_writable(cx, &mut self.ex, self.tunnel, tcp);
        }
    }

    fn on_dial_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<TcpId, DialError>) {}

    fn on_resolve_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<SocketAddr, DialError>) {
    }

    fn on_udp_socket(
        &mut self,
        _: &mut Cx<'_>,
        _: SocketOpId,
        _: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
    }

    fn on_udp_rx(&mut self, _: &mut Cx<'_>, _: UdpSocketId, _: SocketAddr, _: &[u8]) {}

    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        let (_, h) = self.mitm.on_timer(cx, &mut self.ex, self.tunnel, id);
        self.handoff(cx, h);
    }

    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.mitm.on_shutdown(cx, &mut self.ex);
    }
}
