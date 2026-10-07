// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §7: the MITM front.

pub mod ca;
mod conn;
pub mod head;
#[cfg(feature = "test-support")]
pub mod host;
pub mod leaf;
pub mod policy;
mod stream;

use super::Owner;
use super::exchange::{Exchanges, Ready};
use crate::config::MitmConfig;
use conn::{End, MitmConn, Phase};
use leaf::LeafStore;
use mq_runtime::{Cx, KeepAlive, TcpEnd, TcpId, TimerId};
use mq_transport_api::ConnId;
use policy::{MitmPolicy, Why};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// One browser conn of the MITM front (its socket).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MConnId(pub(crate) TcpId);

/// One h2 stream of a MITM conn: the owner of its exchange (SP4 spec §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MStreamKey {
    pub conn: MConnId,
    pub stream: u32,
}

/// SP4 spec §7.3 "Opaque": the socket left `Mitm`. The caller calls
/// `tcp_set_read(false)` and hands it to the SP1 path
/// `request(.., Transparent, target)`; the peeked bytes are still in `rx`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handoff {
    pub tcp: TcpId,
    pub target: mq_runtime::Target,
}

/// SP4 spec §7.10: the cumulative counters of the `mq.mitm` line.
#[derive(Debug, Default)]
struct Stats {
    mitm: u64,
    /// By `Why as usize`.
    opaque: [u64; 11],
    tls_fail: u64,
    h2_fail: u64,
    dead: u64,
    reqs: u64,
    rejects: u64,
}

/// The `opaque_*` keys of the `mq.mitm` line, in `Why` order.
const WHY_KEYS: [&str; 11] = [
    "not_tls",
    "no_sni",
    "bad_sni",
    "no_h2",
    "ignored",
    "ca_scope",
    "tls_incompat",
    "timeout",
    "too_large",
    "eof",
    "capacity",
];

/// SP4 spec §2.2: the front's timers, by id → their conn.
#[derive(Default)]
struct Timers(HashMap<TimerId, TcpId>);

impl Timers {
    fn arm(&mut self, cx: &mut Cx<'_>, tcp: TcpId, after: Duration) -> TimerId {
        let id = cx.set_timer(after);
        self.0.insert(id, tcp);
        id
    }

    fn disarm(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        if self.0.remove(&id).is_some() {
            cx.cancel_timer(id);
        }
    }
}

/// SP4 spec §7: the MITM front of one shard — its conn table, routing glue
/// and metrics, driven by `Client`.
pub struct Mitm {
    conns: HashMap<TcpId, MitmConn>,
    policy: MitmPolicy,
    leaf: LeafStore,
    tuning: MitmTuning,
    /// `"Bearer " + token` for `map_request` (SP4 spec §7.5 step 5).
    auth: Vec<u8>,
    h2: h2::server::Builder,
    stats: Stats,
    timers: Timers,
    /// The pump's pass budget: `PUMP_CAP` (R2); a test hook lowers it.
    pump_cap: usize,
}

impl Mitm {
    /// `LeafStore::new` generates the shard's leaf key here, never per conn.
    pub(crate) fn new(cfg: &MitmConfig, token: &str) -> Self {
        let mut h2 = h2::server::Builder::new();
        // SP4 spec §7.4 (D9); push and extended CONNECT stay off (defaults).
        h2.max_concurrent_streams(cfg.tuning.mstream_max as u32)
            .initial_window_size(256 * 1024)
            .initial_connection_window_size(512 * 1024)
            .max_frame_size(16 * 1024)
            .max_header_list_size(mq_http::limits::SECTION_MAX as u32 + 1)
            .max_send_buffer_size(64 * 1024);
        Mitm {
            conns: HashMap::new(),
            policy: MitmPolicy {
                ignore: cfg.ignore.clone(),
                scope: cfg.ca.scope.clone(),
            },
            leaf: LeafStore::new(cfg.ca.clone(), SystemTime::now),
            tuning: cfg.tuning,
            auth: head::auth_value(token),
            h2,
            stats: Stats::default(),
            timers: Timers::default(),
            pump_cap: crate::server::origin::PUMP_CAP,
        }
    }

    pub(crate) fn owns_tcp(&self, tcp: TcpId) -> bool {
        self.conns.contains_key(&tcp)
    }

    /// SP4 spec §7.3 "Accept": a `TRANSPARENT` socket with its original
    /// destination enters `Peek`, or goes opaque at capacity.
    pub(crate) fn on_accepted(
        &mut self,
        cx: &mut Cx<'_>,
        tcp: TcpId,
        target: mq_runtime::Target,
    ) -> Option<Handoff> {
        if self.conns.len() >= self.tuning.max_conns {
            self.count_opaque(Why::AtCapacity, None);
            return Some(Handoff { tcp, target });
        }
        cx.tcp_set_rx_limit(tcp, crate::ingress::INGRESS_CAP);
        let timer = self.timers.arm(cx, tcp, self.tuning.peek);
        let phase = Phase::Peek {
            acceptor: Box::default(),
            fed: 0,
            target,
        };
        self.conns.insert(tcp, MitmConn::new(tcp, timer, phase));
        None
    }

    pub(crate) fn on_tcp_data(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) -> Option<Handoff> {
        if let Phase::Peek { .. } = self.conns.get(&tcp)?.phase {
            return self.peek(cx, ex, tunnel, tcp);
        }
        self.pump(cx, ex, tunnel, tcp);
        None
    }

    pub(crate) fn on_tcp_writable(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) {
        self.pump(cx, ex, tunnel, tcp);
    }

    /// SP4 spec §7.3 "EOF and errors while peeking"; §7.4 "Ends" item 5.
    pub(crate) fn on_tcp_end(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
        end: TcpEnd,
    ) -> Option<Handoff> {
        let c = self.conns.get_mut(&tcp)?;
        if let TcpEnd::Error(_) = end {
            // The shard already reset the socket: no `Closing`.
            if let Phase::Live(_) = c.phase {
                self.end_conn(cx, ex, tcp, End::SocketError);
            }
            self.remove(cx, tcp);
            return None;
        }
        c.eof = true;
        if let Phase::Peek { .. } = c.phase {
            if cx.tcp_rx(tcp).is_empty() {
                cx.tcp_close(tcp);
                self.remove(cx, tcp);
                return None;
            }
            return self.opaque(cx, tcp, Why::Eof, None);
        }
        self.pump(cx, ex, tunnel, tcp);
        None
    }

    /// An `Exchanges` readiness for one of the conn's streams.
    pub(crate) fn on_ready(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        key: MStreamKey,
        r: Ready,
    ) {
        if let Some(c) = self.conns.get_mut(&key.conn.0) {
            c.on_ready(key.stream, r);
        }
        self.pump(cx, ex, tunnel, key.conn.0);
    }

    /// `(true, ..)` when `id` was one of ours (SP4 spec §7.8).
    pub(crate) fn on_timer(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        id: TimerId,
    ) -> (bool, Option<Handoff>) {
        let Some(tcp) = self.timers.0.remove(&id) else {
            return (false, None);
        };
        let Some(c) = self.conns.get_mut(&tcp) else {
            return (true, None);
        };
        if c.cont == Some(id) {
            c.cont = None;
            self.pump(cx, ex, tunnel, tcp);
            return (true, None);
        }
        let t = self.tuning;
        match &mut c.phase {
            Phase::Peek { .. } => return (true, self.opaque(cx, tcp, Why::Timeout, None)),
            Phase::Live(l) if !l.h2_ready() => self.end_conn(cx, ex, tcp, End::Handshake),
            // §7.8: idle with no open stream (R7: from the later of
            // `last_rx` and the last stream's end), else the watchdog from
            // `last_rx`; either is re-armed for the remainder.
            Phase::Live(l) => {
                let quiet = cx.now() - l.last_rx;
                let open = !l.streams.is_empty();
                if !open && l.idle_quiet(cx.now()) >= t.idle {
                    self.end_conn(cx, ex, tcp, End::Idle);
                } else if open && quiet >= t.dead_after {
                    self.end_conn(cx, ex, tcp, End::Dead);
                } else {
                    if open && quiet >= t.ping_after {
                        l.ping();
                    }
                    c.arm_liveness(cx, &mut self.timers, &t);
                }
            }
            // §7.4 "Deadline": whatever the stage, even after a `tcp_close`.
            Phase::Closing(_) => {
                cx.tcp_abort(tcp);
                self.remove(cx, tcp);
                return (true, None);
            }
        }
        self.pump(cx, ex, tunnel, tcp);
        (true, None)
    }

    /// SP4 spec §7.9: `Peek` sockets close; `Live` conns end as `Shutdown`.
    pub(crate) fn on_shutdown(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>) {
        let tcps: Vec<TcpId> = self.conns.keys().copied().collect();
        for tcp in tcps {
            match self.conns[&tcp].phase {
                Phase::Peek { .. } => {
                    cx.tcp_close(tcp);
                    self.remove(cx, tcp);
                }
                Phase::Live(_) => {
                    self.end_conn(cx, ex, tcp, End::Shutdown);
                    self.pump(cx, ex, None, tcp);
                }
                Phase::Closing(_) => {}
            }
        }
    }

    /// SP4 spec §7.10; `None` while every counter is zero.
    pub(crate) fn metrics_line(&self) -> Option<String> {
        let s = &self.stats;
        let (mut live, mut streams) = (0u64, 0);
        for c in self.conns.values() {
            if let Phase::Live(l) = &c.phase {
                live += 1;
                streams += l.streams.len();
            }
        }
        let leaf = self.leaf.stats();
        let mut line = format!("mq.mitm conns={live} streams={streams} mitm={}", s.mitm);
        for (k, n) in WHY_KEYS.iter().zip(s.opaque) {
            line += &format!(" opaque_{k}={n}");
        }
        line += &format!(
            " tls_fail={} h2_fail={} dead={} leaf_hit={} leaf_miss={} reqs={} rejects={}",
            s.tls_fail, s.h2_fail, s.dead, leaf.hit, leaf.miss, s.reqs, s.rejects
        );
        let rest = [
            live, s.mitm, s.tls_fail, s.h2_fail, s.dead, leaf.hit, leaf.miss,
        ];
        let zero = (rest.iter().chain(&s.opaque)).all(|&n| n == 0) && s.reqs + s.rejects == 0;
        (!zero).then_some(line)
    }

    /// Drops the conn and its timers; the socket is the caller's business.
    fn remove(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        if let Some(c) = self.conns.remove(&tcp) {
            self.timers.disarm(cx, c.timer);
            if let Some(t) = c.cont {
                self.timers.disarm(cx, t);
            }
        }
    }

    /// SP4 spec §7.3 "Opaque" steps 1 and 4; the caller does 2 and 3.
    fn opaque(
        &mut self,
        cx: &mut Cx<'_>,
        tcp: TcpId,
        why: Why,
        sni: Option<&str>,
    ) -> Option<Handoff> {
        let Phase::Peek { target, .. } = &self.conns.get(&tcp)?.phase else {
            return None;
        };
        let target = target.clone();
        self.remove(cx, tcp);
        self.count_opaque(why, sni);
        Some(Handoff { tcp, target })
    }

    fn count_opaque(&mut self, why: Why, sni: Option<&str>) {
        self.stats.opaque[why as usize] += 1;
        log::debug!("mq_mitm: {} → opaque({why:?})", sni.unwrap_or("-"));
    }
}

/// SP4 spec Global Constraints: the MITM limits and deadlines. Tests lower
/// them through `MitmConfig.tuning`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MitmTuning {
    pub max_conns: usize,
    pub mstream_max: usize,
    /// Deadline for the ClientHello peek.
    pub peek: Duration,
    /// Deadline for the TLS + h2 handshake.
    pub handshake: Duration,
    /// Idle close, counted only while no stream is open.
    pub idle: Duration,
    /// Send one PING after this much inbound silence (open streams only).
    pub ping_after: Duration,
    /// Close after this much inbound silence (open streams only).
    pub dead_after: Duration,
    /// Closing deadline before `tcp_abort`.
    pub closing: Duration,
    pub keepalive: KeepAlive,
}

impl Default for MitmTuning {
    fn default() -> Self {
        let s = Duration::from_secs;
        Self {
            max_conns: 256,
            mstream_max: 128,
            peek: s(5),
            handshake: s(5),
            idle: s(60),
            ping_after: s(60),
            dead_after: s(90),
            closing: s(1),
            keepalive: KeepAlive {
                idle: s(60),
                interval: s(10),
                count: 3,
                user_timeout: s(90),
            },
        }
    }
}
