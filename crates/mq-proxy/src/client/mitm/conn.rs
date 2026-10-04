//! SP4 spec §7.3 / §7.4 / §7.8: one browser conn — the ClientHello peek,
//! the TLS + h2 pump with its streams, idle and the open-stream watchdog,
//! and the `Closing` drain.

use super::policy::{Route, Sni, Why};
use super::stream::MStream;
use super::{Handoff, MConnId, MStreamKey, Mitm, MitmTuning, Stats, Timers};
use crate::client::Owner;
use crate::client::exchange::{Exchanges, Ready};
use crate::ingress::INGRESS_CAP;
use crate::tls_pipe::{Dirty, PipeIo, TlsIo, pipe};
use bytes::Bytes;
use mq_runtime::{Cx, TCP_BUF, Target, TcpId, TimerId};
use mq_transport_api::{ConnId, Time};
use rustls::ServerConnection;
use rustls::server::{Accepted, Acceptor};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

pub(super) struct MitmConn {
    tcp: TcpId,
    /// The phase's deadline: peek, handshake, idle or watchdog, or `Closing`.
    pub(super) timer: TimerId,
    /// The 0-delay continuation of a pump that ran out of passes.
    pub(super) cont: Option<TimerId>,
    /// TCP read EOF seen.
    pub(super) eof: bool,
    pub(super) phase: Phase,
}

pub(super) enum Phase {
    Peek {
        acceptor: Box<Acceptor>,
        /// `rx` bytes handed to the acceptor; `rx` is not consumed while peeking.
        fed: usize,
        target: Target,
    },
    Live(Box<Live>),
    Closing(Box<Closing>),
}

pub(super) struct Live {
    sni: Sni,
    tls: TlsIo<ServerConnection>,
    h2: H2,
    /// In round-robin order: each pass starts at the front and rotates it
    /// (fairness under the budget, §7.4 step 3).
    pub(super) streams: VecDeque<MStream>,
    /// Last inbound TLS bytes.
    pub(super) last_rx: Time,
    /// h2 `Ready`, or the open-stream count's last drop to zero (R7).
    idle_since: Time,
    /// Taken once at h2 `Ready`; one outstanding PING at most (§7.8).
    ping: Option<h2::PingPong>,
    /// The liveness timer is the watchdog (streams open), not idle.
    watchdog: bool,
    dirty: Arc<Dirty>,
}

/// The parts of `Mitm` a conn borrows next to its own table entry.
pub(super) struct Env<'a> {
    pub(super) ex: &'a mut Exchanges<Owner>,
    /// `H3Tunnel::pick_conn()` (R6).
    pub(super) tunnel: Option<ConnId>,
    pub(super) timers: &'a mut Timers,
    pub(super) tuning: &'a MitmTuning,
    pub(super) stats: &'a mut Stats,
    pub(super) auth: &'a [u8],
}

enum H2 {
    Handshaking(h2::server::Handshake<PipeIo, Bytes>),
    Ready(h2::server::Connection<PipeIo, Bytes>),
}

/// SP4 spec §7.4 "Ends" item 2: ordered, so close_notify never overtakes
/// the GOAWAY. Boxed in `Phase`, so the variant sizes do not matter.
#[derive(Default)]
#[allow(clippy::large_enum_variant)]
pub(super) enum Closing {
    FlushH2 {
        h2: h2::server::Connection<PipeIo, Bytes>,
        tls: TlsIo<ServerConnection>,
        dirty: Arc<Dirty>,
    },
    FlushTls {
        tls: TlsIo<ServerConnection>,
    },
    /// `tcp_close` called; the deadline still aborts (§7.4 item 4).
    #[default]
    Done,
}

/// Why a live conn ends (counted and logged, §7.4 item 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum End {
    Eof,
    TlsFatal,
    /// The browser ended h2 (GOAWAY, close_notify).
    H2Closed,
    H2Fail,
    Handshake,
    Idle,
    /// The watchdog: `dead_after` of inbound silence with open streams.
    Dead,
    Shutdown,
    SocketError,
}

#[allow(clippy::large_enum_variant)] // a stack temporary of `peek`
enum Peeked {
    Wait,
    Opaque(Why),
    Hello(Accepted),
}

impl Live {
    pub(super) fn h2_ready(&self) -> bool {
        matches!(self.h2, H2::Ready(_))
    }

    /// SP4 spec §7.8, R7: the idle clock runs from the later of the last
    /// inbound bytes and the moment no stream was left open.
    pub(super) fn idle_quiet(&self, now: Time) -> Duration {
        now - self.last_rx.max(self.idle_since)
    }

    /// §7.8 watchdog: one PING unless one is outstanding. `poll_pong` first
    /// clears a PONG already seen; while one is pending `send_ping` refuses.
    pub(super) fn ping(&mut self) {
        let waker = Waker::from(self.dirty.clone());
        let mut tcx = Context::from_waker(&waker);
        if let Some(p) = &mut self.ping {
            let _ = p.poll_pong(&mut tcx);
            let _ = p.send_ping(h2::Ping::opaque());
        }
    }
}

impl MitmConn {
    pub(super) fn new(tcp: TcpId, timer: TimerId, phase: Phase) -> Self {
        MitmConn {
            tcp,
            timer,
            cont: None,
            eof: false,
            phase,
        }
    }

    /// An `Exchanges` readiness for stream `stream`.
    pub(super) fn on_ready(&mut self, stream: u32, r: Ready) {
        if let Phase::Live(l) = &mut self.phase
            && let Some(s) = l.streams.iter_mut().find(|s| s.id == stream)
        {
            s.on_ready(r);
        }
    }

    /// SP4 spec §7.8: idle with no open stream (R7: `idle_quiet`); the
    /// watchdog's PING, then dead deadline, from `last_rx` otherwise.
    pub(super) fn arm_liveness(&mut self, cx: &mut Cx<'_>, timers: &mut Timers, t: &MitmTuning) {
        let Phase::Live(l) = &mut self.phase else {
            return;
        };
        let now = cx.now();
        let open = !l.streams.is_empty();
        if l.watchdog && !open {
            l.idle_since = now; // the count crossed to zero
        }
        l.watchdog = open;
        let quiet = now - l.last_rx;
        let (quiet, at) = match open {
            false => (l.idle_quiet(now), t.idle),
            true if quiet < t.ping_after => (quiet, t.ping_after),
            true => (quiet, t.dead_after),
        };
        timers.disarm(cx, self.timer);
        self.timer = timers.arm(cx, self.tcp, at.saturating_sub(quiet));
    }

    /// One pump pass (§7.4): TLS in → h2 → streams → TLS out; `Closing`
    /// drains. `Ok(true)` when something moved or a waker fired.
    fn pass(&mut self, cx: &mut Cx<'_>, env: &mut Env<'_>) -> Result<bool, End> {
        let tcp = self.tcp;
        let l = match &mut self.phase {
            Phase::Peek { .. } => return Ok(false),
            Phase::Closing(cl) => return Ok(closing_pass(cx, tcp, cl)),
            Phase::Live(l) => l,
        };
        let or_eof = |e| if self.eof { End::Eof } else { e };
        let waker = Waker::from(l.dirty.clone());
        let mut tcx = Context::from_waker(&waker);
        l.dirty.take();
        // 1. TLS in. On `Err` the alert is queued; `Closing` flushes it.
        let i = (l.tls.input(cx.tcp_rx(tcp), self.eof)).map_err(|_| End::TlsFatal)?;
        cx.tcp_consume(tcp, i.consumed);
        if i.consumed > 0 {
            l.last_rx = cx.now();
        }
        let mut moved = i.moved;
        // 2. h2.
        match &mut l.h2 {
            H2::Handshaking(hs) => match Pin::new(hs).poll(&mut tcx) {
                Poll::Pending => {}
                Poll::Ready(Ok(mut conn)) => {
                    l.ping = conn.ping_pong();
                    l.h2 = H2::Ready(conn);
                    l.idle_since = cx.now();
                    // §7.8: the handshake deadline gives way to the idle timer.
                    env.timers.disarm(cx, self.timer);
                    self.timer = env.timers.arm(cx, tcp, env.tuning.idle);
                    moved = true;
                }
                Poll::Ready(Err(_)) => return Err(or_eof(End::H2Fail)),
            },
            H2::Ready(conn) => loop {
                match conn.poll_accept(&mut tcx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok((req, mut respond)))) => {
                        env.stats.reqs += 1;
                        moved = true;
                        // §7.6 "Admission": h2 stops counting a stream that
                        // is closed toward the browser but still draining.
                        if l.streams.len() >= env.tuning.mstream_max {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                            env.stats.rejects += 1;
                            continue;
                        }
                        let key = MStreamKey {
                            conn: MConnId(tcp),
                            stream: respond.stream_id().as_u32(),
                        };
                        let (ex, tunnel, auth) = (&mut *env.ex, env.tunnel, env.auth);
                        match MStream::open(cx, ex, tunnel, key, (req, respond), &l.sni, auth) {
                            Some(s) => l.streams.push_back(s),
                            None => env.stats.rejects += 1,
                        }
                    }
                    Poll::Ready(Some(Err(_))) => return Err(or_eof(End::H2Fail)),
                    Poll::Ready(None) => return Err(or_eof(End::H2Closed)),
                }
            },
        }
        // 3. Streams, from the front; the front rotates each pass.
        let room = l.tls.out_has_room();
        for s in &mut l.streams {
            moved |= s.step(cx, env.ex, &mut tcx, room);
        }
        l.streams.retain(|s| !s.done());
        if !l.streams.is_empty() {
            l.streams.rotate_left(1);
        }
        // 4. TLS out; what TCP refuses waits in `out` for `on_tcp_writable`.
        moved |= l.tls.output(cx, tcp);
        Ok(moved || l.dirty.take())
    }

    /// SP4 spec §7.4 "Ends": the conn's exchanges are reset, then `Closing`
    /// under the 1 s deadline; a socket error only settles (the caller removes).
    fn end(&mut self, cx: &mut Cx<'_>, env: &mut Env<'_>, end: End) {
        if !matches!(self.phase, Phase::Live(_)) {
            return;
        }
        let id = MConnId(self.tcp);
        (env.ex).drain_owner(cx, |o| matches!(o, Owner::Mitm(k) if k.conn == id));
        match end {
            End::TlsFatal => env.stats.tls_fail += 1,
            End::H2Fail => env.stats.h2_fail += 1,
            End::Dead => env.stats.dead += 1,
            _ => {}
        }
        let Phase::Live(mut l) = std::mem::replace(&mut self.phase, Phase::Closing(Box::default()))
        else {
            unreachable!("checked above")
        };
        // §7.4 "Ends" item 1: the streams go with their exchanges.
        let streams = std::mem::take(&mut l.streams).len();
        log::info!(
            "mq_mitm: {} closed ({end:?}, streams={streams})",
            l.sni.as_str()
        );
        if end == End::SocketError {
            return;
        }
        env.timers.disarm(cx, self.timer);
        self.timer = env.timers.arm(cx, self.tcp, env.tuning.closing);
        let Live {
            mut tls, h2, dirty, ..
        } = *l;
        let next = match h2 {
            H2::Ready(mut h2) if end != End::TlsFatal => {
                // No PING round trip, unlike `graceful_shutdown`.
                h2.abrupt_shutdown(h2::Reason::NO_ERROR);
                Closing::FlushH2 { h2, tls, dirty }
            }
            // §7.4 item 3: an unfinished handshake is dropped without a
            // GOAWAY; a TLS-fatal end sends only its alert.
            _ => {
                tls.pipe().with_tx(usize::MAX, <[u8]>::len);
                if end != End::TlsFatal {
                    tls.tls.send_close_notify();
                }
                Closing::FlushTls { tls }
            }
        };
        self.phase = Phase::Closing(Box::new(next));
    }
}

/// One `Closing` pass. Inbound bytes are discarded: unread data would turn
/// the final close into a reset.
fn closing_pass(cx: &mut Cx<'_>, tcp: TcpId, cl: &mut Closing) -> bool {
    let n = cx.tcp_rx(tcp).len();
    cx.tcp_consume(tcp, n);
    match cl {
        Closing::FlushH2 { h2, tls, dirty } => {
            dirty.take();
            let waker = Waker::from(dirty.clone());
            // Ready once h2 has written its GOAWAY into the pipe.
            let closed = h2.poll_closed(&mut Context::from_waker(&waker)).is_ready();
            let moved = tls.output(cx, tcp);
            if closed && tls.pipe().tx_len() == 0 {
                let Closing::FlushH2 { mut tls, .. } = std::mem::take(cl) else {
                    unreachable!("matched above")
                };
                tls.tls.send_close_notify();
                *cl = Closing::FlushTls { tls };
                return true;
            }
            moved || dirty.take()
        }
        Closing::FlushTls { tls } => {
            let moved = tls.output(cx, tcp);
            if tls.drained() {
                cx.tcp_close(tcp);
                *cl = Closing::Done;
            }
            moved
        }
        Closing::Done => false,
    }
}

impl Mitm {
    /// A live conn's `Dirty` flag (test-support).
    #[cfg(feature = "test-support")]
    pub(super) fn dirty(&self, tcp: TcpId) -> bool {
        let c = self.conns.get(&tcp).map(|c| &c.phase);
        matches!(c, Some(Phase::Live(l)) if l.dirty.is_set())
    }

    /// SP4 spec §7.3 "Peek": feed the unfed `rx` until it is exhausted or a
    /// decision is made (rustls reads ≤ 4 KiB per `read_tls`).
    pub(super) fn peek(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) -> Option<Handoff> {
        let Phase::Peek { acceptor, fed, .. } = &mut self.conns.get_mut(&tcp)?.phase else {
            return None;
        };
        let rx = cx.tcp_rx(tcp);
        let got = loop {
            if *fed < rx.len() {
                match acceptor.read_tls(&mut &rx[*fed..]) {
                    Ok(n) if n > 0 => *fed += n,
                    _ => break Peeked::Opaque(Why::NotTls),
                }
            }
            match acceptor.accept() {
                Ok(Some(a)) => break Peeked::Hello(a),
                Ok(None) if *fed < rx.len() => {}
                Ok(None) if rx.len() >= INGRESS_CAP => break Peeked::Opaque(Why::TooLarge),
                Ok(None) => break Peeked::Wait,
                // The `AcceptedAlert` is dropped unsent.
                Err(_) => break Peeked::Opaque(Why::NotTls),
            }
        };
        let fed = *fed;
        match got {
            Peeked::Wait => None,
            Peeked::Opaque(w) => self.opaque(cx, tcp, w, None),
            Peeked::Hello(a) => self.decide(cx, ex, tunnel, tcp, a, fed),
        }
    }

    /// SP4 spec §7.3 `route`, then "Mitm": nothing is committed before
    /// `tcp_consume`, so every earlier failure goes opaque.
    fn decide(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
        a: Accepted,
        fed: usize,
    ) -> Option<Handoff> {
        let hello = a.client_hello();
        let raw = hello.server_name().map(str::to_owned);
        let h2 = hello.alpn().is_some_and(|mut p| p.any(|p| p == b"h2"));
        let sni = match self.policy.route(raw.as_deref(), h2) {
            Route::Opaque(w) => return self.opaque(cx, tcp, w, raw.as_deref()),
            Route::Mitm(sni) => sni,
        };
        let cfg = match self.leaf.config_for(&sni) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("mq_mitm: {}: {e}", sni.as_str());
                return self.opaque(cx, tcp, Why::BadSni, raw.as_deref());
            }
        };
        // E.g. no signature scheme our P-256 leaf can use; the alert is dropped.
        let Ok(tls) = a.into_connection(cfg) else {
            return self.opaque(cx, tcp, Why::TlsIncompatible, raw.as_deref());
        };
        cx.tcp_consume(tcp, fed); // the commit point: rustls holds the bytes
        self.go_live(cx, tcp, sni, tls);
        self.pump(cx, ex, tunnel, tcp);
        None
    }

    /// §7.3 "Mitm" step 4 and §7.8 "Dead peer".
    fn go_live(&mut self, cx: &mut Cx<'_>, tcp: TcpId, sni: Sni, tls: ServerConnection) {
        let c = self.conns.get_mut(&tcp).expect("peeking");
        self.timers.disarm(cx, c.timer);
        c.timer = self.timers.arm(cx, tcp, self.tuning.handshake);
        cx.tcp_set_keepalive(tcp, self.tuning.keepalive);
        // The 8 KiB peek cap does not apply to the TLS stream.
        cx.tcp_set_rx_limit(tcp, TCP_BUF);
        log::debug!("mq_mitm: {} → mitm", sni.as_str());
        let (io, handle) = pipe();
        c.phase = Phase::Live(Box::new(Live {
            sni,
            tls: TlsIo::new(tls, handle),
            h2: H2::Handshaking(self.h2.handshake(io)),
            streams: VecDeque::new(),
            last_rx: cx.now(),
            idle_since: cx.now(),
            ping: None,
            watchdog: false,
            dirty: Arc::default(),
        }));
        self.stats.mitm += 1;
    }

    /// SP4 spec §7.4 "Pump": at most `PUMP_CAP` passes (R2). A last pass
    /// that still moved arms the 0-delay continuation instead of looping on:
    /// moving is the only signal of leftover work (e.g. TLS input held back
    /// by a full pipe, which no waker reports). Then §7.8: the liveness
    /// timer switches when the open-stream count crosses zero.
    pub(super) fn pump(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) {
        let budget = self.pump_cap;
        let (c, mut env) = self.split(ex, tunnel, tcp);
        let Some(c) = c else { return };
        let mut more = true;
        for _ in 0..budget {
            match c.pass(cx, &mut env) {
                Ok(false) => {
                    more = false;
                    break;
                }
                Ok(true) => {}
                Err(end) => c.end(cx, &mut env, end),
            }
        }
        if more && c.cont.is_none() {
            c.cont = Some(env.timers.arm(cx, tcp, Duration::ZERO));
        }
        if let Phase::Live(l) = &c.phase
            && l.h2_ready()
        {
            // The timer is still the watchdog with no stream open, or idle
            // with one: the open-stream count crossed zero.
            let crossed = l.watchdog == l.streams.is_empty();
            if crossed {
                c.arm_liveness(cx, env.timers, env.tuning);
            }
        }
    }

    /// Ends a live conn (`Closing`, or settled on a socket error).
    pub(super) fn end_conn(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcp: TcpId,
        end: End,
    ) {
        if let (Some(c), mut env) = self.split(ex, None, tcp) {
            c.end(cx, &mut env, end);
        }
    }

    /// Conn `tcp` and the rest of `Mitm`, borrowed side by side.
    fn split<'a>(
        &'a mut self,
        ex: &'a mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) -> (Option<&'a mut MitmConn>, Env<'a>) {
        let env = Env {
            ex,
            tunnel,
            timers: &mut self.timers,
            tuning: &self.tuning,
            stats: &mut self.stats,
            auth: &self.auth,
        };
        (self.conns.get_mut(&tcp), env)
    }
}
