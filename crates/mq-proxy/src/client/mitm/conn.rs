//! SP4 spec §7.3 / §7.4 / §7.8: one browser conn — the ClientHello peek,
//! the TLS + h2 pump, idle, and the `Closing` drain.
#![cfg_attr(not(feature = "test-support"), allow(dead_code))]

use super::head::reject_response;
use super::policy::{Route, Sni, Why};
use super::{Handoff, MConnId, Mitm, MitmTuning, Stats, Timers};
use crate::client::Owner;
use crate::client::exchange::Exchanges;
use crate::ingress::INGRESS_CAP;
use crate::server::origin::PUMP_CAP;
use crate::tls_pipe::{Dirty, PipeIo, TlsIo, pipe};
use bytes::Bytes;
use mq_http::headers::Reject;
use mq_runtime::{Cx, TCP_BUF, Target, TcpId, TimerId};
use mq_transport_api::Time;
use rustls::ServerConnection;
use rustls::server::{Accepted, Acceptor};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

pub(super) struct MitmConn {
    tcp: TcpId,
    /// The phase's deadline: peek, handshake, idle, or `Closing`.
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
    /// Last inbound TLS bytes.
    pub(super) last_rx: Time,
    dirty: Arc<Dirty>,
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

    /// One pump pass (§7.4): TLS in → h2 → TLS out; `Closing` drains.
    /// `Ok(true)` when something moved or a waker fired.
    fn pass(
        &mut self,
        cx: &mut Cx<'_>,
        timers: &mut Timers,
        tuning: &MitmTuning,
        stats: &mut Stats,
    ) -> Result<bool, End> {
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
                Poll::Ready(Ok(conn)) => {
                    l.h2 = H2::Ready(conn);
                    // §7.8: the handshake deadline gives way to the idle timer.
                    timers.disarm(cx, self.timer);
                    self.timer = timers.arm(cx, tcp, tuning.idle);
                    moved = true;
                }
                Poll::Ready(Err(_)) => return Err(or_eof(End::H2Fail)),
            },
            H2::Ready(conn) => loop {
                match conn.poll_accept(&mut tcx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok((_req, mut respond)))) => {
                        // Task 7.2 stub: no tunnel streams yet, so every
                        // request is answered 502 and nothing is retained.
                        stats.reqs += 1;
                        stats.rejects += 1;
                        let resp = reject_response(Reject::TunnelUnavailable);
                        let _ = respond.send_response(resp, true);
                        moved = true;
                    }
                    Poll::Ready(Some(Err(_))) => return Err(or_eof(End::H2Fail)),
                    Poll::Ready(None) => return Err(or_eof(End::H2Closed)),
                }
            },
        }
        // 4. TLS out; what TCP refuses waits in `out` for `on_tcp_writable`.
        moved |= l.tls.output(cx, tcp);
        Ok(moved || l.dirty.take())
    }

    /// SP4 spec §7.4 "Ends": the conn's exchanges are reset, then `Closing`
    /// under the 1 s deadline; a socket error only settles (the caller removes).
    fn end(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        timers: &mut Timers,
        tuning: &MitmTuning,
        stats: &mut Stats,
        end: End,
    ) {
        if !matches!(self.phase, Phase::Live(_)) {
            return;
        }
        let id = MConnId(self.tcp);
        ex.drain_owner(cx, |o| matches!(o, Owner::Mitm(k) if k.conn == id));
        match end {
            End::TlsFatal => stats.tls_fail += 1,
            End::H2Fail => stats.h2_fail += 1,
            _ => {}
        }
        let Phase::Live(l) = std::mem::replace(&mut self.phase, Phase::Closing(Box::default()))
        else {
            unreachable!("checked above")
        };
        log::info!("mq_mitm: {} closed ({end:?}, streams=0)", l.sni.as_str());
        if end == End::SocketError {
            return;
        }
        timers.disarm(cx, self.timer);
        self.timer = timers.arm(cx, self.tcp, tuning.closing);
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
    /// SP4 spec §7.3 "Peek": feed the unfed `rx` until it is exhausted or a
    /// decision is made (rustls reads ≤ 4 KiB per `read_tls`).
    pub(super) fn peek(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
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
            Peeked::Hello(a) => self.decide(cx, ex, tcp, a, fed),
        }
    }

    /// SP4 spec §7.3 `route`, then "Mitm": nothing is committed before
    /// `tcp_consume`, so every earlier failure goes opaque.
    fn decide(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
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
        self.pump(cx, ex, tcp);
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
            last_rx: cx.now(),
            dirty: Arc::default(),
        }));
        self.stats.mitm += 1;
    }

    /// SP4 spec §7.4 "Pump": at most `PUMP_CAP` passes (R2); work left over
    /// arms the 0-delay continuation instead of looping on.
    pub(super) fn pump(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId) {
        let Mitm {
            conns,
            timers,
            tuning,
            stats,
            ..
        } = self;
        let Some(c) = conns.get_mut(&tcp) else {
            return;
        };
        for _ in 0..PUMP_CAP {
            match c.pass(cx, timers, tuning, stats) {
                Ok(false) => return,
                Ok(true) => {}
                Err(end) => c.end(cx, ex, timers, tuning, stats, end),
            }
        }
        if c.cont.is_none() {
            c.cont = Some(timers.arm(cx, tcp, Duration::ZERO));
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
        let Mitm {
            conns,
            timers,
            tuning,
            stats,
            ..
        } = self;
        if let Some(c) = conns.get_mut(&tcp) {
            c.end(cx, ex, timers, tuning, stats, end);
        }
    }
}
