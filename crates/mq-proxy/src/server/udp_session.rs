//! spec §7.1: the server's UDP sessions — the OPEN's admission gates, the
//! resolve, the app socket and the RESP; spec §7.2 `end_session`.
//!
//! ```text
//! Request ──OPEN──→ Resolving ──Ok──→ Opening ──Ok──→ Live (RESP OK)
//!    │                  └──Err──────────┴──Err──→ Retiring (error RESP+FIN)
//!    ├── --no-udp / 1024 sessions / undialable ──→ Retiring
//!    └── malformed / FIN / duplicate sid ──→ stream_reset
//! Resolving | Opening | Live: FIN, Err(Reset), StreamClosed or a failed
//! RESP OK → drop_data → end_session, stream_reset
//! ```
//! The session stream stays in `Server::data` (phase `Udp(sid)`) and holds
//! one of the connection's 4096 budget entries like any app-held stream.

use super::{Phase as Stream, Server};
use crate::app_stream;
use crate::udp::MAX_SESSIONS_PER_CONN;
use mq_runtime::{Cx, DialError, DialOpId, SocketOpId, Target, UdpSocketId};
use mq_transport_api::{ConnId, StreamId};
use mq_wire::frames::{MAX_FRAME, STATUS_ERROR, STATUS_OK, UdpErr, UdpSessionResp};
use mq_wire::varint;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// spec §7.1: an admitted session's step; each holds what an end disposes of.
#[derive(Copy, Clone, Debug)]
pub(super) enum Phase {
    Resolving(DialOpId),
    /// `target` is the resolved address in canonical form (spec §7.2).
    Opening {
        op: SocketOpId,
        target: SocketAddr,
    },
    Live {
        sock: UdpSocketId,
        #[allow(dead_code)] // read by the §7.2 datagram paths (Task 6.3)
        target: SocketAddr,
    },
}

/// spec §7.1: an admitted session, held under its sid in `Conn::udp`.
pub(super) struct SrvSession {
    pub(super) stream: StreamId,
    pub(super) phase: Phase,
    /// The negotiated idle timeout, fixed at admission (spec §7.2).
    pub(super) idle_len: Duration,
}

/// spec §7.1: `UDP_SESSION_RESP`, no message — OK with the negotiated idle
/// timeout, or an error with idle 0 (C `srv_open_reject`).
fn udp_resp(r: Result<u64, UdpErr>) -> Vec<u8> {
    let (status, error_code, idle_timeout_ms) = match r {
        Ok(idle) => (STATUS_OK, 0, idle),
        Err(e) => (STATUS_ERROR, e as u64, 0),
    };
    let mut b = vec![0u8; MAX_FRAME];
    let n = UdpSessionResp {
        status,
        error_code,
        message: b"",
        idle_timeout_ms,
    }
    .encode(&mut b)
    .expect("fits");
    b.truncate(n);
    b
}

/// spec §7.1: `min(requested or default, --udp-idle-timeout)` in ms. The
/// server value is unbounded in config, so it saturates at the largest varint.
fn negotiated_idle(requested_ms: u64, server: Duration) -> u64 {
    let server = server.as_millis().min(u128::from(varint::MAX)) as u64;
    if requested_ms == 0 {
        server
    } else {
        requested_ms.min(server)
    }
}

/// spec §7.2: the form `target` is kept in — IPv4-mapped unmapped, unspecified
/// → loopback (C `connect()`s to it and the kernel picks loopback).
fn canonical(mut a: SocketAddr) -> SocketAddr {
    a.set_ip(match a.ip().to_canonical() {
        IpAddr::V4(v) if v.is_unspecified() => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(v) if v.is_unspecified() => Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    });
    a
}

impl Server {
    /// spec §7.1: admitted UDP sessions on `c`.
    #[cfg(feature = "test-support")]
    pub fn udp_sessions(&self, c: ConnId) -> Option<usize> {
        self.conns.get(&c).map(|k| k.udp.len())
    }

    /// spec §7.2: session `sid`'s canonical target, once resolved.
    #[cfg(feature = "test-support")]
    pub fn udp_target(&self, c: ConnId, sid: u32) -> Option<SocketAddr> {
        match self.conns.get(&c)?.udp.get(&sid)?.phase {
            Phase::Resolving(_) => None,
            Phase::Opening { target, .. } | Phase::Live { target, .. } => Some(target),
        }
    }

    fn session(&mut self, c: ConnId, sid: u32) -> &mut SrvSession {
        let k = self.conns.get_mut(&c).expect("admitted");
        k.udp.get_mut(&sid).expect("admitted")
    }

    /// spec §7.1: the gates in order (an unauthenticated connection's streams
    /// are reset at `NewStream`), then admission — the sid and one of the
    /// 1024 slots are taken before the resolve (15 s, the dial deadline) starts.
    pub(super) fn udp_open(
        &mut self,
        cx: &mut Cx<'_>,
        s: StreamId,
        sid: u32,
        target: Option<Target>,
        requested_ms: u64,
    ) {
        if !self.cfg.udp_enabled {
            return self.respond_error(cx, s, udp_resp(Err(UdpErr::PolicyDenied)));
        }
        let c = self.data[&s].conn;
        let udp = &self.conns[&c].udp;
        if udp.contains_key(&sid) {
            // C design §9.2: the existing session is kept.
            log::warn!("mq_udp_srv: duplicate session_id {sid}, resetting new stream (no RESP)");
            return self.drop_data(cx, s, true);
        }
        if udp.len() >= MAX_SESSIONS_PER_CONN {
            return self.respond_error(cx, s, udp_resp(Err(UdpErr::SessionLimit)));
        }
        let Some(target) = target else {
            return self.respond_error(cx, s, udp_resp(Err(UdpErr::DnsFailed)));
        };
        let op = cx.resolve(target, self.cfg.dial_deadline);
        self.resolves.insert(op, (c, sid));
        let d = self.data.get_mut(&s).expect("present");
        if let Stream::Request(t) = std::mem::replace(&mut d.phase, Stream::Udp(sid)) {
            self.cancel(cx, t);
        }
        let idle = negotiated_idle(requested_ms, self.cfg.udp_idle_timeout);
        let sess = SrvSession {
            stream: s,
            phase: Phase::Resolving(op),
            idle_len: Duration::from_millis(idle),
        };
        self.conns
            .get_mut(&c)
            .expect("present")
            .udp
            .insert(sid, sess);
    }

    /// spec §7.1: `Resolving` → `Opening` on a socket of the resolved
    /// address's family, or `DnsFailed` (`Dns` and `Timeout` alike, as C).
    pub(super) fn udp_resolved(
        &mut self,
        cx: &mut Cx<'_>,
        op: DialOpId,
        r: Result<SocketAddr, DialError>,
    ) {
        let Some((c, sid)) = self.resolves.remove(&op) else {
            return;
        };
        let addr = match r {
            Ok(a) => a,
            Err(e) => {
                log::warn!("mq_udp_srv: session {sid} resolve failed ({e:?})");
                return self.refuse(cx, c, sid, UdpErr::DnsFailed);
            }
        };
        let local: IpAddr = match addr {
            SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let op = cx.open_app_udp_socket(local);
        self.socket_opens.insert(op, (c, sid));
        let target = canonical(addr);
        self.session(c, sid).phase = Phase::Opening { op, target };
    }

    /// spec §7.1: `Opening` → `Live` and the RESP OK, or `SocketFailed`. An
    /// unaccepted RESP tail is retried on `StreamWritable` (`on_writable`).
    pub(super) fn udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        let Some((c, sid)) = self.socket_opens.remove(&op) else {
            return;
        };
        let sock = match r {
            Ok((sock, _)) => sock,
            Err(k) => {
                log::warn!("mq_udp_srv: session {sid} socket failed ({k:?})");
                return self.refuse(cx, c, sid, UdpErr::SocketFailed);
            }
        };
        let sess = self.session(c, sid);
        let Phase::Opening { target, .. } = sess.phase else {
            unreachable!("socket_opens holds Opening sessions");
        };
        sess.phase = Phase::Live { sock, target };
        // Exact: `idle_len` was built from these milliseconds.
        let (s, idle) = (sess.stream, sess.idle_len.as_millis() as u64);
        log::info!("mq_udp_srv: session {sid} OPEN ok (idle={idle}ms)");
        let d = self.data.get_mut(&s).expect("session stream");
        d.tx = udp_resp(Ok(idle));
        if !app_stream::flush(cx, s, &mut d.tx, false) {
            log::warn!("mq_udp_srv: session {sid} UDP_SESSION_RESP send failed");
            self.drop_data(cx, s, true);
        }
    }

    /// spec §7.1: a session refused after admission frees its sid and slot;
    /// its stream retires with the error RESP.
    fn refuse(&mut self, cx: &mut Cx<'_>, c: ConnId, sid: u32, e: UdpErr) {
        let k = self.conns.get_mut(&c).expect("admitted");
        let sess = k.udp.remove(&sid).expect("admitted");
        self.respond_error(cx, sess.stream, udp_resp(Err(e)));
    }

    /// spec §7.2 `end_session`, run by `drop_data` (which resets and forgets
    /// the stream): dispose of the socket or the pending resolve / open, and
    /// free the sid and its slot.
    pub(super) fn end_session(&mut self, cx: &mut Cx<'_>, c: ConnId, sid: u32) {
        let Some(sess) = self.conns.get_mut(&c).and_then(|k| k.udp.remove(&sid)) else {
            return;
        };
        match sess.phase {
            Phase::Resolving(op) => {
                self.resolves.remove(&op);
                cx.cancel_resolve(op);
            }
            Phase::Opening { op, .. } => {
                self.socket_opens.remove(&op);
                cx.cancel_udp_socket(op);
            }
            Phase::Live { sock, .. } => cx.close_udp_socket(sock),
        }
        log::info!("mq_udp_srv: session {sid} closed");
    }
}
