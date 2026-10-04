//! SP3 spec §5: the client gateway — the fetch listener's requests and their own
//! H3 tunnel connection (§5.7), composed into `Client` (§5.8).

mod download;
mod head;

use super::backoff::Backoff;
use super::paths::Paths;
use super::{SNI, log_conn_metrics};
use crate::config::ClientConfig;
use download::{HeadCollector, Malformed, render_head};
use head::{Head, synth_error};
use mq_http::h1::{self, HEAD_MAX, Progress};
use mq_http::headers::{Method, Reject, body_check_applies, is_head, reject_status, reject_xmq};
use mq_runtime::{AcceptMeta, Cx, SocketOpId, TCP_BUF, TcpEnd, TcpId, TimerId, UdpSocketId};
use mq_transport_api::{
    ConnConfig, ConnId, ConnProto, Event, H3Header, H3ReqId, StreamError, Unread,
};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// SP3 spec §5.3/§5.4: one upload copy, one download read.
const DL_CHUNK: usize = 16 * 1024;

/// SP3 spec §5.1: the only request the fetch listener serves.
const FETCH_METHOD: &[u8] = b"POST";
const FETCH_PATH: &[u8] = b"/_mqproxy/fetch";

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
    /// The H3 request is open (§5.2 accept): upload §5.3, download §5.4.
    Open {
        h3: H3ReqId,
        /// The fetch method (`X-Mq-Method`), for the head render and body check.
        method: Method,
        upload: Upload,
        download: Download,
    },
    /// SP3 spec §5.5 finish: the H3 side is done; `pending`, then frames cut
    /// from the rescued `src` from `off` (§3.7 (2)), then the chunk terminator
    /// when `chunked`, then `tcp_close`.
    Finishing {
        src: Option<Unread>,
        off: usize,
        pending: Vec<u8>,
        chunked: bool,
    },
}

/// SP3 spec §5.3: the local request body still to send.
struct Upload {
    remaining: u64,
}

/// SP3 spec §5.4: the response relayed so far.
#[derive(Default)]
struct Download {
    /// The response head was written.
    started: bool,
    /// No `content-length`: the body is chunk-framed.
    chunked: bool,
    /// A framed read that did not fit (`SendBufFull`); nothing is read meanwhile.
    pending: Vec<u8>,
    /// Body bytes read from H3.
    delivered: u64,
    /// A single, strictly numeric `content-length`.
    cl: Option<u64>,
    status: u16,
}

impl Download {
    /// SP3 spec §5.4: render the collected head and write it (it fits:
    /// nothing was written before, ≤ 8192 bytes); `Ok(fin)` of the section.
    fn start(
        &mut self,
        cx: &mut Cx<'_>,
        tcp: TcpId,
        method: &Method,
        col: HeadCollector,
        fin: bool,
    ) -> Result<bool, Malformed> {
        let head = col.finish(fin)?;
        let bytes = render_head(&head, is_head(method))?;
        self.started = true;
        self.chunked = !head.has_cl;
        self.cl = head.cl;
        self.status = head.status;
        if cx.tcp_write(tcp, &bytes).is_err() {
            self.pending = bytes;
        }
        Ok(head.fin)
    }
}

/// Write `reply` (it always fits: nothing else was written) and close (§5.2, §5.6).
fn reply_close(cx: &mut Cx<'_>, tcp: TcpId, reply: &[u8]) {
    let _ = cx.tcp_write(tcp, reply);
    cx.tcp_close(tcp);
}

/// SP3 spec §2.2: the listener-owned replies carry no `X-Mq-Error`.
fn listener_reply(cx: &mut Cx<'_>, tcp: TcpId, code: u16, phrase: &str) {
    reply_close(cx, tcp, &h1::error_reply(code, phrase, None));
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
            Event::PathRemoved(c, p) if mine == Some(c) => self.tunnel.paths.on_path_removed(cx, p),
            // Ignored once EOF was read (out of `by_h3`, §5.5).
            Event::H3Closed(r, close) => {
                if let Some(tcp) = self.by_h3.remove(&r) {
                    self.h3_closed(cx, tcp, close.unread);
                }
            }
            // Only the gateway holds H3 requests on the client (§5.8).
            Event::H3Writable(r) => {
                if let Some(&tcp) = self.by_h3.get(&r) {
                    self.upload(cx, tcp);
                }
            }
            Event::H3Readable(r) => {
                if let Some(&tcp) = self.by_h3.get(&r) {
                    self.download(cx, tcp);
                }
            }
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

    /// SP3 spec §5.2 (head) / §5.3 (upload).
    pub fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        match self.reqs.get(&tcp) {
            Some(GwReq::Head { .. }) => self.head_data(cx, tcp),
            Some(GwReq::Open { .. }) => self.upload(cx, tcp),
            _ => {}
        }
    }

    /// SP3 spec §5.2: parse the head; listener replies, then the reject
    /// sequence, then open the H3 request and hand over to the upload.
    fn head_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let rx = cx.tcp_rx(tcp);
        let parsed = match h1::parse_head(rx) {
            Progress::Need if rx.len() < HEAD_MAX => return,
            Progress::Done { consumed, head } => {
                if head.method != FETCH_METHOD || head.target != FETCH_PATH {
                    Err((404, "Not Found"))
                } else if head.has_chunked_te {
                    Err((411, "Length Required"))
                } else {
                    Ok((consumed, Head::from_h1(&head)))
                }
            }
            Progress::Need | Progress::TooLarge | Progress::Bad => Err((400, "Bad Request")),
        };
        if let Some(GwReq::Head { timer }) = self.reqs.remove(&tcp) {
            self.cancel(cx, timer);
        }
        let (consumed, head) = match parsed {
            Ok(p) => p,
            Err((code, phrase)) => return listener_reply(cx, tcp, code, phrase),
        };
        cx.tcp_consume(tcp, consumed);
        let (h3, method) = match self.open(cx, &head) {
            Ok(x) => x,
            Err(r) => {
                let code = reject_status(r);
                let phrase = if code == 400 {
                    "Bad Request"
                } else {
                    "Bad Gateway"
                };
                return reply_close(cx, tcp, &h1::error_reply(code, phrase, Some(reject_xmq(r))));
            }
        };
        let upload = Upload {
            remaining: head.content_length,
        };
        let download = Download::default();
        let open = GwReq::Open {
            h3,
            method,
            upload,
            download,
        };
        self.reqs.insert(tcp, open);
        self.by_h3.insert(h3, tcp);
        cx.tcp_set_rx_limit(tcp, TCP_BUF);
        // Body bytes from the head's read get no further `on_tcp_data`.
        self.upload(cx, tcp);
    }

    /// SP3 spec §5.2 steps 1–10; on `Err` nothing is left open.
    fn open(&self, cx: &mut Cx<'_>, head: &Head) -> Result<(H3ReqId, Method), Reject> {
        let checked = head::check(head)?;
        let conn = self.pick_conn().ok_or(Reject::TunnelUnavailable)?;
        let h3 = cx
            .open_h3_request(conn)
            .map_err(|_| Reject::TunnelUnavailable)?;
        let fwd = head::forwarded_headers(head, &checked);
        let hs: Vec<H3Header<'_>> = fwd
            .iter()
            .map(|(name, value)| H3Header { name, value })
            .collect();
        // Fail closed, no retry (as C): `Blocked` too.
        if cx
            .h3_send_headers(h3, &hs, head.content_length == 0)
            .is_err()
        {
            cx.h3_reset(h3);
            return Err(Reject::TunnelUnavailable);
        }
        Ok((h3, checked.method))
    }

    /// SP3 spec §5.3: send what `tcp_rx` holds, up to the remaining length,
    /// the FIN riding the last byte; bytes beyond it are discarded. `Blocked`
    /// consumes nothing and waits for `H3Writable`; any other error aborts.
    fn upload(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(GwReq::Open { h3, upload, .. }) = self.reqs.get_mut(&tcp) else {
            return;
        };
        let h3 = *h3;
        let mut buf = [0u8; DL_CHUNK];
        loop {
            let rx = cx.tcp_rx(tcp);
            if upload.remaining == 0 {
                let extra = rx.len();
                cx.tcp_consume(tcp, extra);
                return;
            }
            let take = usize::try_from(upload.remaining)
                .unwrap_or(usize::MAX)
                .min(rx.len())
                .min(DL_CHUNK);
            if take == 0 {
                return;
            }
            buf[..take].copy_from_slice(&rx[..take]);
            let fin = take as u64 == upload.remaining;
            match cx.h3_send_body(h3, &buf[..take], fin) {
                Ok(0) | Err(StreamError::Blocked) => return,
                Ok(n) => {
                    cx.tcp_consume(tcp, n);
                    upload.remaining -= n as u64;
                }
                Err(_) => return self.abort(cx, tcp),
            }
        }
    }

    /// SP3 spec §5.4: the response head, then the body pump — 16 KiB reads,
    /// chunk-framed without a `content-length`, written until `SendBufFull`
    /// (the frame waits in `pending` for `on_tcp_writable`); `fin` ends it.
    fn download(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(GwReq::Open {
            h3,
            method,
            download: d,
            ..
        }) = self.reqs.get_mut(&tcp)
        else {
            return;
        };
        let h3 = *h3;
        if !d.started {
            let mut col = HeadCollector::default();
            let fin = match cx.h3_recv_headers(h3, &mut |n, v| col.push(n, v)) {
                Ok(fin) => fin,
                // Stale: a readiness queued before xquic destroyed the request;
                // its `H3Closed` follows with the rescue (§3.7 (2)).
                Err(StreamError::Blocked | StreamError::Stale) => return,
                Err(_) => return self.abort(cx, tcp),
            };
            match d.start(cx, tcp, method, col, fin) {
                Ok(true) => return self.finish(cx, tcp, None),
                Ok(false) => {}
                Err(Malformed) => return self.synth_reply(cx, tcp, Reject::UpstreamProtocol),
            }
        }
        let mut buf = [0u8; DL_CHUNK];
        while d.pending.is_empty() {
            let (n, fin) = match cx.h3_recv_body(h3, &mut buf) {
                Ok(x) => x,
                Err(StreamError::Blocked | StreamError::Stale) => return, // as above
                Err(_) => return self.abort(cx, tcp),
            };
            // A zero-length read is never framed (it would end the body).
            if n > 0 {
                d.delivered += n as u64;
                if d.chunked {
                    let mut f = Vec::with_capacity(n + 12);
                    h1::chunk_frame(&mut f, &buf[..n]);
                    if cx.tcp_write(tcp, &f).is_err() {
                        d.pending = f;
                    }
                } else if cx.tcp_write(tcp, &buf[..n]).is_err() {
                    d.pending = buf[..n].to_vec();
                }
            }
            if fin {
                return self.finish(cx, tcp, None);
            }
        }
    }

    /// SP3 spec §5.5 `H3Closed` before the pump read EOF (already out of
    /// `by_h3`): the rescued leftovers (§3.7 (2)) — the header section while
    /// `!started`, then the body — finish the request; without them, 502
    /// `upstream-reset` before the head, abort after it.
    fn h3_closed(&mut self, cx: &mut Cx<'_>, tcp: TcpId, unread: Option<Unread>) {
        let Some(GwReq::Open {
            method,
            download: d,
            ..
        }) = self.reqs.get_mut(&tcp)
        else {
            return;
        };
        // Without headers while `!started`, `unread` is treated as absent.
        let Some(mut u) = unread.filter(|u| d.started || u.headers.is_some()) else {
            if d.started {
                return self.abort(cx, tcp);
            }
            return self.synth_reply(cx, tcp, Reject::UpstreamReset);
        };
        if !d.started {
            let mut col = HeadCollector::default();
            for (n, v) in u.headers.take().iter().flatten() {
                col.push(n, v);
            }
            if d.start(cx, tcp, method, col, false).is_err() {
                return self.synth_reply(cx, tcp, Reject::UpstreamProtocol);
            }
        }
        self.finish(cx, tcp, Some(u));
    }

    /// SP3 spec §5.5 finish: the §5.4 body check on the delivered plus the
    /// rescued bytes (xquic's fin does not prove frame completeness, §3.7) —
    /// a shortfall aborts — then `Finishing`. EOF was read: the H3 side leaves
    /// `by_h3` (a later `H3Closed` is ignored) and is reset when the upload is
    /// incomplete (an early response; the truncation is real, §12).
    fn finish(&mut self, cx: &mut Cx<'_>, tcp: TcpId, src: Option<Unread>) {
        let Some(GwReq::Open {
            h3,
            method,
            upload,
            download: d,
        }) = self.reqs.get_mut(&tcp)
        else {
            return;
        };
        let rescued = src.as_ref().map_or(0, |u| u.body.len() as u64);
        if body_check_applies(method, d.status) && d.cl.is_some_and(|cl| d.delivered + rescued < cl)
        {
            return self.abort(cx, tcp);
        }
        if self.by_h3.remove(h3).is_some() && upload.remaining > 0 {
            cx.h3_reset(*h3);
        }
        let f = GwReq::Finishing {
            src,
            off: 0,
            pending: std::mem::take(&mut d.pending),
            chunked: d.chunked,
        };
        self.reqs.insert(tcp, f);
        self.flush(cx, tcp);
    }

    /// SP3 spec §5.5 `Finishing`: write `pending`, then `DL_CHUNK` frames cut
    /// from `src`, then the chunk terminator, then `tcp_close` — each only
    /// once the previous write was accepted; a `SendBufFull` waits for
    /// `on_tcp_writable`.
    fn flush(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(GwReq::Finishing {
            src,
            off,
            pending,
            chunked,
        }) = self.reqs.get_mut(&tcp)
        else {
            return;
        };
        loop {
            if !pending.is_empty() {
                if cx.tcp_write(tcp, pending).is_err() {
                    return;
                }
                pending.clear();
            }
            if let Some(u) = src.as_ref().filter(|u| *off < u.body.len()) {
                let b = &u.body[*off..u.body.len().min(*off + DL_CHUNK)];
                *off += b.len();
                if *chunked {
                    h1::chunk_frame(pending, b);
                } else {
                    pending.extend_from_slice(b);
                }
            } else if std::mem::take(chunked) {
                h1::chunk_end(pending);
            } else {
                break;
            }
        }
        self.reqs.remove(&tcp);
        cx.tcp_close(tcp);
    }

    /// SP3 spec §5.6: the synthesised error reply, then remove.
    fn synth_reply(&mut self, cx: &mut Cx<'_>, tcp: TcpId, r: Reject) {
        reply_close(cx, tcp, &synth_error(reject_status(r), reject_xmq(r)));
        self.remove(cx, tcp);
    }

    /// Remove the request: cancel a `Head` timer; `h3_reset` while its H3
    /// side is live (in `by_h3` until EOF or `H3Closed`, §5.5).
    fn remove(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        match self.reqs.remove(&tcp) {
            Some(GwReq::Head { timer }) => self.cancel(cx, timer),
            Some(GwReq::Open { h3, .. }) if self.by_h3.remove(&h3).is_some() => cx.h3_reset(h3),
            _ => {}
        }
    }

    /// SP3 spec §5.5 abort (truncation visible): `tcp_abort`, `h3_reset` if
    /// live, remove.
    fn abort(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        cx.tcp_abort(tcp);
        self.remove(cx, tcp);
    }

    /// SP3 spec §5.2 (an end before the head is complete closes silently)
    /// and §5.3 (EOF rule; `Error` resets and removes — the shard already
    /// closed the socket).
    pub fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        match (self.reqs.get(&tcp), end) {
            (Some(&GwReq::Head { timer }), _) => {
                self.reqs.remove(&tcp);
                self.cancel(cx, timer);
                if end == TcpEnd::ReadEof {
                    cx.tcp_close(tcp);
                }
            }
            (Some(_), TcpEnd::Error(_)) => self.remove(cx, tcp),
            // The tail may still sit in `tcp_rx` behind a `Blocked` H3 side:
            // only a shortfall is a truncation (never a fake FIN).
            (Some(GwReq::Open { upload, .. }), TcpEnd::ReadEof)
                if (cx.tcp_rx(tcp).len() as u64) < upload.remaining =>
            {
                self.abort(cx, tcp)
            }
            _ => {}
        }
    }

    /// SP3 spec §5.4: write the pending frame; if it fits, resume the pump.
    /// §5.5: keep flushing a finishing request.
    pub fn on_tcp_writable(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        match self.reqs.get_mut(&tcp) {
            Some(GwReq::Open { download: d, .. }) => {
                if cx.tcp_write(tcp, &d.pending).is_ok() {
                    d.pending.clear();
                    self.download(cx, tcp);
                }
            }
            Some(GwReq::Finishing { .. }) => self.flush(cx, tcp),
            _ => {}
        }
    }

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
            // A path retry of the tunnel (§5.7: own backoff and paths).
            let conn = self.tunnel.conn.filter(|_| !self.shutting_down);
            return self.tunnel.paths.on_timer(cx, conn, id);
        };
        match tm {
            GwTm::Reconnect => {
                self.tunnel.reconnect = None;
                if !self.connect(cx) {
                    self.arm_reconnect(cx);
                }
            }
            // §5.1: only armed while in `Head` (cancelled on leaving it).
            GwTm::Head(tcp) => {
                if self.reqs.remove(&tcp).is_some() {
                    listener_reply(cx, tcp, 400, "Bad Request");
                }
            }
        }
        true
    }

    /// SP3 spec §5.9: dump the tunnel's block, abort every request (one
    /// `h3_reset` while live), close the tunnel; `Client` exits once both
    /// tunnels are gone.
    pub fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.shutting_down = true;
        if let Some(t) = self.tunnel.reconnect.take() {
            self.cancel(cx, t);
        }
        self.dump_metrics(cx);
        let live: Vec<TcpId> = self.reqs.keys().copied().collect();
        for tcp in live {
            self.abort(cx, tcp);
        }
        if let Some(c) = self.tunnel.conn {
            cx.close_conn(c);
        }
    }

    /// SP3 spec §5.7: the tunnel's `mq.conn` / `mq.path` block.
    pub fn dump_metrics(&self, cx: &Cx<'_>) {
        log_conn_metrics(cx, self.tunnel.conn);
    }
}
