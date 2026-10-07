// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §5: the client gateway — the fetch listener's requests, composed
//! into `Client` (§5.8). SP4 spec §6: the fetch front (①) — H1 parse and
//! render, the TCP side only; the H3 request goes through the exchange core.

mod download;
mod head;

use super::{Owner, discard};
use crate::client::exchange::{BodyOut, EofOut, Exchanges, HeadOut, Ready, SendOut};
use crate::config::ClientConfig;
use download::render_head;
use head::{fetch_head, synth_error};
use mq_http::h1::{self, HEAD_MAX, Progress};
use mq_http::headers::{Method, Reject, is_head, reject_status, reject_xmq};
use mq_runtime::{AcceptMeta, Cx, TCP_BUF, TcpEnd, TcpId, TimerId};
use mq_transport_api::{ConnId, H3ReqId};
use std::collections::HashMap;
use std::time::Duration;

/// SP3 spec §5.3/§5.4: one upload copy, one download read.
const DL_CHUNK: usize = 16 * 1024;

/// SP3 spec §5.1: the only request the fetch listener serves.
const FETCH_METHOD: &[u8] = b"POST";
const FETCH_PATH: &[u8] = b"/_mqproxy/fetch";

/// SP3 spec §5.8: the gateway's timers (`Tm::GwHead`).
#[derive(Copy, Clone, Debug)]
pub enum GwTm {
    Head(TcpId),
}

/// SP3 spec §5.1–§5.5: one fetch request, by local socket.
enum GwReq {
    /// Waiting for the complete request head (§5.2).
    Head { timer: TimerId },
    /// The exchange is open (SP4 spec §6.2): upload §5.3, download §5.4.
    Open {
        h3: H3ReqId,
        /// The fetch method (`X-Mq-Method`), for the head render.
        method: Method,
        /// The response head was written.
        started: bool,
        /// No `content-length`: the body is chunk-framed.
        chunked: bool,
        /// A framed read that did not fit (`SendBufFull`); nothing is read meanwhile.
        pending: Vec<u8>,
    },
    /// SP4 spec §6.1: the exchange ended (`Last`); `pending`, then the chunk
    /// terminator when `chunked`, then `tcp_close`.
    Finishing { pending: Vec<u8>, chunked: bool },
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
    ingress_deadline: Duration,
}

/// SP3 spec §5: the client gateway.
pub struct Gateway {
    reqs: HashMap<TcpId, GwReq>,
    timers: HashMap<TimerId, GwTm>,
    cfg: GwCfg,
}

impl Gateway {
    pub fn new(cfg: &ClientConfig) -> Gateway {
        Gateway {
            reqs: HashMap::new(),
            timers: HashMap::new(),
            cfg: GwCfg {
                ingress_deadline: cfg.ingress_deadline,
            },
        }
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

    /// SP3 spec §5.1.
    pub fn on_accepted(&mut self, cx: &mut Cx<'_>, tcp: TcpId, _meta: AcceptMeta) {
        cx.tcp_set_rx_limit(tcp, HEAD_MAX);
        let timer = self.timer(cx, self.cfg.ingress_deadline, GwTm::Head(tcp));
        self.reqs.insert(tcp, GwReq::Head { timer });
    }

    pub fn owns_tcp(&self, tcp: TcpId) -> bool {
        self.reqs.contains_key(&tcp)
    }

    /// SP3 spec §5.2 (head) / §5.3 (upload); SP4 spec §4.5: once the
    /// exchange ended, the rest of the upload is discarded.
    pub(crate) fn on_tcp_data(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) {
        match self.reqs.get(&tcp) {
            Some(GwReq::Head { .. }) => self.head_data(cx, ex, tunnel, tcp),
            Some(GwReq::Open { .. }) => self.upload(cx, ex, tcp),
            Some(GwReq::Finishing { .. }) => discard(cx, tcp),
            None => {}
        }
    }

    /// SP4 spec §2.2: the exchange core's readiness for this request.
    pub(crate) fn on_ready(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcp: TcpId,
        ready: Ready,
    ) {
        match ready {
            Ready::Readable => self.download(cx, ex, tcp),
            Ready::Writable => self.upload(cx, ex, tcp),
        }
    }

    /// SP3 spec §5.2: parse the head; listener replies, then the reject
    /// sequence, then open the exchange and hand over to the upload.
    fn head_data(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        tcp: TcpId,
    ) {
        let rx = cx.tcp_rx(tcp);
        let parsed = match h1::parse_head(rx) {
            Progress::Need if rx.len() < HEAD_MAX => return,
            Progress::Done { consumed, head } => {
                if head.method != FETCH_METHOD || head.target != FETCH_PATH {
                    Err((404, "Not Found"))
                } else if head.has_chunked_te {
                    Err((411, "Length Required"))
                } else {
                    Ok((consumed, fetch_head(&head)))
                }
            }
            Progress::Need | Progress::TooLarge | Progress::Bad => Err((400, "Bad Request")),
        };
        if let Some(GwReq::Head { timer }) = self.reqs.remove(&tcp) {
            self.cancel(cx, timer);
        }
        let (consumed, req) = match parsed {
            Ok(p) => p,
            Err((code, phrase)) => return listener_reply(cx, tcp, code, phrase),
        };
        cx.tcp_consume(tcp, consumed);
        // SP3 spec §5.2 steps 9–10: the size checks run in `open` (SP4 spec §4.4).
        let opened = req.and_then(|req| {
            let conn = tunnel.ok_or(Reject::TunnelUnavailable)?;
            Ok((ex.open(cx, conn, &req, Owner::Fetch(tcp))?, req.method))
        });
        let (h3, method) = match opened {
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
        let open = GwReq::Open {
            h3,
            method,
            started: false,
            chunked: false,
            pending: Vec::new(),
        };
        self.reqs.insert(tcp, open);
        cx.tcp_set_rx_limit(tcp, TCP_BUF);
        // Body bytes from the head's read get no further `on_tcp_data`.
        self.upload(cx, ex, tcp);
    }

    /// SP3 spec §5.3 through `send_body` (SP4 spec §6.2): offer what `tcp_rx`
    /// holds in `DL_CHUNK` slices; the core takes at most the remaining length
    /// (the FIN riding the last byte) and reports the excess as taken.
    /// `Blocked` consumes nothing and waits for `Ready::Writable`; `Done`
    /// discards the rest and pulls the response.
    fn upload(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId) {
        let Some(&GwReq::Open { h3, .. }) = self.reqs.get(&tcp) else {
            return;
        };
        let mut buf = [0u8; DL_CHUNK];
        loop {
            let rx = cx.tcp_rx(tcp);
            let take = rx.len().min(DL_CHUNK);
            if take == 0 {
                return;
            }
            buf[..take].copy_from_slice(&rx[..take]);
            match ex.send_body(cx, h3, &buf[..take], false) {
                SendOut::Accepted(n) => cx.tcp_consume(tcp, n),
                SendOut::Blocked => return,
                // A send error failed the response, and no readiness follows:
                // pull it now (a no-op `Wait` otherwise).
                SendOut::Done => {
                    discard(cx, tcp);
                    return self.download(cx, ex, tcp);
                }
            }
        }
    }

    /// SP3 spec §5.4 through `read_head` / `read_body` (SP4 spec §6.2): the
    /// response head, then the body pump — 16 KiB reads, chunk-framed without
    /// a `content-length`, read only while `pending` is empty (a frame that
    /// hit `SendBufFull` waits for `on_tcp_writable`); `Last` finishes.
    fn download(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId) {
        let Some(GwReq::Open {
            h3,
            method,
            started,
            chunked,
            pending,
        }) = self.reqs.get_mut(&tcp)
        else {
            return;
        };
        let h3 = *h3;
        if !*started {
            let head = match ex.read_head(cx, h3) {
                HeadOut::Head(head) => head,
                HeadOut::Wait => return,
                HeadOut::Fail(r) => return self.synth_reply(cx, ex, tcp, r),
            };
            // Nothing was written before, so the head always fits.
            let Ok(bytes) = render_head(&head, is_head(method)) else {
                return self.synth_reply(cx, ex, tcp, Reject::UpstreamProtocol);
            };
            *started = true;
            *chunked = !head.has_cl;
            if cx.tcp_write(tcp, &bytes).is_err() {
                *pending = bytes;
            }
        }
        let mut buf = [0u8; DL_CHUNK];
        while pending.is_empty() {
            let (n, last) = match ex.read_body(cx, h3, &mut buf) {
                BodyOut::Data(n) => (n, false),
                BodyOut::Last(n) => (n, true),
                BodyOut::Wait => return,
                BodyOut::Fail => return self.abort(cx, ex, tcp),
            };
            // A zero-length read is never framed (it would end the body).
            if n > 0 {
                let mut f = Vec::new();
                let frame = if *chunked {
                    h1::chunk_frame(&mut f, &buf[..n]);
                    &f[..]
                } else {
                    &buf[..n]
                };
                if cx.tcp_write(tcp, frame).is_err() {
                    *pending = frame.to_vec();
                }
            }
            if last {
                let f = GwReq::Finishing {
                    pending: std::mem::take(pending),
                    chunked: *chunked,
                };
                self.reqs.insert(tcp, f);
                return self.flush(cx, tcp);
            }
        }
    }

    /// SP4 spec §6.1 `Finishing`: write `pending`, then the chunk terminator,
    /// then `tcp_close` — each only once the previous write was accepted; a
    /// `SendBufFull` waits for `on_tcp_writable`.
    fn flush(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(GwReq::Finishing { pending, chunked }) = self.reqs.get_mut(&tcp) else {
            return;
        };
        loop {
            if !pending.is_empty() {
                if cx.tcp_write(tcp, pending).is_err() {
                    return;
                }
                pending.clear();
            }
            if !std::mem::take(chunked) {
                break;
            }
            h1::chunk_end(pending);
        }
        self.reqs.remove(&tcp);
        cx.tcp_close(tcp);
    }

    /// SP3 spec §5.6: the synthesised error reply, then remove.
    fn synth_reply(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId, r: Reject) {
        reply_close(cx, tcp, &synth_error(reject_status(r), reject_xmq(r)));
        self.remove(cx, ex, tcp);
    }

    /// Remove the request: cancel a `Head` timer; reset an open exchange (a
    /// no-op once the core removed it, SP4 spec §4.3).
    fn remove(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId) {
        match self.reqs.remove(&tcp) {
            Some(GwReq::Head { timer }) => self.cancel(cx, timer),
            Some(GwReq::Open { h3, .. }) => ex.reset(cx, h3),
            _ => {}
        }
    }

    /// SP3 spec §5.5 abort (truncation visible): `tcp_abort`, reset, remove.
    fn abort(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tcp: TcpId) {
        cx.tcp_abort(tcp);
        self.remove(cx, ex, tcp);
    }

    /// SP3 spec §5.2 (an end before the head is complete closes silently)
    /// and §5.3 (the EOF rule, the core's `upload_eof`: a shortfall is a
    /// truncation; `Error` resets and removes — the shard already closed the
    /// socket).
    pub(crate) fn on_tcp_end(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcp: TcpId,
        end: TcpEnd,
    ) {
        match (self.reqs.get(&tcp), end) {
            (Some(&GwReq::Head { timer }), _) => {
                self.reqs.remove(&tcp);
                self.cancel(cx, timer);
                if end == TcpEnd::ReadEof {
                    cx.tcp_close(tcp);
                }
            }
            (Some(_), TcpEnd::Error(_)) => self.remove(cx, ex, tcp),
            (Some(&GwReq::Open { h3, .. }), TcpEnd::ReadEof) => {
                let buffered = cx.tcp_rx(tcp).len() as u64;
                if ex.upload_eof(cx, h3, buffered) == EofOut::Truncated {
                    self.abort(cx, ex, tcp);
                }
            }
            _ => {}
        }
    }

    /// SP3 spec §5.4: write the pending frame; if it fits, resume the pump.
    /// §5.5: keep flushing a finishing request.
    pub(crate) fn on_tcp_writable(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcp: TcpId,
    ) {
        match self.reqs.get_mut(&tcp) {
            Some(GwReq::Open { pending, .. }) => {
                if cx.tcp_write(tcp, pending).is_ok() {
                    pending.clear();
                    self.download(cx, ex, tcp);
                }
            }
            Some(GwReq::Finishing { .. }) => self.flush(cx, tcp),
            _ => {}
        }
    }

    /// SP3 spec §5.8: `false` = not the gateway's timer.
    pub fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) -> bool {
        let Some(tm) = self.timers.remove(&id) else {
            return false;
        };
        match tm {
            // §5.1: only armed while in `Head` (cancelled on leaving it).
            GwTm::Head(tcp) => {
                if self.reqs.remove(&tcp).is_some() {
                    listener_reply(cx, tcp, 400, "Bad Request");
                }
            }
        }
        true
    }

    /// SP3 spec §5.9: abort every request (one `h3_reset` while live); the
    /// tunnel is closed by `H3Tunnel::on_shutdown`.
    pub(crate) fn on_shutdown(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>) {
        let live: Vec<TcpId> = self.reqs.keys().copied().collect();
        for tcp in live {
            self.abort(cx, ex, tcp);
        }
    }
}
