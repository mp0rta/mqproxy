// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §7.5 / §7.6: `MStream` — one h2 stream ⇄ one H3 exchange. The
//! settlement table is the only place a stream's state ends.

use super::MStreamKey;
use super::head::{MapErr, map_request, map_response, misdirected_response, reject_response};
use super::policy::Sni;
use crate::client::Owner;
use crate::client::exchange::{BodyOut, Exchanges, HeadOut, Ready, SendOut};
use bytes::{Buf, Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{Reason, RecvStream, SendStream};
use http::{Method, Request, Response};
use mq_http::headers::Reject;
use mq_runtime::Cx;
use mq_transport_api::{ConnId, H3ReqId};
use std::task::{Context, Poll};

/// SP4 spec §7.6 step 6: one download read; also the stream's per-pass
/// budget (R2: one pass moves at most `MSTREAM_MAX × DL_CHUNK` downloads).
const DL_CHUNK: usize = 16 * 1024;

pub(super) struct MStream {
    /// The h2 stream id (`MStreamKey.stream`).
    pub(super) id: u32,
    /// `Some` until `Last` / `Fail` / `reset`.
    ex: Option<H3ReqId>,
    method_is_head: bool,
    up: Up,
    down: Down,
    /// Download scratch, reused.
    buf: BytesMut,
    /// The exchange may have body bytes (§7.6 readiness gate).
    h3_ready: bool,
}

enum Up {
    Recv {
        recv: RecvStream,
        carry: Bytes,
        /// `send_body` said `Blocked`: wait for `Ready::Writable`.
        blocked: bool,
    },
    Done,
}

enum Down {
    AwaitHead(SendResponse<Bytes>),
    Body(SendStream<Bytes>),
    /// The bodiless response already ended toward the browser; the exchange
    /// is read to `Last` / `Fail` and discarded. The handle is kept only to
    /// see a browser reset.
    Drain(SendStream<Bytes>),
    Done,
}

impl MStream {
    /// SP4 spec §7.5: map and open, or answer at once (reject, 421,
    /// `RST_STREAM(PROTOCOL_ERROR)`). `None` when nothing is retained.
    pub(super) fn open(
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tunnel: Option<ConnId>,
        key: MStreamKey,
        (req, mut respond): (Request<RecvStream>, SendResponse<Bytes>),
        sni: &Sni,
        auth: &[u8],
    ) -> Option<MStream> {
        let (parts, recv) = req.into_parts();
        let end = recv.is_end_stream();
        let head = match map_request(&parts, end, sni, auth) {
            Ok(h) => h,
            Err(MapErr::Reject(r)) => return answer(respond, reject_response(r)),
            Err(MapErr::Misdirected) => return answer(respond, misdirected_response()),
            Err(MapErr::Malformed) => {
                respond.send_reset(Reason::PROTOCOL_ERROR);
                return None;
            }
        };
        let opened = (tunnel.ok_or(Reject::TunnelUnavailable))
            .and_then(|conn| ex.open(cx, conn, &head, Owner::Mitm(key)));
        let id = match opened {
            Ok(id) => id,
            Err(r) => return answer(respond, reject_response(r)),
        };
        let up = match end {
            true => Up::Done,
            false => Up::Recv {
                recv,
                carry: Bytes::new(),
                blocked: false,
            },
        };
        Some(MStream {
            id: key.stream,
            ex: Some(id),
            method_is_head: parts.method == Method::HEAD,
            up,
            down: Down::AwaitHead(respond),
            buf: BytesMut::new(),
            h3_ready: false,
        })
    }

    /// The exchange's readiness for this stream.
    pub(super) fn on_ready(&mut self, r: Ready) {
        match r {
            Ready::Readable => self.h3_ready = true,
            Ready::Writable => {
                if let Up::Recv { blocked, .. } = &mut self.up {
                    *blocked = false;
                }
            }
        }
    }

    /// Settled: the stream can be removed (§7.6).
    pub(super) fn done(&self) -> bool {
        self.ex.is_none() && matches!(self.up, Up::Done) && matches!(self.down, Down::Done)
    }

    /// One §7.6 step: the upload, then the download, which always runs after
    /// a `SendOut::Done` (a send error leaves the core `Failed` with no
    /// readiness to follow, Task 5.1 ruling). `room`: the TLS output is below
    /// its caps. `true` when anything moved.
    pub(super) fn step(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
        room: bool,
    ) -> bool {
        let up = self.upload(cx, ex, tcx);
        self.download(cx, ex, tcx, room) || up
    }

    /// Settlement "browser cancel": the exchange is reset, both sides dropped.
    fn cancel(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>) {
        if let Some(id) = self.ex.take() {
            ex.reset(cx, id);
        }
        self.up = Up::Done;
        self.down = Down::Done;
    }

    /// Settlement "`read_*` returns `Last` or `Fail`": dropping `recv` lets
    /// h2 send its implicit RST_STREAM(NO_ERROR) after the queued response.
    fn ended(&mut self) {
        self.ex = None;
        self.up = Up::Done;
    }

    /// SP4 spec §7.6 "Upload": credit returns to the browser only for what
    /// the tunnel took.
    fn upload(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
    ) -> bool {
        let mut moved = false;
        loop {
            let (
                Some(id),
                Up::Recv {
                    recv,
                    carry,
                    blocked,
                },
            ) = (self.ex, &mut self.up)
            else {
                return moved;
            };
            if *blocked {
                return moved;
            }
            let mut fin = false;
            if carry.is_empty() {
                match recv.poll_data(tcx) {
                    Poll::Pending => return moved,
                    // An empty DATA frame is skipped: forwarding it would
                    // enter xquic's zero-length send path.
                    Poll::Ready(Some(Ok(b))) => {
                        *carry = b;
                        continue;
                    }
                    Poll::Ready(Some(Err(_))) => {
                        self.cancel(cx, ex);
                        return true;
                    }
                    Poll::Ready(None) => fin = true,
                }
            }
            match ex.send_body(cx, id, carry, fin) {
                SendOut::Accepted(n) => {
                    carry.advance(n);
                    let _ = recv.flow_control().release_capacity(n);
                    moved |= n > 0;
                    if fin {
                        self.up = Up::Done;
                        return true;
                    }
                }
                SendOut::Blocked => {
                    *blocked = true;
                    return moved;
                }
                // The download goes on.
                SendOut::Done => {
                    let _ = recv.flow_control().release_capacity(carry.len());
                    self.up = Up::Done;
                    return true;
                }
            }
        }
    }

    /// SP4 spec §7.6 "Download": the control path (cancel, end, failure)
    /// never waits for send capacity.
    fn download(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
        room: bool,
    ) -> bool {
        let Some(id) = self.ex else { return false };
        match &mut self.down {
            Down::AwaitHead(_) => self.await_head(cx, ex, tcx, id, room),
            Down::Body(_) => self.body(cx, ex, tcx, id, room),
            Down::Drain(_) => self.drain(cx, ex, tcx, id),
            Down::Done => false,
        }
    }

    fn await_head(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
        id: H3ReqId,
        room: bool,
    ) -> bool {
        let Down::AwaitHead(respond) = &mut self.down else {
            return false;
        };
        if respond.poll_reset(tcx).is_ready() {
            self.cancel(cx, ex);
            return true;
        }
        let head = match ex.read_head(cx, id) {
            HeadOut::Wait => return false,
            HeadOut::Fail(r) => {
                let _ = respond.send_response(reject_response(r), true);
                self.ended();
                self.down = Down::Done;
                return true;
            }
            HeadOut::Head(h) => h,
        };
        // §7.7: a refused name or value, or a user error, is malformed.
        let bodiless = self.method_is_head || matches!(head.status, 204 | 304);
        let sent = (map_response(&head).ok()).and_then(|r| respond.send_response(r, bodiless).ok());
        let Some(send) = sent else {
            respond.send_reset(Reason::INTERNAL_ERROR);
            self.cancel(cx, ex);
            return true;
        };
        self.h3_ready = true;
        if bodiless {
            self.down = Down::Drain(send);
            self.drain(cx, ex, tcx, id);
        } else {
            self.down = Down::Body(send);
            self.body(cx, ex, tcx, id, room);
        }
        true
    }

    /// `Body`, steps 1–6 in the §7.6 order.
    fn body(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
        id: H3ReqId,
        room: bool,
    ) -> bool {
        let Down::Body(send) = &mut self.down else {
            return false;
        };
        // 1. Cancel.
        if send.poll_reset(tcx).is_ready() {
            self.cancel(cx, ex);
            return true;
        }
        // 2. Terminal probe: an empty read sees an empty transport FIN
        // without capacity (R1). Its `Wait` never touches `h3_ready`.
        match ex.read_body(cx, id, &mut []) {
            BodyOut::Last(_) => return self.finish(cx, ex, Bytes::new()),
            BodyOut::Fail => return self.fail(),
            BodyOut::Wait | BodyOut::Data(_) => {}
        }
        // 3. Readiness gate: nothing reserved or polled for an idle body.
        if !self.h3_ready {
            send.reserve_capacity(0);
            return false;
        }
        let mut budget = true;
        let mut moved = false;
        loop {
            // 4. Output gate; the flush or the continuation re-pumps.
            if !room || !budget {
                send.reserve_capacity(0);
                return moved;
            }
            // 5. Capacity. A `Pending` keeps the reservation: h2 wakes
            // `dirty` when it assigns the credit.
            let mut cap = send.capacity();
            while cap == 0 {
                send.reserve_capacity(DL_CHUNK);
                match send.poll_capacity(tcx) {
                    Poll::Ready(Some(Ok(_))) => cap = send.capacity(),
                    Poll::Pending => return moved,
                    Poll::Ready(None | Some(Err(_))) => {
                        self.cancel(cx, ex);
                        return true;
                    }
                }
            }
            // 6. Payload.
            self.buf.clear();
            self.buf.resize(cap.min(DL_CHUNK), 0);
            match ex.read_body(cx, id, &mut self.buf) {
                BodyOut::Data(n) => {
                    if send
                        .send_data(self.buf.split_to(n).freeze(), false)
                        .is_err()
                    {
                        self.cancel(cx, ex);
                        return true;
                    }
                    budget = false;
                    moved = true;
                }
                BodyOut::Last(n) => {
                    let tail = self.buf.split_to(n).freeze();
                    return self.finish(cx, ex, tail);
                }
                BodyOut::Fail => return self.fail(),
                BodyOut::Wait => {
                    self.h3_ready = false;
                    send.reserve_capacity(0);
                    return moved;
                }
            }
        }
    }

    /// `Body` got `Last`: the tail with END_STREAM (an empty one needs no
    /// capacity), then settled.
    fn finish(&mut self, cx: &mut Cx<'_>, ex: &mut Exchanges<Owner>, tail: Bytes) -> bool {
        self.ended();
        if let Down::Body(send) = &mut self.down
            && send.send_data(tail, true).is_err()
        {
            self.cancel(cx, ex);
        }
        self.down = Down::Done;
        true
    }

    /// `Body` got `Fail`: RST_STREAM(INTERNAL_ERROR), settled.
    fn fail(&mut self) -> bool {
        self.ended();
        if let Down::Body(send) = &mut self.down {
            send.send_reset(Reason::INTERNAL_ERROR);
        }
        self.down = Down::Done;
        true
    }

    /// `Drain`: read and discard until `Last` or `Fail`, one chunk per step
    /// (the per-stream budget, R2); the next pass goes on.
    fn drain(
        &mut self,
        cx: &mut Cx<'_>,
        ex: &mut Exchanges<Owner>,
        tcx: &mut Context<'_>,
        id: H3ReqId,
    ) -> bool {
        let Down::Drain(send) = &mut self.down else {
            return false;
        };
        if send.poll_reset(tcx).is_ready() {
            self.cancel(cx, ex);
            return true;
        }
        self.buf.clear();
        self.buf.resize(DL_CHUNK, 0);
        match ex.read_body(cx, id, &mut self.buf) {
            BodyOut::Data(_) => true,
            BodyOut::Wait => false,
            BodyOut::Last(_) | BodyOut::Fail => {
                self.ended();
                self.down = Down::Done;
                true
            }
        }
    }
}

/// Settlement "a reject response is queued": nothing is retained.
fn answer(mut respond: SendResponse<Bytes>, resp: Response<()>) -> Option<MStream> {
    let _ = respond.send_response(resp, true);
    None
}
