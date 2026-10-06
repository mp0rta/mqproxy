//! Request receive: HEADERS bootstrap, header delivery, body pull and the request-stream
//! transport events (adoption spec §4.3, §4.4).

use crate::conn::log_closed;
use crate::req::{Terminal, req_id};
use crate::{BOOT_READ, H3Wire};
use h3wire::{Event as H3Event, H3Code, HeadersKind, Recv, StreamId as Q};
use mq_transport_api::{
    ConnId, Event, H3Close, H3ReqId, StreamError, StreamId, Time, TransportOps,
};

/// The carry slice to feed with a `cap`-byte buffer: its length, and whether the carried
/// FIN goes with it (only with the whole remaining carry; adoption spec §4.4).
fn slice(carry: usize, carry_fin: bool, cap: usize) -> (usize, bool) {
    let n = carry.min(cap);
    (n, carry_fin && n == carry)
}

impl<T: TransportOps> H3Wire<T> {
    /// Applies `c`'s h3wire events to the requests and queues what the gateway sees
    /// (adoption spec §4.3 "Start", §4.4). Returns the streams aborted with their FIN
    /// unread: they need the retirement read of spec §3.
    pub(crate) fn dispatch(&mut self, c: ConnId) -> Vec<StreamId> {
        let mut retire = Vec::new();
        let Some(conn) = self.conns.get_mut(&c) else {
            return retire;
        };
        while let Some(e) = conn.h3.poll_event() {
            let q = match e {
                H3Event::Headers { stream, .. }
                | H3Event::Finished(stream)
                | H3Event::StreamAborted { stream, .. }
                | H3Event::SendStopped { stream, .. } => stream,
                // The last event. On a live conn the fan-out follows the transport's
                // ConnClosed; with the transport gone, the retained requests close now
                // (adoption spec §4.3 step 4).
                H3Event::Closed { .. } => {
                    conn.h3_closed = true;
                    if conn.gone {
                        let ids: Vec<H3ReqId> = self
                            .reqs
                            .iter()
                            .filter(|(_, r)| r.conn == c)
                            .map(|(&id, _)| id)
                            .collect();
                        for id in ids {
                            self.close_req(id);
                        }
                        self.settle_conn(c);
                    }
                    return retire;
                }
                // GoAway: its cutoff arrives as StreamAborted. PeerSettings, UniStream:
                // nothing to do.
                _ => continue,
            };
            let id = conn.mq.get(&q.0).map(|&s| req_id(s));
            let req = id.and_then(|id| Some((id, self.reqs.get_mut(&id)?)));
            let Some((id, req)) = req else {
                if let H3Event::Headers { block, .. } = e {
                    conn.h3.release(block);
                }
                continue;
            };
            match e {
                H3Event::Headers {
                    block,
                    kind: HeadersKind::Request | HeadersKind::Response,
                    ..
                } => {
                    req.pending_block = Some(block);
                    req.booted = true;
                    if !req.known {
                        // The gateway creates its record on this, and starts intake on
                        // the H3Readable that follows.
                        req.known = true;
                        self.queue.push(Event::H3Request(c, id));
                    }
                    self.queue.push(Event::H3Readable(id));
                    continue;
                }
                // Informational and trailers are released internally.
                H3Event::Headers { block, .. } => {
                    conn.h3.release(block);
                    continue;
                }
                // adoption spec §4.5: the client discards later body, the server resets.
                H3Event::SendStopped { .. } => {
                    req.stop_send();
                    if req.known {
                        self.queue.push(Event::H3Writable(id)); // a blocked pump learns it
                    }
                    continue;
                }
                H3Event::Finished(_) => req.terminal = Some(Terminal::Finished),
                H3Event::StreamAborted { code, source, .. } => {
                    req.terminal = Some(Terminal::Aborted { code, source });
                    if !req.fin_read {
                        retire.push(req.stream);
                    }
                    if let Some(b) = req.pending_block.take() {
                        conn.h3.release(b);
                    }
                    req.carry = Vec::new();
                    req.carry_fin = false;
                    // Aborted: a later StreamClosed is not a peer reset to pass on.
                    req.reset_code_pending = false;
                }
                _ => unreachable!("filtered above"),
            }
            req.booted = true;
            if req.known && !req.handed {
                self.queue.push(Event::H3Readable(id));
            }
        }
        retire
    }

    /// `dispatch`, then the retirement read (adoption spec §3) of every stream it
    /// aborted with the FIN unread, unless the transport already closed it.
    pub(crate) fn dispatch_retire(&mut self, now: Time, c: ConnId) {
        for s in self.dispatch(c) {
            if self.streams.contains_key(&s) {
                self.retire_read(now, s);
            }
        }
    }

    /// Feeds request `id` until a stop condition (adoption spec §4.4).
    ///
    /// `out = None` is the bootstrap: `BOOT_READ` reads, stopping at a gateway-visible
    /// block. `Some(buf)` is a body pull: reads and carry slices of at most `buf.len()`,
    /// stopping at the first payload, which is copied into `buf`. Both stop at a terminal
    /// event, `Paused` and a blocked transport. Returns the payload bytes copied.
    fn feed(
        &mut self,
        now: Time,
        id: H3ReqId,
        mut out: Option<&mut [u8]>,
    ) -> Result<usize, StreamError> {
        let cap = out.as_ref().map_or(BOOT_READ, |b| b.len());
        loop {
            let Some(req) = self.reqs.get_mut(&id) else {
                return Err(StreamError::Stale);
            };
            if req.terminal.is_some() || req.reset_code_pending || (out.is_none() && req.booted) {
                return Ok(0);
            }
            if req.carry.is_empty() && !req.carry_fin {
                req.carry.resize(cap, 0);
                match self.inner.stream_recv(now, req.stream, &mut req.carry) {
                    Ok((n, fin)) => {
                        req.carry.truncate(n);
                        req.carry_fin = fin;
                        req.fin_read = fin;
                        if n == 0 && !fin {
                            return Ok(0);
                        }
                    }
                    Err(e) => {
                        req.carry.clear();
                        // "Reset, code pending": fed nothing more until the code pops.
                        req.reset_code_pending = e == StreamError::Reset;
                        req.fin_read = req.reset_code_pending;
                        return Err(e);
                    }
                }
            }
            let (len, fin) = slice(req.carry.len(), req.carry_fin, cap);
            let Some(conn) = self.conns.get_mut(&req.conn) else {
                return Err(StreamError::Conn);
            };
            let (consumed, body) = match conn.h3.recv(Q(req.quic_id), &req.carry[..len], fin) {
                Err(e) => {
                    log::debug!("h3wire: {e}");
                    req.carry = Vec::new(); // never fed again
                    return Err(StreamError::Conn);
                }
                Ok(Recv::Paused) => return Ok(0),
                Ok(Recv::Body { consumed, range }) => (consumed, Some(range)),
                Ok(
                    Recv::Consumed(n)
                    | Recv::Frame { consumed: n, .. }
                    | Recv::Raw { consumed: n, .. },
                ) => (n, None),
            };
            let mut n = 0;
            if let Some(range) = body {
                // The range lies inside a slice of at most `buf.len()` bytes.
                match out.as_deref_mut() {
                    Some(buf) => {
                        n = range.len();
                        buf[..n].copy_from_slice(&req.carry[range]);
                    }
                    None => debug_assert!(false, "the bootstrap never produces body bytes"),
                }
            }
            let fin_fed = fin && consumed == len;
            req.carry.drain(..consumed);
            req.carry_fin &= !fin_fed;
            // An abort by this feed (malformed, content-length, no final response) gets its
            // retirement read here: raw xquic does not re-notify for bytes it already
            // holds, and later StreamReadables continue it (spec §3).
            let c = req.conn;
            self.dispatch_retire(now, c);
            if n > 0 || (consumed == 0 && !fin_fed) {
                return Ok(n);
            }
        }
    }

    pub(crate) fn recv_headers(
        &mut self,
        now: Time,
        id: H3ReqId,
        each: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError> {
        let req = self
            .reqs
            .get_mut(&id)
            .filter(|r| r.known)
            .ok_or(StreamError::Stale)?;
        if req.aborted() || req.reset_code_pending {
            req.handed = true;
            return Err(StreamError::Reset);
        }
        let b = req.pending_block.ok_or(StreamError::Blocked)?;
        let conn = self.conns.get_mut(&req.conn).ok_or(StreamError::Conn)?;
        match conn.h3.headers(b) {
            Ok(block) => {
                let p = block.pseudo();
                let pseudo = [
                    (&b":method"[..], p.method),
                    (b":scheme", p.scheme),
                    (b":authority", p.authority),
                    (b":path", p.path),
                    (b":protocol", p.protocol),
                ];
                for (n, v) in pseudo {
                    if let Some(v) = v {
                        each(n, v);
                    }
                }
                if let Some(s) = p.status {
                    let d = [s / 100, s / 10 % 10, s % 10].map(|d| b'0' + d as u8);
                    each(b":status", &d);
                }
                for f in block.iter() {
                    each(f.name, f.value);
                }
            }
            Err(h3wire::UsageError::Closed(_)) => return Err(StreamError::Conn),
            Err(e) => {
                debug_assert!(false, "headers({b:?}): {e:?}");
                return Err(StreamError::Conn);
            }
        }
        conn.h3.release(b);
        req.pending_block = None;
        let fin = req.terminal == Some(Terminal::Finished);
        req.handed |= fin;
        if !req.carry.is_empty() || req.carry_fin {
            self.queue.push(Event::H3Readable(id));
        }
        self.maybe_close(id);
        self.drive_inner(now);
        Ok(fin)
    }

    pub(crate) fn recv_body(
        &mut self,
        now: Time,
        id: H3ReqId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        let req = self
            .reqs
            .get(&id)
            .filter(|r| r.known)
            .ok_or(StreamError::Stale)?;
        if !req.booted {
            return Err(StreamError::Blocked); // no head yet: body bytes wait
        }
        let r = self.feed(now, id, Some(buf));
        let req = self.reqs.get_mut(&id).ok_or(StreamError::Stale)?;
        let out = match r {
            _ if req.aborted() || req.reset_code_pending => Err(StreamError::Reset),
            Ok(n) if req.terminal == Some(Terminal::Finished) => Ok((n, true)),
            Ok(0) => Err(StreamError::Blocked),
            Ok(n) => Ok((n, false)),
            Err(e) => Err(e),
        };
        if let Ok((n, _)) = out {
            req.recv_body += n as u64;
        }
        req.handed |= matches!(out, Ok((_, true)) | Err(StreamError::Reset));
        self.maybe_close(id);
        self.drive_inner(now);
        out
    }

    /// `StreamReadable`, `StreamPeerReset` and `StreamClosed` of request stream `s`
    /// (adoption spec §4.3, §4.4). Returns false for the other events.
    pub(crate) fn on_req_event(
        &mut self,
        now: Time,
        c: ConnId,
        s: StreamId,
        q: Q,
        e: &Event,
    ) -> bool {
        let id = req_id(s);
        match e {
            Event::StreamReadable(_) => {
                let Some(req) = self.reqs.get(&id) else {
                    return true;
                };
                if req.reset_code_pending {
                    // Fed nothing more until the code pops (adoption spec §4.4).
                } else if req.aborted() {
                    self.retire_read(now, s);
                } else if !req.booted {
                    let _ = self.feed(now, id, None);
                } else if req.known && !req.handed {
                    self.queue.push(Event::H3Readable(id));
                }
            }
            Event::StreamPeerReset(_, code) => {
                // Not passed on for a request h3wire already aborted or holds no state for.
                if let Some(req) = self.reqs.get_mut(&id)
                    && req.core
                    && !req.aborted()
                {
                    req.reset_code_pending = false;
                    if let Some(conn) = self.conns.get_mut(&c) {
                        log_closed(conn.h3.stream_reset_received(q, H3Code(*code)));
                    }
                    // After `Finished` h3wire resets our send side with no event: as
                    // `SendStopped`.
                    if req.terminal == Some(Terminal::Finished) {
                        req.stop_send();
                        if req.known {
                            self.queue.push(Event::H3Writable(id));
                        }
                    }
                }
                // The probe always runs (spec §3), before the events are dispatched by
                // the caller's `service`, so the abort owes no second read.
                self.retire_read(now, s);
            }
            Event::StreamWritable(_) => {
                if self.reqs.get(&id).is_some_and(|r| r.known) {
                    self.queue.push(Event::H3Writable(id)); // adoption spec §4.5
                }
            }
            Event::StreamCloseStats(_, st) => {
                // Only a known request's snapshot is kept (adoption spec §4.4).
                if let Some(req) = self.reqs.get_mut(&id).filter(|r| r.known) {
                    req.snapshot = Some(st.clone());
                }
            }
            Event::StreamClosed(_) => {
                // Unrouted first, so actions queued for the gone stream are dropped. The
                // quic id stays mapped: carried bytes may still yield its h3wire events.
                self.streams.remove(&s);
                if let Some(conn) = self.conns.get_mut(&c) {
                    conn.fins.remove(&s);
                }
                let Some(req) = self.reqs.get_mut(&id) else {
                    return true;
                };
                req.stream_closed = true;
                // A pending code was dropped with the slot: "reset, code unknown".
                if std::mem::take(&mut req.reset_code_pending) {
                    if let Some(conn) = self.conns.get_mut(&c) {
                        log_closed(conn.h3.stream_reset_received(q, H3Code::REQUEST_CANCELLED));
                    }
                    self.dispatch_retire(now, c);
                }
                self.maybe_close(id);
            }
            _ => return false,
        }
        true
    }

    /// Closure (adoption spec §4.3): once the transport closed the stream (1) and the
    /// gateway has the receive end or the request was aborted (2). A request the gateway
    /// never saw goes at (1).
    pub(crate) fn maybe_close(&mut self, id: H3ReqId) {
        let Some(req) = self.reqs.get(&id) else {
            return;
        };
        if !req.stream_closed || (req.known && !req.handed && !req.aborted()) {
            return;
        }
        let c = req.conn;
        self.close_req(id);
        self.settle_conn(c); // the last retained request of a gone conn
    }

    /// Removes request `id`, with one `H3Closed` if the gateway knows it: the single place
    /// that builds the `H3Close` (adoption spec §4.6).
    pub(crate) fn close_req(&mut self, id: H3ReqId) {
        let Some(req) = self.reqs.remove(&id) else {
            return;
        };
        let mut conn_err = None;
        if let Some(conn) = self.conns.get_mut(&req.conn) {
            conn_err = conn.conn_err;
            conn.mq.remove(&req.quic_id);
            if let Some(b) = req.pending_block {
                conn.h3.release(b);
            }
        }
        if req.known {
            let close = H3Close {
                stats: req.stats(conn_err),
                unread: None,
            };
            self.queue.push(Event::H3Closed(id, Box::new(close)));
        }
    }

    /// Retirement read (adoption spec §3): discards what is left until FIN, the reset
    /// or a blocked transport.
    pub(crate) fn retire_read(&mut self, now: Time, s: StreamId) {
        let mut buf = [0u8; BOOT_READ];
        let end = loop {
            match self.inner.stream_recv(now, s, &mut buf) {
                Ok((_, true)) | Err(StreamError::Reset) => break true,
                Ok((n, false)) if n > 0 => {}
                _ => break false,
            }
        };
        if let Some(req) = self.reqs.get_mut(&req_id(s)) {
            req.fin_read |= end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::slice;

    #[test]
    fn carry_slices_fit_the_buffer() {
        assert_eq!(slice(3003, false, 1024), (1024, false));
        assert_eq!(
            slice(3003, true, 1024),
            (1024, false),
            "FIN only with the rest"
        );
        assert_eq!(slice(955, true, 1024), (955, true));
        assert_eq!(slice(1024, true, 1024), (1024, true));
        assert_eq!(slice(0, true, 1024), (0, true), "a bare carried FIN");
        assert_eq!(slice(10, true, 0), (0, false), "an empty buf feeds nothing");
        assert_eq!(slice(0, true, 0), (0, true), "but takes a bare FIN");
    }
}
