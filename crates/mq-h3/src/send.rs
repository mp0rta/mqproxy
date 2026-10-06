//! h3wire actions and core bytes on the transport (adoption spec §4.5).

use crate::H3Wire;
use crate::req::{Req, Terminal, req_id};
use h3wire::{
    AbortSource, Action, Connection, DataFrame, FieldRef, H3Code, StreamId as Q, UsageError,
};
use mq_transport_api::{ConnId, Error, Event, H3Header, H3ReqId, StreamError, Time, TransportOps};

/// The DATA frame `h3_send_body` started: its prefix, then `payload_left` bytes the
/// gateway re-offers (adoption spec §4.5). Fixed-size (spec §5.4).
#[derive(Clone, Copy, Debug)]
pub(crate) struct InFlight {
    prefix: DataFrame,
    prefix_written: usize,
    payload_left: u64,
    /// Started with `end`: h3wire queues the FIN once the frame is written.
    end: bool,
}

impl InFlight {
    fn new(prefix: DataFrame, payload: usize, end: bool) -> InFlight {
        InFlight {
            prefix,
            prefix_written: 0,
            payload_left: payload as u64,
            end,
        }
    }

    /// The prefix bytes not yet accepted.
    fn prefix_rest(&self) -> &[u8] {
        &self.prefix.prefix()[self.prefix_written..]
    }

    /// Payload bytes to offer from `avail` re-offered ones: none until the prefix is
    /// accepted whole.
    fn payload_take(&self, avail: usize) -> usize {
        if self.prefix_rest().is_empty() {
            avail.min(usize::try_from(self.payload_left).unwrap_or(usize::MAX))
        } else {
            0
        }
    }

    /// The transport accepted `n` more bytes: the prefix first, then the payload.
    fn advance(&mut self, n: usize) {
        let p = n.min(self.prefix_rest().len());
        self.prefix_written += p;
        self.payload_left -= (n - p) as u64;
    }

    fn done(&self) -> bool {
        self.prefix_rest().is_empty() && self.payload_left == 0
    }
}

/// `send_data(0, true)` for a latched finish, once it is no longer `Blocked`
/// (adoption spec §4.5); it queues `FinishStream`.
fn try_finish(h3: &mut Connection, req: &mut Req) -> Result<(), StreamError> {
    if !req.finish_latched {
        return Ok(());
    }
    match h3.send_data(Q(req.quic_id), 0, true) {
        Err(UsageError::Blocked) => Ok(()),
        r => {
            req.finish_latched = false;
            r.map(drop).map_err(usage_err)
        }
    }
}

/// A refused h3wire call (Global Constraints error table, adoption spec §5.1).
pub(crate) fn usage_err(e: UsageError) -> StreamError {
    match e {
        UsageError::Blocked => StreamError::Blocked,
        UsageError::Closed(_) | UsageError::GoingAway => StreamError::Conn,
        UsageError::InvalidField | UsageError::WrongPhase | UsageError::ForbiddenCode => {
            log::warn!("h3wire refused gateway output: {e}");
            StreamError::Reset
        }
        UsageError::UnknownStream => StreamError::Stale,
        UsageError::WrongStreamKind
        | UsageError::NotNegotiated
        | UsageError::StaleBlock
        | UsageError::Reserved
        | UsageError::OutOfRange => {
            debug_assert!(false, "unreachable by construction: {e:?}");
            StreamError::Conn
        }
    }
}

impl<T: TransportOps> H3Wire<T> {
    /// Client request start (adoption spec §4.3): the request exists from `open_stream`;
    /// h3wire holds state for it once `send_headers` succeeds.
    pub(crate) fn open_req(&mut self, now: Time, c: ConnId) -> Result<H3ReqId, Error> {
        // The xqc_h3 backend's order (`reserve_local`): role, conn, protocol.
        let r = match self.conns.get(&c) {
            _ if self.server => Err(Error::Role),
            None if self.inner.conn_stats(c).is_ok() => Err(Error::Other), // a raw conn
            None => Err(Error::Stale),
            Some(_) => self.inner.open_stream(now, c).and_then(|s| {
                let q = self.inner.stream_info(s)?.quic_id;
                let conn = self.conns.get_mut(&c).expect("checked above");
                conn.mq.insert(q, s);
                self.streams.insert(s, (c, Q(q)));
                let id = req_id(s);
                self.reqs.insert(id, Req::new(now, c, s, q, true));
                Ok(id)
            }),
        };
        self.drive_inner(now);
        r
    }

    /// `send_headers`, all-or-error (adoption spec §4.5). Task C4 adds the send-side state.
    pub(crate) fn send_headers(
        &mut self,
        now: Time,
        id: H3ReqId,
        hs: &[H3Header<'_>],
        fin: bool,
    ) -> Result<(), StreamError> {
        let req = self
            .reqs
            .get_mut(&id)
            .filter(|r| r.known)
            .ok_or(StreamError::Stale)?;
        // Our send side is over (adoption spec §4.5): h3wire would answer `UnknownStream`
        // (reaped) or `WrongPhase`, but the request is still held.
        if req.aborted() || req.send_stopped {
            return Err(StreamError::Reset);
        }
        let conn = self.conns.get_mut(&req.conn).ok_or(StreamError::Conn)?;
        let fields: Vec<_> = hs.iter().map(|h| FieldRef::new(h.name, h.value)).collect();
        let r = conn.h3.send_headers(Q(req.quic_id), &fields, fin);
        req.core |= r.is_ok();
        self.drive_inner(now);
        r.map_err(usage_err)
    }

    /// The request's role, if `id` is a request the gateway knows (else `Stale`) on a
    /// live conn (else `Conn`).
    fn client_of(&self, id: H3ReqId) -> Result<bool, StreamError> {
        let req = self
            .reqs
            .get(&id)
            .filter(|r| r.known)
            .ok_or(StreamError::Stale)?;
        let conn = self.conns.get(&req.conn).ok_or(StreamError::Conn)?;
        Ok(conn.client)
    }

    /// `h3_send_body` (adoption spec §4.5): `Ok(n)` counts accepted payload bytes, and
    /// `fin` is committed only when `n == data.len()`.
    pub(crate) fn send_body(
        &mut self,
        now: Time,
        id: H3ReqId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        let client = self.client_of(id)?;
        let r = self.body(now, id, data, fin, client);
        if let (Ok(n), Some(req)) = (&r, self.reqs.get_mut(&id)) {
            req.send_body += *n as u64;
        }
        self.drive_inner(now);
        r
    }

    fn body(
        &mut self,
        now: Time,
        id: H3ReqId,
        data: &[u8],
        fin: bool,
        client: bool,
    ) -> Result<usize, StreamError> {
        let req = &self.reqs[&id];
        // A retained request (client only) accepts and discards like after SendStopped,
        // so a running upload pump cannot abort the response (adoption spec §4.3).
        if req.send_stopped || self.conns[&req.conn].gone {
            // RFC 9114 §4.1: the client's response keeps flowing; xqc_h3 resets the server.
            return if client {
                Ok(data.len())
            } else {
                Err(StreamError::Reset)
            };
        }
        if req.aborted() {
            return Err(StreamError::Reset);
        }
        // Continue the frame in flight; the gateway re-offers from its first unaccepted
        // byte. ponytail: a `fin` call offering less than the frame still needs cannot
        // end it; the gateway never does that (it re-offers its whole pending buffer).
        let mut n = 0;
        if let Some(f) = req.frame {
            n = self.write_frame(now, id, data)?;
            if self.reqs[&id].frame.is_some() {
                return if n == 0 {
                    Err(StreamError::Blocked)
                } else {
                    Ok(n)
                };
            }
            if f.end {
                return Ok(n); // h3wire queues the FIN
            }
        }
        let rest = &data[n..];
        let req = self.reqs.get_mut(&id).expect("checked above");
        let conn = self.conns.get_mut(&req.conn).expect("checked above");
        if rest.is_empty() {
            if fin {
                req.finish_latched = true;
                try_finish(&mut conn.h3, req)?;
            }
            return Ok(n);
        }
        match conn.h3.send_data(Q(req.quic_id), rest.len() as u64, fin) {
            Ok(prefix) => req.frame = Some(InFlight::new(prefix, rest.len(), fin)),
            Err(UsageError::Blocked) if n == 0 => {
                req.writable_wanted = true; // HEADERS bytes are still queued
                return Err(StreamError::Blocked);
            }
            Err(_) if n > 0 => return Ok(n),
            Err(e) => return Err(usage_err(e)),
        }
        match self.write_frame(now, id, rest) {
            Ok(0) if n == 0 => Err(StreamError::Blocked),
            Ok(k) => Ok(n + k),
            Err(_) if n > 0 => Ok(n),
            Err(e) => Err(e),
        }
    }

    /// Writes the rest of `id`'s frame in flight from the re-offered `data`: the prefix,
    /// then the payload as a separate `stream_send`, reporting every accepted byte to
    /// h3wire. Returns the payload bytes accepted.
    fn write_frame(&mut self, now: Time, id: H3ReqId, data: &[u8]) -> Result<usize, StreamError> {
        let req = self.reqs.get_mut(&id).expect("caller checked");
        let f = req.frame.as_mut().expect("caller checked");
        let (mut n, mut written, mut err) = (0, 0, None);
        loop {
            let (bytes, payload) = match f.prefix_rest() {
                [] => match f.payload_take(data.len() - n) {
                    0 => break,
                    k => (&data[n..n + k], true),
                },
                p => (p, false),
            };
            let len = bytes.len();
            match self.inner.stream_send(now, req.stream, bytes, false) {
                Ok(k) => {
                    f.advance(k);
                    written += k;
                    n += if payload { k } else { 0 };
                    if k < len {
                        break;
                    }
                }
                Err(StreamError::Blocked) => break,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        if f.done() {
            req.frame = None;
        }
        if written > 0 {
            let conn = self.conns.get_mut(&req.conn).ok_or(StreamError::Conn)?;
            let r = conn.h3.data_written(Q(req.quic_id), written);
            debug_assert!(r.is_ok(), "data_written({written}): {r:?}");
        }
        err.map_or(Ok(n), Err)
    }

    /// `h3_finish`: latches the finish intent and returns `Ok` while HEADERS bytes are
    /// queued, as xqc_h3 does (adoption spec §4.5).
    pub(crate) fn finish(&mut self, now: Time, id: H3ReqId) -> Result<(), StreamError> {
        let client = self.client_of(id)?;
        let r = self.body(now, id, &[], true, client).map(drop);
        self.drive_inner(now);
        r
    }

    /// `h3_reset` (adoption spec §4.3): `Connection::abort` with `REQUEST_CANCELLED`, or,
    /// without h3wire state (a client request whose `send_headers` failed), the raw
    /// stream's `stream_reset`, once. The gateway gave the request up, so nothing is left
    /// to deliver: closure needs only the transport's `StreamClosed`.
    pub(crate) fn reset(&mut self, now: Time, id: H3ReqId) {
        let Some(req) = self.reqs.get_mut(&id).filter(|r| r.known) else {
            return; // stale: a no-op
        };
        if req.core {
            if let Some(conn) = self.conns.get_mut(&req.conn) {
                // A reaped stream is a no-op; Closed: the conn's close covers it.
                if let Err(e) = conn.h3.abort(Q(req.quic_id), H3Code::REQUEST_CANCELLED) {
                    log::debug!("h3wire abort: {e}");
                }
            }
        } else if !req.aborted() {
            self.inner.stream_reset(now, req.stream);
        }
        // Set here, not only by `StreamAborted`: h3wire emits none after `Finished`.
        if !req.aborted() {
            req.terminal = Some(Terminal::Aborted {
                code: H3Code::REQUEST_CANCELLED,
                source: AbortSource::Local,
            });
        }
        req.handed = true;
        self.maybe_close(id);
        self.drive_inner(now); // its sweep runs the abort's actions and retirement read
    }

    /// Executes `c`'s actions and writes its core bytes; runs whenever `c`'s h3wire state
    /// may have changed, so also after every call that takes `now`.
    pub(crate) fn service(&mut self, now: Time, c: ConnId) {
        self.retry_fins(now, c);
        self.run_actions(now, c);
        self.flush(now, c);
        self.run_actions(now, c); // `sent` may queue FinishStream
    }

    /// Pending FINs (adoption spec §4.5): kept while `Blocked`, dropped on any other
    /// result. Runs before the actions, so a FIN just blocked waits for the next call.
    fn retry_fins(&mut self, now: Time, c: ConnId) {
        let Some(conn) = self.conns.get_mut(&c) else {
            return;
        };
        let inner = &mut self.inner;
        conn.fins.retain(|&s| {
            matches!(
                inner.stream_send(now, s, &[], true),
                Err(StreamError::Blocked)
            )
        });
    }

    fn run_actions(&mut self, now: Time, c: ConnId) {
        // Aborts from outside a feed (GOAWAY cutoff, local abort): read the stream to
        // FIN or the reset so it retires (adoption spec §3).
        self.dispatch_retire(now, c);
        let Some(conn) = self.conns.get_mut(&c) else {
            return;
        };
        while let Some(a) = conn.h3.poll_action() {
            if conn.closing {
                continue; // drained and dropped
            }
            // A stream the transport closed is no longer routed: its actions are dropped.
            let streams = &self.streams;
            let mq = |q: Q| {
                conn.mq
                    .get(&q.0)
                    .copied()
                    .filter(|s| streams.contains_key(s))
            };
            match a {
                Action::OpenUni(kind) => {
                    let inner = &mut self.inner;
                    let bound = inner.open_uni(now, c).ok().and_then(|s| {
                        let q = inner.stream_info(s).ok()?.quic_id;
                        conn.h3.bind_uni(kind, Q(q)).ok()?;
                        Some((s, q))
                    });
                    match bound {
                        Some((s, q)) => {
                            conn.mq.insert(q, s);
                            self.streams.insert(s, (c, Q(q)));
                        }
                        // The peer granted fewer than three uni streams (RFC 9114 §6.2).
                        None => {
                            let code = H3Code::GENERAL_PROTOCOL_ERROR.0;
                            self.inner.close_conn_with(now, c, code);
                            conn.closing = true;
                        }
                    }
                }
                Action::CloseConnection { code, .. } => {
                    self.inner.close_conn_with(now, c, code.0);
                    conn.closing = true;
                }
                // A `Blocked` FIN is kept and retried; it survives a peer RESET_STREAM
                // (adoption spec §3, §4.5).
                Action::FinishStream(q) => {
                    if let Some(s) = mq(q)
                        && self.inner.stream_send(now, s, &[], true) == Err(StreamError::Blocked)
                    {
                        conn.fins.insert(s);
                    }
                }
                // Direction guard (adoption spec §4.5): the transport ops do not check.
                Action::ResetStream { stream: q, code } => {
                    let ok = q.is_request() || (q.is_uni() && conn.is_local(q));
                    debug_assert!(ok, "ResetStream on a stream with no send side");
                    if let (true, Some(s)) = (ok, mq(q)) {
                        self.inner.stream_reset_send(now, s, code.0);
                        conn.fins.remove(&s);
                    }
                }
                Action::StopSending { stream: q, code } => {
                    let ok = q.is_request() || (q.is_uni() && !conn.is_local(q));
                    debug_assert!(ok, "StopSending on a stream with no receive side");
                    if let (true, Some(s)) = (ok, mq(q)) {
                        self.inner.stream_stop_sending(now, s, code.0);
                    }
                }
            }
        }
    }

    /// Writes core bytes per stream until the transport accepts less than offered. A
    /// request stream that drains fires its finish latch and wakes a gateway that was
    /// `Blocked` behind them (adoption spec §4.5).
    fn flush(&mut self, now: Time, c: ConnId) {
        let Self {
            conns,
            reqs,
            inner,
            queue,
            ..
        } = self;
        let Some(conn) = conns.get_mut(&c) else {
            return;
        };
        if conn.closing {
            return;
        }
        for q in conn.h3.sendable().collect::<Vec<_>>() {
            let Some(&s) = conn.mq.get(&q.0) else {
                continue;
            };
            let mut req = reqs.get_mut(&req_id(s)).filter(|_| q.is_request());
            while let Some(bytes) = conn.h3.poll_send(q).filter(|b| !b.is_empty()) {
                let len = bytes.len();
                let Ok(n) = inner.stream_send(now, s, bytes, false) else {
                    break;
                };
                if let Some(req) = req.as_mut().filter(|_| n > 0) {
                    req.headers_sent_at.get_or_insert(now);
                }
                let sent = conn.h3.sent(q, n);
                debug_assert!(sent.is_ok(), "sent({q:?}, {n}): {sent:?}");
                if n < len {
                    break;
                }
            }
            if let Some(req) = req.filter(|_| conn.h3.poll_send(q).is_none()) {
                let _ = try_finish(&mut conn.h3, req); // refused: logged by usage_err
                if std::mem::take(&mut req.writable_wanted) && req.known {
                    queue.push(Event::H3Writable(req_id(s)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InFlight;

    #[test]
    fn in_flight_prefix_then_payload() {
        let mut c = h3wire::Connection::new(h3wire::Role::Client, Default::default());
        let q = h3wire::StreamId(0);
        let get = [
            h3wire::FieldRef::new(b":method", b"POST"),
            h3wire::FieldRef::new(b":scheme", b"https"),
            h3wire::FieldRef::new(b":authority", b"a"),
            h3wire::FieldRef::new(b":path", b"/"),
        ];
        c.send_headers(q, &get, false).unwrap();
        let n = c.poll_send(q).unwrap().len();
        c.sent(q, n).unwrap();
        let mut f = InFlight::new(c.send_data(q, 1000, false).unwrap(), 1000, false);
        assert_eq!(f.prefix_rest(), [0x00, 0x43, 0xe8]);
        assert_eq!(
            f.payload_take(1000),
            0,
            "no payload before the whole prefix"
        );
        f.advance(1);
        assert_eq!(f.prefix_rest(), [0x43, 0xe8]);
        f.advance(2);
        assert_eq!(f.payload_take(1000), 1000);
        assert_eq!(f.payload_take(10), 10, "at most what is re-offered");
        assert_eq!(
            f.payload_take(5000),
            1000,
            "at most what the frame declares"
        );
        f.advance(10);
        assert_eq!(f.payload_take(5000), 990);
        assert!(!f.done());
        f.advance(990);
        assert!(f.done());
        assert_eq!(f.payload_take(5000), 0);
    }
}
