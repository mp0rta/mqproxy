//! h3wire actions and core bytes on the transport (adoption spec §4.5).

use crate::H3Wire;
use crate::req::{Req, req_id};
use h3wire::{Action, FieldRef, H3Code, StreamId as Q, UsageError};
use mq_transport_api::{ConnId, Error, H3Header, H3ReqId, StreamError, Time, TransportOps};

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
        let r = match self.conns.get(&c) {
            None => Err(Error::Stale),
            Some(conn) if !conn.client => Err(Error::Role),
            Some(_) => self.inner.open_stream(now, c).and_then(|s| {
                let q = self.inner.stream_info(s)?.quic_id;
                let conn = self.conns.get_mut(&c).expect("checked above");
                conn.mq.insert(q, s);
                self.streams.insert(s, (c, Q(q)));
                let id = req_id(s);
                self.reqs.insert(id, Req::new(c, s, q, true));
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
        let conn = self.conns.get_mut(&req.conn).ok_or(StreamError::Conn)?;
        let fields: Vec<_> = hs.iter().map(|h| FieldRef::new(h.name, h.value)).collect();
        let r = conn.h3.send_headers(Q(req.quic_id), &fields, fin);
        req.core |= r.is_ok();
        self.drive_inner(now);
        r.map_err(usage_err)
    }

    /// Executes `c`'s actions and writes its core bytes; runs whenever `c`'s h3wire state
    /// may have changed.
    pub(crate) fn service(&mut self, now: Time, c: ConnId) {
        self.run_actions(now, c);
        self.flush(now, c);
        self.run_actions(now, c); // `sent` may queue FinishStream
    }

    fn run_actions(&mut self, now: Time, c: ConnId) {
        self.dispatch(c);
        let Some(conn) = self.conns.get_mut(&c) else {
            return;
        };
        while let Some(a) = conn.h3.poll_action() {
            if conn.closing {
                continue; // drained and dropped
            }
            let mq = |q: Q| conn.mq.get(&q.0).copied();
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
                // Task C4 keeps a pending FIN when this is `Blocked`.
                Action::FinishStream(q) => {
                    if let Some(s) = mq(q) {
                        let _ = self.inner.stream_send(now, s, &[], true);
                    }
                }
                // Direction guard (adoption spec §4.5): the transport ops do not check.
                Action::ResetStream { stream: q, code } => {
                    let ok = q.is_request() || (q.is_uni() && conn.is_local(q));
                    debug_assert!(ok, "ResetStream on a stream with no send side");
                    if let (true, Some(s)) = (ok, mq(q)) {
                        self.inner.stream_reset_send(now, s, code.0);
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

    /// Writes core bytes per stream until the transport accepts less than offered.
    fn flush(&mut self, now: Time, c: ConnId) {
        let Some(conn) = self.conns.get_mut(&c) else {
            return;
        };
        if conn.closing {
            return;
        }
        for q in conn.h3.sendable().collect::<Vec<_>>() {
            let Some(&s) = conn.mq.get(&q.0) else {
                continue;
            };
            while let Some(bytes) = conn.h3.poll_send(q).filter(|b| !b.is_empty()) {
                let len = bytes.len();
                let Ok(n) = self.inner.stream_send(now, s, bytes, false) else {
                    break;
                };
                let sent = conn.h3.sent(q, n);
                debug_assert!(sent.is_ok(), "sent({q:?}, {n}): {sent:?}");
                if n < len {
                    break;
                }
            }
        }
    }
}
