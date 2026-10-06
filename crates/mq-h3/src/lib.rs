//! `H3Wire<T>`: a `TransportOps` decorator serving HTTP/3 from h3wire (adoption spec §4.1).
//!
//! Active mode (`H3Wire::new`) runs one h3wire `Connection` per H3 conn and serves the
//! requests from it.
#![forbid(unsafe_code)]

mod conn;
mod queue;
mod recv;
mod req;
mod send;

use conn::H3Conn;
use mq_transport_api::{
    ConnConfig, ConnId, ConnProto, ConnStats, ConnectError, DatagramError, Error, Event, H3Header,
    H3ReqId, H3ReqInfo, PathError, PathId, StreamError, StreamId, StreamInfo, Time, Transmit,
    TransportOps, TxKey,
};
use queue::OutQueue;
use req::Req;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Bootstrap read size for a request stream (adoption spec §4.4).
pub const BOOT_READ: usize = 4096;

pub struct H3Wire<T> {
    inner: T,
    /// `false`: create no H3 state; every op and event passes through (adoption spec §4.1).
    active: bool,
    queue: OutQueue,
    /// Request streams of H3 conns, by request id (adoption spec §4.3).
    reqs: HashMap<H3ReqId, Req>,
    conns: HashMap<ConnId, H3Conn>,
    /// H3 conns whose h3wire state changed since their last `service`, or that still wait
    /// on the transport (a pending FIN, a short core-bytes write): the only ones swept.
    dirty: HashSet<ConnId>,
    /// Every stream of an H3 conn: its conn and quic id.
    streams: HashMap<StreamId, (ConnId, h3wire::StreamId)>,
    /// A `NewConn` was seen: the inner transport is a server. ponytail: learned, not
    /// configured; before its first conn a server reports an unknown conn as `Stale`.
    server: bool,
    /// The largest `h3_recv_body` buf so far: the carry bound (adoption spec §5.4).
    #[cfg(feature = "test-support")]
    max_buf: usize,
    /// `service` runs so far.
    #[cfg(feature = "test-support")]
    services: u64,
}

impl<T: TransportOps> H3Wire<T> {
    /// Serves H3 conns from h3wire (inner must be `h3_backend: Raw`).
    pub fn new(inner: T) -> Self {
        Self::make(inner, true)
    }

    /// Creates no H3 state: every op and event passes through unfiltered (inner may be xqc_h3).
    pub fn passthrough(inner: T) -> Self {
        Self::make(inner, false)
    }

    fn make(inner: T, active: bool) -> Self {
        H3Wire {
            inner,
            active,
            queue: OutQueue::default(),
            reqs: HashMap::new(),
            conns: HashMap::new(),
            dirty: HashSet::new(),
            streams: HashMap::new(),
            server: false,
            #[cfg(feature = "test-support")]
            max_buf: 0,
            #[cfg(feature = "test-support")]
            services: 0,
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Request `r`'s h3wire state may change: its conn is swept next (adoption spec §4.5).
    fn touch(&mut self, r: H3ReqId) {
        if let Some(q) = self.reqs.get(&r) {
            self.dirty.insert(q.conn);
        }
    }

    /// The h3wire abort of request `r` (code, source), if it was aborted.
    #[cfg(feature = "test-support")]
    pub fn debug_abort(&self, r: H3ReqId) -> Option<(h3wire::H3Code, h3wire::AbortSource)> {
        match self.reqs.get(&r)?.terminal? {
            req::Terminal::Aborted { code, source } => Some((code, source)),
            req::Terminal::Finished => None,
        }
    }

    /// How many times `service` ran.
    #[cfg(feature = "test-support")]
    pub fn debug_services(&self) -> u64 {
        self.services
    }

    /// Streams the core-bytes flush visits per service: our uni streams plus the request
    /// streams with HEADERS bytes not yet drained.
    #[cfg(feature = "test-support")]
    pub fn debug_core_streams(&self) -> usize {
        self.conns.values().map(|c| c.core.len()).sum()
    }

    /// Every request's carry <= max(BOOT_READ, largest buf passed so far), and every
    /// connection's h3wire `debug_buffered_bytes() <= debug_bound()` (adoption spec §5.4).
    #[cfg(feature = "test-support")]
    pub fn debug_bounds_hold(&self) -> bool {
        let carry = BOOT_READ.max(self.max_buf);
        self.reqs.values().all(|r| r.carry.len() <= carry)
            && self
                .conns
                .values()
                .all(|c| c.h3.debug_buffered_bytes() <= c.h3.debug_bound())
    }

    /// Services the dirty H3 conns, then moves the inner queue into ours, consuming what
    /// belongs to H3 conns; runs at the end of every method that takes `now` (adoption spec
    /// §4.1).
    fn drive_inner(&mut self, now: Time) {
        // Core bytes and actions after every call that takes `now` (adoption spec §4.5).
        // Running first covers what this call changed; each event below services its own
        // conn. A conn nothing touched has nothing to run, so only dirty ones are swept.
        let cs: Vec<ConnId> = self.dirty.iter().copied().collect();
        for c in cs {
            self.service(now, c);
        }
        while let Some(e) = self.inner.poll_event() {
            let out = if self.active {
                self.on_event(now, e)
            } else {
                Some(e)
            };
            if let Some(e) = out {
                self.queue.push(e);
            }
        }
    }
}

/// Runs a forwarding op, then drains the inner queue.
macro_rules! fwd {
    ($self:ident, $now:ident, $e:expr) => {{
        let out = $e;
        $self.drive_inner($now);
        out
    }};
}

impl<T: TransportOps> TransportOps for H3Wire<T> {
    fn recv_datagram(&mut self, now: Time, local: SocketAddr, peer: SocketAddr, data: &[u8]) {
        fwd!(self, now, self.inner.recv_datagram(now, local, peer, data))
    }

    fn drive(&mut self, now: Time) {
        fwd!(self, now, self.inner.drive(now))
    }

    fn pending_transmit(&self, out: &mut Vec<TxKey>) {
        self.inner.pending_transmit(out)
    }

    fn peek_transmit(&mut self, key: TxKey) -> Option<Transmit<'_>> {
        self.inner.peek_transmit(key)
    }

    fn transmit_done(&mut self, key: TxKey, datagrams: usize) {
        self.inner.transmit_done(key, datagrams)
    }

    fn resume_pending(&self) -> bool {
        self.inner.resume_pending()
    }

    /// Pops our own queue; stale readiness/creation events are dropped, close events never
    /// (adoption spec §4.1). The inner transport filtered at drain time; an object can go
    /// stale between that drain and this pop, so the same checks run again here.
    fn poll_event(&mut self) -> Option<Event> {
        let Self {
            inner,
            active,
            queue,
            reqs,
            ..
        } = self;
        queue.pop(|e| match e {
            // ponytail: `conn_stats` is the only conn probe `TransportOps` has, and on xquic
            // it collects path stats; add a cheap `conn_live` op if these pops show up.
            Event::ConnEstablished(c)
            | Event::NewConn(c, _)
            | Event::MpReady(c)
            | Event::DatagramReadable(c)
            | Event::PathRemoved(c, _) => inner.conn_stats(*c).is_ok(),
            Event::NewStream(_, s, _)
            | Event::StreamReadable(s)
            | Event::StreamWritable(s)
            | Event::StreamPeerReset(s, _)
            | Event::StreamStopSending(s, _) => inner.stream_info(*s).is_ok(),
            Event::H3Request(_, r) | Event::H3Readable(r) | Event::H3Writable(r) if !*active => {
                inner.h3_req_info(*r).is_ok()
            }
            // An H3Readable after the receive end was handed over has nothing to deliver.
            Event::H3Readable(r) => reqs.get(r).is_some_and(|q| !q.handed),
            Event::H3Request(_, r) | Event::H3Writable(r) => reqs.contains_key(r),
            Event::ConnClosed(..)
            | Event::StreamClosed(_)
            | Event::StreamCloseStats(..)
            | Event::H3Closed(..) => true,
        })
    }

    fn next_timeout(&self) -> Option<Time> {
        self.inner.next_timeout()
    }

    fn connect(&mut self, now: Time, cfg: &ConnConfig) -> Result<ConnId, ConnectError> {
        let r = self.inner.connect(now, cfg);
        if let (true, ConnProto::H3, Ok(c)) = (self.active, cfg.proto, r) {
            self.add_conn(now, c, h3wire::Role::Client);
        }
        self.drive_inner(now);
        r
    }

    fn open_stream(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error> {
        fwd!(self, now, self.inner.open_stream(now, conn))
    }

    fn stream_send(
        &mut self,
        now: Time,
        s: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        fwd!(self, now, self.inner.stream_send(now, s, data, fin))
    }

    fn stream_recv(
        &mut self,
        now: Time,
        s: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        fwd!(self, now, self.inner.stream_recv(now, s, buf))
    }

    fn stream_reset(&mut self, now: Time, s: StreamId) {
        fwd!(self, now, self.inner.stream_reset(now, s))
    }

    fn open_uni(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error> {
        fwd!(self, now, self.inner.open_uni(now, conn))
    }

    fn stream_reset_send(&mut self, now: Time, s: StreamId, code: u64) {
        fwd!(self, now, self.inner.stream_reset_send(now, s, code))
    }

    fn stream_stop_sending(&mut self, now: Time, s: StreamId, code: u64) {
        fwd!(self, now, self.inner.stream_stop_sending(now, s, code))
    }

    fn add_path(&mut self, now: Time, conn: ConnId, standby: bool) -> Result<PathId, PathError> {
        fwd!(self, now, self.inner.add_path(now, conn, standby))
    }

    fn close_conn(&mut self, now: Time, conn: ConnId) {
        fwd!(self, now, self.inner.close_conn(now, conn))
    }

    fn close_conn_with(&mut self, now: Time, conn: ConnId, code: u64) {
        fwd!(self, now, self.inner.close_conn_with(now, conn, code))
    }

    fn mark_conn_authed(&mut self, conn: ConnId) {
        self.inner.mark_conn_authed(conn)
    }

    fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error> {
        self.inner.conn_stats(conn)
    }

    fn stream_info(&self, s: StreamId) -> Result<StreamInfo, Error> {
        self.inner.stream_info(s)
    }

    fn datagram_send(&mut self, now: Time, conn: ConnId, data: &[u8]) -> Result<(), DatagramError> {
        fwd!(self, now, self.inner.datagram_send(now, conn, data))
    }

    fn datagram_mss(&self, conn: ConnId) -> usize {
        self.inner.datagram_mss(conn)
    }

    fn datagram_recv(&mut self, conn: ConnId, buf: &mut [u8]) -> Option<usize> {
        self.inner.datagram_recv(conn, buf)
    }

    // H3 ops. Active: served from h3wire, never forwarded; an id not held is stale
    // (adoption spec §4.1).
    fn open_h3_request(&mut self, now: Time, conn: ConnId) -> Result<H3ReqId, Error> {
        if self.active {
            return self.open_req(now, conn);
        }
        fwd!(self, now, self.inner.open_h3_request(now, conn))
    }

    fn h3_send_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        hs: &[H3Header<'_>],
        fin: bool,
    ) -> Result<(), StreamError> {
        if self.active {
            self.touch(r);
            return self.send_headers(now, r, hs, fin);
        }
        fwd!(self, now, self.inner.h3_send_headers(now, r, hs, fin))
    }

    fn h3_send_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        if self.active {
            self.touch(r);
            return self.send_body(now, r, data, fin);
        }
        fwd!(self, now, self.inner.h3_send_body(now, r, data, fin))
    }

    fn h3_finish(&mut self, now: Time, r: H3ReqId) -> Result<(), StreamError> {
        if self.active {
            self.touch(r);
            return self.finish(now, r);
        }
        fwd!(self, now, self.inner.h3_finish(now, r))
    }

    fn h3_recv_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        each: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError> {
        if self.active {
            self.touch(r);
            return self.recv_headers(now, r, each);
        }
        fwd!(self, now, self.inner.h3_recv_headers(now, r, each))
    }

    fn h3_recv_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        #[cfg(feature = "test-support")]
        {
            self.max_buf = self.max_buf.max(buf.len());
        }
        if self.active {
            self.touch(r);
            return self.recv_body(now, r, buf);
        }
        fwd!(self, now, self.inner.h3_recv_body(now, r, buf))
    }

    fn h3_reset(&mut self, now: Time, r: H3ReqId) {
        if self.active {
            self.touch(r);
            return self.reset(now, r);
        }
        fwd!(self, now, self.inner.h3_reset(now, r))
    }

    fn h3_req_info(&self, r: H3ReqId) -> Result<H3ReqInfo, Error> {
        if self.active {
            // Cached at request start: the inner slot is gone before StreamClosed.
            return match self.reqs.get(&r) {
                Some(q) if q.known => Ok(H3ReqInfo {
                    conn: q.conn,
                    quic_id: q.quic_id,
                }),
                _ => Err(Error::Stale),
            };
        }
        self.inner.h3_req_info(r)
    }
}
