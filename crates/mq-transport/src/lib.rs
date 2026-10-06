//! spec §4
//!
//! Rules (spec §4.8): methods copy `inner.engine` before calling xquic and hold no `&`/`&mut` into
//! `Inner` across the call; trampolines reach `Inner` only through `clock::current()` in short
//! raw-pointer scopes; `new` enters with `Time(0)` and `release_thread`s on failure; `close(self, now)`
//! destroys under the guard and `Drop` must not destroy twice (an `engine: *mut` nulled after destroy).
//! Every method that takes `now` records it in `last_now` (`Drop` destroys with it, spec §4.2).

mod clock;
mod conn;
mod datagram;
mod engine;
pub use engine::H3_FIELD_SECTION_MAX;
mod events;
mod ffi;
mod h3;
mod slots;
mod stream;
mod txq;

use mq_transport_api::{
    ConnConfig, ConnId, ConnStats, ConnectError, DatagramError, Event, H3Header, H3ReqId,
    H3ReqInfo, PathError, PathId, StreamError, StreamId, StreamInfo, Time, Transmit,
    TransportConfig, TransportOps, TxKey,
};
use slots::{ConnSlot, H3ReqSlot, Slots, StreamSlot};
use std::ffi::CString;
use std::fs::File;
use std::net::SocketAddr;

/// Everything a callback can reach (spec §4.8). Lives in a `Box` owned by `Transport`, so its
/// address is stable for the transport's lifetime.
pub(crate) struct Inner {
    /// Null once destroyed (destroy-once, spec §4.2 `close`).
    engine: *mut xquic_sys::xqc_engine_t,
    /// Role, max_conns, scheduler, cc: read by `connect` / admission.
    cfg: TransportConfig,
    /// NUL-terminated copy of `cfg.alpn` for `xqc_connect`.
    alpn: CString,
    /// Established connections that passed the second cap check (spec §4.7).
    n_counted: u32,
    /// Accepted, not yet admitted or released (spec §4.7).
    n_provisional: u32,
    /// Admissions so far: the next `ConnSlot::admitted` (spec §4.7).
    n_admitted: u64,
    conns: Slots<ConnSlot>,
    streams: Slots<StreamSlot>,
    h3reqs: Slots<H3ReqSlot>,
    txq: txq::TxQueues,
    events: events::Events,
    /// Recorded by `set_event_timer` (spec §4.3).
    deadline: Option<Time>,
    /// The last `now` a method was given; `Drop` destroys with it (spec §4.2).
    last_now: Time,
    /// qlog sink; written only while open (spec §4.9).
    qlog: Option<File>,
}

impl Inner {
    fn new(cfg: TransportConfig, alpn: CString) -> Inner {
        Inner {
            engine: core::ptr::null_mut(),
            cfg,
            alpn,
            n_counted: 0,
            n_provisional: 0,
            n_admitted: 0,
            conns: Default::default(),
            streams: Default::default(),
            h3reqs: Default::default(),
            txq: Default::default(),
            events: Default::default(),
            deadline: None,
            last_now: Time(0),
            qlog: None,
        }
    }
}

/// One xquic engine (spec §4). `!Send + !Sync` through the raw engine pointer in `Inner`.
pub struct Transport {
    inner: Box<Inner>,
}

#[derive(Debug)]
pub enum Error {
    /// spec §4.6
    EngineAlreadyOnThread,
    /// `xqc_engine_create` (e.g. unreadable cert/key) or ALPN registration failed.
    EngineCreate,
    /// Invalid configuration (e.g. a path or ALPN with an interior NUL).
    Config(String),
    Qlog(std::io::Error),
}

impl Transport {
    /// Records `now` and runs `f(inner, engine)` inside the clock guard (spec §4.3). `f` gets
    /// only raw pointers: no reference into `Inner` is held while xquic runs (spec §4.8).
    fn with_engine<R>(
        &mut self,
        now: Time,
        f: impl FnOnce(*mut Inner, *mut xquic_sys::xqc_engine_t) -> R,
    ) -> R {
        self.inner.last_now = now;
        let engine = self.inner.engine;
        let inner: *mut Inner = &mut *self.inner;
        clock::enter(inner, now, || f(inner, engine))
    }
}

impl TransportOps for Transport {
    fn recv_datagram(&mut self, now: Time, local: SocketAddr, peer: SocketAddr, data: &[u8]) {
        conn::recv_datagram(self, now, local, peer, data)
    }

    fn drive(&mut self, now: Time) {
        conn::drive(self, now)
    }

    fn pending_transmit(&self, out: &mut Vec<TxKey>) {
        self.inner.txq.keys(out)
    }

    fn peek_transmit(&mut self, key: TxKey) -> Option<Transmit<'_>> {
        self.inner.txq.peek(key)
    }

    fn transmit_done(&mut self, key: TxKey, datagrams: usize) {
        if datagrams != 0 {
            self.inner.txq.done(key, datagrams)
        }
    }

    fn resume_pending(&self) -> bool {
        self.inner.txq.resume_pending()
    }

    /// Ids are invalidated inside notifications (spec §4.8): events whose object is gone are
    /// dropped, except the close events, which are the last word on an id.
    fn poll_event(&mut self) -> Option<Event> {
        let Inner {
            events,
            streams,
            conns,
            h3reqs,
            ..
        } = &mut *self.inner;
        loop {
            let e = events.pop(streams, conns, h3reqs)?;
            let live = match &e {
                Event::ConnEstablished(c)
                | Event::NewConn(c, _)
                | Event::MpReady(c)
                | Event::DatagramReadable(c)
                | Event::PathRemoved(c, _) => conns.is_live(c.slot()),
                Event::NewStream(_, s, _)
                | Event::StreamReadable(s)
                | Event::StreamWritable(s)
                | Event::StreamPeerReset(s, _)
                | Event::StreamStopSending(s, _) => streams.is_live(s.slot()),
                Event::H3Request(_, r) | Event::H3Readable(r) | Event::H3Writable(r) => {
                    h3reqs.is_live(r.slot())
                }
                Event::ConnClosed(..)
                | Event::StreamClosed(_)
                | Event::StreamCloseStats(..)
                | Event::H3Closed(..) => true,
            };
            if live {
                return Some(e);
            }
        }
    }

    fn next_timeout(&self) -> Option<Time> {
        conn::next_timeout(&self.inner)
    }

    fn connect(&mut self, now: Time, cfg: &ConnConfig) -> Result<ConnId, ConnectError> {
        conn::connect(self, now, cfg)
    }

    fn open_stream(&mut self, now: Time, c: ConnId) -> Result<StreamId, mq_transport_api::Error> {
        stream::open_stream(self, now, c)
    }

    fn open_uni(&mut self, now: Time, c: ConnId) -> Result<StreamId, mq_transport_api::Error> {
        stream::open_uni(self, now, c)
    }

    fn stream_send(
        &mut self,
        now: Time,
        s: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        stream::stream_send(self, now, s, data, fin)
    }

    fn stream_recv(
        &mut self,
        now: Time,
        s: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        stream::stream_recv(self, now, s, buf)
    }

    fn stream_reset(&mut self, now: Time, s: StreamId) {
        stream::stream_reset(self, now, s)
    }

    fn stream_reset_send(&mut self, now: Time, s: StreamId, code: u64) {
        stream::stream_reset_send(self, now, s, code)
    }

    fn stream_stop_sending(&mut self, now: Time, s: StreamId, code: u64) {
        stream::stream_stop_sending(self, now, s, code)
    }

    fn add_path(&mut self, now: Time, c: ConnId, standby: bool) -> Result<PathId, PathError> {
        conn::add_path(self, now, c, standby)
    }

    fn close_conn(&mut self, now: Time, c: ConnId) {
        conn::close_conn(self, now, c)
    }

    fn close_conn_with(&mut self, now: Time, c: ConnId, code: u64) {
        conn::close_conn_with(self, now, c, code)
    }

    fn mark_conn_authed(&mut self, c: ConnId) {
        if let Some(s) = self.inner.conns.get_mut(c.slot()) {
            s.authed = true;
        }
    }

    fn conn_stats(&self, c: ConnId) -> Result<ConnStats, mq_transport_api::Error> {
        conn::conn_stats(self, c)
    }

    fn stream_info(&self, s: StreamId) -> Result<StreamInfo, mq_transport_api::Error> {
        stream::stream_info(self, s)
    }

    fn datagram_send(&mut self, now: Time, c: ConnId, data: &[u8]) -> Result<(), DatagramError> {
        datagram::datagram_send(self, now, c, data)
    }

    fn datagram_mss(&self, c: ConnId) -> usize {
        datagram::datagram_mss(self, c)
    }

    fn datagram_recv(&mut self, c: ConnId, buf: &mut [u8]) -> Option<usize> {
        datagram::ring_pop(self.inner.conns.get_mut(c.slot())?, buf)
    }

    fn open_h3_request(
        &mut self,
        now: Time,
        c: ConnId,
    ) -> Result<H3ReqId, mq_transport_api::Error> {
        h3::open_h3_request(self, now, c)
    }

    fn h3_send_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        hs: &[H3Header<'_>],
        fin: bool,
    ) -> Result<(), StreamError> {
        h3::h3_send_headers(self, now, r, hs, fin)
    }

    fn h3_send_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        h3::h3_send_body(self, now, r, data, fin)
    }

    fn h3_finish(&mut self, now: Time, r: H3ReqId) -> Result<(), StreamError> {
        h3::h3_finish(self, now, r)
    }

    fn h3_recv_headers(
        &mut self,
        now: Time,
        r: H3ReqId,
        each: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<bool, StreamError> {
        h3::h3_recv_headers(self, now, r, each)
    }

    fn h3_recv_body(
        &mut self,
        now: Time,
        r: H3ReqId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        h3::h3_recv_body(self, now, r, buf)
    }

    fn h3_reset(&mut self, now: Time, r: H3ReqId) {
        h3::h3_reset(self, now, r)
    }

    fn h3_req_info(&self, r: H3ReqId) -> Result<H3ReqInfo, mq_transport_api::Error> {
        h3::h3_req_info(self, r)
    }
}

/// Accessors for the fabric, shard-pair and loopback tests (spec §8.1).
#[cfg(feature = "test-support")]
impl Transport {
    pub fn queued_bytes(&self, key: TxKey) -> usize {
        self.inner.txq.queued_bytes(key)
    }

    /// Connections counted against `max_conns` (spec §4.7).
    pub fn conn_count(&self) -> u32 {
        self.inner.n_counted
    }

    /// Accepted connections not yet admitted or released (spec §4.7).
    pub fn n_provisional(&self) -> u32 {
        self.inner.n_provisional
    }

    /// Connections refused by a write callback and not yet resumable (spec §4.4).
    pub fn blocked_conns(&self) -> Vec<ConnId> {
        self.inner.txq.blocked_conns()
    }

    /// Live stream slots of `c` (0 for a stale id).
    pub fn stream_count(&self, c: ConnId) -> u32 {
        self.inner.conns.get(c.slot()).map_or(0, |s| s.streams)
    }

    /// Datagrams `c`'s receive ring dropped (SP2 spec §3.1); 0 for a stale id.
    pub fn dgram_rx_dropped(&self, c: ConnId) -> u64 {
        self.inner
            .conns
            .get(c.slot())
            .map_or(0, |s| s.dgram_rx_dropped)
    }

    /// The deferred close `drive` will apply (spec §4.2 ceiling).
    pub fn pending_close(&self, c: ConnId) -> Option<u64> {
        self.inner.conns.get(c.slot()).and_then(|s| s.pending_close)
    }

    /// `open_stream` with a chosen QUIC id, for sparse-id tests (spec §7, §8.4).
    pub fn open_stream_with_id(
        &mut self,
        now: Time,
        c: ConnId,
        quic_id: u64,
    ) -> Result<StreamId, mq_transport_api::Error> {
        stream::open_stream_with_id(self, now, c, quic_id)
    }

    /// xquic's live count of implicitly opened stream ids on `c` (spec §7); 0 for a stale id
    /// or a connection xquic no longer knows.
    pub fn implicit_stream_count(&self, c: ConnId) -> u64 {
        let Some(cid) = self.inner.conns.get(c.slot()).map(|s| s.cid) else {
            return 0;
        };
        // SAFETY: the engine is live; the cid outlives the call; a plain getter, no callbacks.
        unsafe { xquic_sys::xqc_conn_implicit_stream_count(self.inner.engine, &cid) }
    }
}
