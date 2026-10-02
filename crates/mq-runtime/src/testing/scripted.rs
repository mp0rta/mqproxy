//! `ScriptedTransport`: a `TransportOps` without xquic whose every result can
//! be scripted (spec §5.1, §8.1).

use mq_transport_api::{
    CloseReason, ConnConfig, ConnId, ConnStats, ConnectError, DatagramError, ErrType, Error, Event,
    PathError, PathId, SlotId, StreamError, StreamId, StreamInfo, Time, Transmit, TransportOps,
    TxKey,
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// One recorded `TransportOps` call, in call order (spec §8.1 "call log").
/// Pure queries (`pending_transmit`, `resume_pending`, `poll_event`,
/// `next_timeout`, `conn_stats`, `stream_info`, `datagram_mss`) are not logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    RecvDatagram {
        now: Time,
        local: SocketAddr,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    Drive(Time),
    PeekTransmit(TxKey),
    TransmitDone {
        key: TxKey,
        n: usize,
    },
    Connect,
    OpenStream(ConnId),
    /// `bytes` is everything offered, not just the accepted prefix.
    StreamSend {
        s: StreamId,
        bytes: Vec<u8>,
        fin: bool,
    },
    StreamRecv {
        s: StreamId,
        cap: usize,
    },
    StreamReset(StreamId),
    AddPath {
        conn: ConnId,
        standby: bool,
    },
    CloseConn(ConnId),
    /// `bytes` is what was offered, whether or not the call succeeded.
    DatagramSend {
        conn: ConnId,
        bytes: Vec<u8>,
    },
}

type RecvChunk = Result<(Vec<u8>, bool), StreamError>;
type ConnectRule = Box<dyn Fn(&ScriptedHandle) -> Result<ConnId, ConnectError> + Send>;
type OpenRule = Box<dyn Fn(&ScriptedHandle, ConnId) -> Result<StreamId, Error> + Send>;
type DriveRule = Box<dyn Fn(&ScriptedHandle, Time) + Send>;
type SendRule =
    Box<dyn Fn(&ScriptedHandle, StreamId, &[u8], bool) -> Result<usize, StreamError> + Send>;

/// Default inbound datagram ring size, like the real facade's (spec §3.2).
const DGRAM_RING_CAP: usize = 16 << 20;

/// One connection's inbound datagrams; `cap` bounds the stored payload bytes.
struct DgramRx {
    q: VecDeque<Vec<u8>>,
    bytes: usize,
    cap: usize,
    dropped: u64,
    /// A `DatagramReadable` is queued and not yet popped (spec §3.1).
    readable_queued: bool,
}

impl Default for DgramRx {
    fn default() -> Self {
        DgramRx {
            q: VecDeque::new(),
            bytes: 0,
            cap: DGRAM_RING_CAP,
            dropped: 0,
            readable_queued: false,
        }
    }
}

#[derive(Default)]
struct ScriptState {
    next_id: u32,
    next_path: u64,
    connect: VecDeque<Result<ConnId, ConnectError>>,
    open_stream: VecDeque<Result<StreamId, Error>>,
    add_path: VecDeque<Result<PathId, PathError>>,
    send: HashMap<StreamId, VecDeque<Result<usize, StreamError>>>,
    recv: HashMap<StreamId, VecDeque<RecvChunk>>,
    stream_info: HashMap<StreamId, StreamInfo>,
    conn_stats: HashMap<ConnId, ConnStats>,
    transmits: HashMap<TxKey, (SocketAddr, VecDeque<Vec<u8>>)>,
    resume_pending: bool,
    next_timeout: Option<Time>,
    polling: bool,
    /// `close_conn` queues no `ConnClosed`; the test pushes it (xquic raises it
    /// after the closing period, so events still reach a closing connection).
    hold_close: bool,
    /// Events queued by the transport itself (e.g. `close_conn`).
    events: VecDeque<Event>,
    /// Injection queue, drained after `events`.
    injected: VecDeque<Event>,
    on_connect: Option<ConnectRule>,
    on_open_stream: Option<OpenRule>,
    on_stream_send: Option<SendRule>,
    on_drive: Option<DriveRule>,
    log: Vec<Call>,
    sent: HashMap<StreamId, Vec<u8>>,
    dgram_send: HashMap<ConnId, VecDeque<Result<(), DatagramError>>>,
    dgram_sent: HashMap<ConnId, Vec<Vec<u8>>>,
    dgram_rx: HashMap<ConnId, DgramRx>,
    dgram_mss: HashMap<ConnId, usize>,
    dgram_mss_calls: HashMap<ConnId, usize>,
}

impl ScriptState {
    fn fresh_slot(&mut self) -> SlotId {
        self.next_id += 1;
        SlotId::new(self.next_id, 1)
    }
}

/// Scripting side of a `ScriptedTransport`; `Clone + Send`, so a test thread
/// can script a transport running on a driver thread (spec §8.1).
#[derive(Clone)]
pub struct ScriptedHandle(Arc<Mutex<ScriptState>>);

/// Scripted `TransportOps` (spec §5.1). Unscripted defaults: `connect` /
/// `open_stream` return fresh ids, `stream_send` accepts everything,
/// `stream_recv` is `Blocked`, `add_path` returns sequential ids, `drive` only
/// records `now`, `next_timeout` is `None`, `close_conn` queues `ConnClosed`
/// (unless held), `datagram_send` accepts everything, `datagram_mss` is 1200,
/// `datagram_recv` is `None`.
pub struct ScriptedTransport {
    h: ScriptedHandle,
    last_now: Time,
    /// `peek_transmit` copies here: a `Transmit<'_>` cannot borrow through the mutex.
    staging: Vec<u8>,
}

impl ScriptedTransport {
    pub fn new() -> (Self, ScriptedHandle) {
        let h = ScriptedHandle(Arc::default());
        let t = ScriptedTransport {
            h: h.clone(),
            last_now: Time::ZERO,
            staging: Vec::new(),
        };
        (t, h)
    }

    fn st(&self) -> MutexGuard<'_, ScriptState> {
        self.h.st()
    }
}

impl ScriptedHandle {
    fn st(&self) -> MutexGuard<'_, ScriptState> {
        // A panicking test thread must not hide the original failure.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn expect_connect(&self, r: Result<ConnId, ConnectError>) {
        self.st().connect.push_back(r);
    }
    pub fn expect_open_stream(&self, r: Result<StreamId, Error>) {
        self.st().open_stream.push_back(r);
    }
    /// `Ok(n)` with `n` below the offered length accepts only that prefix.
    pub fn expect_stream_send(&self, s: StreamId, r: Result<usize, StreamError>) {
        self.st().send.entry(s).or_default().push_back(r);
    }
    /// A chunk larger than the caller's buffer is split; the remainder is
    /// returned by the next call (its FIN with the last piece).
    pub fn expect_stream_recv(&self, s: StreamId, r: Result<(Vec<u8>, bool), StreamError>) {
        self.st().recv.entry(s).or_default().push_back(r);
    }
    pub fn expect_add_path(&self, r: Result<PathId, PathError>) {
        self.st().add_path.push_back(r);
    }
    pub fn set_stream_info(&self, s: StreamId, info: StreamInfo) {
        self.st().stream_info.insert(s, info);
    }
    /// Queued results for `datagram_send` on `c`; a failed send records no bytes.
    pub fn expect_datagram_send(&self, c: ConnId, r: Result<(), DatagramError>) {
        self.st().dgram_send.entry(c).or_default().push_back(r);
    }
    /// Default 1200.
    pub fn set_datagram_mss(&self, c: ConnId, mss: usize) {
        self.st().dgram_mss.insert(c, mss);
    }
    /// Bounds the stored payload bytes of `c`'s inbound ring (default 16 MiB); an
    /// `inject_datagram` beyond it is dropped and counted.
    pub fn set_datagram_ring_cap(&self, c: ConnId, bytes: usize) {
        self.st().dgram_rx.entry(c).or_default().cap = bytes;
    }
    /// Queues one inbound datagram for `c`; `DatagramReadable` is pushed once,
    /// coalesced until it is popped (spec §3.1).
    pub fn inject_datagram(&self, c: ConnId, data: Vec<u8>) {
        let mut st = self.st();
        let rx = st.dgram_rx.entry(c).or_default();
        if rx.bytes + data.len() > rx.cap {
            rx.dropped += 1;
            return;
        }
        rx.bytes += data.len();
        rx.q.push_back(data);
        if !std::mem::replace(&mut rx.readable_queued, true) {
            st.injected.push_back(Event::DatagramReadable(c));
        }
    }
    /// Datagrams dropped on `c`'s inbound side (ring full, or a `datagram_recv` buffer too small).
    pub fn datagram_rx_dropped(&self, c: ConnId) -> u64 {
        self.st().dgram_rx.get(&c).map_or(0, |rx| rx.dropped)
    }
    /// Datagrams accepted by `datagram_send` on `c`, in order.
    pub fn datagram_sends(&self, c: ConnId) -> Vec<Vec<u8>> {
        self.st().dgram_sent.get(&c).cloned().unwrap_or_default()
    }
    /// How often `datagram_mss(c)` was queried.
    pub fn datagram_mss_calls(&self, c: ConnId) -> usize {
        self.st().dgram_mss_calls.get(&c).copied().unwrap_or(0)
    }
    pub fn set_conn_stats(&self, c: ConnId, st: ConnStats) {
        self.st().conn_stats.insert(c, st);
    }
    /// Replaces the queue for `key`; `transmit_done` removes from the front.
    pub fn set_transmit(&self, key: TxKey, dst: SocketAddr, datagrams: Vec<Vec<u8>>) {
        self.st().transmits.insert(key, (dst, datagrams.into()));
    }
    pub fn set_resume_pending(&self, v: bool) {
        self.st().resume_pending = v;
    }
    pub fn set_next_timeout(&self, t: Option<Time>) {
        self.st().next_timeout = t;
    }
    /// See `ScriptState::hold_close`.
    pub fn hold_conn_closed(&self, on: bool) {
        self.st().hold_close = on;
    }
    /// Injection queue; safe to call from any thread or from a reactive rule.
    pub fn push_event(&self, e: Event) {
        self.st().injected.push_back(e);
    }
    /// While on, `next_timeout()` is last `drive`/call `now` + 1 ms (spec §8.1).
    pub fn set_polling(&self, on: bool) {
        self.st().polling = on;
    }
    pub fn on_connect(
        &self,
        f: impl Fn(&ScriptedHandle) -> Result<ConnId, ConnectError> + Send + 'static,
    ) {
        self.st().on_connect = Some(Box::new(f));
    }
    pub fn on_open_stream(
        &self,
        f: impl Fn(&ScriptedHandle, ConnId) -> Result<StreamId, Error> + Send + 'static,
    ) {
        self.st().on_open_stream = Some(Box::new(f));
    }
    pub fn on_stream_send(
        &self,
        f: impl Fn(&ScriptedHandle, StreamId, &[u8], bool) -> Result<usize, StreamError>
        + Send
        + 'static,
    ) {
        self.st().on_stream_send = Some(Box::new(f));
    }
    /// Runs after every `drive` is logged.
    pub fn on_drive(&self, f: impl Fn(&ScriptedHandle, Time) + Send + 'static) {
        self.st().on_drive = Some(Box::new(f));
    }
    pub fn new_conn_id(&self) -> ConnId {
        ConnId::from_slot(self.st().fresh_slot()).expect("generation 1")
    }
    pub fn new_stream_id(&self) -> StreamId {
        StreamId::from_slot(self.st().fresh_slot()).expect("generation 1")
    }
    pub fn log(&self) -> Vec<Call> {
        self.st().log.clone()
    }
    /// Bytes accepted by `stream_send` on `s`, concatenated.
    pub fn sent_bytes(&self, s: StreamId) -> Vec<u8> {
        self.st().sent.get(&s).cloned().unwrap_or_default()
    }
}

/// Runs a reactive rule outside the lock: take it out, call it, put it back
/// unless the rule installed a replacement meanwhile.
fn run_rule<R: ?Sized, T>(
    h: &ScriptedHandle,
    slot: fn(&mut ScriptState) -> &mut Option<Box<R>>,
    call: impl FnOnce(&R) -> T,
) -> Option<T> {
    let rule = slot(&mut h.st()).take()?;
    let out = call(&rule);
    let mut st = h.st();
    let s = slot(&mut st);
    if s.is_none() {
        *s = Some(rule);
    }
    Some(out)
}

impl TransportOps for ScriptedTransport {
    fn recv_datagram(&mut self, now: Time, local: SocketAddr, peer: SocketAddr, data: &[u8]) {
        self.last_now = now;
        self.st().log.push(Call::RecvDatagram {
            now,
            local,
            peer,
            data: data.to_vec(),
        });
    }

    fn drive(&mut self, now: Time) {
        self.last_now = now;
        self.st().log.push(Call::Drive(now));
        run_rule(&self.h, |s| &mut s.on_drive, |f| f(&self.h, now));
    }

    fn pending_transmit(&self, out: &mut Vec<TxKey>) {
        let st = self.st();
        out.extend(
            st.transmits
                .iter()
                .filter(|(_, (_, q))| !q.is_empty())
                .map(|(k, _)| *k),
        );
    }

    /// The front run of equal-length datagrams, closed by one shorter
    /// datagram, like the real transmit queue (spec §4.2 `Transmit`).
    fn peek_transmit(&mut self, key: TxKey) -> Option<Transmit<'_>> {
        let mut st = self.h.st();
        st.log.push(Call::PeekTransmit(key));
        let (dst, q) = st.transmits.get(&key)?;
        let seg = q.front()?.len();
        self.staging.clear();
        for d in q {
            if d.len() > seg {
                break;
            }
            self.staging.extend_from_slice(d);
            if d.len() < seg {
                break;
            }
        }
        let dst = *dst;
        drop(st);
        Some(Transmit {
            dst,
            segment_size: seg,
            payload: &self.staging,
        })
    }

    fn transmit_done(&mut self, key: TxKey, datagrams: usize) {
        let mut st = self.st();
        st.log.push(Call::TransmitDone { key, n: datagrams });
        if let Some((_, q)) = st.transmits.get_mut(&key) {
            q.drain(..datagrams.min(q.len()));
        }
    }

    fn resume_pending(&self) -> bool {
        self.st().resume_pending
    }

    fn poll_event(&mut self) -> Option<Event> {
        let mut st = self.st();
        let e = st.events.pop_front().or_else(|| st.injected.pop_front())?;
        if let Event::DatagramReadable(c) = e {
            if let Some(rx) = st.dgram_rx.get_mut(&c) {
                rx.readable_queued = false;
            }
        }
        Some(e)
    }

    fn next_timeout(&self) -> Option<Time> {
        let st = self.st();
        if st.polling {
            Some(self.last_now + Duration::from_millis(1))
        } else {
            st.next_timeout
        }
    }

    fn connect(&mut self, now: Time, _cfg: &ConnConfig) -> Result<ConnId, ConnectError> {
        self.last_now = now;
        let scripted = {
            let mut st = self.st();
            st.log.push(Call::Connect);
            st.connect.pop_front()
        };
        if let Some(r) = scripted {
            return r;
        }
        run_rule(&self.h, |s| &mut s.on_connect, |f| f(&self.h))
            .unwrap_or_else(|| Ok(self.h.new_conn_id()))
    }

    fn open_stream(&mut self, now: Time, conn: ConnId) -> Result<StreamId, Error> {
        self.last_now = now;
        let scripted = {
            let mut st = self.st();
            st.log.push(Call::OpenStream(conn));
            st.open_stream.pop_front()
        };
        if let Some(r) = scripted {
            return r;
        }
        run_rule(&self.h, |s| &mut s.on_open_stream, |f| f(&self.h, conn))
            .unwrap_or_else(|| Ok(self.h.new_stream_id()))
    }

    fn stream_send(
        &mut self,
        now: Time,
        s: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, StreamError> {
        self.last_now = now;
        let scripted = {
            let mut st = self.st();
            st.log.push(Call::StreamSend {
                s,
                bytes: data.to_vec(),
                fin,
            });
            st.send.get_mut(&s).and_then(VecDeque::pop_front)
        };
        let r = match scripted {
            Some(r) => r,
            None => run_rule(
                &self.h,
                |st| &mut st.on_stream_send,
                |f| f(&self.h, s, data, fin),
            )
            .unwrap_or(Ok(data.len())),
        };
        if let Ok(n) = r {
            let n = n.min(data.len());
            self.st()
                .sent
                .entry(s)
                .or_default()
                .extend_from_slice(&data[..n]);
        }
        r
    }

    fn stream_recv(
        &mut self,
        now: Time,
        s: StreamId,
        buf: &mut [u8],
    ) -> Result<(usize, bool), StreamError> {
        self.last_now = now;
        let mut st = self.st();
        st.log.push(Call::StreamRecv { s, cap: buf.len() });
        let Some(q) = st.recv.get_mut(&s) else {
            return Err(StreamError::Blocked);
        };
        match q.front_mut() {
            None => Err(StreamError::Blocked),
            Some(Ok((chunk, _))) if chunk.len() > buf.len() => {
                let n = buf.len();
                buf.copy_from_slice(&chunk[..n]);
                chunk.drain(..n);
                Ok((n, false))
            }
            Some(_) => {
                let r = q.pop_front().expect("front exists");
                r.map(|(chunk, fin)| {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    (chunk.len(), fin)
                })
            }
        }
    }

    fn stream_reset(&mut self, now: Time, s: StreamId) {
        self.last_now = now;
        self.st().log.push(Call::StreamReset(s));
    }

    fn add_path(&mut self, now: Time, conn: ConnId, standby: bool) -> Result<PathId, PathError> {
        self.last_now = now;
        let mut st = self.st();
        st.log.push(Call::AddPath { conn, standby });
        st.add_path.pop_front().unwrap_or_else(|| {
            st.next_path += 1;
            Ok(PathId(st.next_path))
        })
    }

    fn close_conn(&mut self, now: Time, conn: ConnId) {
        self.last_now = now;
        let mut st = self.st();
        st.log.push(Call::CloseConn(conn));
        if st.hold_close {
            return;
        }
        st.events.push_back(Event::ConnClosed(
            conn,
            CloseReason {
                err_type: ErrType::Unknown,
                code: 0,
            },
        ));
    }

    fn conn_stats(&self, conn: ConnId) -> Result<ConnStats, Error> {
        self.st().conn_stats.get(&conn).cloned().ok_or(Error::Stale)
    }

    fn stream_info(&self, s: StreamId) -> Result<StreamInfo, Error> {
        self.st().stream_info.get(&s).copied().ok_or(Error::Stale)
    }

    fn datagram_send(&mut self, now: Time, conn: ConnId, data: &[u8]) -> Result<(), DatagramError> {
        self.last_now = now;
        let mut st = self.st();
        st.log.push(Call::DatagramSend {
            conn,
            bytes: data.to_vec(),
        });
        let r = st
            .dgram_send
            .get_mut(&conn)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Ok(()));
        if r.is_ok() {
            st.dgram_sent.entry(conn).or_default().push(data.to_vec());
        }
        r
    }

    fn datagram_mss(&self, conn: ConnId) -> usize {
        let mut st = self.st();
        *st.dgram_mss_calls.entry(conn).or_default() += 1;
        st.dgram_mss.get(&conn).copied().unwrap_or(1200)
    }

    fn datagram_recv(&mut self, conn: ConnId, buf: &mut [u8]) -> Option<usize> {
        let mut st = self.st();
        let rx = st.dgram_rx.get_mut(&conn)?;
        let d = rx.q.pop_front()?;
        rx.bytes -= d.len();
        if d.len() > buf.len() {
            // the real facade's clause (spec §3.1): drop, count, keep the caller's drain going
            rx.dropped += 1;
            return Some(0);
        }
        buf[..d.len()].copy_from_slice(&d);
        Some(d.len())
    }
}
