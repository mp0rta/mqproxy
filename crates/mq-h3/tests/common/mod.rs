//! `Rig`: an `H3Wire<ScriptedTransport>` joined to a real `h3wire::Connection` peer.
#![allow(dead_code)]

use h3wire::{Action, Config, Connection, H3Code, Recv, Role, StreamId as Q};
use mq_h3::H3Wire;
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_transport_api::{
    CloseReason, ConnConfig, ConnId, ConnProto, ErrType, Error, Event, StreamCloseStats,
    StreamError, StreamId, StreamInfo, StreamKind, Time, TransportOps,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

/// `w` → peer bytes of one stream, as the transport accepted them.
#[derive(Default)]
struct Out {
    buf: Vec<u8>,
    /// Bytes already fed to the peer.
    at: usize,
    fin: bool,
    fin_fed: bool,
    /// Accepted `stream_send` calls with `fin`.
    fins: usize,
}

/// State shared with the `on_stream_send` / `on_open_stream` rules.
#[derive(Default)]
struct Wire {
    q_of: HashMap<StreamId, u64>,
    mq_of: HashMap<u64, StreamId>,
    out: BTreeMap<StreamId, Out>,
    /// Caps on the next `stream_send` calls per stream, one each (None: uncapped).
    limit: HashMap<StreamId, VecDeque<Option<usize>>>,
    /// Quic id of the next request stream `w` opens.
    next_req: u64,
    /// The conn is closed: `open_stream` fails like the real transport's (`Stale`).
    conn_closed: bool,
}

impl Wire {
    fn map(&mut self, s: StreamId, q: u64) {
        self.q_of.insert(s, q);
        self.mq_of.insert(q, s);
    }
}

pub struct Rig {
    pub w: H3Wire<ScriptedTransport>,
    pub h: ScriptedHandle,
    pub peer: Connection,
    pub peer_events: Vec<h3wire::Event>,
    /// DATA payload the peer received, per quic id.
    peer_body: BTreeMap<u64, Vec<u8>>,
    pub conn: ConnId,
    pub now: Time,
    wire: Arc<Mutex<Wire>>,
    /// Peer → `w` bytes not yet delivered, and whether FIN follows them.
    to_w: BTreeMap<u64, (Vec<u8>, bool)>,
    /// Quic id of the next uni stream the peer opens.
    next_peer_uni: u64,
    /// Streams the transport closed (`close_stream`).
    closed: HashSet<StreamId>,
    /// Streams whose transport receive side was given its end (FIN or reset).
    recv_end: HashSet<StreamId>,
    /// Streams whose send side `w` reset, or the transport reset on a peer STOP_SENDING.
    send_reset: HashSet<StreamId>,
    /// `relay_aborts` cursor into the call log.
    log_at: usize,
    /// `relay_aborts` saw `w` close the conn.
    w_closed: bool,
    /// Quic ids `peer_raw_reset` reset: later peer bytes on them are dropped.
    raw_reset: HashSet<u64>,
}

/// Generous; hitting it means the two sides never settle.
const MAX_ROUNDS: usize = 1000;

impl Rig {
    /// `w` is the server; the peer is an h3wire client.
    pub fn server() -> Rig {
        let rig = Rig::new(Role::Client, [3, 7, 11]);
        rig.h.push_event(Event::NewConn(rig.conn, ConnProto::H3));
        rig
    }

    /// `w` is the client; the peer is an h3wire server.
    pub fn client() -> Rig {
        let mut rig = Rig::new(Role::Server, [2, 6, 10]);
        rig.h.expect_connect(Ok(rig.conn));
        let cfg = ConnConfig {
            peer: "127.0.0.1:4433".parse().unwrap(),
            sni: "mqproxy",
            idle_timeout: None,
            proto: ConnProto::H3,
        };
        assert_eq!(rig.w.connect(rig.now, &cfg), Ok(rig.conn));
        rig.h.push_event(Event::ConnEstablished(rig.conn));
        rig
    }

    /// `local_uni`: the quic ids of `w`'s three uni streams, in open order.
    fn new(peer_role: Role, local_uni: [u64; 3]) -> Rig {
        let (t, h) = ScriptedTransport::new();
        let conn = h.new_conn_id();
        h.set_conn_stats(conn, Default::default()); // live: its conn events pop
        let wire = Arc::new(Mutex::new(Wire::default()));
        for q in local_uni {
            let s = h.new_stream_id();
            h.set_stream_info(s, info(conn, q));
            h.expect_open_uni(Ok(s));
            lock(&wire).map(s, q);
        }
        let ww = wire.clone();
        h.on_open_stream(move |h, conn| {
            let mut w = lock(&ww);
            if w.conn_closed {
                return Err(Error::Stale);
            }
            let s = h.new_stream_id();
            let q = w.next_req;
            w.next_req += 4;
            w.map(s, q);
            h.set_stream_info(s, info(conn, q));
            Ok(s)
        });
        let ww = wire.clone();
        h.on_stream_send(move |_, s, data, fin| {
            let mut w = lock(&ww);
            let n = match w.limit.get_mut(&s).and_then(VecDeque::pop_front).flatten() {
                Some(0) => return Err(StreamError::Blocked),
                Some(cap) => data.len().min(cap),
                None => data.len(),
            };
            let out = w.out.entry(s).or_default();
            out.buf.extend_from_slice(&data[..n]);
            let fin = fin && n == data.len();
            out.fin |= fin;
            out.fins += usize::from(fin);
            Ok(n)
        });
        Rig {
            w: H3Wire::new(t),
            h,
            peer: Connection::new(peer_role, Config::default()),
            peer_events: Vec::new(),
            peer_body: BTreeMap::new(),
            conn,
            now: Time::ZERO,
            wire,
            to_w: BTreeMap::new(),
            next_peer_uni: if peer_role == Role::Client { 2 } else { 3 },
            closed: HashSet::new(),
            recv_end: HashSet::new(),
            send_reset: HashSet::new(),
            log_at: 0,
            w_closed: false,
            raw_reset: HashSet::new(),
        }
    }

    /// Moves accepted bytes both ways and executes actions on both sides until nothing moves.
    /// After the transport conn closed, only drives `w`.
    pub fn pump(&mut self) {
        if self.conn_closed() {
            self.w.drive(self.now);
            return;
        }
        for _ in 0..MAX_ROUNDS {
            self.w.drive(self.now);
            let mut moved = self.feed_peer();
            moved |= self.drain_peer();
            moved |= self.flush_to_w();
            if !moved {
                return;
            }
        }
        panic!("pump did not settle");
    }

    /// Drains `w.poll_event()`.
    pub fn events(&mut self) -> Vec<Event> {
        std::iter::from_fn(|| self.w.poll_event()).collect()
    }

    /// The mq id of a quic id (either side's stream).
    pub fn peer_stream(&self, q: Q) -> StreamId {
        lock(&self.wire).mq_of[&q.0]
    }

    /// Caps how many bytes one later `stream_send` on `s` accepts (None = all); 0 is
    /// `Blocked`. Caps queue: the n-th call caps the n-th following send.
    pub fn limit(&mut self, s: StreamId, n: Option<usize>) {
        lock(&self.wire).limit.entry(s).or_default().push_back(n);
    }

    /// How many `stream_send` calls with `fin` on `s` the transport accepted.
    pub fn fins(&self, s: StreamId) -> usize {
        lock(&self.wire).out.get(&s).map_or(0, |o| o.fins)
    }

    /// The DATA payload the peer received on `q`.
    pub fn peer_body(&self, q: Q) -> Vec<u8> {
        self.peer_body.get(&q.0).cloned().unwrap_or_default()
    }

    /// Peer DATA through send_data / data_written; the bytes reach `w` on the next pump.
    pub fn peer_send_body(&mut self, q: Q, body: &[u8], fin: bool) {
        assert!(self.try_peer_send_body(q, body, fin), "peer send_data");
    }

    /// `peer_send_body`, returning false if the peer refuses.
    pub fn try_peer_send_body(&mut self, q: Q, body: &[u8], fin: bool) -> bool {
        self.drain_peer(); // queued HEADERS go first
        let Ok(f) = self.peer.send_data(q, body.len() as u64, fin) else {
            return false;
        };
        let pipe = &mut self.to_w.entry(q.0).or_default().0;
        pipe.extend_from_slice(f.prefix());
        pipe.extend_from_slice(body);
        let n = f.prefix().len() + body.len();
        if n > 0 {
            self.peer.data_written(q, n).expect("peer data_written");
        }
        true
    }

    /// Raw bytes on a peer stream (the "raw" cases only).
    pub fn deliver(&mut self, q: Q, bytes: &[u8], fin: bool) {
        let e = self.to_w.entry(q.0).or_default();
        e.0.extend_from_slice(bytes);
        e.1 |= fin;
    }

    /// Pushes ConnClosed(conn, reason) into the inner transport (transport close, not H3),
    /// once; nothing moves between the two sides afterwards.
    pub fn close_transport(&mut self, reason: CloseReason) {
        if !std::mem::replace(&mut lock(&self.wire).conn_closed, true) {
            self.h.push_event(Event::ConnClosed(self.conn, reason));
        }
    }

    /// `close_transport` as xquic does it: every stream's `StreamCloseStats` +
    /// `StreamClosed` first, then `ConnClosed` (adoption spec §3, A.5).
    pub fn close_transport_streams(&mut self, reason: CloseReason) {
        if self.conn_closed() {
            return;
        }
        for (_, s) in self.streams() {
            self.close_stream(s);
        }
        self.close_transport(reason);
    }

    /// The transport conn is closed: nothing moves between the two sides any more.
    pub fn conn_closed(&self) -> bool {
        lock(&self.wire).conn_closed
    }

    /// `w` closed the conn (`close_conn` / `close_conn_with`) and the transport has not
    /// reported it yet; seen by `relay_aborts`.
    pub fn w_closed(&self) -> bool {
        self.w_closed && !self.conn_closed()
    }

    /// The mq id of quic id `q`, if mapped.
    pub fn stream_of(&self, q: u64) -> Option<StreamId> {
        lock(&self.wire).mq_of.get(&q).copied()
    }

    /// Every mapped stream (quic id, mq id) the transport has not closed, by quic id.
    pub fn streams(&self) -> Vec<(u64, StreamId)> {
        let w = lock(&self.wire);
        let mut v: Vec<_> = w
            .mq_of
            .iter()
            .filter(|(_, s)| !self.closed.contains(s))
            .map(|(&q, &s)| (q, s))
            .collect();
        v.sort();
        v
    }

    /// The transport handed `s`'s receive end to `w` (FIN or reset).
    pub fn recv_ended(&self, s: StreamId) -> bool {
        self.recv_end.contains(&s)
    }

    /// The transport closed `s` (`close_stream`).
    pub fn is_closed(&self, s: StreamId) -> bool {
        self.closed.contains(&s)
    }

    /// `StreamCloseStats` + `StreamClosed` for `s`, once (xquic destroys the stream).
    pub fn close_stream(&mut self, s: StreamId) {
        if !self.closed.insert(s) {
            return;
        }
        let st = StreamCloseStats {
            fin_send_us: 0,
            fin_ack_us: 0,
            mp_state: 0,
            stream_err: 0,
            close_msg: None,
        };
        self.h.push_event(Event::StreamCloseStats(s, Box::new(st)));
        self.h.push_event(Event::StreamClosed(s));
    }

    /// xquic may close `s` on its own: both directions are over. Receive: the transport
    /// gave its end (FIN or reset) and `w` read everything. Send: `w`'s FIN was accepted,
    /// or the send side was reset (by `w`, or by xquic on a peer STOP_SENDING). Needs
    /// `relay_aborts` to have seen the latest calls.
    pub fn retirable(&self, s: StreamId) -> bool {
        let Some(&q) = lock(&self.wire).q_of.get(&s) else {
            return false;
        };
        !self.closed.contains(&s)
            && self.recv_end.contains(&s)
            && self.h.recv_pending(s) == 0
            && !self.to_w.contains_key(&q)
            && (self.fins(s) > 0 || self.send_reset.contains(&s))
    }

    /// The peer knows stream `s`: it opened it, or `w` has sent it bytes.
    fn peer_knows(&self, s: StreamId) -> bool {
        let peer_client = self.next_peer_uni % 4 == 2;
        peer_client || lock(&self.wire).out.get(&s).is_some_and(|o| o.at > 0)
    }

    /// A peer STOP_SENDING on `w`'s stream `q`: the transport event, then xquic's
    /// RESET_STREAM reply (unless `w`'s FIN was accepted), which the peer receives.
    pub fn peer_stop_sending(&mut self, q: u64, code: u64) {
        let Some(s) = self.stream_of(q) else {
            return;
        };
        if self.conn_closed() || self.closed.contains(&s) || !self.peer_knows(s) {
            return;
        }
        self.h.push_event(Event::StreamStopSending(s, code));
        if self.fins(s) == 0 && self.send_reset.insert(s) {
            self.abandon(s);
            let _ = self
                .peer
                .stream_reset_received(Q(q), H3Code::REQUEST_CANCELLED);
        }
    }

    /// A RESET_STREAM on `q` from a peer stack that resets even after its FIN;
    /// the h3wire peer is not told and its later bytes on `q`
    /// are dropped.
    pub fn peer_raw_reset(&mut self, q: u64, code: u64) {
        let Some(s) = self.stream_of(q) else {
            return;
        };
        if self.conn_closed()
            || self.closed.contains(&s)
            || !self.peer_knows(s)
            || !self.raw_reset.insert(q)
        {
            return;
        }
        self.to_w.remove(&q);
        self.recv_end.insert(s);
        self.h.expect_stream_recv(s, Err(StreamError::Reset));
        self.h.push_event(Event::StreamPeerReset(s, code));
    }

    /// Delivers `w`'s RESET_STREAM / STOP_SENDING calls since the last call to the peer.
    /// A STOP_SENDING makes the peer reset its send side, as its transport would.
    pub fn relay_aborts(&mut self) {
        let log = self.h.log();
        let new = &log[self.log_at..];
        self.log_at = log.len();
        for c in new {
            let (s, reset, stop) = match *c {
                Call::StreamResetSend { s, code } => (s, Some(code), None),
                Call::StreamStopSending { s, code } => (s, None, Some(code)),
                Call::StreamReset(s) => (s, Some(0x10c), Some(0x10c)),
                Call::CloseConn(_) | Call::CloseConnWith { .. } => {
                    self.w_closed = true;
                    continue;
                }
                _ => continue,
            };
            if reset.is_some() {
                self.send_reset.insert(s);
            }
            let q = lock(&self.wire).q_of.get(&s).copied();
            let Some(q) = q.filter(|_| !self.conn_closed() && !self.closed.contains(&s)) else {
                continue;
            };
            if let Some(code) = reset {
                self.abandon(s);
                let _ = self.peer.stream_reset_received(Q(q), H3Code(code));
            }
            if let Some(code) = stop {
                let _ = self.peer.stop_sending_received(Q(q), H3Code(code));
            }
        }
    }

    /// RESET_STREAM abandons what `w` sent on `s` and the peer has not received.
    fn abandon(&mut self, s: StreamId) {
        if let Some(o) = lock(&self.wire).out.get_mut(&s) {
            o.at = o.buf.len();
            o.fin_fed = true;
        }
    }

    /// Feeds every accepted `w` → peer byte to the peer; returns whether anything moved.
    fn feed_peer(&mut self) -> bool {
        let wire = self.wire.clone();
        let mut w = lock(&wire);
        let Wire { q_of, out, .. } = &mut *w;
        let mut moved = false;
        for (s, o) in out.iter_mut() {
            let q = Q(q_of[s]);
            loop {
                let rest = &o.buf[o.at..];
                let fin = o.fin && !o.fin_fed;
                if rest.is_empty() && !fin {
                    break;
                }
                let n = match self.peer.recv(q, rest, fin) {
                    Ok(Recv::Paused) => break,
                    Ok(Recv::Body { consumed, range }) => {
                        let body = self.peer_body.entry(q.0).or_default();
                        body.extend_from_slice(&rest[range]);
                        consumed
                    }
                    Ok(
                        Recv::Consumed(n)
                        | Recv::Frame { consumed: n, .. }
                        | Recv::Raw { consumed: n, .. },
                    ) => n,
                    Err(_) => rest.len(), // the peer is closed: discard
                };
                moved = true;
                o.at += n;
                o.fin_fed |= fin && n == rest.len();
            }
        }
        moved
    }

    /// Records peer events, executes peer actions and stages its core bytes for `w`.
    fn drain_peer(&mut self) -> bool {
        let mut moved = false;
        loop {
            self.peer_events
                .extend(std::iter::from_fn(|| self.peer.poll_event()));
            let mut any = false;
            while let Some(a) = self.peer.poll_action() {
                any = true;
                self.peer_action(a);
            }
            for q in self.peer.sendable().collect::<Vec<_>>() {
                let Some(bytes) = self.peer.poll_send(q) else {
                    continue;
                };
                let n = bytes.len();
                self.to_w.entry(q.0).or_default().0.extend_from_slice(bytes);
                self.peer.sent(q, n).expect("peer sent");
                any = true;
            }
            if !any {
                return moved;
            }
            moved = true;
        }
    }

    fn peer_action(&mut self, a: Action) {
        if self.conn_closed() {
            return;
        }
        match a {
            Action::OpenUni(kind) => {
                let q = self.next_peer_uni;
                self.next_peer_uni += 4;
                self.peer.bind_uni(kind, Q(q)).expect("peer bind_uni");
                self.mq(q);
            }
            Action::FinishStream(q) => self.to_w.entry(q.0).or_default().1 = true,
            Action::ResetStream { stream, code } => {
                self.to_w.remove(&stream.0); // RESET_STREAM abandons what is unsent
                let s = self.mq(stream.0);
                if self.closed.contains(&s) {
                    return;
                }
                self.recv_end.insert(s);
                self.h.expect_stream_recv(s, Err(StreamError::Reset));
                self.h.push_event(Event::StreamPeerReset(s, code.0));
            }
            Action::StopSending { stream, code } => {
                let s = self.mq(stream.0);
                if self.closed.contains(&s) {
                    return;
                }
                self.h.push_event(Event::StreamStopSending(s, code.0));
            }
            Action::CloseConnection { code, .. } => self.close_transport(CloseReason {
                err_type: ErrType::Application,
                code: code.0,
            }),
        }
    }

    /// Delivers staged peer bytes: one `stream_recv` chunk plus `StreamReadable` per stream.
    fn flush_to_w(&mut self) -> bool {
        let staged = std::mem::take(&mut self.to_w);
        let mut moved = false;
        for (q, (bytes, fin)) in staged {
            if self.conn_closed() || self.raw_reset.contains(&q) || (bytes.is_empty() && !fin) {
                continue;
            }
            let s = self.mq(q);
            if self.closed.contains(&s) {
                continue; // the transport stream is gone
            }
            if fin {
                self.recv_end.insert(s);
            }
            self.h.expect_stream_recv(s, Ok((bytes, fin)));
            self.h.push_event(Event::StreamReadable(s));
            moved = true;
        }
        moved
    }

    /// The mq id of quic id `q`; a stream the peer opens is announced with `NewStream`.
    fn mq(&mut self, q: u64) -> StreamId {
        let mut w = lock(&self.wire);
        if let Some(&s) = w.mq_of.get(&q) {
            return s;
        }
        let s = self.h.new_stream_id();
        w.map(s, q);
        let i = info(self.conn, q);
        self.h.set_stream_info(s, i);
        self.h.push_event(Event::NewStream(self.conn, s, i));
        s
    }
}

fn info(conn: ConnId, q: u64) -> StreamInfo {
    let kind = if q & 2 != 0 {
        StreamKind::Uni
    } else {
        StreamKind::Bidi
    };
    StreamInfo {
        conn,
        quic_id: q,
        kind,
    }
}

fn lock(w: &Mutex<Wire>) -> MutexGuard<'_, Wire> {
    w.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reset / STOP_SENDING calls on `s`, in order.
pub fn aborts(r: &Rig, s: StreamId) -> Vec<Call> {
    r.h.log()
        .into_iter()
        .filter(|c| {
            matches!(c, Call::StreamResetSend { s: x, .. } | Call::StreamStopSending { s: x, .. }
                | Call::StreamReset(x) if *x == s)
        })
        .collect()
}

/// `stream_recv` calls on `s`.
pub fn recvs(r: &Rig, s: StreamId) -> usize {
    r.h.log()
        .iter()
        .filter(|c| matches!(c, Call::StreamRecv { s: x, .. } if *x == s))
        .count()
}
