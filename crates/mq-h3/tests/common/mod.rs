//! `Rig`: an `H3Wire<ScriptedTransport>` joined to a real `h3wire::Connection` peer.
#![allow(dead_code)]

use h3wire::{Action, Config, Connection, Recv, Role, StreamId as Q};
use mq_h3::H3Wire;
use mq_runtime::testing::{ScriptedHandle, ScriptedTransport};
use mq_transport_api::{
    CloseReason, ConnConfig, ConnId, ConnProto, ErrType, Event, StreamError, StreamId, StreamInfo,
    StreamKind, Time, TransportOps,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

/// `w` → peer bytes of one stream, as the transport accepted them.
#[derive(Default)]
struct Out {
    buf: Vec<u8>,
    /// Bytes already fed to the peer.
    at: usize,
    fin: bool,
    fin_fed: bool,
}

/// State shared with the `on_stream_send` / `on_open_stream` rules.
#[derive(Default)]
struct Wire {
    q_of: HashMap<StreamId, u64>,
    mq_of: HashMap<u64, StreamId>,
    out: BTreeMap<StreamId, Out>,
    /// One-shot cap on the next `stream_send` per stream.
    limit: HashMap<StreamId, usize>,
    /// Quic id of the next request stream `w` opens.
    next_req: u64,
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
    pub conn: ConnId,
    pub now: Time,
    wire: Arc<Mutex<Wire>>,
    /// Peer → `w` bytes not yet delivered, and whether FIN follows them.
    to_w: BTreeMap<u64, (Vec<u8>, bool)>,
    /// Quic id of the next uni stream the peer opens.
    next_peer_uni: u64,
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
        let wire = Arc::new(Mutex::new(Wire::default()));
        for q in local_uni {
            let s = h.new_stream_id();
            h.set_stream_info(s, info(conn, q));
            h.expect_open_uni(Ok(s));
            lock(&wire).map(s, q);
        }
        let ww = wire.clone();
        h.on_open_stream(move |h, conn| {
            let s = h.new_stream_id();
            let mut w = lock(&ww);
            let q = w.next_req;
            w.next_req += 4;
            w.map(s, q);
            h.set_stream_info(s, info(conn, q));
            Ok(s)
        });
        let ww = wire.clone();
        h.on_stream_send(move |_, s, data, fin| {
            let mut w = lock(&ww);
            let n = match w.limit.remove(&s) {
                Some(0) => return Err(StreamError::Blocked),
                Some(cap) => data.len().min(cap),
                None => data.len(),
            };
            let out = w.out.entry(s).or_default();
            out.buf.extend_from_slice(&data[..n]);
            out.fin |= fin && n == data.len();
            Ok(n)
        });
        Rig {
            w: H3Wire::new(t),
            h,
            peer: Connection::new(peer_role, Config::default()),
            peer_events: Vec::new(),
            conn,
            now: Time::ZERO,
            wire,
            to_w: BTreeMap::new(),
            next_peer_uni: if peer_role == Role::Client { 2 } else { 3 },
        }
    }

    /// Moves accepted bytes both ways and executes actions on both sides until nothing moves.
    pub fn pump(&mut self) {
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

    /// Caps how many bytes the next `stream_send` on `s` accepts (None = all); 0 is `Blocked`.
    pub fn limit(&mut self, s: StreamId, n: Option<usize>) {
        let mut w = lock(&self.wire);
        match n {
            Some(n) => w.limit.insert(s, n),
            None => w.limit.remove(&s),
        };
    }

    /// Peer DATA through send_data / data_written; the bytes reach `w` on the next pump.
    pub fn peer_send_body(&mut self, q: Q, body: &[u8], fin: bool) {
        self.drain_peer(); // queued HEADERS go first
        let f = self
            .peer
            .send_data(q, body.len() as u64, fin)
            .expect("peer send_data");
        let pipe = &mut self.to_w.entry(q.0).or_default().0;
        pipe.extend_from_slice(f.prefix());
        pipe.extend_from_slice(body);
        self.peer
            .data_written(q, f.prefix().len() + body.len())
            .expect("peer data_written");
    }

    /// Raw bytes on a peer stream (the "raw" cases only).
    pub fn deliver(&mut self, q: Q, bytes: &[u8], fin: bool) {
        let e = self.to_w.entry(q.0).or_default();
        e.0.extend_from_slice(bytes);
        e.1 |= fin;
    }

    /// Pushes ConnClosed(conn, reason) into the inner transport (transport close, not H3).
    pub fn close_transport(&mut self, reason: CloseReason) {
        self.h.push_event(Event::ConnClosed(self.conn, reason));
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
                    Ok(
                        Recv::Consumed(n)
                        | Recv::Body { consumed: n, .. }
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
                self.h.expect_stream_recv(s, Err(StreamError::Reset));
                self.h.push_event(Event::StreamPeerReset(s, code.0));
            }
            Action::StopSending { stream, code } => {
                let s = self.mq(stream.0);
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
            if bytes.is_empty() && !fin {
                continue;
            }
            let s = self.mq(q);
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
