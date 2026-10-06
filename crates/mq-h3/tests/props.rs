//! Property test (adoption spec §6.1, §5.4, §4.3): random peer, gateway and transport steps
//! over a `Rig`, both roles.
//!
//! After every step: no panic and `debug_bounds_hold()`. Throughout: `H3Request` once per
//! request, no H3 event after a request's `H3Closed`, at most one `ConnClosed`, and a
//! request whose stream the transport closed has its `H3Closed` once the gateway has its
//! receive end or called `h3_reset` (§4.3 "Closure"). At the end, after the transport close
//! and a drain of every request still open, each request that got `H3Request` or was opened
//! has exactly one `H3Closed`.
//!
//! Transport model (what xquic could deliver; the Rig enforces the rest):
//! - Peer bytes, resets and STOP_SENDING come from the real h3wire peer. A peer STOP_SENDING
//!   (h3wire has no API for it alone) is the transport event plus xquic's RESET_STREAM reply,
//!   unless our FIN was accepted. `w`'s RESET_STREAM / STOP_SENDING reach the peer
//!   (`relay_aborts`); a STOP_SENDING makes the peer reset, as its transport would.
//! - `StreamClosed` (always after `StreamCloseStats`) only for a request stream whose two
//!   directions are over (`Rig::retirable`), and for every stream at a connection close
//!   that models xquic's order. Nothing reaches a closed stream, and after `ConnClosed`
//!   nothing moves between the sides.
//! - `ConnClosed` comes once: from the close step, the peer's `CloseConnection`, or after
//!   `w`'s own `close_conn_with` (held, then replayed with or without the stream closes).
//! - The gateway keeps its contract: `h3_send_body` re-offers every unaccepted byte, no send
//!   after its FIN, `h3_finish` only with nothing pending. Op order is otherwise random.
#![cfg(feature = "test-support")]

mod common;

use common::Rig;
use h3wire::{FieldRef, H3Code, StreamId as Q};
use mq_transport_api::{CloseReason, ErrType, Event, H3Header, H3ReqId, StreamError, TransportOps};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};

const CLOSE: CloseReason = CloseReason {
    err_type: ErrType::Application,
    code: 0x10c,
};

#[derive(Clone, Debug)]
enum Step {
    PeerHeaders { q: u8, fin: bool, info: bool },
    PeerBody { q: u8, len: usize, fin: bool },
    PeerFin { q: u8 },
    PeerReset { q: u8 },
    PeerRawReset { q: u8 },
    PeerStopSending { q: u8 },
    PeerGoaway { finish: bool },
    Open,
    SendHeaders { r: u8, set: u8, fin: bool },
    SendBody { r: u8, add: usize, fin: bool },
    Finish { r: u8 },
    Reset { r: u8 },
    RecvHeaders { r: u8 },
    RecvBody { r: u8, cap: usize },
    Writable { q: u8 },
    StreamClosed { q: u8 },
    Close { streams_first: bool },
    Limit { q: u8, cap: Option<usize> },
    Pump,
}

fn step() -> impl Strategy<Value = Step> {
    let q = any::<u8>;
    prop_oneof![
        20 => (q(), any::<bool>(), prop::bool::weighted(0.2))
            .prop_map(|(q, fin, info)| Step::PeerHeaders { q, fin, info }),
        12 => (q(), 0usize..20_000, any::<bool>())
            .prop_map(|(q, len, fin)| Step::PeerBody { q, len, fin }),
        4 => q().prop_map(|q| Step::PeerFin { q }),
        4 => q().prop_map(|q| Step::PeerReset { q }),
        2 => q().prop_map(|q| Step::PeerRawReset { q }),
        4 => q().prop_map(|q| Step::PeerStopSending { q }),
        4 => any::<bool>().prop_map(|finish| Step::PeerGoaway { finish }),
        16 => Just(Step::Open),
        12 => (q(), 0u8..8, any::<bool>())
            .prop_map(|(r, set, fin)| Step::SendHeaders { r, set, fin }),
        12 => (q(), 0usize..20_000, any::<bool>())
            .prop_map(|(r, add, fin)| Step::SendBody { r, add, fin }),
        4 => q().prop_map(|r| Step::Finish { r }),
        4 => q().prop_map(|r| Step::Reset { r }),
        8 => q().prop_map(|r| Step::RecvHeaders { r }),
        16 => (q(), 1usize..32 * 1024).prop_map(|(r, cap)| Step::RecvBody { r, cap }),
        4 => q().prop_map(|q| Step::Writable { q }),
        16 => q().prop_map(|q| Step::StreamClosed { q }),
        1 => any::<bool>().prop_map(|streams_first| Step::Close { streams_first }),
        8 => (q(), prop_oneof![Just(Some(0)), (1usize..64).prop_map(Some), Just(None)])
            .prop_map(|(q, cap)| Step::Limit { q, cap }),
        20 => Just(Step::Pump),
    ]
}

/// The gateway's view of one request.
struct Gw {
    id: H3ReqId,
    quic: Option<u64>,
    /// Body bytes offered and not accepted: re-offered first.
    pending: usize,
    fin_sent: bool,
    /// The gateway got `fin` or `Err(Reset)` from a read, or called `h3_reset`.
    done: bool,
}

struct Model {
    r: Rig,
    server: bool,
    reqs: Vec<Gw>,
    known: HashSet<H3ReqId>,
    closed: HashMap<H3ReqId, usize>,
    conn_closed: usize,
    /// Peer blocks released so far (index into `peer_events`).
    peer_seen: usize,
}

fn f<'a>(n: &'a str, v: &'a str) -> FieldRef<'a> {
    FieldRef::new(n.as_bytes(), v.as_bytes())
}

fn h<'a>(n: &'a str, v: &'a str) -> H3Header<'a> {
    H3Header {
        name: n.as_bytes(),
        value: v.as_bytes(),
    }
}

fn pick<T: Copy>(v: &[T], i: u8) -> Option<T> {
    (!v.is_empty()).then(|| v[i as usize % v.len()])
}

impl Model {
    fn new(server: bool) -> Model {
        let r = if server { Rig::server() } else { Rig::client() };
        // `w`'s own closes are replayed through the Rig, so ConnClosed comes once.
        r.h.hold_conn_closed(true);
        let mut m = Model {
            r,
            server,
            reqs: Vec::new(),
            known: HashSet::new(),
            closed: HashMap::new(),
            conn_closed: 0,
            peer_seen: 0,
        };
        m.pump();
        m.events();
        m
    }

    /// Request quic ids the peer may act on: the peer opens 0..12 (server), or those `w`
    /// opened (client).
    fn peer_q(&self, i: u8) -> Option<Q> {
        if self.server {
            return Some(Q(4 * u64::from(i % 4)));
        }
        let opened: Vec<u64> = self.reqs.iter().filter_map(|g| g.quic).collect();
        pick(&opened, i).map(Q)
    }

    /// `w`'s request and local uni streams the transport still has.
    fn w_stream(&self, i: u8) -> Option<mq_transport_api::StreamId> {
        let local_uni = if self.server { 3 } else { 2 };
        let v: Vec<_> = self
            .r
            .streams()
            .into_iter()
            .filter(|&(q, _)| q % 4 == 0 || q % 4 == local_uni)
            .map(|(_, s)| s)
            .collect();
        pick(&v, i)
    }

    fn gw(&mut self, i: u8) -> Option<&mut Gw> {
        let n = self.reqs.len();
        (n > 0).then(|| &mut self.reqs[i as usize % n])
    }

    fn pump(&mut self) {
        self.r.relay_aborts();
        self.r.pump();
        // The peer application takes every block it gets.
        let blocks: Vec<_> = self.r.peer_events[self.peer_seen..]
            .iter()
            .filter_map(|e| match *e {
                h3wire::Event::Headers { block, .. } => Some(block),
                _ => None,
            })
            .collect();
        self.peer_seen = self.r.peer_events.len();
        for b in blocks {
            self.r.peer.release(b);
        }
    }

    fn apply(&mut self, s: &Step) {
        let now = self.r.now;
        match *s {
            Step::PeerHeaders { q, fin, info } => {
                let Some(q) = self.peer_q(q) else { return };
                let req = [
                    f(":method", "POST"),
                    f(":scheme", "https"),
                    f(":authority", "example.com"),
                    f(":path", "/p"),
                ];
                let fields: &[FieldRef] = match (self.server, info) {
                    (true, _) => &req,
                    (false, true) => &[f(":status", "103")],
                    (false, false) => &[f(":status", "200")],
                };
                let _ = self.r.peer.send_headers(q, fields, fin);
            }
            Step::PeerBody { q, len, fin } => {
                if let Some(q) = self.peer_q(q) {
                    let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
                    self.r.try_peer_send_body(q, &body, fin);
                }
            }
            Step::PeerFin { q } => {
                if let Some(q) = self.peer_q(q) {
                    self.r.try_peer_send_body(q, &[], true);
                }
            }
            Step::PeerReset { q } => {
                if let Some(q) = self.peer_q(q) {
                    let _ = self.r.peer.abort(q, H3Code::REQUEST_CANCELLED);
                }
            }
            Step::PeerRawReset { q } => {
                if let Some(q) = self.peer_q(q) {
                    self.r.peer_raw_reset(q.0, H3Code::REQUEST_CANCELLED.0);
                }
            }
            Step::PeerStopSending { q } => {
                if let Some(q) = self.peer_q(q) {
                    self.r.peer_stop_sending(q.0, H3Code::REQUEST_CANCELLED.0);
                }
            }
            Step::PeerGoaway { finish } => {
                let _ = if finish {
                    self.r.peer.finish_shutdown()
                } else {
                    self.r.peer.start_shutdown()
                };
            }
            Step::Open => {
                if let Ok(id) = self.r.w.open_h3_request(now, self.r.conn) {
                    self.known.insert(id);
                    self.add(id);
                }
            }
            Step::SendHeaders { r, set, fin } => {
                let Some(id) = self.gw(r).map(|g| g.id) else {
                    return;
                };
                let req = [
                    h(":method", "POST"),
                    h(":scheme", "https"),
                    h(":authority", "example.com"),
                    h(":path", "/"),
                ];
                // Mostly what the gateway sends for its role; also a 103 and a field
                // h3wire refuses.
                let hs: &[H3Header] = match set {
                    0..6 if self.server => &[h(":status", "200")],
                    0..6 => &req,
                    6 => &[h(":status", "103")],
                    _ => &[h(":status", "200"), h("X-Upper", "invalid")],
                };
                let ok = self.r.w.h3_send_headers(now, id, hs, fin).is_ok();
                if let Some(g) = self.gw(r).filter(|_| ok && fin) {
                    g.fin_sent = true;
                }
            }
            Step::SendBody { r, add, fin } => {
                let Some(g) = self.gw(r).filter(|g| !g.fin_sent) else {
                    return;
                };
                let (id, offer) = (g.id, g.pending + add);
                let data: Vec<u8> = (0..offer).map(|i| i as u8).collect();
                let res = self.r.w.h3_send_body(now, id, &data, fin);
                let g = self.gw(r).expect("picked above");
                match res {
                    Ok(n) => {
                        assert!(n <= offer, "accepted {n} of {offer}");
                        g.pending = offer - n;
                        g.fin_sent = fin && n == offer;
                    }
                    Err(StreamError::Blocked) => g.pending = offer,
                    Err(_) => g.pending = 0,
                }
            }
            Step::Finish { r } => {
                let Some(g) = self.gw(r).filter(|g| !g.fin_sent && g.pending == 0) else {
                    return;
                };
                let id = g.id;
                let ok = self.r.w.h3_finish(now, id).is_ok();
                self.gw(r).expect("picked above").fin_sent = ok;
            }
            Step::Reset { r } => {
                if let Some(g) = self.gw(r) {
                    g.done = true;
                    let id = g.id;
                    self.r.w.h3_reset(now, id);
                }
            }
            Step::RecvHeaders { r } => {
                if let Some(id) = self.gw(r).map(|g| g.id) {
                    let res = self.r.w.h3_recv_headers(now, id, &mut |_, _| {});
                    let g = self.gw(r).expect("picked above");
                    g.done |= matches!(res, Ok(true) | Err(StreamError::Reset));
                }
            }
            Step::RecvBody { r, cap } => {
                if let Some(id) = self.gw(r).map(|g| g.id) {
                    let mut buf = vec![0u8; cap];
                    let res = self.r.w.h3_recv_body(now, id, &mut buf);
                    if let Ok((n, _)) = res {
                        assert!(n <= cap);
                    }
                    let g = self.gw(r).expect("picked above");
                    g.done |= matches!(res, Ok((_, true)) | Err(StreamError::Reset));
                }
            }
            Step::Writable { q } => {
                if let Some(s) = self.w_stream(q).filter(|_| !self.r.conn_closed()) {
                    self.r.h.push_event(Event::StreamWritable(s));
                }
            }
            Step::StreamClosed { q } => {
                self.r.relay_aborts();
                let v: Vec<_> = self
                    .r
                    .streams()
                    .into_iter()
                    .filter(|&(q, s)| q % 4 == 0 && self.r.retirable(s))
                    .map(|(_, s)| s)
                    .collect();
                if let Some(s) = pick(&v, q) {
                    self.r.close_stream(s);
                }
            }
            Step::Close { streams_first } => self.close(streams_first),
            Step::Limit { q, cap } => {
                if let Some(s) = self.w_stream(q) {
                    self.r.limit(s, cap);
                }
            }
            Step::Pump => self.pump(),
        }
        self.r.w.drive(now);
        self.r.relay_aborts();
        // `w` closed the conn itself (held above): the transport reports it now, in
        // xquic's order.
        if self.r.w_closed() {
            self.close(true);
        }
    }

    fn close(&mut self, streams_first: bool) {
        if streams_first {
            self.r.close_transport_streams(CLOSE);
        } else {
            self.r.close_transport(CLOSE);
        }
        self.r.w.drive(self.r.now);
    }

    /// Drains `w`'s events, checking the per-request event rules.
    fn events(&mut self) {
        for e in self.r.events() {
            match e {
                Event::H3Request(c, id) => {
                    assert_eq!(c, self.r.conn);
                    assert!(self.known.insert(id), "second H3Request for {id:?}");
                    self.add(id);
                }
                Event::H3Readable(id) | Event::H3Writable(id) => {
                    assert!(self.known.contains(&id), "{e:?} for an unknown request");
                    assert!(!self.closed.contains_key(&id), "{e:?} after H3Closed");
                }
                Event::H3Closed(id, _) => {
                    assert!(self.known.contains(&id), "H3Closed for an unknown request");
                    *self.closed.entry(id).or_default() += 1;
                    assert_eq!(self.closed[&id], 1, "second H3Closed for {id:?}");
                }
                Event::ConnClosed(..) => self.conn_closed += 1,
                _ => {}
            }
        }
        assert!(self.conn_closed <= 1, "ConnClosed twice");
        for g in &self.reqs {
            let gone = g.quic.and_then(|q| self.r.stream_of(q));
            if g.done && gone.is_some_and(|s| self.r.is_closed(s)) {
                assert!(self.closed.contains_key(&g.id), "{:?}: no H3Closed", g.id);
            }
        }
    }

    fn add(&mut self, id: H3ReqId) {
        let quic = self.r.w.h3_req_info(id).ok().map(|i| i.quic_id);
        self.reqs.push(Gw {
            id,
            quic,
            pending: 0,
            fin_sent: false,
            done: false,
        });
    }

    /// The gateway reads every open request to its end.
    fn drain(&mut self) {
        let now = self.r.now;
        for _ in 0..64 {
            let open: Vec<H3ReqId> = self
                .known
                .iter()
                .filter(|id| !self.closed.contains_key(id))
                .copied()
                .collect();
            if open.is_empty() {
                return;
            }
            for id in open {
                let _ = self.r.w.h3_recv_headers(now, id, &mut |_, _| {});
                let mut buf = [0u8; 4096];
                while let Ok((_, false)) = self.r.w.h3_recv_body(now, id, &mut buf) {}
                self.events();
                assert!(self.r.w.debug_bounds_hold(), "bounds after drain");
            }
        }
    }
}

fn run(server: bool, steps: &[Step], streams_first: bool) {
    let mut m = Model::new(server);
    for (i, s) in steps.iter().enumerate() {
        m.apply(s);
        m.events();
        assert!(m.r.w.debug_bounds_hold(), "bounds after step {i}: {s:?}");
    }
    m.close(streams_first);
    m.events();
    m.drain();
    assert_eq!(m.conn_closed, 1, "one ConnClosed");
    for id in &m.known {
        assert_eq!(m.closed.get(id), Some(&1), "{id:?}: one H3Closed");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn random_ops_hold_invariants(
        server in any::<bool>(),
        steps in prop::collection::vec(step(), 0..=64),
        streams_first in any::<bool>(),
    ) {
        run(server, &steps, streams_first);
    }
}
