//! spec §6.3: the client's UDP sessions — sid allocation, the 1024 cap, the
//! `PendingAuth` queue, the optimistic OPEN and both datagram paths; spec §6.4
//! the session stream's RESP and every session end.

use super::{Client, Tm, UdpAvail};
use crate::app_stream::{self, CHUNK, Recv};
use crate::udp::defrag::{Defrag, Feed};
use crate::udp::send::{MssCache, send_packet};
use crate::udp::socks5udp::{self, Dst};
use crate::udp::{
    Counters, MAX_SESSIONS_PER_CONN, NEG_CACHE, PREAUTH_SENDQ_BYTES, PREAUTH_SENDQ_DGRAMS,
    SESSION_RESP_WAIT, SessionEnd, UDP_MSG_HDR,
};
use mq_runtime::{Cx, Target, TcpId, TimerId};
use mq_transport_api::{ConnId, Error, StreamId};
use mq_wire::frames::{
    DecodeError, MAX_FRAME, STREAM_TYPE_UDP_SESSION, UdpSessionOpen, UdpSessionResp,
};
use mq_wire::udp_msg::UdpMsgHdr;
use std::collections::{BTreeMap, HashMap, VecDeque};

/// The largest UDP datagram: the receive scratch, and the bound of a reply.
const MAX_DGRAM: usize = 65_535;

enum Phase {
    /// Opened while UDP is `Unknown`: datagrams wait for auth, at most 8 / 8 KiB.
    PendingAuth { queue: VecDeque<Vec<u8>> },
    /// OPEN sent; its RESP (`rx`, the bytes so far) is due before `deadline`
    /// (spec §5 `SESSION_RESP_WAIT`).
    AwaitResp { deadline: TimerId, rx: Vec<u8> },
    /// RESP OK: stream bytes are discarded (spec §6.4).
    Open,
}

struct Session {
    assoc: TcpId,
    target: Target,
    /// `None` while `PendingAuth`.
    stream: Option<StreamId>,
    /// Unsent rest of the type byte + `UDP_SESSION_OPEN`.
    tx: Vec<u8>,
    phase: Phase,
    defrag: Defrag,
    packet_id: u16,
}

/// spec §6.3: the session table of the client (one connection at a time).
pub(super) struct Sessions {
    /// Per client: it survives connections, as C `next_sid`.
    next_sid: u32,
    /// By sid; ordered, so a post-auth flush runs in sid order (creation
    /// order until the counter wraps).
    by_sid: BTreeMap<u32, Session>,
    pub(super) by_stream: HashMap<StreamId, u32>,
    mss: MssCache,
    pub(super) counters: Counters,
    /// `datagram_recv` scratch, `MAX_DGRAM` once used.
    rx: Vec<u8>,
}

impl Sessions {
    pub(super) fn new() -> Sessions {
        Sessions {
            next_sid: 1, // as C: 0 is valid, 1 reads better in logs
            by_sid: BTreeMap::new(),
            by_stream: HashMap::new(),
            mss: MssCache::new(),
            counters: Counters::default(),
            rx: Vec::new(),
        }
    }
}

/// spec §6.3: the next sid not `live`; the counter wraps.
fn alloc_sid(next: &mut u32, live: impl Fn(u32) -> bool) -> u32 {
    loop {
        let sid = *next;
        *next = next.wrapping_add(1);
        if !live(sid) {
            return sid;
        }
    }
}

/// spec §6.3: C `cli_sendq_push` — an item over 8 KiB on its own is dropped,
/// otherwise the oldest go until both bounds hold; each loss is one `sendq_evictions`.
fn enqueue(q: &mut VecDeque<Vec<u8>>, p: &[u8], c: &mut Counters) {
    if p.len() > PREAUTH_SENDQ_BYTES {
        c.sendq_evictions += 1;
        return;
    }
    let mut bytes: usize = q.iter().map(Vec::len).sum();
    while q.len() >= PREAUTH_SENDQ_DGRAMS || bytes + p.len() > PREAUTH_SENDQ_BYTES {
        bytes -= q.pop_front().expect("non-empty while over a bound").len();
        c.sendq_evictions += 1;
    }
    q.push_back(p.to_vec());
}

/// spec §6.3: stream type `0x02` then `UDP_SESSION_OPEN` for `dst` with
/// `idle_timeout_ms = 0` (the server default), as C `mq_udp_cli_open`.
fn open_request(sid: u32, dst: &Dst<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; MAX_FRAME];
    buf[0] = STREAM_TYPE_UDP_SESSION as u8;
    let n = UdpSessionOpen {
        session_id: sid,
        flags: 0,
        address_type: dst.atype,
        host: dst.addr,
        port: dst.port,
        idle_timeout_ms: 0,
    }
    .encode(&mut buf[1..])
    .expect("a SOCKS5 address fits 512 bytes");
    buf.truncate(1 + n);
    buf
}

impl Client {
    /// spec §6.3 Outbound: a datagram from the client of association `tcp`,
    /// source checked: DST lookup (or open), then the tunnel.
    pub(super) fn udp_outbound(&mut self, cx: &mut Cx<'_>, tcp: TcpId, d: &[u8]) {
        let Some((dst, off)) = socks5udp::parse(d) else {
            return;
        };
        let Some(target) = socks5udp::target_of(&dst) else {
            return;
        };
        let (payload, now) = (&d[off..], cx.now());
        let a = self.assocs.get_mut(&tcp).expect("the caller found it");
        match a.dsts.get(&target).map(|e| (e.session, e.failed_at)) {
            Some((Some(sid), _)) => return self.session_send(cx, sid, payload),
            // spec §6.3: the negative cache.
            Some((None, Some(f))) if now - f < NEG_CACHE => return,
            _ => {}
        }
        if self.sess.by_sid.len() >= MAX_SESSIONS_PER_CONN {
            return; // spec §6.3: no OPEN past 1024 sessions
        }
        if !a.dsts.contains_key(&target) {
            let mut reply_hdr = Vec::new();
            socks5udp::build(&mut reply_hdr, &dst);
            if a.insert_dst(target.clone(), reply_hdr, now).is_none() {
                return; // spec §6.3: 64 DSTs, none reclaimable
            }
        }
        let sess = &mut self.sess;
        let sid = alloc_sid(&mut sess.next_sid, |s| sess.by_sid.contains_key(&s));
        let e = a.dsts.get_mut(&target).expect("present");
        (e.session, e.failed_at) = (Some(sid), None);
        let s = Session {
            assoc: tcp,
            target,
            stream: None,
            tx: open_request(sid, &dst),
            phase: Phase::PendingAuth {
                queue: VecDeque::new(),
            },
            defrag: Defrag::new(),
            packet_id: 0,
        };
        self.sess.by_sid.insert(sid, s);
        // spec §6.3: the triggering datagram goes out at once (optimistic send).
        if self.udp == UdpAvail::Available && !self.issue(cx, sid) {
            return;
        }
        self.session_send(cx, sid, payload);
    }

    /// spec §6.3/§5: queue while `PendingAuth`, else split onto the tunnel
    /// under the fragment send policy; `packet_id` moves iff the split ran (C).
    fn session_send(&mut self, cx: &mut Cx<'_>, sid: u32, payload: &[u8]) {
        let Sessions {
            by_sid,
            mss,
            counters: c,
            ..
        } = &mut self.sess;
        let Some(s) = by_sid.get_mut(&sid) else {
            return;
        };
        if let Phase::PendingAuth { queue } = &mut s.phase {
            return enqueue(queue, payload, c);
        }
        let Some(conn) = &self.conn else {
            return; // issued sessions end with their connection (spec §6.4)
        };
        let out = send_packet(cx, conn.id, mss, sid, s.packet_id, payload, c);
        if out.frags_ok + out.failed > 0 {
            s.packet_id = s.packet_id.wrapping_add(1);
        }
    }

    /// spec §6.3: open the session's stream, write the OPEN (an unaccepted
    /// tail waits for `StreamWritable`), arm the RESP deadline, flush the
    /// `PendingAuth` queue in order. `false` when the open failed and the
    /// session ended (spec §6.4 "Local open failure").
    fn issue(&mut self, cx: &mut Cx<'_>, sid: u32) -> bool {
        let r = match &self.conn {
            Some(c) => cx.open_stream(c.id),
            None => Err(Error::Stale),
        };
        let st = match r {
            Ok(st) => st,
            Err(e) => {
                log::warn!("mq_udp_cli: open 0x02 stream failed ({e})");
                self.end_session(cx, sid, SessionEnd::Closed, true);
                return false;
            }
        };
        let s = self.sess.by_sid.get_mut(&sid).expect("live");
        s.stream = Some(st);
        self.sess.by_stream.insert(st, sid);
        if !app_stream::flush(cx, st, &mut s.tx, false) {
            log::warn!("mq_udp_cli: send UDP_SESSION_OPEN failed");
            self.end_session(cx, sid, SessionEnd::Closed, true);
            return false;
        }
        let deadline = self.timer(cx, SESSION_RESP_WAIT, Tm::UdpResp(sid));
        let s = self.sess.by_sid.get_mut(&sid).expect("live");
        let rx = Vec::new();
        let queued = match std::mem::replace(&mut s.phase, Phase::AwaitResp { deadline, rx }) {
            Phase::PendingAuth { queue } => queue,
            _ => VecDeque::new(),
        };
        for p in queued {
            self.session_send(cx, sid, &p);
        }
        true
    }

    /// spec §6.2/§6.3: UDP became `Available` on a new connection: every
    /// `PendingAuth` session opens and flushes; one that fails is dropped
    /// and the flush goes on.
    pub(super) fn udp_available(&mut self, cx: &mut Cx<'_>) {
        self.sess.mss.invalidate(); // one reading per connection (spec §5)
        let pending: Vec<u32> = self
            .sess
            .by_sid
            .iter()
            .filter(|(_, s)| matches!(s.phase, Phase::PendingAuth { .. }))
            .map(|(&sid, _)| sid)
            .collect();
        for sid in pending {
            self.issue(cx, sid);
        }
    }

    /// spec §6.3: the rest of an OPEN on `StreamWritable`; a hard error ends
    /// the session (spec §6.4 "Local open failure").
    pub(super) fn session_writable(&mut self, cx: &mut Cx<'_>, st: StreamId) {
        let sid = self.sess.by_stream[&st];
        let tx = &mut self.sess.by_sid.get_mut(&sid).expect("mirrored").tx;
        if !app_stream::flush(cx, st, tx, false) {
            log::warn!("mq_udp_cli: send UDP_SESSION_OPEN failed");
            self.end_session(cx, sid, SessionEnd::Closed, true);
        }
    }

    /// spec §5/§6.4: read a session stream until `Blocked`, FIN or reset; each
    /// read is its bytes, then its FIN. `AwaitResp` collects the RESP, `Open`
    /// discards.
    pub(super) fn session_readable(&mut self, cx: &mut Cx<'_>, st: StreamId) {
        let sid = self.sess.by_stream[&st];
        let mut scratch = Vec::with_capacity(CHUNK);
        let (end, live) = loop {
            let s = self.sess.by_sid.get_mut(&sid).expect("mirrored");
            let buf = match &mut s.phase {
                Phase::AwaitResp { rx, .. } => rx,
                _ => {
                    scratch.clear();
                    &mut scratch
                }
            };
            let fin = match app_stream::recv(cx, st, buf, CHUNK) {
                Recv::Data { n: 0, fin: false } | Recv::Blocked => return,
                Recv::Data { fin, .. } => fin,
                Recv::Failed => break (SessionEnd::Closed, false), // `recv` reset it
            };
            let Phase::AwaitResp { deadline, rx } = &s.phase else {
                if fin {
                    break (SessionEnd::Closed, true); // defensive: neither server sends one
                }
                continue;
            };
            let deadline = *deadline;
            match UdpSessionResp::decode(rx) {
                Err(DecodeError::Short) if !fin && rx.len() < MAX_FRAME => {}
                // With a FIN in the same read the server has already ended it.
                Ok((r, used)) if r.is_ok() && used <= MAX_FRAME && !fin => {
                    let idle = r.idle_timeout_ms;
                    log::debug!("mq_udp_cli: session {sid} open (server idle {idle} ms)");
                    s.phase = Phase::Open;
                    self.cancel(cx, deadline);
                }
                Ok((r, used)) if !r.is_ok() && used <= MAX_FRAME => {
                    let end = r.error().map_or(SessionEnd::Closed, SessionEnd::Refused);
                    break (end, true);
                }
                // Malformed or over 512 bytes, OK with FIN, or FIN before a RESP.
                _ => break (SessionEnd::Closed, true),
            }
        };
        self.end_session(cx, sid, end, live);
    }

    /// spec §5/§6.4: every session end — cancel the deadline, clear the DST's
    /// session (the entry stays; a refusal sets its `failed_at`), reset the
    /// stream if the facade still holds it (`live`) and forget it.
    pub(super) fn end_session(&mut self, cx: &mut Cx<'_>, sid: u32, end: SessionEnd, live: bool) {
        let Some(s) = self.sess.by_sid.remove(&sid) else {
            return;
        };
        log::debug!("mq_udp_cli: session {sid} ended ({end:?})");
        if let Phase::AwaitResp { deadline, .. } = s.phase {
            self.cancel(cx, deadline);
        }
        let a = self.assocs.get_mut(&s.assoc);
        if let Some(e) = a.and_then(|a| a.dsts.get_mut(&s.target)) {
            e.session = None;
            if let SessionEnd::Refused(_) = end {
                e.failed_at = Some(cx.now());
            }
        }
        if let Some(st) = s.stream {
            self.sess.by_stream.remove(&st);
            if live {
                cx.stream_reset(st);
            }
        }
    }

    /// spec §6.1/§6.4: an association ends locally: its sessions end
    /// `Closed`, their streams reset, and its UDP socket goes.
    pub(super) fn end_assoc(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let Some(a) = self.assocs.remove(&tcp) else {
            return;
        };
        a.release(cx);
        for sid in a.dsts.values().filter_map(|e| e.session) {
            self.end_session(cx, sid, SessionEnd::Closed, true);
        }
    }

    /// spec §6.4: the connection is gone with its streams; every session
    /// ends `Closed`, `PendingAuth` ones included. Associations stay.
    pub(super) fn udp_conn_gone(&mut self, cx: &mut Cx<'_>) {
        let all: Vec<u32> = self.sess.by_sid.keys().copied().collect();
        for sid in all {
            self.end_session(cx, sid, SessionEnd::Closed, false);
        }
    }

    /// spec §6.3 Inbound: drain the connection's datagrams to the associations.
    pub(super) fn udp_inbound(&mut self, cx: &mut Cx<'_>, conn: ConnId) {
        let mut buf = std::mem::take(&mut self.sess.rx);
        buf.resize(MAX_DGRAM, 0);
        while let Some(n) = cx.datagram_recv(conn, &mut buf) {
            self.deliver(cx, &buf[..n]);
        }
        self.sess.rx = buf;
    }

    /// spec §6.3 Inbound: one tunnel datagram → defrag → `build(dst) || payload`
    /// to the learned source.
    fn deliver(&mut self, cx: &mut Cx<'_>, d: &[u8]) {
        let Some(h) = UdpMsgHdr::decode(d) else {
            return; // short: silent, as C
        };
        let c = &mut self.sess.counters;
        let Some(s) = self.sess.by_sid.get_mut(&h.session_id) else {
            c.drops_unknown_sid += 1;
            return;
        };
        let p = match s.defrag.feed(&h, &d[UDP_MSG_HDR..]) {
            Feed::Complete(p) => p,
            Feed::Pending => return,
            Feed::Rejected => {
                c.defrag_drops += 1;
                return;
            }
        };
        if h.frag_count > 1 {
            c.frags_reassembled += 1;
        }
        let Some(a) = self.assocs.get(&s.assoc) else {
            return;
        };
        let Some(e) = a.dsts.get(&s.target) else {
            return;
        };
        if e.dst_bytes.len() + p.len() > MAX_DGRAM {
            c.drops_oversize += 1;
            return;
        }
        let (Some(sock), Some(to)) = (a.sock, a.learned) else {
            return;
        };
        let reply = [&e.dst_bytes[..], &p].concat();
        if cx.udp_send(sock, to, &reply).is_err() {
            c.drops_send_fail += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sid_alloc_wrap_skips_live() {
        let mut live = HashSet::from([u32::MAX, 0]);
        let mut next = u32::MAX - 1;
        let mut alloc = || {
            let sid = alloc_sid(&mut next, |s| live.contains(&s));
            live.insert(sid);
            sid
        };
        assert_eq!(alloc(), u32::MAX - 1);
        assert_eq!(alloc(), 1, "u32::MAX and 0 are live");
    }
}
