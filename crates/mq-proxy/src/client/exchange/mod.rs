//! SP4 spec §4: the pull-based H3 exchange core shared by the fetch front and
//! the MITM front. Nothing is buffered here: QUIC flow control is the buffer,
//! and fronts read only what they can take.

pub mod resp;
pub(crate) mod wire;

use mq_http::headers::{HttpVer, Method, Reject, Target, body_check_applies};
use mq_runtime::Cx;
use mq_transport_api::{ConnId, Event, H3Header, H3ReqId, StreamError, Unread};
use resp::{HeadCollector, RespHead};
use std::collections::HashMap;

/// What the request body is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyLen {
    Empty,
    Known(u64),
    Unknown,
}

/// A front-neutral request head. Validated as a whole when rendered
/// (`wire::render`, spec §4.4).
#[derive(Debug)]
pub struct ReqHead {
    /// At most `METHOD_MAX`, case as given; never CONNECT.
    pub method: Method,
    pub target: Target,
    /// `Bearer <token>`.
    pub auth: Vec<u8>,
    /// `x-mq-class`.
    pub class: Option<Vec<u8>>,
    /// Parsed version plus the raw token (the wire carries the token).
    pub origin_proto: Option<(HttpVer, Vec<u8>)>,
    /// Raw valid TTL token (wire identity only).
    pub cache: Option<Vec<u8>>,
    /// Non-empty `X-Mq-Accept-Encoding`.
    pub accept_encoding: Option<Vec<u8>>,
    /// End-to-end headers, filtered by the front.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: BodyLen,
}

/// `read_head` result (SP4 spec §4.3).
#[derive(Debug, PartialEq, Eq)]
pub enum HeadOut {
    Head(RespHead),
    Wait,
    /// `UpstreamReset` or `UpstreamProtocol`; the exchange was removed.
    Fail(Reject),
}

/// `read_body` result (SP4 spec §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyOut {
    /// More than 0 bytes in `buf`; more may follow.
    Data(usize),
    /// The final n ≥ 0 bytes are in `buf`; the exchange completed and was removed.
    Last(usize),
    /// Nothing now; a `Ready::Readable` follows.
    Wait,
    /// After the head; the exchange was removed. The front aborts its side.
    Fail,
}

/// `send_body` result (SP4 spec §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOut {
    Accepted(usize),
    /// Wait for `Ready::Writable`.
    Blocked,
    /// The upload is over; the response is unaffected.
    Done,
}

/// `upload_eof` result (SP4 spec §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofOut {
    Complete,
    /// The exchange was reset and removed.
    Truncated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ready {
    Readable,
    Writable,
}

/// SP4 spec §4.2: the upload side.
enum Up {
    Known { remaining: u64 },
    Streaming,
    Done,
}

/// SP4 spec §4.2: the response side.
enum Down {
    AwaitHead,
    /// `H3Closed` arrived first: rescue or none.
    ClosedBeforeHead(Option<Unread>),
    /// `fin`: the transport fin was observed.
    Body {
        status: u16,
        cl: Option<u64>,
        delivered: u64,
        fin: bool,
    },
    Rescued {
        status: u16,
        cl: Option<u64>,
        delivered: u64,
        body: Vec<u8>,
        off: usize,
    },
    /// The next `read_head` / `read_body` returns `Fail`.
    Failed,
}

struct Exch<O> {
    owner: O,
    /// Body-check exemptions.
    method: Method,
    /// Neither `H3Closed` seen nor reset by the core: `fail()` resets it.
    live: bool,
    up: Up,
    down: Down,
}

/// SP4 spec §4: the client's H3 requests, by id. An exchange that ended is
/// removed, so a stale id is absent.
pub struct Exchanges<O: Copy> {
    by_id: HashMap<H3ReqId, Exch<O>>,
}

impl<O: Copy> Default for Exchanges<O> {
    fn default() -> Self {
        Exchanges {
            by_id: HashMap::new(),
        }
    }
}

impl<O: Copy> Exchanges<O> {
    pub fn new() -> Self {
        Self::default()
    }

    /// SP4 spec §4.3: render and validate the head (`HeaderTooLong`), open
    /// the request on `conn` and send the head, with the FIN iff there is no
    /// body. Any error, `Blocked` included, resets: `TunnelUnavailable`, no
    /// retry (the SP3 rule).
    pub fn open(
        &mut self,
        cx: &mut Cx<'_>,
        conn: ConnId,
        head: &ReqHead,
        owner: O,
    ) -> Result<H3ReqId, Reject> {
        let wire = wire::render(head)?;
        let id = cx
            .open_h3_request(conn)
            .map_err(|_| Reject::TunnelUnavailable)?;
        let up = match head.body {
            BodyLen::Empty | BodyLen::Known(0) => Up::Done,
            BodyLen::Known(remaining) => Up::Known { remaining },
            BodyLen::Unknown => Up::Streaming,
        };
        let hs: Vec<H3Header<'_>> = wire.headers().collect();
        if cx.h3_send_headers(id, &hs, matches!(up, Up::Done)).is_err() {
            cx.h3_reset(id);
            return Err(Reject::TunnelUnavailable);
        }
        let x = Exch {
            owner,
            method: head.method,
            live: true,
            up,
            down: Down::AwaitHead,
        };
        self.by_id.insert(id, x);
        Ok(id)
    }

    /// SP4 spec §4.3: `Known` takes at most `remaining`, the FIN riding the
    /// last byte (the excess is accepted and dropped); `Streaming` passes
    /// `fin` through, a bare FIN being `h3_finish`. `Stale` is `Blocked`: the
    /// queued `H3Closed` ends the upload. `Reset` / `Conn` reset the request
    /// and fail the response. Never removes the exchange.
    pub fn send_body(&mut self, cx: &mut Cx<'_>, id: H3ReqId, data: &[u8], fin: bool) -> SendOut {
        let Some(x) = self.by_id.get_mut(&id) else {
            return SendOut::Done;
        };
        let (data, fin, excess) = match x.up {
            Up::Done => return SendOut::Done,
            Up::Known { remaining } => {
                let take = data
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                (&data[..take], take as u64 == remaining, data.len() - take)
            }
            Up::Streaming => (data, fin, 0),
        };
        if data.is_empty() && !fin {
            return SendOut::Accepted(0);
        }
        let sent = if data.is_empty() {
            cx.h3_finish(id).map(|()| 0)
        } else {
            cx.h3_send_body(id, data, fin)
        };
        match sent {
            Ok(0) if !data.is_empty() => SendOut::Blocked,
            Err(StreamError::Blocked | StreamError::Stale) => SendOut::Blocked,
            Ok(n) => {
                if let Up::Known { remaining } = &mut x.up {
                    *remaining -= n as u64;
                }
                if fin && n == data.len() {
                    x.up = Up::Done;
                    return SendOut::Accepted(n + excess);
                }
                SendOut::Accepted(n)
            }
            Err(StreamError::Reset | StreamError::Conn) => {
                cx.h3_reset(id);
                x.live = false;
                x.up = Up::Done;
                x.down = Down::Failed;
                SendOut::Done
            }
        }
    }

    /// SP4 spec §4.3: the front's read side reached EOF with `buffered` bytes
    /// still to send. Short of a known length, the exchange is reset and
    /// removed; otherwise the tail (or, streaming, the front's FIN) follows.
    pub fn upload_eof(&mut self, cx: &mut Cx<'_>, id: H3ReqId, buffered: u64) -> EofOut {
        match self.by_id.get(&id) {
            Some(Exch {
                up: Up::Known { remaining },
                ..
            }) if buffered < *remaining => {
                self.fail(cx, id);
                EofOut::Truncated
            }
            _ => EofOut::Complete,
        }
    }

    /// SP4 spec §4.3: `h3_reset` if live, then remove; a no-op on an unknown id.
    pub fn reset(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        self.fail(cx, id);
    }

    /// SP4 spec §4.3: readiness goes to the owner; `H3Closed` ends the upload,
    /// moves the response side (rescue or failure) and reads as `Readable`.
    /// Events for unknown ids give `None`.
    pub fn on_event(&mut self, ev: &Event) -> Option<(O, H3ReqId, Ready)> {
        let (id, ready) = match ev {
            Event::H3Readable(id) => (*id, Ready::Readable),
            Event::H3Writable(id) => (*id, Ready::Writable),
            Event::H3Closed(id, close) => {
                let x = self.by_id.get_mut(id)?;
                // The transport already removed the request slot: later ops are `Stale`.
                x.live = false;
                x.up = Up::Done;
                x.down = match std::mem::replace(&mut x.down, Down::Failed) {
                    Down::AwaitHead => Down::ClosedBeforeHead(close.unread.clone()),
                    // `fin: true` keeps `Body`: nothing is rescued after a consumed fin.
                    Down::Body {
                        status,
                        cl,
                        delivered,
                        fin: false,
                    } => match &close.unread {
                        Some(u) => Down::Rescued {
                            status,
                            cl,
                            delivered,
                            body: u.body.clone(),
                            off: 0,
                        },
                        None => Down::Failed,
                    },
                    d => d,
                };
                (*id, Ready::Readable)
            }
            _ => return None,
        };
        Some((self.by_id.get(&id)?.owner, id, ready))
    }

    /// SP4 spec §4.3: settle every exchange whose owner matches (a front
    /// tearing down, shutdown).
    pub fn drain_owner(&mut self, cx: &mut Cx<'_>, mut pred: impl FnMut(&O) -> bool) {
        let ids: Vec<H3ReqId> = (self.by_id.iter())
            .filter(|(_, x)| pred(&x.owner))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.fail(cx, id);
        }
    }

    /// SP4 spec §4.3 `read_head`: collect the head under the §5 limits, from
    /// the transport or from a rescue. `Blocked` / `Stale` wait (a stale
    /// readiness waits for `H3Closed`, SP3-1). A `Fail` removes the exchange.
    /// After `Head` it is a no-op `Wait`.
    pub fn read_head(&mut self, cx: &mut Cx<'_>, id: H3ReqId) -> HeadOut {
        let Some(x) = self.by_id.get_mut(&id) else {
            return HeadOut::Fail(Reject::UpstreamReset);
        };
        let mut col = HeadCollector::default();
        let (head, rescue) = match &mut x.down {
            Down::AwaitHead => match cx.h3_recv_headers(id, &mut |n, v| col.push(n, v)) {
                Ok(fin) => (col.finish(fin), None),
                Err(StreamError::Blocked | StreamError::Stale) => return HeadOut::Wait,
                Err(StreamError::Reset | StreamError::Conn) => {
                    self.fail(cx, id);
                    return HeadOut::Fail(Reject::UpstreamReset);
                }
            },
            Down::ClosedBeforeHead(Some(u)) if u.headers.is_some() => {
                for (n, v) in u.headers.iter().flatten() {
                    col.push(n, v);
                }
                // The end comes from the rescue, through `read_body`.
                (col.finish(false), Some(std::mem::take(&mut u.body)))
            }
            Down::ClosedBeforeHead(_) | Down::Failed => {
                self.fail(cx, id);
                return HeadOut::Fail(Reject::UpstreamReset);
            }
            Down::Body { .. } | Down::Rescued { .. } => return HeadOut::Wait,
        };
        let Ok(head) = head else {
            self.fail(cx, id);
            return HeadOut::Fail(Reject::UpstreamProtocol);
        };
        let (status, cl) = (head.status, head.cl);
        x.down = match rescue {
            None => Down::Body {
                status,
                cl,
                delivered: 0,
                fin: head.fin,
            },
            Some(body) => Down::Rescued {
                status,
                cl,
                delivered: 0,
                body,
                off: 0,
            },
        };
        HeadOut::Head(head)
    }

    /// SP4 spec §4.3 `read_body`: the transport's bytes, or the rescue in
    /// `buf`-sized slices; the read that ends the body goes through the end
    /// rule. An empty `buf` consumes nothing; on a live body it is `Wait`
    /// without a transport call (xquic answers it with EAGAIN, R1). Before
    /// `Head` it is a no-op `Wait`.
    pub fn read_body(&mut self, cx: &mut Cx<'_>, id: H3ReqId, buf: &mut [u8]) -> BodyOut {
        let Some(x) = self.by_id.get_mut(&id) else {
            return BodyOut::Fail;
        };
        let method = x.method;
        let short = |status, cl: Option<u64>, delivered| {
            body_check_applies(&method, status) && cl.is_some_and(|c| delivered < c)
        };
        // `(n, Some(short))` when this read ends the body.
        let (n, end) = match &mut x.down {
            Down::AwaitHead | Down::ClosedBeforeHead(_) => return BodyOut::Wait,
            Down::Failed => {
                self.fail(cx, id);
                return BodyOut::Fail;
            }
            Down::Body {
                status,
                cl,
                delivered,
                fin: true,
            } => (0, Some(short(*status, *cl, *delivered))),
            Down::Body {
                status,
                cl,
                delivered,
                fin: false,
            } => {
                if buf.is_empty() {
                    return BodyOut::Wait;
                }
                match cx.h3_recv_body(id, buf) {
                    Ok((0, false)) | Err(StreamError::Blocked | StreamError::Stale) => {
                        return BodyOut::Wait;
                    }
                    Ok((n, fin)) => {
                        *delivered += n as u64;
                        (n, fin.then(|| short(*status, *cl, *delivered)))
                    }
                    Err(StreamError::Reset | StreamError::Conn) => {
                        self.fail(cx, id);
                        return BodyOut::Fail;
                    }
                }
            }
            Down::Rescued {
                status,
                cl,
                delivered,
                body,
                off,
            } => {
                let n = buf.len().min(body.len() - *off);
                if n == 0 && *off < body.len() {
                    return BodyOut::Wait;
                }
                buf[..n].copy_from_slice(&body[*off..*off + n]);
                *off += n;
                *delivered += n as u64;
                let end = *off == body.len();
                (n, end.then(|| short(*status, *cl, *delivered)))
            }
        };
        match end {
            None => BodyOut::Data(n),
            // End rule 1: xquic's fin does not prove the frame complete
            // (SP3 §3.7); the bytes in `buf` are abandoned.
            Some(true) => {
                self.fail(cx, id);
                BodyOut::Fail
            }
            // End rules 2 and 3: an early response (SP4 spec §4.5) resets the upload;
            // `up != Done` implies live.
            Some(false) => {
                if self
                    .by_id
                    .remove(&id)
                    .is_some_and(|x| !matches!(x.up, Up::Done))
                {
                    cx.h3_reset(id);
                }
                BodyOut::Last(n)
            }
        }
    }

    pub fn contains(&self, id: H3ReqId) -> bool {
        self.by_id.contains_key(&id)
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// SP4 spec §4.3 failure settlement, the one removal path besides the end
    /// rule: `h3_reset` while live, then remove. No owner-less live request
    /// remains.
    fn fail(&mut self, cx: &mut Cx<'_>, id: H3ReqId) {
        if self.by_id.remove(&id).is_some_and(|x| x.live) {
            cx.h3_reset(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_http::headers::{parse_method, parse_target};
    use mq_runtime::Shard;
    use mq_runtime::testing::{Call, RecordingApp, ScriptedHandle, ScriptedTransport};
    use mq_transport_api::{H3Close, H3ReqStats, Time};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, SocketAddr};

    const IDS: usize = 4;

    #[derive(Clone, Debug)]
    enum Op {
        /// The head (with a `content-length` of `len` when `cl`) the first
        /// time, `len` body bytes after; `err` injects a receive `Reset`.
        Readable {
            id: usize,
            len: usize,
            cl: bool,
            fin: bool,
            err: bool,
        },
        Writable(usize),
        Closed {
            id: usize,
            unread: bool,
            headers: bool,
        },
        Send {
            id: usize,
            len: usize,
            fin: bool,
            err: bool,
        },
        Eof {
            id: usize,
            buffered: u64,
        },
        ReadHead(usize),
        ReadBody {
            id: usize,
            cap: usize,
        },
        Reset(usize),
        Drain(u32),
    }

    fn op() -> impl Strategy<Value = Op> {
        let id = 0..IDS;
        prop_oneof![
            (
                id.clone(),
                0..6usize,
                any::<bool>(),
                any::<bool>(),
                prop::bool::weighted(0.1)
            )
                .prop_map(|(id, len, cl, fin, err)| Op::Readable {
                    id,
                    len,
                    cl,
                    fin,
                    err
                }),
            id.clone().prop_map(Op::Writable),
            (id.clone(), any::<bool>(), any::<bool>()).prop_map(|(id, unread, headers)| {
                Op::Closed {
                    id,
                    unread,
                    headers,
                }
            }),
            (
                id.clone(),
                0..4usize,
                any::<bool>(),
                prop::bool::weighted(0.1)
            )
                .prop_map(|(id, len, fin, err)| Op::Send { id, len, fin, err }),
            (id.clone(), 0..6u64).prop_map(|(id, buffered)| Op::Eof { id, buffered }),
            id.clone().prop_map(Op::ReadHead),
            (id.clone(), 0..5usize).prop_map(|(id, cap)| Op::ReadBody { id, cap }),
            id.prop_map(Op::Reset),
            (0..3u32).prop_map(Op::Drain),
        ]
    }

    fn req_head() -> impl Strategy<Value = (&'static str, BodyLen)> {
        let body = prop_oneof![
            Just(BodyLen::Empty),
            (0..6u64).prop_map(BodyLen::Known),
            Just(BodyLen::Unknown),
        ];
        (prop::sample::select(vec!["GET", "HEAD", "POST"]), body)
    }

    /// The reference model of one id (SP4 spec §4.2/§4.3 settlement).
    #[derive(Default)]
    struct M {
        removed: bool,
        closed: bool,
        head: bool,
        head_injected: bool,
        fin_injected: bool,
        /// `h3_reset`s logged when it was removed / closed: none may follow.
        resets_frozen: Option<usize>,
    }

    fn close(unread: Option<Unread>) -> H3Close {
        let stats = H3ReqStats {
            send_body: 0,
            recv_body: 0,
            begin_us: 0,
            header_send_us: 0,
            fin_send_us: 0,
            fin_ack_us: 0,
            mp_state: 0,
            stream_err: 0,
            close_msg: None,
        };
        H3Close { stats, unread }
    }

    fn resets(t: &ScriptedHandle, r: H3ReqId) -> usize {
        t.log().iter().filter(|c| **c == Call::H3Reset(r)).count()
    }

    fn hs(pairs: &[(&str, String)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.clone().into_bytes()))
            .collect()
    }

    proptest! {
        #[test]
        fn settlement_matches_model(
            heads in prop::collection::vec(req_head(), IDS),
            ops in prop::collection::vec(op(), 0..48),
        ) {
            let (transport, t) = ScriptedTransport::new();
            let conn = t.new_conn_id();
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let mut sh = Shard::new(transport, RecordingApp::new().0, addr, 7);
            let now = Time::from_micros(1_000_000);
            sh.start(now);
            let mut ex = Exchanges::<u32>::new();
            let owner = |i: usize| (i % 2) as u32;
            let mut ids = Vec::new();
            for (i, (method, body)) in heads.iter().enumerate() {
                let head = ReqHead {
                    method: parse_method(method.as_bytes()).unwrap(),
                    target: parse_target(b"https://example.com/p").unwrap(),
                    auth: b"Bearer t".to_vec(),
                    class: None,
                    origin_proto: None,
                    cache: None,
                    accept_encoding: None,
                    headers: vec![],
                    body: *body,
                };
                let r = sh.with_app(now, |_, cx| ex.open(cx, conn, &head, owner(i)));
                ids.push(r.unwrap());
            }
            let mut m: Vec<M> = (0..IDS).map(|_| M::default()).collect();

            for op in ops {
                let calls = t.log().len();
                // The ids this op removes, by the model.
                let mut gone: Vec<usize> = Vec::new();
                match op {
                    Op::Readable { id, len, cl, fin, err } => {
                        let (r, s) = (ids[id], &mut m[id]);
                        if err {
                            t.inject_h3_error(r, StreamError::Reset);
                        } else if !s.head_injected {
                            let mut h = vec![(":status", "200".to_owned())];
                            if cl {
                                h.push(("content-length", len.to_string()));
                            }
                            t.inject_h3_headers(r, hs(&h), fin);
                            s.head_injected = true;
                            s.fin_injected = fin;
                        } else if !s.fin_injected {
                            t.inject_h3_body(r, vec![b'x'; len], fin);
                            s.fin_injected = fin;
                        }
                        let got = ex.on_event(&Event::H3Readable(r));
                        let want = (!s.removed).then_some((owner(id), r, Ready::Readable));
                        prop_assert_eq!(got, want);
                    }
                    Op::Writable(id) => {
                        let r = ids[id];
                        let got = ex.on_event(&Event::H3Writable(r));
                        let want = (!m[id].removed).then_some((owner(id), r, Ready::Writable));
                        prop_assert_eq!(got, want);
                    }
                    Op::Closed { id, unread, headers } => {
                        let (r, s) = (ids[id], &mut m[id]);
                        if !s.closed {
                            s.closed = true;
                            let u = unread.then(|| Unread {
                                headers: headers.then(|| hs(&[(":status", "200".to_owned())])),
                                body: b"xyz".to_vec(),
                            });
                            t.close_h3(r, close(u.clone()));
                            let got = ex.on_event(&Event::H3Closed(r, Box::new(close(u))));
                            let want = (!s.removed).then_some((owner(id), r, Ready::Readable));
                            prop_assert_eq!(got, want);
                        }
                    }
                    Op::Send { id, len, fin, err } => {
                        let r = ids[id];
                        if err {
                            t.expect_h3_send_body(r, Err(StreamError::Reset));
                        }
                        let data = vec![b'u'; len];
                        let got = sh.with_app(now, |_, cx| ex.send_body(cx, r, &data, fin));
                        if m[id].removed {
                            prop_assert_eq!(got, SendOut::Done);
                        }
                    }
                    Op::Eof { id, buffered } => {
                        let r = ids[id];
                        let got = sh.with_app(now, |_, cx| ex.upload_eof(cx, r, buffered));
                        if got == EofOut::Truncated {
                            prop_assert!(!m[id].removed);
                            gone.push(id);
                        }
                    }
                    Op::ReadHead(id) => {
                        let r = ids[id];
                        let got = sh.with_app(now, |_, cx| ex.read_head(cx, r));
                        let s = &mut m[id];
                        let quiet = s.head || s.removed;
                        match got {
                            HeadOut::Head(_) => {
                                prop_assert!(!s.removed && !s.head);
                                s.head = true;
                            }
                            HeadOut::Wait => prop_assert!(!s.removed),
                            HeadOut::Fail(e) => {
                                // After the head only `Failed` (or a stale id) fails it.
                                let want = if quiet {
                                    e == Reject::UpstreamReset
                                } else {
                                    matches!(e, Reject::UpstreamReset | Reject::UpstreamProtocol)
                                };
                                prop_assert!(want, "{:?}", e);
                                if !s.removed {
                                    gone.push(id);
                                }
                            }
                        }
                        if quiet {
                            // A no-op after the head; a stale id makes no transport call.
                            prop_assert_eq!(t.log().len(), calls);
                        }
                    }
                    Op::ReadBody { id, cap } => {
                        let r = ids[id];
                        let mut buf = vec![0u8; cap];
                        let got = sh.with_app(now, |_, cx| ex.read_body(cx, r, &mut buf));
                        let s = &m[id];
                        match got {
                            BodyOut::Data(n) => prop_assert!(s.head && n > 0 && n <= cap),
                            BodyOut::Last(n) => {
                                prop_assert!(s.head && !s.removed && n <= cap);
                                gone.push(id);
                            }
                            BodyOut::Wait => prop_assert!(!s.removed),
                            // `Failed` fails either read, before the head too.
                            BodyOut::Fail => {
                                if !s.removed {
                                    gone.push(id);
                                }
                            }
                        }
                        if s.removed || !s.head || cap == 0 {
                            // Stale, before the head, or an empty probe: no h3_recv_body.
                            let recv = t.log()[calls..]
                                .iter()
                                .any(|c| matches!(c, Call::H3RecvBody { .. }));
                            prop_assert!(!recv);
                        }
                    }
                    Op::Reset(id) => {
                        let r = ids[id];
                        sh.with_app(now, |_, cx| ex.reset(cx, r));
                        if !m[id].removed {
                            gone.push(id);
                        }
                    }
                    Op::Drain(o) => {
                        sh.with_app(now, |_, cx| ex.drain_owner(cx, |x| *x == o));
                        gone.extend((0..IDS).filter(|&i| owner(i) == o && !m[i].removed));
                    }
                }
                for i in gone {
                    m[i].removed = true;
                }
                for (i, s) in m.iter_mut().enumerate() {
                    let n = resets(&t, ids[i]);
                    prop_assert!(n <= 1, "id {} reset {} times", i, n);
                    prop_assert_eq!(ex.contains(ids[i]), !s.removed, "id {}", i);
                    if let Some(frozen) = s.resets_frozen {
                        prop_assert_eq!(n, frozen, "a reset after removal or H3Closed, id {}", i);
                    } else if s.removed || s.closed {
                        s.resets_frozen = Some(n);
                    }
                }
            }
            sh.with_app(now, |_, cx| ex.drain_owner(cx, |_| true));
            prop_assert_eq!(ex.len(), 0);
            for (i, s) in m.iter().enumerate() {
                let n = resets(&t, ids[i]);
                prop_assert!(n <= 1);
                if let Some(frozen) = s.resets_frozen {
                    prop_assert_eq!(n, frozen);
                }
            }
        }
    }
}
