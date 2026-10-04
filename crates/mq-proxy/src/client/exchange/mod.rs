//! SP4 spec §4: the pull-based H3 exchange core shared by the fetch front and
//! the MITM front. Nothing is buffered here: QUIC flow control is the buffer,
//! and fronts read only what they can take.

pub mod resp;
pub(crate) mod wire;

use mq_http::headers::{HttpVer, Method, Reject, Target};
use mq_runtime::Cx;
use mq_transport_api::{ConnId, Event, H3Header, H3ReqId, StreamError, Unread};
use resp::RespHead;
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
#[expect(
    dead_code,
    reason = "built and read by read_head / read_body, Task 4.3"
)]
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
    #[expect(dead_code, reason = "the end rule, Task 4.3")]
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

    /// SP4 spec §4.3 `read_head`; implemented in Task 4.3.
    pub fn read_head(&mut self, _cx: &mut Cx<'_>, _id: H3ReqId) -> HeadOut {
        HeadOut::Wait
    }

    /// SP4 spec §4.3 `read_body`; implemented in Task 4.3.
    pub fn read_body(&mut self, _cx: &mut Cx<'_>, _id: H3ReqId, _buf: &mut [u8]) -> BodyOut {
        BodyOut::Wait
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
