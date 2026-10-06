//! H3 test apps (spec §10.3): an echo server with fault modes and a scripted client. Both run
//! on a `DriverThread`, where an app can be neither commanded nor inspected, so their scripts
//! are fixed at spawn and their observations come back through an `H3Handle`.

use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, SocketOpId, TcpEnd, TcpId, TimerId,
    UdpSocketId,
};
use mq_transport_api::{ConnConfig, ConnProto, Event, H3Close, H3Header, H3ReqId};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

/// What an app observed.
#[derive(Debug, Default)]
pub struct H3Recorded {
    /// Server: `H3Request`s seen.
    pub requests: usize,
    /// Client: what the app read itself (`h3_recv_headers` / `h3_recv_body`), and its fin.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
    pub fin: bool,
    /// Server: the request header sections it read itself, in arrival order.
    pub request_headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Every `H3Closed`, with its arrival time.
    pub closed: Vec<(H3Close, Instant)>,
}

/// `Clone + Send` view of an app's `H3Recorded`.
#[derive(Clone, Debug, Default)]
pub struct H3Handle(Arc<Mutex<H3Recorded>>);

impl H3Handle {
    pub fn lock(&self) -> MutexGuard<'_, H3Recorded> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Reads the pending header section and body of `r`; `true` on fin.
fn read_all(
    cx: &mut Cx<'_>,
    r: H3ReqId,
    headers: &mut Vec<(Vec<u8>, Vec<u8>)>,
    body: &mut Vec<u8>,
) -> bool {
    let mut each = |n: &[u8], v: &[u8]| headers.push((n.to_vec(), v.to_vec()));
    let mut fin = cx.h3_recv_headers(r, &mut each) == Ok(true);
    let mut buf = vec![0u8; 64 * 1024];
    while !fin {
        match cx.h3_recv_body(r, &mut buf) {
            Ok((n, f)) => {
                body.extend_from_slice(&buf[..n]);
                fin = f;
            }
            Err(_) => break,
        }
    }
    fin
}

/// Sends `data[*sent..]` (+ `fin`, committed with the last byte); the rest waits for
/// `H3Writable`.
fn push(cx: &mut Cx<'_>, r: H3ReqId, data: &[u8], sent: &mut usize, fin: bool) {
    if let Ok(n) = cx.h3_send_body(r, &data[*sent..], fin) {
        *sent += n;
    }
}

fn hdrs(hs: &[(String, String)]) -> Vec<H3Header<'_>> {
    hs.iter()
        .map(|(n, v)| H3Header {
            name: n.as_bytes(),
            value: v.as_bytes(),
        })
        .collect()
}

/// The `App` callbacks the H3 apps ignore.
macro_rules! no_io {
    () => {
        fn on_accepted(&mut self, _: &mut Cx<'_>, _: ListenerTag, _: TcpId, _: AcceptMeta) {}
        fn on_tcp_data(&mut self, _: &mut Cx<'_>, _: TcpId) {}
        fn on_tcp_end(&mut self, _: &mut Cx<'_>, _: TcpId, _: TcpEnd) {}
        fn on_dial_result(&mut self, _: &mut Cx<'_>, _: DialOpId, _: Result<TcpId, DialError>) {}
        fn on_resolve_result(
            &mut self,
            _: &mut Cx<'_>,
            _: DialOpId,
            _: Result<SocketAddr, DialError>,
        ) {
        }
        fn on_udp_socket(
            &mut self,
            _: &mut Cx<'_>,
            _: SocketOpId,
            _: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
        ) {
        }
        fn on_udp_rx(&mut self, _: &mut Cx<'_>, _: UdpSocketId, _: SocketAddr, _: &[u8]) {}
        fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
            cx.request_exit(0);
        }
    };
}
pub(crate) use no_io;

/// How `H3EchoServer` answers a fully read request (every answer has `:status 200`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EchoMode {
    /// The request body + FIN.
    #[default]
    Echo,
    /// `content-length: cl` over a complete `sent`-byte DATA frame + FIN.
    ShortCl { cl: u64, sent: usize },
}

#[derive(Default)]
struct EchoReq {
    body: Vec<u8>,
    resp: Vec<u8>,
    sent: usize,
    fin: bool,
    responding: bool,
}

/// An `App` that answers every `H3Request` per its `EchoMode`.
pub struct H3EchoServer {
    mode: EchoMode,
    /// Added to every response head after `:status`.
    resp_headers: Vec<(String, String)>,
    h: H3Handle,
    reqs: HashMap<H3ReqId, EchoReq>,
}

impl H3EchoServer {
    pub fn new(mode: EchoMode) -> (H3EchoServer, H3Handle) {
        let h = H3Handle::default();
        let app = H3EchoServer {
            mode,
            resp_headers: Vec::new(),
            h: h.clone(),
            reqs: HashMap::new(),
        };
        (app, h)
    }

    /// Extra response headers (e.g. a section larger than xquic's old 32 KiB default).
    pub fn with_response_headers(mut self, hs: Vec<(String, String)>) -> H3EchoServer {
        self.resp_headers = hs;
        self
    }

    fn respond(&mut self, cx: &mut Cx<'_>, r: H3ReqId) {
        let Some(q) = self.reqs.get_mut(&r) else {
            return;
        };
        q.responding = true;
        let mut hs = vec![(":status".to_owned(), "200".to_owned())];
        hs.extend(self.resp_headers.iter().cloned());
        let cl = |n: u64| ("content-length".to_owned(), n.to_string());
        match self.mode {
            EchoMode::Echo => (q.resp, q.fin) = (std::mem::take(&mut q.body), true),
            EchoMode::ShortCl { cl: n, sent } => {
                hs.push(cl(n));
                (q.resp, q.fin) = (vec![b'x'; sent], true);
            }
        }
        let _ = cx.h3_send_headers(r, &hdrs(&hs), q.fin && q.resp.is_empty());
        if !q.resp.is_empty() {
            push(cx, r, &q.resp, &mut q.sent, q.fin);
        }
    }
}

impl App for H3EchoServer {
    fn on_timer(&mut self, _: &mut Cx<'_>, _: TimerId) {}
    fn on_start(&mut self, _: &mut Cx<'_>) {}

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::H3Request(_, r) => {
                let q = EchoReq::default();
                self.reqs.insert(r, q);
                self.h.lock().requests += 1;
            }
            Event::H3Readable(r) => {
                let done = match self.reqs.get_mut(&r) {
                    Some(q) if !q.responding => {
                        let mut rec = self.h.lock();
                        read_all(cx, r, &mut rec.request_headers, &mut q.body)
                    }
                    _ => false,
                };
                if done {
                    self.respond(cx, r);
                }
            }
            Event::H3Writable(r) => {
                if let Some(q) = self.reqs.get_mut(&r).filter(|q| q.responding)
                    && q.sent < q.resp.len()
                {
                    push(cx, r, &q.resp, &mut q.sent, q.fin);
                }
            }
            Event::H3Closed(r, close) => {
                self.reqs.remove(&r);
                self.h.lock().closed.push((*close, Instant::now()));
            }
            _ => {}
        }
    }

    no_io!();
}

/// `H3Client`'s script.
#[derive(Clone, Debug, Default)]
pub struct H3Script {
    pub headers: Vec<(String, String)>,
    /// Sent with FIN (on the headers when empty).
    pub body: Vec<u8>,
}

/// An `App` that connects (H3) to `peer` on start, sends its one scripted request once the
/// connection is established and records the response.
pub struct H3Client {
    peer: SocketAddr,
    s: H3Script,
    h: H3Handle,
    req: Option<H3ReqId>,
    sent: usize,
}

impl H3Client {
    pub fn new(peer: SocketAddr, s: H3Script) -> (H3Client, H3Handle) {
        let h = H3Handle::default();
        let app = H3Client {
            peer,
            s,
            h: h.clone(),
            req: None,
            sent: 0,
        };
        (app, h)
    }

    fn send(&mut self, cx: &mut Cx<'_>, r: H3ReqId) {
        if self.sent == self.s.body.len() {
            return;
        }
        push(cx, r, &self.s.body, &mut self.sent, true);
    }

    fn read(&mut self, cx: &mut Cx<'_>, r: H3ReqId) {
        let mut rec = self.h.lock();
        let rec = &mut *rec;
        rec.fin |= read_all(cx, r, &mut rec.headers, &mut rec.body);
    }
}

impl App for H3Client {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        let cfg = ConnConfig {
            peer: self.peer,
            sni: "mqproxy",
            idle_timeout: None,
            proto: ConnProto::H3,
        };
        cx.connect(&cfg).expect("connect");
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::ConnEstablished(c) if self.req.is_none() => {
                let r = cx.open_h3_request(c).expect("open_h3_request");
                self.req = Some(r);
                let _ = cx.h3_send_headers(r, &hdrs(&self.s.headers), self.s.body.is_empty());
                self.send(cx, r);
            }
            Event::H3Writable(r) => self.send(cx, r),
            Event::H3Readable(r) => self.read(cx, r),
            Event::H3Closed(_, close) => self.h.lock().closed.push((*close, Instant::now())),
            _ => {}
        }
    }

    fn on_timer(&mut self, _: &mut Cx<'_>, _: TimerId) {}

    no_io!();
}
