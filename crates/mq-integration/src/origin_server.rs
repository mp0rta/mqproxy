//! `OriginServer`: a real origin for the bridge tests (spec §10.3). The hyper
//! modes run a hyper 1.10 **server** on a tokio current_thread runtime on a
//! std thread (TLS through tokio-rustls); the raw modes are canned-bytes peers
//! on std threads, one per connection (TLS through a synchronous
//! `rustls::ServerConnection`), for what a hyper server cannot produce. Body byte `i` is `upload_byte(i)`.

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use mq_proxy::server::origin::host::upload_byte;
use mq_proxy::server::origin::install_ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::convert::Infallible;
use std::future::{Future, pending};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, watch};

pub const ORIGIN_CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/certs/origin-ca.crt"
);
/// Leaf (CA:FALSE), SAN IP:127.0.0.1 and DNS:localhost.
pub const ORIGIN_CRT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/origin.crt");
pub const ORIGIN_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/origin.key");

/// One generated body frame.
const CHUNK: u64 = 16 * 1024;
/// The raw peers' read timeout: how often they look at `stop` / `release`.
const POLL: Duration = Duration::from_millis(10);
/// How long a finished hyper connection keeps its socket (`run_conn`).
const LINGER: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub enum Proto {
    H1Plain,
    /// ALPN `http/1.1`.
    H1Tls,
    /// ALPN `h2`, `http/1.1` (an h1-forced request still connects); served
    /// as negotiated.
    H2Tls,
    /// Per connection: reads one head (and its declared body), writes `reply`
    /// and closes — for 1xx, trailers and NUL, which a hyper server cannot
    /// produce. `tls`: ALPN `http/1.1`.
    RawH1 {
        tls: bool,
        reply: Vec<u8>,
    },
    /// Plain h1 keep-alive: answers `replies` heads (each body read first)
    /// with `200` + `ok`, then applies `then` — per accepted connection.
    RawH1KeepAlive {
        replies: u32,
        then: Then,
    },
    /// A canned-bytes h2 peer over TLS (ALPN `h2`): server SETTINGS{}, ACKs
    /// the client's SETTINGS and PINGs, answers the first HEADERS with
    /// `:status 200` (HPACK `0x88`) without END_STREAM, ignores the rest and
    /// records every inbound frame; after `release()` it writes
    /// SETTINGS(MAX_CONCURRENT_STREAMS = 1), GOAWAY(last_stream_id = 1,
    /// NO_ERROR) and DATA(END_STREAM) for stream 1. `handler` is unused.
    RawH2Tls,
    /// Reads one TLS record (the ClientHello) and closes.
    RawTlsCloseAfterClientHello,
}

/// `RawH1KeepAlive`'s end of a connection.
#[derive(Copy, Clone, Debug)]
pub enum Then {
    /// Reads head `replies + 1` and its declared content-length body, then
    /// closes without replying (`IncompleteMessage`, nothing received).
    CloseAfterNextHead,
    /// Closes the idle keep-alive conn after the delay.
    CloseIdle(Duration),
    /// The first connection answers `replies` heads, every later one none;
    /// then each behaves as `CloseAfterNextHead`.
    CloseEvery,
    /// Reads head `replies + 1` and its body, writes the partial head
    /// `HTTP/1.1 200` and closes (`IncompleteMessage` after response bytes).
    PartialHeadAfterNextHead,
}

#[derive(Clone, Debug)]
pub enum Handler {
    /// `200`, the request body streamed back.
    Echo,
    /// `200`, `content-length: len`.
    FileBytes(u64),
    /// `FileBytes`, the head at once, the body only after `release()`.
    FileBytesGated(u64),
    /// By exact path; `404` for anything else.
    PerPath(Vec<(&'static str, Handler)>),
    /// `200`, `len` bytes without a content-length, then a trailers frame
    /// (`x-trailer: done`). The h1 half is `RawH1` (hyper sends trailers only
    /// with `TE: trailers`).
    Trailers(u64),
    /// That status, no body (204 / 304).
    Status(u16),
    /// `200` with END_STREAM; the request body is kept unread (no
    /// WINDOW_UPDATE, no RST) until `reset_stream(path)`.
    EarlyOkKeepBodyUnread,
    /// `200` with END_STREAM; the request body is dropped, so h2 sends
    /// RST_STREAM(NO_ERROR) after the response.
    EarlyOkThenRstNoError,
    /// `200`, `2 × after_bytes` bytes under a content-length; once
    /// `after_bytes` were yielded the connection is shut down gracefully
    /// (h2: GOAWAY(NO_ERROR)).
    GoawayMidResponse(u64),
    /// `101 Switching Protocols` (h1).
    Upgrade101,
    /// `200` with `count` headers `x-h<i>` of `size` bytes each.
    Headers(usize, usize),
    /// `200` with one header of `n` bytes.
    HeaderListBytes(usize),
    /// An HTTP/1.0 response of `len` bytes ended by the close.
    CloseDelimited(u64),
    /// No response; `release()` writes a plaintext alert record on the
    /// socket under the TLS session, which the client fails to decrypt — a
    /// sticky fatal error. Not a real encrypted alert, deliberately.
    FatalAlertAfterHandshake,
    /// `content-length: cl`, `send` bytes, then RST_STREAM(NO_ERROR) (h2;
    /// h1: hyper aborts the connection).
    ClTooShort {
        cl: u64,
        send: u64,
    },
    /// `200` with `n` `set-cookie: c<i>=<i>` headers, in order.
    SetCookies(usize),
    HangNoResponse,
    /// Closes the connection without a response.
    CloseWithoutResponse,
}

#[derive(Clone, Debug)]
pub struct OriginServerMode {
    pub proto: Proto,
    /// h2 SETTINGS, independent of the handler.
    pub max_concurrent_streams: Option<u32>,
    /// Accept one connection at a time (the e2e python origin's behaviour).
    pub single_conn: bool,
    pub handler: Handler,
}

impl OriginServerMode {
    /// No stream limit, concurrent connections.
    pub fn new(proto: Proto, handler: Handler) -> OriginServerMode {
        OriginServerMode {
            proto,
            max_concurrent_streams: None,
            single_conn: false,
            handler,
        }
    }
}

struct Shared {
    stop: watch::Sender<bool>,
    release: watch::Sender<bool>,
    frames: Mutex<Vec<(u8, u32)>>,
    /// `RawH2Tls`: outbound frames as (type, flags).
    sent: Mutex<Vec<(u8, u8)>>,
    /// Connections accepted (the bridge's dials that reached the origin).
    accepted: AtomicU32,
    /// `EarlyOkKeepBodyUnread`'s request bodies, by path.
    stash: Mutex<Vec<(String, Incoming)>>,
}

impl Shared {
    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }
    fn released(&self) -> bool {
        *self.release.borrow()
    }
}

pub struct OriginServer {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl OriginServer {
    pub fn spawn(mode: OriginServerMode) -> OriginServer {
        install_ring();
        let l = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        l.set_nonblocking(true).expect("nonblocking listener");
        let addr = l.local_addr().expect("origin addr");
        let shared = Arc::new(Shared {
            stop: watch::Sender::new(false),
            release: watch::Sender::new(false),
            frames: Mutex::default(),
            sent: Mutex::default(),
            accepted: AtomicU32::new(0),
            stash: Mutex::default(),
        });
        let sh = shared.clone();
        let thread = thread::spawn(move || match mode.proto {
            Proto::H1Plain | Proto::H1Tls | Proto::H2Tls => serve(l, mode, sh),
            _ => raw(l, mode, sh),
        });
        OriginServer {
            addr,
            shared,
            thread: Some(thread),
        }
    }

    /// Stops accepting and closes every connection.
    pub fn stop(&mut self) {
        self.shared.stop.send_replace(true);
        if let Some(t) = self.thread.take() {
            if t.join().is_err() && !thread::panicking() {
                panic!("origin server thread panicked");
            }
        }
    }

    /// Opens the handler barrier (`FileBytesGated`, `FatalAlertAfterHandshake`)
    /// and triggers `RawH2Tls`'s frames.
    pub fn release(&self) {
        self.shared.release.send_replace(true);
    }

    /// Drops the stashed unread request body of the stalled h2 stream serving
    /// `path`: h2 then sends RST_STREAM(NO_ERROR), the only reason a hyper
    /// server can produce here (h2 0.4.19 streams.rs:1686–1704 `maybe_cancel`).
    pub fn reset_stream(&self, path: &str) {
        let gone: Vec<_> = {
            let mut s = self.shared.stash.lock().unwrap();
            let (gone, keep) = s.drain(..).partition(|(p, _)| p == path);
            *s = keep;
            gone
        };
        drop(gone);
    }

    /// Connections accepted so far.
    pub fn accepted(&self) -> u32 {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// `RawH2Tls`: the inbound frames so far, as (type, stream id).
    pub fn frames(&self) -> Vec<(u8, u32)> {
        self.shared.frames.lock().unwrap().clone()
    }

    /// `RawH2Tls`: the frames written so far, as (type, flags).
    pub fn sent(&self) -> Vec<(u8, u8)> {
        self.shared.sent.lock().unwrap().clone()
    }
}

impl Drop for OriginServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn server_config(alpn: &[&[u8]]) -> Arc<ServerConfig> {
    install_ring();
    let certs = CertificateDer::pem_file_iter(ORIGIN_CRT)
        .and_then(|i| i.collect::<Result<Vec<_>, _>>())
        .expect("origin.crt");
    let key = PrivateKeyDer::from_pem_file(ORIGIN_KEY).expect("origin.key");
    let mut c = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("origin server config");
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

// ---- hyper modes ----

/// hyper's `rt` IO over a tokio stream, without `unsafe`: reads land in an
/// initialised buffer and are copied into hyper's cursor.
struct TokioIo<T>(T);

impl<T: AsyncRead + Unpin> hyper::rt::Read for TokioIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut tmp = [0u8; CHUNK as usize];
        let n = buf.remaining().min(tmp.len());
        let mut rb = tokio::io::ReadBuf::new(&mut tmp[..n]);
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut rb))?;
        buf.put_slice(rb.filled());
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for TokioIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Copy, Clone)]
struct TokioExec;

impl<F> hyper::rt::Executor<F> for TokioExec
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, f: F) {
        tokio::spawn(f);
    }
}

/// What a handler asks of its connection's task.
#[derive(Default)]
struct ConnCtl {
    goaway: Notify,
    close: Notify,
}

fn serve(l: TcpListener, mode: OriginServerMode, sh: Arc<Shared>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("origin runtime");
    let tls = match mode.proto {
        Proto::H1Tls => Some(server_config(&[b"http/1.1"])),
        Proto::H2Tls => Some(server_config(&[b"h2", b"http/1.1"])),
        _ => None,
    };
    rt.block_on(async move {
        let l = tokio::net::TcpListener::from_std(l).expect("tokio listener");
        let mut stop = sh.stop.subscribe();
        loop {
            let tcp = tokio::select! {
                r = l.accept() => match r {
                    Ok((tcp, _)) => {
                        sh.accepted.fetch_add(1, Ordering::SeqCst);
                        tcp
                    }
                    Err(_) => continue,
                },
                _ = stop.wait_for(|s| *s) => return,
            };
            let conn = serve_conn(tcp, tls.clone(), mode.clone(), sh.clone());
            if mode.single_conn {
                tokio::select! {
                    _ = conn => {}
                    _ = stop.wait_for(|s| *s) => return,
                }
            } else {
                tokio::spawn(conn);
            }
        }
    });
    // Dropping the runtime closes every connection.
}

async fn serve_conn(
    tcp: tokio::net::TcpStream,
    tls: Option<Arc<ServerConfig>>,
    mode: OriginServerMode,
    sh: Arc<Shared>,
) {
    // A second fd on the socket, for `FatalAlertAfterHandshake`.
    let Ok(std) = tcp.into_std() else { return };
    let Ok(raw) = std.try_clone() else { return };
    let Ok(tcp) = tokio::net::TcpStream::from_std(std) else {
        return;
    };
    match tls {
        None => drive(TokioIo(tcp), false, raw, mode, sh).await,
        Some(cfg) => {
            let Ok(s) = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await else {
                return;
            };
            let h2 = s.get_ref().1.alpn_protocol() == Some(b"h2");
            drive(TokioIo(s), h2, raw, mode, sh).await
        }
    }
}

async fn drive<S>(io: TokioIo<S>, h2: bool, raw: TcpStream, mode: OriginServerMode, sh: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ctl = Arc::new(ConnCtl::default());
    let alert = matches!(mode.handler, Handler::FatalAlertAfterHandshake).then_some(raw);
    let svc = {
        let (ctl, sh, handler) = (ctl.clone(), sh.clone(), mode.handler.clone());
        service_fn(move |req: Request<Incoming>| {
            let h = pick(&handler, req.uri().path());
            respond(req, h, ctl.clone(), sh.clone())
        })
    };
    if h2 {
        let mut b = http2::Builder::new(TokioExec);
        b.max_concurrent_streams(mode.max_concurrent_streams);
        let conn = b.serve_connection(io, svc);
        run_conn(conn, |c| c.graceful_shutdown(), &ctl, alert, &sh).await
    } else {
        let conn = http1::Builder::new().serve_connection(io, svc);
        run_conn(conn, |c| c.graceful_shutdown(), &ctl, alert, &sh).await
    }
}

/// Drives a hyper connection to its end, applying the handlers' requests; a
/// closed connection is simply dropped.
async fn run_conn<C: Future>(
    conn: C,
    shutdown: impl Fn(Pin<&mut C>),
    ctl: &ConnCtl,
    mut alert: Option<TcpStream>,
    sh: &Shared,
) {
    /// TLS 1.2 framing, fatal handshake_failure — the bytes are decoration.
    const ALERT: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    tokio::pin!(conn);
    let mut release = sh.release.subscribe();
    loop {
        tokio::select! {
            _ = conn.as_mut() => break,
            _ = ctl.goaway.notified() => shutdown(conn.as_mut()),
            _ = ctl.close.notified() => return,
            _ = release.wait_for(|r| *r), if alert.is_some() => {
                let mut raw = alert.take().expect("guarded");
                let _ = raw.write_all(&ALERT);
            }
        }
    }
    // A lingering close: hyper already shut the write side; the socket stays
    // open a moment so the client's late frames (WINDOW_UPDATE, SETTINGS ACK
    // after a GOAWAY) do not meet a closed socket, whose RST would discard
    // the response tail still queued at the client.
    tokio::time::sleep(LINGER).await;
}

fn pick(h: &Handler, path: &str) -> Handler {
    match h {
        Handler::PerPath(routes) => routes
            .iter()
            .find(|(p, _)| *p == path)
            .map_or(Handler::Status(404), |(_, h)| pick(h, path)),
        h => h.clone(),
    }
}

async fn respond(
    req: Request<Incoming>,
    handler: Handler,
    ctl: Arc<ConnCtl>,
    sh: Arc<Shared>,
) -> Result<Response<OBody>, Infallible> {
    let mut resp = Response::new(OBody::Gen(Gen::new(0, Some(0))));
    let mut h = HeaderMap::new();
    let body = match handler {
        Handler::Echo => OBody::Echo(req.into_body()),
        Handler::FileBytes(n) => OBody::Gen(Gen::new(n, Some(n))),
        Handler::FileBytesGated(n) => {
            let mut rx = sh.release.subscribe();
            let mut g = Gen::new(n, Some(n));
            g.gate = Some(Box::pin(async move {
                let _ = rx.wait_for(|r| *r).await;
            }));
            OBody::Gen(g)
        }
        Handler::PerPath(_) => unreachable!("resolved by pick"),
        Handler::Trailers(n) => {
            let mut g = Gen::new(n, None);
            g.tail = Tail::Trailers;
            OBody::Gen(g)
        }
        Handler::Status(s) => {
            *resp.status_mut() = StatusCode::from_u16(s).expect("Handler::Status");
            OBody::Gen(Gen::new(0, None))
        }
        Handler::EarlyOkKeepBodyUnread => {
            let path = req.uri().path().to_owned();
            sh.stash.lock().unwrap().push((path, req.into_body()));
            OBody::Gen(Gen::new(0, Some(0)))
        }
        Handler::EarlyOkThenRstNoError => {
            drop(req);
            OBody::Gen(Gen::new(0, Some(0)))
        }
        Handler::GoawayMidResponse(after) => {
            let mut g = Gen::new(2 * after, Some(2 * after));
            g.goaway = Some((after, ctl));
            OBody::Gen(g)
        }
        Handler::Upgrade101 => {
            *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            h.insert("connection", HeaderValue::from_static("upgrade"));
            h.insert("upgrade", HeaderValue::from_static("mq-test"));
            OBody::Gen(Gen::new(0, None))
        }
        Handler::Headers(count, size) => {
            for i in 0..count {
                h.insert(header_name(&format!("x-h{i}")), filler(size));
            }
            OBody::Gen(Gen::new(0, Some(0)))
        }
        Handler::HeaderListBytes(n) => {
            h.insert("x-big", filler(n));
            OBody::Gen(Gen::new(0, Some(0)))
        }
        Handler::CloseDelimited(n) => {
            *resp.version_mut() = Version::HTTP_10;
            OBody::Gen(Gen::new(n, None))
        }
        Handler::ClTooShort { cl, send } => {
            let mut g = Gen::new(send, Some(cl));
            g.tail = Tail::Reset;
            OBody::Gen(g)
        }
        Handler::SetCookies(n) => {
            for i in 0..n {
                let v = HeaderValue::from_str(&format!("c{i}={i}")).expect("cookie");
                h.append("set-cookie", v);
            }
            OBody::Gen(Gen::new(0, Some(0)))
        }
        Handler::FatalAlertAfterHandshake | Handler::HangNoResponse => {
            let _req = req;
            return pending().await;
        }
        Handler::CloseWithoutResponse => {
            ctl.close.notify_one();
            let _req = req;
            return pending().await;
        }
    };
    *resp.headers_mut() = h;
    *resp.body_mut() = body;
    Ok(resp)
}

fn header_name(s: &str) -> HeaderName {
    HeaderName::from_bytes(s.as_bytes()).expect("header name")
}

fn filler(n: usize) -> HeaderValue {
    HeaderValue::from_str(&"v".repeat(n)).expect("header value")
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The handlers' response bodies.
enum OBody {
    Echo(Incoming),
    Gen(Gen),
}

#[derive(PartialEq, Eq)]
enum Tail {
    None,
    Trailers,
    /// `Err(NO_ERROR)`: hyper resets the stream with that reason (h2).
    Reset,
}

/// `len` pattern bytes in `CHUNK` frames, then the tail.
struct Gen {
    off: u64,
    len: u64,
    /// The declared length (`content-length`).
    cl: Option<u64>,
    gate: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    /// Graceful shutdown once this many bytes were yielded.
    goaway: Option<(u64, Arc<ConnCtl>)>,
    tail: Tail,
    /// `Tail::Reset` waited for the frames before it to be written.
    flushed: bool,
}

impl Gen {
    fn new(len: u64, cl: Option<u64>) -> Gen {
        Gen {
            off: 0,
            len,
            cl,
            gate: None,
            goaway: None,
            tail: Tail::None,
            flushed: false,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if let Some(g) = &mut self.gate {
            ready!(g.as_mut().poll(cx));
            self.gate = None;
        }
        if self.off < self.len {
            let end = self.len.min(self.off + CHUNK);
            let data: Vec<u8> = (self.off..end).map(upload_byte).collect();
            self.off = end;
            if let Some((at, ctl)) = &self.goaway {
                if self.off >= *at {
                    ctl.goaway.notify_one();
                    self.goaway = None;
                }
            }
            return Poll::Ready(Some(Ok(Frame::data(data.into()))));
        }
        if self.tail == Tail::Reset && !self.flushed {
            // h2's `send_reset` drops the stream's unflushed frames
            // (send.rs:253–267 `clear_queue`): let the connection task write
            // the head and the bytes first, or the peer sees only the reset.
            self.flushed = true;
            self.gate = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
            return self.poll(cx);
        }
        Poll::Ready(match std::mem::replace(&mut self.tail, Tail::None) {
            Tail::None => None,
            Tail::Trailers => {
                let mut t = HeaderMap::new();
                t.insert("x-trailer", HeaderValue::from_static("done"));
                Some(Ok(Frame::trailers(t)))
            }
            Tail::Reset => Some(Err(h2::Error::from(h2::Reason::NO_ERROR).into())),
        })
    }
}

impl Body for OBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            OBody::Echo(b) => Pin::new(b).poll_frame(cx).map_err(Into::into),
            OBody::Gen(g) => g.poll(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            OBody::Echo(b) => b.is_end_stream(),
            OBody::Gen(g) => g.off >= g.len && g.gate.is_none() && g.tail == Tail::None,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            OBody::Echo(b) => b.size_hint(),
            OBody::Gen(g) => g.cl.map_or_else(SizeHint::default, SizeHint::with_exact),
        }
    }
}

// ---- raw modes (std threads, one per connection) ----

/// Accepts until `stop`; each connection is served on its own thread, or
/// inline (one at a time) under `single_conn`.
fn raw(l: TcpListener, mode: OriginServerMode, sh: Arc<Shared>) {
    let mut conns = Vec::new();
    while !sh.stopped() {
        let Ok((tcp, _)) = l.accept() else {
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        let index = sh.accepted.fetch_add(1, Ordering::SeqCst);
        if tcp.set_nonblocking(false).is_err() || tcp.set_read_timeout(Some(POLL)).is_err() {
            continue;
        }
        if mode.single_conn {
            raw_conn(tcp, index, &mode.proto, &sh);
        } else {
            let (proto, sh) = (mode.proto.clone(), sh.clone());
            conns.push(thread::spawn(move || raw_conn(tcp, index, &proto, &sh)));
        }
    }
    for t in conns {
        let _ = t.join();
    }
}

/// Serves connection number `index` (0-based, in accept order).
fn raw_conn(tcp: TcpStream, index: u32, proto: &Proto, sh: &Shared) {
    // A peer that goes away mid-exchange is not a harness failure.
    let _ = match proto {
        Proto::RawH1 { tls, reply } => {
            let s: Box<dyn RawStream> = if *tls {
                Box::new(tls_stream(tcp, b"http/1.1"))
            } else {
                Box::new(tcp)
            };
            raw_h1(RawConn::new(s, sh), reply)
        }
        Proto::RawH1KeepAlive { replies, then } => {
            let replies = match then {
                Then::CloseEvery if index > 0 => 0,
                _ => *replies,
            };
            keep_alive(RawConn::new(Box::new(tcp), sh), replies, *then)
        }
        Proto::RawH2Tls => raw_h2(RawConn::new(Box::new(tls_stream(tcp, b"h2")), sh)),
        Proto::RawTlsCloseAfterClientHello => close_after_hello(RawConn::new(Box::new(tcp), sh)),
        Proto::H1Plain | Proto::H1Tls | Proto::H2Tls => unreachable!("hyper modes"),
    };
}

trait RawStream: Read + Write {
    /// The end of a reply: close_notify under TLS.
    fn finish(&mut self) {}
}

impl RawStream for TcpStream {}

impl RawStream for StreamOwned<ServerConnection, TcpStream> {
    fn finish(&mut self) {
        self.conn.send_close_notify();
        let _ = self.flush();
    }
}

fn tls_stream(tcp: TcpStream, alpn: &[u8]) -> StreamOwned<ServerConnection, TcpStream> {
    let conn = ServerConnection::new(server_config(&[alpn])).expect("server conn");
    StreamOwned::new(conn, tcp)
}

/// A raw peer's connection: buffered reads that give up only on `stop`.
struct RawConn<'a> {
    s: Box<dyn RawStream>,
    buf: Vec<u8>,
    sh: &'a Shared,
}

impl<'a> RawConn<'a> {
    fn new(s: Box<dyn RawStream>, sh: &'a Shared) -> RawConn<'a> {
        RawConn {
            s,
            buf: Vec::new(),
            sh,
        }
    }

    /// One read: `Some(false)` at EOF, `None` when nothing came within `POLL`.
    fn poll_fill(&mut self) -> io::Result<Option<bool>> {
        let mut tmp = [0u8; CHUNK as usize];
        match self.s.read(&mut tmp) {
            Ok(0) => Ok(Some(false)),
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(Some(true))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// More bytes; `false` at EOF.
    fn fill(&mut self) -> io::Result<bool> {
        loop {
            if let Some(more) = self.poll_fill()? {
                return Ok(more);
            }
            if self.sh.stopped() {
                return Err(io::ErrorKind::Interrupted.into());
            }
        }
    }

    /// Reads one request head and its declared body; `false` at EOF.
    fn request(&mut self) -> io::Result<bool> {
        let head = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break self.buf.drain(..i + 4).collect::<Vec<u8>>();
            }
            if !self.fill()? {
                return Ok(false);
            }
        };
        let mut left = content_length(&head);
        loop {
            let k = left.min(self.buf.len());
            self.buf.drain(..k);
            left -= k;
            if left == 0 {
                return Ok(true);
            }
            if !self.fill()? {
                return Ok(false);
            }
        }
    }

    fn send(&mut self, b: &[u8]) -> io::Result<()> {
        self.s.write_all(b)?;
        self.s.flush()
    }

    /// One h2 frame, recorded in `sent`.
    fn send_frame(&mut self, ty: u8, flags: u8, sid: u32, payload: &[u8]) -> io::Result<()> {
        self.sh.sent.lock().unwrap().push((ty, flags));
        self.send(&frame(ty, flags, sid, payload))
    }
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head)
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

fn raw_h1(mut c: RawConn<'_>, reply: &[u8]) -> io::Result<()> {
    if c.request()? {
        c.send(reply)?;
        c.s.finish();
    }
    Ok(())
}

fn keep_alive(mut c: RawConn<'_>, replies: u32, then: Then) -> io::Result<()> {
    for _ in 0..replies {
        if !c.request()? {
            return Ok(());
        }
        c.send(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")?;
    }
    match then {
        Then::CloseAfterNextHead | Then::CloseEvery => {
            c.request()?;
        }
        Then::PartialHeadAfterNextHead => {
            if c.request()? {
                c.send(b"HTTP/1.1 200")?;
            }
        }
        Then::CloseIdle(d) => {
            // Interruptible, so `stop` never waits for `d`.
            let end = std::time::Instant::now() + d;
            while !c.sh.stopped() {
                let left = end.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                thread::sleep(POLL.min(left));
            }
        }
    }
    Ok(()) // the drop closes
}

fn close_after_hello(mut c: RawConn<'_>) -> io::Result<()> {
    // The record header: type, version (2), length (2).
    while c.buf.len() < 5 || c.buf.len() < 5 + usize::from(u16::from_be_bytes([c.buf[3], c.buf[4]]))
    {
        if !c.fill()? {
            break;
        }
    }
    Ok(())
}

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn frame(ty: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = len.to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[ty, flags]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn raw_h2(mut c: RawConn<'_>) -> io::Result<()> {
    const PREFACE: usize = 24; // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    while c.buf.len() < PREFACE {
        if !c.fill()? {
            return Ok(());
        }
    }
    c.buf.drain(..PREFACE);
    c.send_frame(SETTINGS, 0, 0, &[])?;
    let (mut answered, mut released) = (false, false);
    loop {
        while c.buf.len() >= 9 {
            let len = u32::from_be_bytes([0, c.buf[0], c.buf[1], c.buf[2]]) as usize;
            if c.buf.len() < 9 + len {
                break;
            }
            let f: Vec<u8> = c.buf.drain(..9 + len).collect();
            let (ty, flags) = (f[3], f[4]);
            let sid = u32::from_be_bytes([f[5], f[6], f[7], f[8]]) & 0x7fff_ffff;
            c.sh.frames.lock().unwrap().push((ty, sid));
            match ty {
                SETTINGS if flags & ACK == 0 => c.send_frame(SETTINGS, ACK, 0, &[])?,
                PING if flags & ACK == 0 => c.send_frame(PING, ACK, 0, &f[9..])?,
                HEADERS if !answered => {
                    answered = true;
                    c.send_frame(HEADERS, END_HEADERS, sid, &[0x88])?;
                }
                _ => {}
            }
        }
        if answered && !released && c.sh.released() {
            released = true;
            c.send_frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 1])?;
            c.send_frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0])?;
            c.send_frame(DATA, END_STREAM, 1, &[])?;
        }
        if c.poll_fill()? == Some(false) || c.sh.stopped() {
            return Ok(());
        }
    }
}
