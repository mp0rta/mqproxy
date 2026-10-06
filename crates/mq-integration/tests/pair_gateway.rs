//! spec §10.3 (H3 pair, gateway items): the fetch client and the gateway server on two
//! production drivers over loopback UDP, real xquic, against real origins. The test thread
//! plays the local fetch caller (HTTP/1.1 over `std::net`) and, for the direct-H3 cases, an
//! `H3Client` or a `RawH3Peer` on a third driver.
#![forbid(unsafe_code)]

use mq_integration::driver_harness::DriverThread;
use mq_integration::h3_apps::{EchoMode, H3Client, H3EchoServer, H3Handle, H3Recorded, H3Script};
use mq_integration::log_tap;
use mq_integration::loopback::{Backend, LoopbackProxy, h3_transport};
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
use mq_integration::raw_h3::{
    RawH3Handle, RawH3Peer, RawH3Script, data_frame, field, headers_frame,
};
use mq_integration::{matrix, receivers};
use mq_proxy::config::{ClientConfig, GatewayConfig, ServerConfig};
use mq_proxy::server::origin::host::upload_byte;
use mq_runtime::driver::{DriverConfig, StdResolver};
use mq_runtime::{App, Shard};
use mq_transport_api::{CloseReason, ErrType, Role};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TOKEN: &str = "s3cret";
const MIB: usize = 1 << 20;
const T: Duration = Duration::from_secs(10);

fn server_cfg() -> ServerConfig {
    ServerConfig {
        token: TOKEN.into(),
        gateway: Some(GatewayConfig {
            request_metrics: true,
            ..GatewayConfig::default()
        }),
        ..ServerConfig::default()
    }
}

/// The gateway pair on the (client, server) backends `cells` (adoption spec §6.2).
fn gateway_with(server: ServerConfig, cells: (Backend, Backend)) -> LoopbackProxy {
    log_tap::install();
    let client = ClientConfig::default();
    LoopbackProxy::spawn_gateway_on(client, server, Path::new(ORIGIN_CA), cells)
}

fn gateway(cells: (Backend, Backend)) -> LoopbackProxy {
    gateway_with(server_cfg(), cells)
}

/// Polls `cond` every 5 ms until it holds (at most `T`).
fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let end = Instant::now() + T;
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The first `log_tap` line containing every marker (at most `T`).
fn wait_log(markers: &[&str]) -> String {
    let find = || {
        log_tap::lines()
            .into_iter()
            .find(|l| markers.iter().all(|m| l.contains(m)))
    };
    wait_until(&format!("a log line with {markers:?}"), || find().is_some());
    find().unwrap()
}

/// adoption spec §6.2: `line` is the `mq.req` record `want` (written without its `mq.req
/// cid=- ` prefix), field for field. A timing field written `T` in `want` (`ttfb_ms`,
/// `duration_ms`, `origin_connect_ms`, `completion_ms`) only needs a value ≥ 0, i.e. its
/// stamps were set; `-1` (a stamp unset) stays exact.
fn assert_req(line: &str, want: &str) {
    let got = line.split_once("mq.req cid=- ").map_or("", |(_, r)| r);
    let (g, w): (Vec<&str>, Vec<&str>) = (got.split(' ').collect(), want.split(' ').collect());
    assert_eq!(g.len(), w.len(), "\n got: {got}\nwant: {want}");
    for (g, w) in g.iter().zip(&w) {
        let ok = match w.strip_suffix("=T") {
            Some(k) => g
                .strip_prefix(k)
                .and_then(|v| v.strip_prefix('='))
                .is_some_and(|v| v.parse::<u64>().is_ok()),
            None => g == w,
        };
        assert!(ok, "{w}\n got: {got}\nwant: {want}");
    }
}

/// adoption spec §6.2: the response header list is `want`, in order; the volatile `date`
/// value is normalised to `T`.
fn assert_headers(got: &[(String, String)], want: &[(&str, &str)]) {
    let got: Vec<(&str, &str)> = got
        .iter()
        .map(|(n, v)| (n.as_str(), if n == "date" { "T" } else { v.as_str() }))
        .collect();
    assert_eq!(got, want);
}

/// The gateway server's H3 response to a direct request an h1 origin answered `ok`.
const H3_OK: [(&str, &str); 3] = [
    (":status", "200"),
    ("x-mq-origin-protocol", "http/1.1"),
    ("content-length", "2"),
];

/// The H3 response header list of an `H3Client`.
fn h3_headers(r: &H3Recorded) -> Vec<(String, String)> {
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    r.headers.iter().map(|(n, v)| (s(n), s(v))).collect()
}

/// The `mq.req` line of the request to `path` (at most `T`).
fn req_line(path: &str) -> String {
    wait_log(&["mq.req", &format!("path=\"{path}\"")])
}

/// The cell's index (xx 0, xw 1, wx 2, ww 3), for a marker unique to the cell.
fn cell_index((c, s): (Backend, Backend)) -> usize {
    2 * usize::from(c == Backend::Wire) + usize::from(s == Backend::Wire)
}

// ---- the local fetch caller ----

/// Sends `POST /_mqproxy/fetch` with `headers` and `body` (written on its own thread, so a
/// response streamed during the upload is read concurrently) and reads the reply until EOF.
/// `Err` is how a local reset (`tcp_abort`) shows.
fn fetch_raw(addr: SocketAddr, headers: &[(String, String)], body: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(T))?;
    let mut head = String::from("POST /_mqproxy/fetch HTTP/1.1\r\nHost: gw\r\n");
    for (n, v) in headers {
        head += &format!("{n}: {v}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    let mut w = s.try_clone()?;
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    // A reply may come (and the socket close) before the whole body was taken.
    let writer = thread::spawn(move || {
        let _ = w.write_all(&out);
    });
    let mut reply = Vec::new();
    let r = s.read_to_end(&mut reply);
    let _ = writer.join();
    r.map(|_| reply)
}

/// A parsed local reply.
#[derive(Debug)]
struct Reply {
    status: u16,
    /// Lowercased names.
    headers: Vec<(String, String)>,
    /// De-chunked when the reply was chunked.
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        let h = self.headers.iter().find(|(n, _)| n == name);
        h.map(|(_, v)| v.as_str())
    }
}

fn parse(raw: &[u8]) -> Reply {
    let i = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head");
    let head = String::from_utf8_lossy(&raw[..i]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|l| {
            let (n, v) = l.split_once(':').expect("header");
            (n.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    let mut r = Reply {
        status,
        headers,
        body: raw[i + 4..].to_vec(),
    };
    if r.header("transfer-encoding") == Some("chunked") {
        r.body = dechunk(&r.body).expect("complete chunked body");
    }
    r
}

/// `None` when the terminator is missing.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let i = b.windows(2).position(|w| w == b"\r\n")?;
        let n = usize::from_str_radix(std::str::from_utf8(&b[..i]).ok()?, 16).ok()?;
        b = &b[i + 2..];
        if n == 0 {
            return (b == b"\r\n").then_some(out);
        }
        out.extend_from_slice(b.get(..n)?);
        b = b.get(n + 2..)?;
    }
}

fn is_reset(r: &io::Result<Vec<u8>>) -> bool {
    matches!(r, Err(e) if e.kind() == io::ErrorKind::ConnectionReset)
}

fn tunnel_down(r: &io::Result<Vec<u8>>) -> bool {
    let needle: &[u8] = b"X-Mq-Error: tunnel-unavailable";
    matches!(r, Ok(b) if b.windows(needle.len()).any(|w| w == needle))
}

/// `fetch_raw`, repeated while the client answers 502 `tunnel-unavailable` (its H3 tunnel
/// is not up yet). Only for bodiless requests: a body would race the early reply.
fn fetch_when_up(addr: SocketAddr, headers: &[(String, String)]) -> io::Result<Vec<u8>> {
    let end = Instant::now() + T;
    loop {
        let r = fetch_raw(addr, headers, b"");
        if !tunnel_down(&r) || Instant::now() >= end {
            return r;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// Waits for the tunnel with a wrong-token probe (the server answers 403, nothing else).
fn wait_up(p: &LoopbackProxy, tag: &str) {
    let target = format!("http://127.0.0.1:1/probe-{tag}");
    let r = fetch_when_up(p.fetch_addr(), &auth(&target, "nope"));
    assert_eq!(parse(&r.expect("probe")).status, 403);
}

fn auth(target: &str, token: &str) -> Vec<(String, String)> {
    vec![
        ("X-Mq-Auth".into(), format!("Bearer {token}")),
        ("X-Mq-Target".into(), target.into()),
    ]
}

fn fetch(
    p: &LoopbackProxy,
    target: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> io::Result<Vec<u8>> {
    let mut hs = auth(target, TOKEN);
    hs.extend(extra.iter().map(|(n, v)| ((*n).into(), (*v).into())));
    fetch_raw(p.fetch_addr(), &hs, body)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len as u64).map(upload_byte).collect()
}

// ---- direct H3 ----

/// The client app `make()` builds, on its own driver on backend `b`.
fn client_on<A: App + 'static, H: Send + 'static>(
    b: Backend,
    make: impl FnOnce() -> (A, H) + Send + 'static,
) -> DriverThread<H> {
    let cfg = DriverConfig {
        resolver: Arc::new(StdResolver),
        install_signal_handlers: false,
        ..DriverConfig::default()
    };
    let lo = Ipv4Addr::LOCALHOST.into();
    let mut d = DriverThread::spawn_on(lo, cfg, Vec::new(), move |local| {
        let (app, h) = make();
        (Shard::new(h3_transport(Role::Client, b), app, local, 3), h)
    });
    d.start();
    d
}

/// An `H3Client` on backend `b` against the gateway server.
fn h3_client(server: SocketAddr, s: H3Script, b: Backend) -> DriverThread<H3Handle> {
    client_on(b, move || H3Client::new(server, s))
}

/// A `RawH3Peer` client writing `stream` + FIN to the gateway server.
fn raw_client(server: SocketAddr, stream: Vec<u8>) -> DriverThread<RawH3Handle> {
    client_on(Backend::Raw, move || {
        RawH3Peer::client(server, RawH3Script { stream, fin: true })
    })
}

fn stop<H>(d: DriverThread<H>) {
    d.shutdown.trigger();
    assert_eq!(d.join(), 0);
}

/// A request to `authority` + `path`; `extra` follows the pseudo-headers.
fn script(
    method: &str,
    authority: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Vec<u8>,
) -> H3Script {
    let headers = [
        (":method", method),
        (":scheme", "http"),
        (":authority", authority),
        (":path", path),
    ]
    .iter()
    .chain(extra)
    .map(|(n, v)| ((*n).into(), (*v).into()))
    .collect();
    H3Script {
        headers,
        body,
        ..H3Script::default()
    }
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

fn wait_h3(h: &H3Handle, cond: impl Fn(&H3Recorded) -> bool) {
    wait_until("the H3 client", || cond(&h.lock()));
}

// ---- a capturing h1 origin ----

/// What `Capture` read on one connection.
#[derive(Clone, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
    /// The declared body (content-length or chunked terminator) arrived in full.
    complete: bool,
}

/// A plain h1 origin that records each connection's request (head, body as on the wire)
/// and answers a complete one with `200` + `ok` + close.
struct Capture {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    accepted: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Capture {
    fn spawn() -> Capture {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let (seen, accepted, stop) = (
            Arc::<Mutex<Vec<Seen>>>::default(),
            Arc::<AtomicU32>::default(),
            Arc::<AtomicBool>::default(),
        );
        let (s, a, st) = (Arc::clone(&seen), Arc::clone(&accepted), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            while !st.load(Ordering::SeqCst) {
                let Ok((tcp, _)) = l.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                a.fetch_add(1, Ordering::SeqCst);
                let seen = capture_one(tcp);
                s.lock().unwrap().push(seen);
            }
        });
        Capture {
            addr,
            seen,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn authority(&self) -> String {
        self.addr.to_string()
    }

    /// Every accepted connection, once each has ended.
    fn settled(&self) -> Vec<Seen> {
        let all_done =
            || self.seen.lock().unwrap().len() as u32 == self.accepted.load(Ordering::SeqCst);
        wait_until("the origin's connections to end", all_done);
        self.seen.lock().unwrap().clone()
    }

    /// The one request seen.
    fn one(&self) -> Seen {
        wait_until("an origin request", || {
            !self.seen.lock().unwrap().is_empty()
        });
        let s = self.settled();
        assert_eq!(s.len(), 1, "{s:?}");
        s[0].clone()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn capture_one(mut tcp: TcpStream) -> Seen {
    let _ = tcp.set_nonblocking(false);
    let _ = tcp.set_read_timeout(Some(T));
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut fill = |buf: &mut Vec<u8>| match tcp.read(&mut chunk) {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
    };
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if !fill(&mut buf) {
            let head = String::from_utf8_lossy(&buf).into_owned();
            let body = Vec::new();
            return Seen {
                head,
                body,
                complete: false,
            };
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let cl: Option<usize> = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse().unwrap());
    let chunked = head.contains("transfer-encoding: chunked");
    let done = |b: &[u8]| match (cl, chunked) {
        (_, true) => b.ends_with(b"0\r\n\r\n") && dechunk(b).is_some(),
        (Some(n), false) => b.len() >= n,
        (None, false) => true,
    };
    let complete = loop {
        if done(&buf[end..]) {
            break true;
        }
        if !fill(&mut buf) {
            break false;
        }
    };
    if complete {
        let _ =
            tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
    }
    Seen {
        head,
        body: buf[end..].to_vec(),
        complete,
    }
}

// ---- fetch API end to end ----

// spec §5.4, §6.4, §10.3: an 8 MiB download with `content-length` over an h2 TLS origin.
matrix!(
    fetch_download_8mib_cl,
    |cells: (Backend, Backend), tag: &str| {
        let len = 8 * MIB;
        let o = OriginServer::spawn(OriginServerMode::new(
            Proto::H2Tls,
            Handler::FileBytes(len as u64),
        ));
        let p = gateway(cells);
        wait_up(&p, tag);
        let url = format!("https://127.0.0.1:{}/dl-{tag}", o.addr.port());
        let r = parse(&fetch(&p, &url, &[], b"").expect("download"));
        let want = [
            ("x-mq-origin-protocol", "h2"),
            ("date", "T"),
            ("content-length", "8388608"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some("8388608"));
        assert!(
            r.body == pattern(len),
            "body differs ({} bytes)",
            r.body.len()
        );
        let path = format!("/dl-{tag}");
        let a = format!("127.0.0.1:{}", o.addr.port());
        let want = format!(
            "sid=4 method=GET status=200 authority=\"{a}\" path=\"{path}\" req_bytes=0 resp_bytes=8388608 ttfb_ms=T duration_ms=T origin_protocol=h2 origin_tls=ok content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\""
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §5.3, §6.3, §10.3: an 8 MiB `PUT` upload, streamed back by an h1 echo origin.
matrix!(
    fetch_upload_8mib_put,
    |cells: (Backend, Backend), tag: &str| {
        let o = OriginServer::spawn(OriginServerMode::new(Proto::H1Plain, Handler::Echo));
        let p = gateway(cells);
        wait_up(&p, tag);
        let body = pattern(8 * MIB);
        let url = format!("http://{}/up-{tag}", o.addr);
        let r = parse(&fetch(&p, &url, &[("X-Mq-Method", "PUT")], &body).expect("upload"));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "8388608"),
            ("date", "T"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some("8388608"));
        assert!(r.body == body, "echo differs ({} bytes)", r.body.len());
        let path = format!("/up-{tag}");
        let want = format!(
            "sid=4 method=PUT status=200 authority=\"{}\" path=\"{path}\" req_bytes=8388608 resp_bytes=8388608 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            o.addr
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §5.4, §5.5, §10.3: `content-length: 100` over a complete 50-byte DATA frame + FIN
// from a peer: the local socket is aborted. On an xqc_h3 client its own body check does it; a
// `Wire` client's h3wire finds the malformed response (RFC 9114 §4.1.2) and aborts the
// stream, which reaches the client as `Err(Reset)`.
matrix!(
    fetch_short_cl_response_aborts_client,
    |cells: (Backend, Backend), tag: &str| {
        let (app, h) = H3EchoServer::new(EchoMode::ShortCl { cl: 100, sent: 50 });
        let p = LoopbackProxy::spawn_gateway_against_on(ClientConfig::default(), app, cells);
        let target = format!("http://x/short-{tag}");
        let r = fetch_when_up(p.fetch_addr(), &auth(&target, "any"));
        assert!(is_reset(&r), "{r:?}");
        assert!(h.lock().requests >= 1);
        assert_eq!(p.join_both(), (0, 0));
    }
);

/// The declared length of a cut DATA frame, and what the raw peer sends of it.
const CUT_DECLARED: u64 = 32 << 20;
const CUT_SENT: usize = 32 * 1024;

/// adoption spec §5.3 (1).
const FRAME_ERROR: CloseReason = CloseReason {
    err_type: ErrType::Application,
    code: 0x106,
};

// spec §3.7 (3), §5.4, Review Focus 5: the response's DATA frame is cut by FIN inside its
// declared length; the local fetch socket is reset in both cells. An xqc_h3 client reads the
// cut as a clean EOF and its body check (or the `H3Closed.unread` path) resets; h3wire closes
// the connection with `H3_FRAME_ERROR` (adoption spec §5.3 (1)).
receivers!(
    fetch_response_cut_inside_frame_aborts,
    |b: Backend, tag: &str| {
        let cl = CUT_DECLARED.to_string();
        let mut stream = headers_frame(&[(b":status", b"200"), (b"content-length", cl.as_bytes())]);
        stream.extend(data_frame(CUT_DECLARED, &[0; CUT_SENT]));
        let (app, h) = RawH3Peer::server(RawH3Script { stream, fin: true });
        let p = LoopbackProxy::spawn_gateway_against_on(
            ClientConfig::default(),
            app,
            (b, Backend::Raw),
        );
        let target = format!("http://x/cut-{tag}");
        let r = fetch_when_up(p.fetch_addr(), &auth(&target, "any"));
        assert!(is_reset(&r), "{:?}", r.as_ref().map(|b| b.len()));
        if b == Backend::Wire {
            wait_until("the peer's ConnClosed", || !h.lock().closed.is_empty());
            assert_eq!(h.lock().closed, [FRAME_ERROR]);
        }
        assert_eq!(p.join_both(), (0, 0));
    }
);

/// adoption spec §6.2: a `RawH3Peer::server` hosts the server side of the gateway pair
/// (`Backend::Raw`); its fixed 200 reaches the fetch socket through each client backend.
#[test]
fn raw_server_smoke() {
    for b in [Backend::XqcH3, Backend::Wire] {
        let mut stream = headers_frame(&[(b":status", b"200"), (b"content-length", b"2")]);
        stream.extend(data_frame(2, b"ok"));
        let (app, h) = RawH3Peer::server(RawH3Script { stream, fin: true });
        let p = LoopbackProxy::spawn_gateway_against_on(
            ClientConfig::default(),
            app,
            (b, Backend::Raw),
        );
        let r = fetch_when_up(p.fetch_addr(), &auth("http://x/raw", "any"));
        let r = parse(&r.unwrap_or_else(|e| panic!("{b:?}: {e}")));
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]), "{b:?}");
        assert!(
            !h.lock().read.is_empty(),
            "{b:?}: the peer read the request"
        );
        assert_eq!(p.join_both(), (0, 0), "{b:?}");
    }
}

// spec §5.4, §6.4, §10.3: a HEAD response and a 304, each carrying `content-length`,
// finish cleanly (the HEAD reply's length is rewritten to 0, §12).
matrix!(
    head_and_304_with_cl_finish_cleanly,
    |cells: (Backend, Backend), tag: &str| {
        let raw = |reply: &[u8]| {
            let proto = Proto::RawH1 {
                tls: false,
                reply: reply.to_vec(),
            };
            OriginServer::spawn(OriginServerMode::new(proto, Handler::Echo))
        };
        let head = raw(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n");
        let nm = raw(b"HTTP/1.1 304 Not Modified\r\ncontent-length: 100\r\n\r\n");
        let p = gateway(cells);
        wait_up(&p, tag);
        let r = fetch(
            &p,
            &format!("http://{}/h-{tag}", head.addr),
            &[("X-Mq-Method", "HEAD")],
            b"",
        );
        let r = parse(&r.expect("HEAD finishes cleanly"));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "0"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!((r.status, r.header("content-length")), (200, Some("0")));
        assert!(r.body.is_empty());
        let r = parse(
            &fetch(&p, &format!("http://{}/n-{tag}", nm.addr), &[], b"")
                .expect("304 finishes cleanly"),
        );
        assert_eq!((r.status, r.header("content-length")), (304, Some("100")));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "100"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert!(r.body.is_empty());
        for (sid, method, status, addr, path) in [
            (4, "HEAD", 200, head.addr, format!("/h-{tag}")),
            (8, "GET", 304, nm.addr, format!("/n-{tag}")),
        ] {
            let want = format!(
                "sid={sid} method={method} status={status} authority=\"{addr}\" path=\"{path}\" req_bytes=0 resp_bytes=0 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\""
            );
            assert_req(&req_line(&path), &want);
        }
        assert_eq!(p.join_both(), (0, 0));
    }
);

// SP4 spec §5: an origin answering with about 30 KiB of headers (five 6 KiB values, under
// `SECTION_MAX`) is relayed to the local caller; the fetch request itself stays small.
matrix!(
    fetch_30k_response_head_relayed,
    |cells: (Backend, Backend), tag: &str| {
        let value = "v".repeat(6 * 1024);
        let mut reply = String::from("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n");
        for i in 0..5 {
            reply += &format!("x-big-{i}: {value}\r\n");
        }
        reply += "\r\nok";
        let proto = Proto::RawH1 {
            tls: false,
            reply: reply.into_bytes(),
        };
        let origin = OriginServer::spawn(OriginServerMode::new(proto, Handler::Echo));
        let p = gateway(cells);
        wait_up(&p, tag);
        let raw = fetch(&p, &format!("http://{}/big-{tag}", origin.addr), &[], b"");
        let r = parse(&raw.expect("fetch"));
        let names: Vec<String> = (0..5).map(|i| format!("x-big-{i}")).collect();
        let mut want = vec![
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "2"),
        ];
        want.extend(names.iter().map(|n| (n.as_str(), value.as_str())));
        want.push(("connection", "close"));
        assert_headers(&r.headers, &want);
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        for i in 0..5 {
            assert_eq!(r.header(&format!("x-big-{i}")), Some(value.as_str()), "{i}");
        }
        let path = format!("/big-{tag}");
        let want = format!(
            "sid=4 method=GET status=200 authority=\"{}\" path=\"{path}\" req_bytes=0 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            origin.addr
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §7.4, §10.3: `/a/../b` reaches the origin as `/b` (the query untouched).
matrix!(
    dot_segments_normalised_at_origin,
    |cells: (Backend, Backend), tag: &str| {
        let o = Capture::spawn();
        let p = gateway(cells);
        wait_up(&p, tag);
        let url = o.url(&format!("/a/../b-{tag}?q=/../x"));
        let r = parse(&fetch(&p, &url, &[], b"").expect("fetch"));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "2"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let head = o.one().head;
        let want = format!("get /b-{tag}?q=/../x http/1.1\r\n");
        assert!(head.starts_with(&want), "{head}");
        // The line keeps the path as sent, cut at `?`.
        let path = format!("/a/../b-{tag}");
        let want = format!(
            "sid=4 method=GET status=200 authority=\"{}\" path=\"{path}\" req_bytes=0 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            o.authority()
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// SP4 spec §5: an empty forwarded `x-test:` is sent, and an empty `accept:`
// is sent and suppresses the default `accept: */*`.
matrix!(
    empty_header_sent_empty_accept_suppresses_default,
    |cells: (Backend, Backend), tag: &str| {
        let o = Capture::spawn();
        let p = gateway(cells);
        wait_up(&p, tag);
        let extra = [("X-Test", ""), ("Accept", ""), ("X-Kept", "yes")];
        let r = parse(&fetch(&p, &o.url(&format!("/empty-{tag}")), &extra, b"").expect("fetch"));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "2"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!(r.status, 200);
        let head = o.one().head;
        assert!(head.contains("\r\nx-kept: yes\r\n"), "{head}");
        assert!(head.contains("\r\nx-test:"), "{head}");
        assert!(head.contains("\r\naccept:"), "{head}");
        assert!(!head.contains("*/*"), "{head}");
        let path = format!("/empty-{tag}");
        let want = format!(
            "sid=4 method=GET status=200 authority=\"{}\" path=\"{path}\" req_bytes=0 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            o.authority()
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §7.2, §7.7, §10.3 (e2e case 13): an h1-forced request reuses the idle h1 conn a
// default request left in the pool — against an origin that serves one conn at a time, a
// second dial would hang until `curl:28`.
matrix!(
    h1_forced_reuses_idle_default_conn,
    |cells: (Backend, Backend), tag: &str| {
        let mode = OriginServerMode {
            single_conn: true,
            ..OriginServerMode::new(Proto::H1Tls, Handler::FileBytes(2))
        };
        let o = OriginServer::spawn(mode);
        let mut cfg = server_cfg();
        if let Some(g) = cfg.gateway.as_mut() {
            g.origin_connect_timeout = Duration::from_secs(2);
        }
        let p = gateway_with(cfg, cells);
        wait_up(&p, tag);
        let url = format!("https://127.0.0.1:{}/c13-{tag}", o.addr.port());
        let r = parse(&fetch(&p, &url, &[], b"").expect("default request"));
        let want = [
            ("x-mq-origin-protocol", "http/1.1"),
            ("content-length", "2"),
            ("date", "T"),
            ("connection", "close"),
        ];
        assert_headers(&r.headers, &want);
        assert_eq!((r.status, r.body.len()), (200, 2));
        let r = fetch(&p, &url, &[("X-Mq-Origin-Protocol", "h1")], b"");
        let r = parse(&r.expect("h1-forced request"));
        assert_headers(&r.headers, &want);
        assert_eq!((r.status, r.body.len()), (200, 2));
        assert_eq!(o.accepted(), 1);
        let path = format!("/c13-{tag}");
        let a = format!("127.0.0.1:{}", o.addr.port());
        // The two lines may close in either order: each is found by its stream id.
        for (sid, reuse) in [(4, 0), (8, 1)] {
            let marker = format!("path=\"{path}\"");
            let line = wait_log(&["mq.req", &format!("sid={sid} "), &marker]);
            let want = format!(
                "sid={sid} method=GET status=200 authority=\"{a}\" path=\"{path}\" req_bytes=0 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=ok content_encoding=none cache=bypass origin_reuse={reuse} origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\""
            );
            assert_req(&line, &want);
        }
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §6.4, §10.3: an h2 origin declares `content-length: 100`, sends 50 bytes and then
// RST_STREAM(NO_ERROR): the server's body check resets the H3 response (pinned by its
// `mq.req`). The Rust client's local reply is an abort, or 502 `upstream-reset` when its
// xquic processes HEADERS and RESET_STREAM in one pass (the reset discards the unread
// head; `ClTooShort` leaves only 10 ms between them, too little on a slow CI).
matrix!(
    h2_cl_100_then_rst_resets_h3_end_to_end,
    |cells: (Backend, Backend), tag: &str| {
        let h = Handler::ClTooShort { cl: 100, send: 50 };
        let o = OriginServer::spawn(OriginServerMode::new(Proto::H2Tls, h));
        let p = gateway(cells);
        wait_up(&p, tag);
        let url = format!("https://127.0.0.1:{}/h2-short-{tag}", o.addr.port());
        let r = fetch(&p, &url, &[], b"");
        let upstream_reset = b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        assert!(
            is_reset(&r) || matches!(&r, Ok(b) if b == upstream_reset),
            "{:?}",
            r.as_ref().map(|b| String::from_utf8_lossy(b).into_owned())
        );
        // The reset is the server's (its check), not only the client's own body check. The
        // origin's failure leaves `origin_tls=connect_fail` and `origin_connect_ms=-1`; the
        // reset leaves no FIN stamps.
        let path = format!("/h2-short-{tag}");
        let want = format!(
            "sid=4 method=GET status=200 authority=\"127.0.0.1:{}\" path=\"{path}\" req_bytes=0 resp_bytes=50 ttfb_ms=T duration_ms=-1 origin_protocol=h2 origin_tls=connect_fail content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=-1 reset=\"local reset\"",
            o.addr.port()
        );
        assert_req(&req_line(&path), &want);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §5.2, §6.2, §10.3: CONNECT is refused by the fetch listener (400 `bad-method`) and
// by the server intake (400 `bad-request`). The direct-H3 CONNECT is the valid authority
// form (RFC 9114 §4.4), so it reaches the gateway on both server backends (adoption spec
// §6.2; the malformed form is a raw-peer case).
matrix!(
    connect_rejected_both_intakes,
    |cells: (Backend, Backend), tag: &str| {
        let p = gateway(cells);
        let target = format!("http://127.0.0.1:1/connect-{tag}");
        let r = fetch(&p, &target, &[("X-Mq-Method", "CONNECT")], b"");
        let want = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Mq-Error: bad-method\r\n\r\n";
        assert_eq!(
            String::from_utf8_lossy(&r.expect("reply")),
            String::from_utf8_lossy(want)
        );
        let auth = bearer();
        let headers = [
            (":method", "CONNECT"),
            (":authority", "127.0.0.1:1"),
            ("x-mq-auth", &auth),
        ];
        // Its line has `path="-"`: a body of `cell + 1` bytes (drained, `req_bytes`) marks it.
        let n = cell_index(cells) + 1;
        let s = H3Script {
            headers: headers.map(|(n, v)| (n.into(), v.into())).to_vec(),
            body: vec![0; n],
            ..H3Script::default()
        };
        let c = h3_client(p.server.udp_addr, s, cells.0);
        wait_h3(&c.handle, |r| r.fin);
        {
            let r = c.handle.lock();
            let want = [
                (":status", "400"),
                ("x-mq-error", "bad-request"),
                ("content-length", "0"),
            ];
            assert_headers(&h3_headers(&r), &want);
        }
        let line = wait_log(&["mq.req", "status=400", &format!("req_bytes={n} ")]);
        let want = format!(
            "sid=0 method=- status=400 authority=\"-\" path=\"-\" req_bytes={n} resp_bytes=0 ttfb_ms=T duration_ms=T origin_protocol=none origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=T reset=\"\""
        );
        assert_req(&line, &want);
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// ---- direct H3 against the gateway server ----

// spec §3.7 (1), §6.3, Review Focus 3: a 4 MiB body sent after a 403 is drained, so the
// server's `recv_body_size` (`req_bytes`) reports the whole body.
// A 403 line has `path="-"`, so the cell's marker is its body length.
matrix!(
    drain_after_403_counts_whole_body,
    |cells: (Backend, Backend), tag: &str| {
        let p = gateway(cells);
        let body_len = 4 * MIB + cell_index(cells);
        let extra = [("x-mq-auth", "Bearer wrong")];
        let path = format!("/drain-{tag}");
        let s = script("POST", "127.0.0.1:1", &path, &extra, vec![7; body_len]);
        let c = h3_client(p.server.udp_addr, s, cells.0);
        wait_h3(&c.handle, |r| !r.closed.is_empty());
        {
            let r = c.handle.lock();
            let want = [
                (":status", "403"),
                ("x-mq-error", "auth-failed"),
                ("content-length", "0"),
            ];
            assert_headers(&h3_headers(&r), &want);
            assert_eq!(r.closed[0].0.stats.stream_err, 0, "{:?}", r.closed);
            assert_eq!(r.closed[0].0.stats.send_body, body_len as u64);
        }
        let line = wait_log(&["mq.req", "status=403", &format!("req_bytes={body_len} ")]);
        let want = format!(
            "sid=0 method=- status=403 authority=\"-\" path=\"-\" req_bytes={body_len} resp_bytes=0 ttfb_ms=T duration_ms=T origin_protocol=none origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=T reset=\"\""
        );
        assert_req(&line, &want);
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §6.2 step 8, §10.3: `content-length: 10` with FIN on HEADERS reaches the origin
// bodiless (no chunked framing, no positive length). adoption spec §5.3 (6): a `Wire` server
// finds the mismatch in the read that delivers the HEADERS, so the gateway's intake read
// fails and the origin sees nothing. Its line has `path="-"` and no field unique to the
// cell, so the cell asserts no `mq.req` (as the brief rules); the client sees the reset.
matrix!(
    direct_h3_cl_with_fin_on_headers_is_bodiless,
    |cells: (Backend, Backend), tag: &str| {
        let o = Capture::spawn();
        let p = gateway(cells);
        let auth = bearer();
        let extra = [("x-mq-auth", auth.as_str()), ("content-length", "10")];
        let path = format!("/fin-{tag}");
        let s = script("POST", &o.authority(), &path, &extra, Vec::new());
        let c = h3_client(p.server.udp_addr, s, cells.0);
        if cells.1 == Backend::Wire {
            wait_h3(&c.handle, |r| !r.closed.is_empty());
            {
                let r = c.handle.lock();
                assert_eq!(r.closed[0].0.stats.stream_err, 0x10e, "{r:?}");
                assert!(r.headers.is_empty() && !r.fin, "{r:?}");
            }
            stop(c);
            assert_eq!(p.join_both(), (0, 0));
            assert!(o.settled().is_empty(), "the origin saw a request");
            return;
        }
        wait_h3(&c.handle, |r| r.fin);
        assert_headers(&h3_headers(&c.handle.lock()), &H3_OK);
        let seen = o.one();
        assert!(seen.complete && seen.body.is_empty(), "{seen:?}");
        assert!(!seen.head.contains("transfer-encoding"), "{}", seen.head);
        let cl = seen
            .head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"));
        assert!(cl.is_none_or(|v| v.trim() == "0"), "{}", seen.head);
        let want = format!(
            "sid=0 method=POST status=200 authority=\"{}\" path=\"{path}\" req_bytes=0 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            o.authority()
        );
        assert_req(&req_line(&path), &want);
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §7.4, §10.3: a GET with an unknown-length DATA body reaches an h1 origin chunked and
// complete.
matrix!(
    direct_h3_get_with_body_is_chunked_on_h1,
    |cells: (Backend, Backend), tag: &str| {
        let o = Capture::spawn();
        let p = gateway(cells);
        let auth = bearer();
        let extra = [("x-mq-auth", auth.as_str())];
        let path = format!("/chunked-{tag}");
        let s = script("GET", &o.authority(), &path, &extra, b"hello body".to_vec());
        let c = h3_client(p.server.udp_addr, s, cells.0);
        wait_h3(&c.handle, |r| r.fin);
        assert_headers(&h3_headers(&c.handle.lock()), &H3_OK);
        let seen = o.one();
        assert!(
            seen.head.contains("\r\ntransfer-encoding: chunked\r\n"),
            "{}",
            seen.head
        );
        assert_eq!(dechunk(&seen.body).as_deref(), Some(&b"hello body"[..]));
        let want = format!(
            "sid=0 method=GET status=200 authority=\"{}\" path=\"{path}\" req_bytes=10 resp_bytes=2 ttfb_ms=T duration_ms=T origin_protocol=h1 origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=T mp_state=0 completion_ms=T reset=\"\"",
            o.authority()
        );
        assert_req(&req_line(&path), &want);
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

/// A direct-H3 upload the server must reset (§6.3): the client sees the reset, the server
/// logs the request, and the origin never received a complete body. On a `Wire` server the
/// reset is h3wire's (`H3_MESSAGE_ERROR`, adoption spec §5.3 (6)) and comes before any body
/// byte reaches the gateway (`req_bytes=0`, where xqc_h3 delivers the 50 bytes); the gateway
/// still logs it as `local reset`.
fn upload_reset(cells: (Backend, Backend), path: &str, cl: &str, body: Vec<u8>) {
    let o = Capture::spawn();
    let p = gateway(cells);
    let auth = bearer();
    let extra = [("x-mq-auth", auth.as_str()), ("content-length", cl)];
    let s = script("POST", &o.authority(), path, &extra, body);
    let c = h3_client(p.server.udp_addr, s, cells.0);
    wait_h3(&c.handle, |r| !r.closed.is_empty());
    let wire = cells.1 == Backend::Wire;
    {
        let r = c.handle.lock();
        let code = r.closed[0].0.stats.stream_err;
        assert!(if wire { code == 0x10e } else { code != 0 }, "{r:?}");
        assert!(!r.fin, "{r:?}");
        assert_headers(&h3_headers(&r), &[]);
    }
    let want = format!(
        "sid=0 method=POST status=0 authority=\"{}\" path=\"{path}\" req_bytes={} resp_bytes=0 ttfb_ms=-1 duration_ms=-1 origin_protocol=none origin_tls=na content_encoding=none cache=bypass origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=-1 reset=\"local reset\"",
        o.authority(),
        if wire { 0 } else { 50 },
    );
    assert_req(&req_line(path), &want);
    let seen = o.settled();
    assert!(seen.iter().all(|s| !s.complete), "{seen:?}");
    stop(c);
    assert_eq!(p.join_both(), (0, 0));
}

// spec §6.3, §10.3: 50 bytes + FIN (a complete frame) under `content-length: 100`.
matrix!(
    direct_h3_short_request_body_resets,
    |cells: (Backend, Backend), tag: &str| {
        upload_reset(cells, &format!("/short-req-{tag}"), "100", vec![1; 50]);
    }
);

// spec §6.3, §10.3: 50 bytes under `content-length: 10`.
matrix!(
    direct_h3_excess_request_body_resets,
    |cells: (Backend, Backend), tag: &str| {
        upload_reset(cells, &format!("/excess-req-{tag}"), "10", vec![1; 50]);
    }
);

// ---- malformed input against each receiver (adoption spec §6.2) ----

/// A HEADERS frame of `fields`, as the raw peer writes it (unvalidated).
fn raw_headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let fs: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
        .collect();
    headers_frame(&fs)
}

/// `RawH3Peer`'s HEADERS was malformed (adoption spec §5.3 (6)): h3wire resets the stream with
/// `H3_MESSAGE_ERROR` and the gateway never sees the request, so no `mq.req` line carries
/// `marker` for 500 ms after the reset.
fn assert_message_error(c: &DriverThread<RawH3Handle>, marker: &str) {
    wait_until("the peer's reset", || !c.handle.lock().resets.is_empty());
    assert_eq!(c.handle.lock().resets[0].1, 0x10e, "{:?}", c.handle.lock());
    let end = Instant::now() + Duration::from_millis(500);
    while Instant::now() < end {
        let lines = log_tap::lines();
        let hit = lines
            .iter()
            .find(|l| l.contains("mq.req") && l.contains(marker));
        assert!(hit.is_none(), "{hit:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The raw response's `name` field.
fn raw_field(c: &DriverThread<RawH3Handle>, name: &str) -> Option<String> {
    let v = field(&c.handle.lock().read, name.as_bytes());
    v.map(|v| String::from_utf8_lossy(&v).into_owned())
}

// spec §3.7 (3), §6.3, Review Focus 5: the request's DATA frame is cut by FIN inside its
// declared length. An xqc_h3 server reads the cut as a clean EOF and its upload check resets
// the request. h3wire closes the connection with `H3_FRAME_ERROR` (adoption spec §5.3 (1));
// the valid HEADERS reached the gateway first, so the connection-close fan-out (§4.3) logs
// the request once, reset.
receivers!(
    direct_h3_request_body_cut_inside_frame_resets,
    |b: Backend, tag: &str| {
        let o = Capture::spawn();
        let p = gateway((Backend::XqcH3, b));
        let (auth, cl, path) = (
            bearer(),
            CUT_DECLARED.to_string(),
            format!("/cut-req-{tag}"),
        );
        let mut stream = raw_headers(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":authority", &o.authority()),
            (":path", &path),
            ("x-mq-auth", &auth),
            ("content-length", &cl),
        ]);
        stream.extend(data_frame(CUT_DECLARED, &[2; CUT_SENT]));
        let c = raw_client(p.server.udp_addr, stream);
        let marker = format!("path=\"{path}\"");
        let line = wait_log(&["mq.req", &marker]);
        if b == Backend::Wire {
            wait_until("the peer's ConnClosed", || {
                !c.handle.lock().closed.is_empty()
            });
            assert_eq!(c.handle.lock().closed, [FRAME_ERROR]);
            assert!(!line.contains("reset=\"\""), "{line}");
            let n = log_tap::lines()
                .iter()
                .filter(|l| l.contains("mq.req") && l.contains(&marker))
                .count();
            assert_eq!(n, 1);
        } else {
            assert!(line.contains("reset=\"local reset\""), "{line}");
        }
        let seen = o.settled();
        assert!(seen.iter().all(|s| !s.complete), "{seen:?}");
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §6.2, §12, §10.3: an embedded NUL in `x-mq-auth`, `:path` and `x-mq-class`. An
// xqc_h3 server passes them to the gateway: 403 / 400 / `?` in the log. RFC 9114 §4.2 makes
// such a request malformed, and h3wire resets it (adoption spec §5.3 (6)).
receivers!(nul_in_auth_path_class_direct_h3, |b: Backend, tag: &str| {
    let o = Capture::spawn();
    let p = gateway((Backend::XqcH3, b));
    let auth = bearer();
    let nul_auth = format!("{auth}\0junk");
    let class = format!("nul\0class-marker-{tag}");
    let a = o.authority();
    let get = |path: &str, extra: &[(&str, &str)]| {
        let mut fs = vec![
            (":method", "GET"),
            (":scheme", "http"),
            (":authority", a.as_str()),
            (":path", path),
        ];
        fs.extend_from_slice(extra);
        raw_headers(&fs)
    };
    let (p_auth, p_path, p_class) = (
        format!("/nul-auth-{tag}"),
        format!("/ok\0junk-{tag}"),
        format!("/nul-class-{tag}"),
    );
    let cases = [
        (
            get(&p_auth, &[("x-mq-auth", &nul_auth)]),
            &p_auth,
            ("403", Some("auth-failed")),
        ),
        (
            get(&p_path, &[("x-mq-auth", &auth)]),
            &p_path,
            ("400", Some("bad-target")),
        ),
        (
            get(&p_class, &[("x-mq-auth", &auth), ("x-mq-class", &class)]),
            &p_class,
            ("200", None),
        ),
    ];
    for (stream, path, (status, xmq)) in cases {
        let c = raw_client(p.server.udp_addr, stream);
        if b == Backend::Wire {
            assert_message_error(&c, &format!("path=\"{path}\""));
        } else {
            wait_until("the response", || c.handle.lock().fin);
            assert_eq!(raw_field(&c, ":status").as_deref(), Some(status));
            assert_eq!(raw_field(&c, "x-mq-error").as_deref(), xmq);
        }
        stop(c);
    }
    let class_line = format!("x-mq-class='nul?class-marker-{tag}'");
    if b == Backend::Wire {
        assert!(!log_tap::lines().iter().any(|l| l.contains(&class_line)));
    } else {
        wait_log(&[&class_line]);
    }
    assert_eq!(p.join_both(), (0, 0));
});

// spec §5.2, §6.2: CONNECT with `:scheme` and `:path` (RFC 9114 §4.4 forbids both). An
// xqc_h3 server passes it to the gateway, which answers 400 `bad-request`; h3wire resets it
// as malformed (adoption spec §5.3 (6)).
receivers!(connect_malformed_direct_h3, |b: Backend, tag: &str| {
    let p = gateway((Backend::XqcH3, b));
    let (auth, path) = (bearer(), format!("/connect-{tag}"));
    let stream = raw_headers(&[
        (":method", "CONNECT"),
        (":scheme", "http"),
        (":authority", "127.0.0.1:1"),
        (":path", &path),
        ("x-mq-auth", &auth),
    ]);
    let c = raw_client(p.server.udp_addr, stream);
    if b == Backend::Wire {
        assert_message_error(&c, &format!("path=\"{path}\""));
    } else {
        wait_until("the response", || c.handle.lock().fin);
        assert_eq!(raw_field(&c, ":status").as_deref(), Some("400"));
        assert_eq!(raw_field(&c, "x-mq-error").as_deref(), Some("bad-request"));
    }
    stop(c);
    assert_eq!(p.join_both(), (0, 0));
});
