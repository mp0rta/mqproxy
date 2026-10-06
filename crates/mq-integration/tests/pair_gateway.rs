//! spec §10.3 (H3 pair, gateway items): the fetch client and the gateway server on two
//! production drivers over loopback UDP, real xquic, against real origins. The test thread
//! plays the local fetch caller (HTTP/1.1 over `std::net`) and, for the direct-H3 cases, an
//! `H3Client` on a third driver.
#![forbid(unsafe_code)]

use mq_integration::driver_harness::DriverThread;
use mq_integration::h3_apps::{
    CUT_BODY, EchoMode, H3Client, H3EchoServer, H3Handle, H3Recorded, H3Script,
};
use mq_integration::log_tap;
use mq_integration::loopback::{Backend, LoopbackProxy, h3_transport};
use mq_integration::matrix;
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
use mq_integration::raw_h3::{RawH3Peer, RawH3Script, data_frame, headers_frame};
use mq_proxy::config::{ClientConfig, GatewayConfig, ServerConfig};
use mq_proxy::server::origin::host::upload_byte;
use mq_runtime::Shard;
use mq_runtime::driver::{DriverConfig, StdResolver};
use mq_transport_api::Role;
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

/// Both endpoints on xqc_h3: the tests outside the matrix.
const XX: (Backend, Backend) = (Backend::XqcH3, Backend::XqcH3);

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

/// An `H3Client` on its own driver, on backend `b`, against the gateway server.
fn h3_client(server: SocketAddr, s: H3Script, b: Backend) -> DriverThread<H3Handle> {
    let cfg = DriverConfig {
        resolver: Arc::new(StdResolver),
        install_signal_handlers: false,
        ..DriverConfig::default()
    };
    let lo = Ipv4Addr::LOCALHOST.into();
    let mut d = DriverThread::spawn_on(lo, cfg, Vec::new(), move |local| {
        let (app, h) = H3Client::new(server, s);
        (Shard::new(h3_transport(Role::Client, b), app, local, 3), h)
    });
    d.start();
    d
}

fn stop(d: DriverThread<H3Handle>) {
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

fn h3_header(r: &H3Recorded, name: &str) -> Option<String> {
    let h = r.headers.iter().find(|(n, _)| n == name.as_bytes());
    h.map(|(_, v)| String::from_utf8_lossy(v).into_owned())
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
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some("8388608"));
        assert!(
            r.body == pattern(len),
            "body differs ({} bytes)",
            r.body.len()
        );
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
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-length"), Some("8388608"));
        assert!(r.body == body, "echo differs ({} bytes)", r.body.len());
        assert_eq!(p.join_both(), (0, 0));
    }
);

/// spec §5.4, §5.5, §10.3: `content-length: 100` over a complete 50-byte DATA frame + FIN
/// from a peer: the client's own body check aborts the local socket.
#[test]
fn fetch_short_cl_response_aborts_client() {
    let (app, h) = H3EchoServer::new(EchoMode::ShortCl { cl: 100, sent: 50 });
    let p = LoopbackProxy::spawn_gateway_against(ClientConfig::default(), app);
    let r = fetch_when_up(p.fetch_addr(), &auth("http://x/short", "any"));
    assert!(is_reset(&r), "{r:?}");
    assert!(h.lock().requests >= 1);
    assert_eq!(p.join_both(), (0, 0));
}

/// spec §3.7 (3), §5.4, Review Focus 5: the response's DATA frame is cut by FIN inside its
/// declared length (xquic reads it as a clean EOF). The local fetch socket is reset — by the
/// body check at fin or through the `H3Closed.unread` path, whichever the reader's speed
/// selects; neither is asserted.
#[test]
fn fetch_response_cut_inside_frame_aborts() {
    let (app, h) = H3EchoServer::new(EchoMode::CutResponseFrame);
    let p = LoopbackProxy::spawn_gateway_against(ClientConfig::default(), app);
    let r = fetch_when_up(p.fetch_addr(), &auth("http://x/cut", "any"));
    assert!(is_reset(&r), "{:?}", r.as_ref().map(|b| b.len()));
    let accepted = h.lock().accepted.expect("the peer sent the cut frame");
    assert!(0 < accepted && accepted < CUT_BODY, "accepted {accepted}");
    assert_eq!(p.join_both(), (0, 0));
}

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
        assert_eq!((r.status, r.header("content-length")), (200, Some("0")));
        assert!(r.body.is_empty());
        let r = parse(
            &fetch(&p, &format!("http://{}/n-{tag}", nm.addr), &[], b"")
                .expect("304 finishes cleanly"),
        );
        assert_eq!((r.status, r.header("content-length")), (304, Some("100")));
        assert!(r.body.is_empty());
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
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        for i in 0..5 {
            assert_eq!(r.header(&format!("x-big-{i}")), Some(value.as_str()), "{i}");
        }
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
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let head = o.one().head;
        let want = format!("get /b-{tag}?q=/../x http/1.1\r\n");
        assert!(head.starts_with(&want), "{head}");
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
        assert_eq!(r.status, 200);
        let head = o.one().head;
        assert!(head.contains("\r\nx-kept: yes\r\n"), "{head}");
        assert!(head.contains("\r\nx-test:"), "{head}");
        assert!(head.contains("\r\naccept:"), "{head}");
        assert!(!head.contains("*/*"), "{head}");
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
        assert_eq!((r.status, r.body.len()), (200, 2));
        let r = fetch(&p, &url, &[("X-Mq-Origin-Protocol", "h1")], b"");
        let r = parse(&r.expect("h1-forced request"));
        assert_eq!((r.status, r.body.len()), (200, 2));
        assert_eq!(o.accepted(), 1);
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
        // The reset is the server's (its check), not only the client's own body check.
        let line = wait_log(&["mq.req", &format!("path=\"/h2-short-{tag}\"")]);
        assert!(line.contains("reset=\"local reset\""), "{line}");
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
        let s = H3Script {
            headers: headers.map(|(n, v)| (n.into(), v.into())).to_vec(),
            ..H3Script::default()
        };
        let c = h3_client(p.server.udp_addr, s, cells.0);
        wait_h3(&c.handle, |r| r.fin);
        {
            let r = c.handle.lock();
            assert_eq!(h3_header(&r, ":status").as_deref(), Some("400"));
            assert_eq!(h3_header(&r, "x-mq-error").as_deref(), Some("bad-request"));
        }
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
        let cell = ["xx", "xw", "wx", "ww"].iter().position(|t| *t == tag);
        let body_len = 4 * MIB + cell.unwrap();
        let extra = [("x-mq-auth", "Bearer wrong")];
        let path = format!("/drain-{tag}");
        let s = script("POST", "127.0.0.1:1", &path, &extra, vec![7; body_len]);
        let c = h3_client(p.server.udp_addr, s, cells.0);
        wait_h3(&c.handle, |r| !r.closed.is_empty());
        {
            let r = c.handle.lock();
            assert_eq!(h3_header(&r, ":status").as_deref(), Some("403"));
            assert_eq!(r.closed[0].0.stats.stream_err, 0, "{:?}", r.closed);
            assert_eq!(r.closed[0].0.stats.send_body, body_len as u64);
        }
        wait_log(&["mq.req", "status=403", &format!("req_bytes={body_len} ")]);
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

// spec §6.2 step 8, §10.3: `content-length: 10` with FIN on HEADERS reaches the origin
// bodiless (no chunked framing, no positive length). adoption spec §5.3 (6): a `Wire` server
// finds the mismatch in the read that delivers the HEADERS, so the gateway's intake read
// fails (its line has `path="-"`, which no cell can match) and the origin sees nothing.
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
            let stats = c.handle.lock().closed[0].0.stats.clone();
            assert_ne!(stats.stream_err, 0, "{stats:?}");
            stop(c);
            assert_eq!(p.join_both(), (0, 0));
            assert!(o.settled().is_empty(), "the origin saw a request");
            return;
        }
        wait_h3(&c.handle, |r| r.fin);
        assert_eq!(
            h3_header(&c.handle.lock(), ":status").as_deref(),
            Some("200")
        );
        let seen = o.one();
        assert!(seen.complete && seen.body.is_empty(), "{seen:?}");
        assert!(!seen.head.contains("transfer-encoding"), "{}", seen.head);
        let cl = seen
            .head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"));
        assert!(cl.is_none_or(|v| v.trim() == "0"), "{}", seen.head);
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
        assert_eq!(
            h3_header(&c.handle.lock(), ":status").as_deref(),
            Some("200")
        );
        let seen = o.one();
        assert!(
            seen.head.contains("\r\ntransfer-encoding: chunked\r\n"),
            "{}",
            seen.head
        );
        assert_eq!(dechunk(&seen.body).as_deref(), Some(&b"hello body"[..]));
        stop(c);
        assert_eq!(p.join_both(), (0, 0));
    }
);

/// A direct-H3 upload the server must reset (§6.3): the client sees the reset, the server
/// logs the request, and the origin never received a complete body. On a `Wire` server the
/// reset is h3wire's (`H3_MESSAGE_ERROR`, adoption spec §5.3 (6)), and the gateway still logs
/// it as `local reset`.
fn upload_reset(
    cells: (Backend, Backend),
    path: &str,
    cl: &str,
    body: Vec<u8>,
    truncate: bool,
) -> H3Handle {
    let o = Capture::spawn();
    let p = gateway(cells);
    let auth = bearer();
    let extra = [("x-mq-auth", auth.as_str()), ("content-length", cl)];
    let mut s = script("POST", &o.authority(), path, &extra, body);
    s.truncate_after_partial = truncate;
    let c = h3_client(p.server.udp_addr, s, cells.0);
    wait_h3(&c.handle, |r| !r.closed.is_empty());
    {
        let r = c.handle.lock();
        assert_ne!(r.closed[0].0.stats.stream_err, 0, "{r:?}");
        assert!(!r.fin, "{r:?}");
    }
    let line = wait_log(&["mq.req", &format!("path=\"{path}\"")]);
    assert!(line.contains("reset=\"local reset\""), "{line}");
    let seen = o.settled();
    assert!(seen.iter().all(|s| !s.complete), "{seen:?}");
    let h = c.handle.clone();
    stop(c);
    assert_eq!(p.join_both(), (0, 0));
    h
}

// spec §6.3, §10.3: 50 bytes + FIN (a complete frame) under `content-length: 100`.
matrix!(
    direct_h3_short_request_body_resets,
    |cells: (Backend, Backend), tag: &str| {
        upload_reset(
            cells,
            &format!("/short-req-{tag}"),
            "100",
            vec![1; 50],
            false,
        );
    }
);

// spec §6.3, §10.3: 50 bytes under `content-length: 10`.
matrix!(
    direct_h3_excess_request_body_resets,
    |cells: (Backend, Backend), tag: &str| {
        upload_reset(
            cells,
            &format!("/excess-req-{tag}"),
            "10",
            vec![1; 50],
            false,
        );
    }
);

/// spec §3.7 (3), §6.3, Review Focus 5: the request's DATA frame is cut by FIN inside its
/// declared length (`CUT_BODY` under `content-length: 33554432`, partial acceptance then
/// `h3_finish`); the server's upload check resets the request.
#[test]
fn direct_h3_request_body_cut_inside_frame_resets() {
    let cl = CUT_BODY.to_string();
    let h = upload_reset(XX, "/cut-req", &cl, vec![2; CUT_BODY], true);
    let accepted = h.lock().accepted.expect("partial acceptance");
    assert!(0 < accepted && accepted < CUT_BODY, "accepted {accepted}");
}

/// spec §6.2, §12, §10.3: an embedded NUL in `x-mq-auth`, `:path` and `x-mq-class` gives
/// 403 / 400 / `?` in the log.
#[test]
fn nul_in_auth_path_class_direct_h3() {
    let o = Capture::spawn();
    let p = gateway(XX);
    let auth = bearer();
    let nul_auth = format!("{auth}\0junk");
    let a = o.authority();
    let cases = [
        (
            script(
                "GET",
                &a,
                "/nul-auth",
                &[("x-mq-auth", &nul_auth)],
                Vec::new(),
            ),
            ("403", Some("auth-failed")),
        ),
        (
            script("GET", &a, "/ok\0junk", &[("x-mq-auth", &auth)], Vec::new()),
            ("400", Some("bad-target")),
        ),
        (
            script(
                "GET",
                &a,
                "/nul-class",
                &[("x-mq-auth", &auth), ("x-mq-class", "nul\0class-marker")],
                Vec::new(),
            ),
            ("200", None),
        ),
    ];
    for (s, (status, xmq)) in cases {
        let c = h3_client(p.server.udp_addr, s, Backend::XqcH3);
        wait_h3(&c.handle, |r| r.fin);
        {
            let r = c.handle.lock();
            assert_eq!(h3_header(&r, ":status").as_deref(), Some(status));
            assert_eq!(h3_header(&r, "x-mq-error").as_deref(), xmq);
        }
        stop(c);
    }
    wait_log(&["x-mq-class='nul?class-marker'"]);
    assert_eq!(p.join_both(), (0, 0));
}
