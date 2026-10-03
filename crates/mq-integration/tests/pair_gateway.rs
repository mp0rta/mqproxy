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
use mq_integration::loopback::{LoopbackProxy, transport};
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
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

fn gateway_with(server: ServerConfig) -> LoopbackProxy {
    log_tap::install();
    LoopbackProxy::spawn_gateway(ClientConfig::default(), server, Path::new(ORIGIN_CA))
}

fn gateway() -> LoopbackProxy {
    gateway_with(server_cfg())
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
fn wait_up(p: &LoopbackProxy) {
    let r = fetch_when_up(p.fetch_addr(), &auth("http://127.0.0.1:1/probe", "nope"));
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

/// An `H3Client` on its own driver against the gateway server.
fn h3_client(server: SocketAddr, s: H3Script) -> DriverThread<H3Handle> {
    let cfg = DriverConfig {
        resolver: Arc::new(StdResolver),
        install_signal_handlers: false,
        ..DriverConfig::default()
    };
    let lo = Ipv4Addr::LOCALHOST.into();
    let mut d = DriverThread::spawn_on(lo, cfg, Vec::new(), move |local| {
        let (app, h) = H3Client::new(server, s);
        (Shard::new(transport(Role::Client, true), app, local, 3), h)
    });
    d.start();
    d
}

fn stop(d: DriverThread<H3Handle>) {
    d.shutdown.trigger();
    d.join();
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

/// spec §5.4, §6.4, §10.3: an 8 MiB download with `content-length` over an h2 TLS origin.
#[test]
fn fetch_download_8mib_cl() {
    let len = 8 * MIB;
    let o = OriginServer::spawn(OriginServerMode::new(
        Proto::H2Tls,
        Handler::FileBytes(len as u64),
    ));
    let p = gateway();
    wait_up(&p);
    let url = format!("https://127.0.0.1:{}/dl", o.addr.port());
    let r = parse(&fetch(&p, &url, &[], b"").expect("download"));
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length"), Some("8388608"));
    assert!(
        r.body == pattern(len),
        "body differs ({} bytes)",
        r.body.len()
    );
    p.join_both();
}

/// spec §5.3, §6.3, §10.3: an 8 MiB `PUT` upload, streamed back by an h1 echo origin.
#[test]
fn fetch_upload_8mib_put() {
    let o = OriginServer::spawn(OriginServerMode::new(Proto::H1Plain, Handler::Echo));
    let p = gateway();
    wait_up(&p);
    let body = pattern(8 * MIB);
    let url = format!("http://{}/up", o.addr);
    let r = parse(&fetch(&p, &url, &[("X-Mq-Method", "PUT")], &body).expect("upload"));
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-length"), Some("8388608"));
    assert!(r.body == body, "echo differs ({} bytes)", r.body.len());
    p.join_both();
}

/// spec §5.4, §5.5, §10.3: `content-length: 100` over a complete 50-byte DATA frame + FIN
/// from a peer: the client's own body check aborts the local socket.
#[test]
fn fetch_short_cl_response_aborts_client() {
    let (app, h) = H3EchoServer::new(EchoMode::ShortCl { cl: 100, sent: 50 });
    let p = LoopbackProxy::spawn_gateway_against(ClientConfig::default(), app);
    let r = fetch_when_up(p.fetch_addr(), &auth("http://x/short", "any"));
    assert!(is_reset(&r), "{r:?}");
    assert!(h.lock().requests >= 1);
    p.join_both();
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
    p.join_both();
}

/// spec §5.4, §6.4, §10.3: a HEAD response and a 304, each carrying `content-length`,
/// finish cleanly (the HEAD reply's length is rewritten to 0, §12).
#[test]
fn head_and_304_with_cl_finish_cleanly() {
    let raw = |reply: &[u8]| {
        let proto = Proto::RawH1 {
            tls: false,
            reply: reply.to_vec(),
        };
        OriginServer::spawn(OriginServerMode::new(proto, Handler::Echo))
    };
    let head = raw(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n");
    let nm = raw(b"HTTP/1.1 304 Not Modified\r\ncontent-length: 100\r\n\r\n");
    let p = gateway();
    wait_up(&p);
    let r = fetch(
        &p,
        &format!("http://{}/h", head.addr),
        &[("X-Mq-Method", "HEAD")],
        b"",
    );
    let r = parse(&r.expect("HEAD finishes cleanly"));
    assert_eq!((r.status, r.header("content-length")), (200, Some("0")));
    assert!(r.body.is_empty());
    let r = parse(
        &fetch(&p, &format!("http://{}/n", nm.addr), &[], b"").expect("304 finishes cleanly"),
    );
    assert_eq!((r.status, r.header("content-length")), (304, Some("100")));
    assert!(r.body.is_empty());
    p.join_both();
}

/// spec §7.4, §10.3: `/a/../b` reaches the origin as `/b` (the query untouched).
#[test]
fn dot_segments_normalised_at_origin() {
    let o = Capture::spawn();
    let p = gateway();
    wait_up(&p);
    let r = parse(&fetch(&p, &o.url("/a/../b?q=/../x"), &[], b"").expect("fetch"));
    assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
    let head = o.one().head;
    assert!(head.starts_with("get /b?q=/../x http/1.1\r\n"), "{head}");
    p.join_both();
}

/// spec §7.4, §10.3: an empty forwarded `x-test:` is not sent, and an empty `accept:`
/// suppresses the default `accept: */*`.
#[test]
fn empty_header_not_sent_empty_accept_suppresses_default() {
    let o = Capture::spawn();
    let p = gateway();
    wait_up(&p);
    let extra = [("X-Test", ""), ("Accept", ""), ("X-Kept", "yes")];
    let r = parse(&fetch(&p, &o.url("/empty"), &extra, b"").expect("fetch"));
    assert_eq!(r.status, 200);
    let head = o.one().head;
    assert!(head.contains("\r\nx-kept: yes\r\n"), "{head}");
    assert!(!head.contains("x-test"), "{head}");
    assert!(!head.contains("\r\naccept:"), "{head}");
    p.join_both();
}

/// spec §7.2, §7.7, §10.3 (e2e case 13): an h1-forced request reuses the idle h1 conn a
/// default request left in the pool — against an origin that serves one conn at a time, a
/// second dial would hang until `curl:28`.
#[test]
fn h1_forced_reuses_idle_default_conn() {
    let mode = OriginServerMode {
        single_conn: true,
        ..OriginServerMode::new(Proto::H1Tls, Handler::FileBytes(2))
    };
    let o = OriginServer::spawn(mode);
    let mut cfg = server_cfg();
    if let Some(g) = cfg.gateway.as_mut() {
        g.origin_connect_timeout = Duration::from_secs(2);
    }
    let p = gateway_with(cfg);
    wait_up(&p);
    let url = format!("https://127.0.0.1:{}/c13", o.addr.port());
    let r = parse(&fetch(&p, &url, &[], b"").expect("default request"));
    assert_eq!((r.status, r.body.len()), (200, 2));
    let r = fetch(&p, &url, &[("X-Mq-Origin-Protocol", "h1")], b"");
    let r = parse(&r.expect("h1-forced request"));
    assert_eq!((r.status, r.body.len()), (200, 2));
    assert_eq!(o.accepted(), 1);
    p.join_both();
}

/// spec §6.4, §10.3: an h2 origin declares `content-length: 100`, sends 50 bytes and then
/// RST_STREAM(NO_ERROR): the server's body check resets the H3 response and the Rust
/// client's local reply is an abort.
#[test]
fn h2_cl_100_then_rst_resets_h3_end_to_end() {
    let h = Handler::ClTooShort { cl: 100, send: 50 };
    let o = OriginServer::spawn(OriginServerMode::new(Proto::H2Tls, h));
    let p = gateway();
    wait_up(&p);
    let url = format!("https://127.0.0.1:{}/h2-short", o.addr.port());
    let r = fetch(&p, &url, &[], b"");
    assert!(
        is_reset(&r),
        "{:?}",
        r.as_ref().map(|b| String::from_utf8_lossy(b).into_owned())
    );
    // The reset is the server's (its check), not only the client's own body check.
    let line = wait_log(&["mq.req", "path=\"/h2-short\""]);
    assert!(line.contains("reset=\"local reset\""), "{line}");
    p.join_both();
}

/// spec §5.2, §6.2, §10.3: CONNECT is refused by the fetch listener (400 `bad-method`) and
/// by the server intake (400 `bad-request`).
#[test]
fn connect_rejected_both_intakes() {
    let p = gateway();
    let r = fetch(
        &p,
        "http://127.0.0.1:1/",
        &[("X-Mq-Method", "CONNECT")],
        b"",
    );
    let want = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\nX-Mq-Error: bad-method\r\n\r\n";
    assert_eq!(
        String::from_utf8_lossy(&r.expect("reply")),
        String::from_utf8_lossy(want)
    );
    let auth = bearer();
    let s = script(
        "CONNECT",
        "127.0.0.1:1",
        "/",
        &[("x-mq-auth", &auth)],
        Vec::new(),
    );
    let c = h3_client(p.server.udp_addr, s);
    wait_h3(&c.handle, |r| r.fin);
    {
        let r = c.handle.lock();
        assert_eq!(h3_header(&r, ":status").as_deref(), Some("400"));
        assert_eq!(h3_header(&r, "x-mq-error").as_deref(), Some("bad-request"));
    }
    stop(c);
    p.join_both();
}

// ---- direct H3 against the gateway server ----

/// spec §3.7 (1), §6.3, Review Focus 3: a 4 MiB body sent after a 403 is drained, so the
/// server's `recv_body_size` (`req_bytes`) reports the whole body.
#[test]
fn drain_after_403_counts_whole_body() {
    let p = gateway();
    let body_len = 4 * MIB;
    let extra = [("x-mq-auth", "Bearer wrong")];
    let s = script("POST", "127.0.0.1:1", "/drain", &extra, vec![7; body_len]);
    let c = h3_client(p.server.udp_addr, s);
    wait_h3(&c.handle, |r| !r.closed.is_empty());
    {
        let r = c.handle.lock();
        assert_eq!(h3_header(&r, ":status").as_deref(), Some("403"));
        assert_eq!(r.closed[0].0.stats.stream_err, 0, "{:?}", r.closed);
        assert_eq!(r.closed[0].0.stats.send_body, body_len as u64);
    }
    wait_log(&["mq.req", "status=403", &format!("req_bytes={body_len} ")]);
    stop(c);
    p.join_both();
}

/// spec §6.2 step 8, §10.3: `content-length: 10` with FIN on HEADERS reaches the origin
/// bodiless (no chunked framing, no positive length).
#[test]
fn direct_h3_cl_with_fin_on_headers_is_bodiless() {
    let o = Capture::spawn();
    let p = gateway();
    let auth = bearer();
    let extra = [("x-mq-auth", auth.as_str()), ("content-length", "10")];
    let c = h3_client(
        p.server.udp_addr,
        script("POST", &o.authority(), "/fin", &extra, Vec::new()),
    );
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
    p.join_both();
}

/// spec §7.4, §10.3: a GET with an unknown-length DATA body reaches an h1 origin chunked and
/// complete.
#[test]
fn direct_h3_get_with_body_is_chunked_on_h1() {
    let o = Capture::spawn();
    let p = gateway();
    let auth = bearer();
    let extra = [("x-mq-auth", auth.as_str())];
    let s = script(
        "GET",
        &o.authority(),
        "/chunked",
        &extra,
        b"hello body".to_vec(),
    );
    let c = h3_client(p.server.udp_addr, s);
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
    p.join_both();
}

/// A direct-H3 upload the server must reset (§6.3): the client sees the reset, the server
/// logs the request, and the origin never received a complete body.
fn upload_reset(path: &str, cl: &str, body: Vec<u8>, truncate: bool) -> H3Handle {
    let o = Capture::spawn();
    let p = gateway();
    let auth = bearer();
    let extra = [("x-mq-auth", auth.as_str()), ("content-length", cl)];
    let mut s = script("POST", &o.authority(), path, &extra, body);
    s.truncate_after_partial = truncate;
    let c = h3_client(p.server.udp_addr, s);
    wait_h3(&c.handle, |r| !r.closed.is_empty());
    {
        let r = c.handle.lock();
        assert_ne!(r.closed[0].0.stats.stream_err, 0, "{r:?}");
        assert!(!r.fin, "{r:?}");
    }
    wait_log(&["mq.req", &format!("path=\"{path}\"")]);
    let seen = o.settled();
    assert!(seen.iter().all(|s| !s.complete), "{seen:?}");
    let h = c.handle.clone();
    stop(c);
    p.join_both();
    h
}

/// spec §6.3, §10.3: 50 bytes + FIN (a complete frame) under `content-length: 100`.
#[test]
fn direct_h3_short_request_body_resets() {
    upload_reset("/short-req", "100", vec![1; 50], false);
}

/// spec §6.3, §10.3: 50 bytes under `content-length: 10`.
#[test]
fn direct_h3_excess_request_body_resets() {
    upload_reset("/excess-req", "10", vec![1; 50], false);
}

/// spec §3.7 (3), §6.3, Review Focus 5: the request's DATA frame is cut by FIN inside its
/// declared length (`CUT_BODY` under `content-length: 33554432`, partial acceptance then
/// `h3_finish`); the server's upload check resets the request.
#[test]
fn direct_h3_request_body_cut_inside_frame_resets() {
    let cl = CUT_BODY.to_string();
    let h = upload_reset("/cut-req", &cl, vec![2; CUT_BODY], true);
    let accepted = h.lock().accepted.expect("partial acceptance");
    assert!(0 < accepted && accepted < CUT_BODY, "accepted {accepted}");
}

/// spec §6.2, §12, §10.3: an embedded NUL in `x-mq-auth`, `:path` and `x-mq-class` gives
/// 403 / 400 / `?` in the log.
#[test]
fn nul_in_auth_path_class_direct_h3() {
    let o = Capture::spawn();
    let p = gateway();
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
        let c = h3_client(p.server.udp_addr, s);
        wait_h3(&c.handle, |r| r.fin);
        {
            let r = c.handle.lock();
            assert_eq!(h3_header(&r, ":status").as_deref(), Some(status));
            assert_eq!(h3_header(&r, "x-mq-error").as_deref(), xmq);
        }
        stop(c);
    }
    wait_log(&["x-mq-class='nul?class-marker'"]);
    p.join_both();
}
