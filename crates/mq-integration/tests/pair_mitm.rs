//! SP4 spec §11.3: the MITM client and the gateway server on two production drivers over
//! loopback UDP, real xquic, against real origins. The test thread plays the browser
//! (`TestBrowser`: rustls + `h2::client`), connecting only to the client's `TRANSPARENT`
//! listener, whose accepts carry the origin's address as their original destination (R3).
#![forbid(unsafe_code)]

use mq_integration::browser::{Body, Resp, TestBrowser, roots};
use mq_integration::log_tap;
use mq_integration::loopback::LoopbackProxy;
use mq_integration::origin_server::{
    Handler, ORIGIN_CA, ORIGIN_CRT, OriginServer, OriginServerMode, Proto,
};
use mq_proxy::client::mitm::MitmTuning;
use mq_proxy::client::mitm::ca::Ca;
use mq_proxy::client::mitm::policy::IgnoreHosts;
use mq_proxy::config::{ClientConfig, MitmConfig, ServerConfig};
use mq_proxy::server::origin::host::upload_byte;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TOKEN: &str = "s3cret";
const MIB: usize = 1 << 20;
const T: Duration = Duration::from_secs(10);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/certs/rust-mitm"
    ))
    .join(name)
}

/// A `MitmConfig` for fixture CA `name`; `Ca::load` needs the key in a 0600 file of ours,
/// so both files are copied into a fresh temp dir first.
fn mitm_cfg(name: &str, ignore: &[&str], tuning: MitmTuning) -> MitmConfig {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("mq-pair-mitm-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let (crt, key) = (format!("{name}.crt"), format!("{name}.key"));
    for f in [&crt, &key] {
        std::fs::copy(fixture(f), d.join(f)).unwrap();
        std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ca = Ca::load(&d.join(&crt), &d.join(&key)).expect("fixture CA");
    std::fs::remove_dir_all(&d).unwrap();
    MitmConfig {
        ca: Arc::new(ca),
        ignore: IgnoreHosts::parse(ignore.iter().copied()).expect("ignore list"),
        tuning,
    }
}

fn p256() -> MitmConfig {
    mitm_cfg("ca-p256", &[], MitmTuning::default())
}

/// The pair, its `TRANSPARENT` accepts stamped with `origin` (R3).
fn proxy(origin: SocketAddr, mitm: MitmConfig) -> LoopbackProxy {
    // The routing decisions are logged at debug (SP4 spec §7.10). Once: `install` resets
    // the level to Info, which would race a parallel test's debug line.
    static TAP: Once = Once::new();
    TAP.call_once(|| {
        log_tap::install();
        log::set_max_level(log::LevelFilter::Debug);
    });
    let client = ClientConfig {
        token: TOKEN.into(),
        reconnect_max_backoff: Duration::from_secs(1),
        ..ClientConfig::default()
    };
    let server = ServerConfig {
        token: TOKEN.into(),
        ..ServerConfig::default()
    };
    LoopbackProxy::spawn_mitm(client, server, Path::new(ORIGIN_CA), mitm, origin)
}

fn origin(proto: Proto, handler: Handler) -> OriginServer {
    // `localhost:<port>` may resolve to ::1 first; the gateway dials one address only.
    OriginServer::spawn(OriginServerMode {
        dual_stack: true,
        ..OriginServerMode::new(proto, handler)
    })
}

/// A browser trusting `roots_pem` (the MITM CA, or the origin CA for opaque routes).
fn browser(p: &LoopbackProxy, o: SocketAddr, roots_pem: &Path) -> TestBrowser {
    let authority = format!("localhost:{}", o.port());
    TestBrowser::new(p.mitm_addr(), authority, roots(roots_pem))
}

/// A browser trusting `ca-p256`, once the H3 tunnel is up.
fn mitm_browser(p: &LoopbackProxy, o: SocketAddr) -> TestBrowser {
    let b = browser(p, o, &fixture("ca-p256.crt"));
    wait_up(&b);
    b
}

fn xmq_error(r: &Resp) -> Option<&str> {
    r.1.get("x-mq-error").map(|v| v.to_str().unwrap())
}

fn tunnel_unavailable(r: &Resp) -> bool {
    r.0 == 502 && xmq_error(r) == Some("tunnel-unavailable")
}

/// HEAD probes until the client stops answering 502 `tunnel-unavailable`.
fn wait_up(b: &TestBrowser) {
    let end = Instant::now() + T;
    loop {
        let r = b
            .request("HEAD", None, "/up", &[], Body::Empty)
            .expect("probe");
        if !tunnel_unavailable(&r) {
            return;
        }
        assert!(Instant::now() < end, "the H3 tunnel never came up");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Polls `cond` every 5 ms until it holds (at most `T`).
fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let end = Instant::now() + T;
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Tests that wait for a log line run one at a time: lines accumulate across this binary.
static SERIAL: Mutex<()> = Mutex::new(());

/// A log marker a test waits for, with `SERIAL` held from before the test starts.
struct Logged {
    marker: &'static str,
    before: usize,
    _serial: MutexGuard<'static, ()>,
}

impl Logged {
    fn start(marker: &'static str) -> Logged {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let before = Logged::count(marker);
        Logged {
            marker,
            before,
            _serial,
        }
    }

    fn count(marker: &str) -> usize {
        log_tap::lines()
            .iter()
            .filter(|l| l.contains(marker))
            .count()
    }

    /// A line with the marker logged since `start` (at most `T`).
    fn wait(&self) {
        let seen = || Logged::count(self.marker) > self.before;
        wait_until(&format!("a log line with {:?}", self.marker), seen);
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len as u64).map(upload_byte).collect()
}

fn origin_cert() -> CertificateDer<'static> {
    CertificateDer::from_pem_file(ORIGIN_CRT).expect("origin.crt")
}

/// An opaque route: the chain is the origin's own, which the origin CA verified.
fn assert_origin_chain(chain: &[CertificateDer<'_>]) {
    assert_eq!(
        chain.first(),
        Some(&origin_cert()),
        "not the origin's certificate"
    );
}

fn header<'a>(h: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    (h.iter().filter(|(n, _)| n == name))
        .map(|(_, v)| &v[..])
        .collect()
}

// ---- data ----

// SP4 spec §11.3: a byte-exact 8 MiB download, from an h1 and an h2 TLS origin.
#[test]
fn mitm_8mib_download_byte_exact_h1_and_h2_origin() {
    let len = 8 * MIB;
    for proto in [Proto::H1Tls, Proto::H2Tls] {
        let o = origin(proto, Handler::FileBytes(len as u64));
        let p = proxy(o.addr, p256());
        let b = mitm_browser(&p, o.addr);
        let (status, h, body) = b.get("/dl", &[]);
        assert_eq!(status, 200);
        assert_eq!(h.get("content-length").unwrap(), "8388608");
        assert!(body == pattern(len), "body differs ({} bytes)", body.len());
        assert_eq!(p.join_both(), (0, 0));
    }
}

// SP4 spec §7.5 step 6, §11.3: 8 MiB uploads echoed back, with a known length (forwarded
// as `content-length`) and streamed (none).
#[test]
fn mitm_8mib_upload_known_cl_and_streaming() {
    let o = origin(Proto::H2Tls, Handler::Echo);
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let data = pattern(8 * MIB);
    for (path, known) in [("/known", true), ("/streaming", false)] {
        let (status, _, body) = b.post(path, &[], data.clone(), known);
        assert_eq!(status, 200, "{path}");
        assert!(body == data, "{path}: echo differs ({} bytes)", body.len());
    }
    let reqs = o.requests();
    let cl = |path: &str| {
        let r = reqs.iter().find(|r| r.path == path).expect("request");
        header(&r.headers, "content-length").concat()
    };
    assert_eq!(cl("/known"), b"8388608");
    assert_eq!(cl("/streaming"), b"");
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §11.3: 16 concurrent streams on one browser connection.
#[test]
fn mitm_16_parallel_streams() {
    let len = 256 * 1024;
    let o = origin(Proto::H2Tls, Handler::FileBytes(len as u64));
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let all = b.get_parallel(16, "/p");
    assert_eq!(all.len(), 16);
    for (status, _, body) in all {
        assert_eq!(status, 200);
        assert!(body == pattern(len), "body differs ({} bytes)", body.len());
    }
    assert_eq!(p.join_both(), (0, 0));
}

// ---- request and response shape ----

// SP4 spec §7.5 step 4: a 6 KiB cookie sent as crumbs arrives as one joined field at an
// h1 origin.
#[test]
fn mitm_split_cookie_joined_at_h1_origin() {
    let o = origin(Proto::H1Tls, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let crumbs: Vec<String> = (0..6)
        .map(|i| format!("c{i}={}", "x".repeat(1020)))
        .collect();
    let hs: Vec<(&str, &[u8])> = crumbs.iter().map(|c| ("cookie", c.as_bytes())).collect();
    assert_eq!(b.get("/cookie", &hs).0, 200);
    let reqs = o.requests();
    let r = reqs.iter().find(|r| r.path == "/cookie").expect("request");
    assert_eq!(header(&r.headers, "cookie"), [crumbs.join("; ").as_bytes()]);
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §5, §11.3: a 4 KiB `:path` and a 6 KiB CSP response header pass.
#[test]
fn mitm_4k_path_and_6k_csp() {
    let csp = "a".repeat(6 * 1024);
    let h = Handler::WithHeaders(
        vec![("content-security-policy", csp.clone())],
        Box::new(Handler::Status(200)),
    );
    let o = origin(Proto::H2Tls, h);
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let path = format!("/long?q={}", "q".repeat(4 * 1024));
    let (status, h, _) = b.get(&path, &[]);
    assert_eq!(status, 200);
    assert_eq!(h.get("content-security-policy").unwrap(), &csp[..]);
    assert!(o.requests().iter().any(|r| r.path == path), "path not seen");
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §5 "Methods", "Empty header values": both reach the origin unchanged.
#[test]
fn mitm_lowercase_method_and_empty_header_reach_origin() {
    let o = origin(Proto::H1Tls, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let r = b.request("purgeit", None, "/m", &[("x-empty", b"")], Body::Empty);
    assert_eq!(r.expect("request").0, 200);
    let reqs = o.requests();
    let r = reqs.iter().find(|r| r.path == "/m").expect("request");
    assert_eq!(r.method, "purgeit");
    assert_eq!(header(&r.headers, "x-empty"), [b""]);
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §5 "Browser h2 side" and "Errors": a browser section over `SECTION_MAX` gets
// h2's own 431 or a reset; a rendered head over a limit gets 400 `header-too-long`; a
// response over a limit gets 502 `upstream-protocol`.
#[test]
fn mitm_over_limit_400_or_431_and_502() {
    let h = Handler::PerPath(vec![("/big-resp", Handler::HeaderListBytes(9000))]);
    let o = origin(Proto::H2Tls, h);
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);

    // 5 × 7000 bytes: every field within FIELD_MAX, the section over SECTION_MAX.
    let v = vec![b'v'; 7000];
    let names: Vec<String> = (0..5).map(|i| format!("x-big{i}")).collect();
    let hs: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &v[..])).collect();
    match b.request("GET", None, "/section", &hs, Body::Empty) {
        Ok(r) => assert_eq!(r.0, 431),
        Err(e) => assert!(e.is_reset(), "{e}"),
    }

    // One 9000-byte field: under SECTION_MAX for h2, over FIELD_MAX for the render.
    let v = vec![b'v'; 9000];
    let r = b.request("GET", None, "/field", &[("x-big", &v)], Body::Empty);
    let r = r.expect("request");
    assert_eq!(
        (r.0.as_u16(), xmq_error(&r)),
        (400, Some("header-too-long"))
    );

    let r = b.get("/big-resp", &[]);
    assert_eq!(
        (r.0.as_u16(), xmq_error(&r)),
        (502, Some("upstream-protocol"))
    );
    assert!(
        !o.requests()
            .iter()
            .any(|r| r.path == "/section" || r.path == "/field")
    );
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.7 (D9): `alt-svc` is dropped; other headers stay.
#[test]
fn mitm_alt_svc_stripped() {
    let h = Handler::WithHeaders(
        vec![
            ("alt-svc", "h3=\":443\"; ma=86400".into()),
            ("x-kept", "yes".into()),
        ],
        Box::new(Handler::Status(200)),
    );
    let o = origin(Proto::H2Tls, h);
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let (status, h, _) = b.get("/alt", &[]);
    assert_eq!(status, 200);
    assert_eq!(h.get("x-kept").unwrap(), "yes");
    assert!(h.get("alt-svc").is_none(), "{h:?}");
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.5 step 3: `:authority` ≠ SNI → 421, no `x-mq-error`, nothing forwarded.
#[test]
fn mitm_421_on_authority_mismatch() {
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    let other = format!("other.localhost:{}", o.addr.port());
    let r = b.request("GET", Some(&other), "/misdirected", &[], Body::Empty);
    let r = r.expect("request");
    assert_eq!((r.0.as_u16(), xmq_error(&r)), (421, None));
    assert!(!o.requests().iter().any(|r| r.path == "/misdirected"));
    assert_eq!(p.join_both(), (0, 0));
}

// ---- tunnel ----

/// One request across a tunnel loss.
#[derive(Debug, PartialEq)]
enum Outage {
    Served,
    Unavailable,
    /// A stream reset, or 502 `upstream-reset` for a request opened on the old tunnel
    /// conn before the client saw it close.
    Transition,
}

/// Requests across a tunnel loss may only see, in this order: 502 `upstream-reset`, then
/// 502 `tunnel-unavailable` (`unavailable` remembers it), then 200 once the tunnel is
/// back; a stream reset anywhere. Anything else fails, and so does a connection error
/// (GOAWAY, I/O): the browser connection must survive the tunnel.
fn during_outage(b: &TestBrowser, path: &str, unavailable: &Cell<bool>) -> Outage {
    match b.request("GET", None, path, &[], Body::Empty) {
        Ok(r) if r.0 == 200 => Outage::Served,
        Ok(r) if tunnel_unavailable(&r) => {
            unavailable.set(true);
            Outage::Unavailable
        }
        Ok(r) => {
            let early = !unavailable.get() && r.0 == 502;
            assert!(early && xmq_error(&r) == Some("upstream-reset"), "{r:?}");
            Outage::Transition
        }
        Err(e) => {
            assert!(e.is_reset() && !e.is_go_away() && !e.is_io(), "{e}");
            Outage::Transition
        }
    }
}

// SP4 spec §10: with the tunnel down, a request gets 502 `tunnel-unavailable` and the
// browser connection stays usable.
#[test]
fn mitm_tunnel_down_502() {
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    assert_eq!(b.get("/before", &[]).0, 200);
    p.server.shutdown.trigger();
    let seen = Cell::new(false);
    wait_until("502 tunnel-unavailable", || {
        during_outage(&b, "/down", &seen) == Outage::Unavailable
    });
    assert_eq!(p.join_both(), (0, 0));
}

// Review Focus 1: the tunnel drops (server restart) while a MITM stream is in flight.
// That stream ends with 502 `upstream-reset` (SP4 spec §10) or a stream reset; requests during the outage follow
// `during_outage`'s order; once the tunnel is back, the same browser
// connection is served on it. `TestBrowser` never redials, so a success on its one
// `SendRequest` after the restart is that connection.
#[test]
fn mitm_survives_tunnel_reconnect() {
    let h = Handler::PerPath(vec![
        ("/hang", Handler::HangNoResponse),
        ("/before", Handler::Status(200)),
        ("/after", Handler::Status(200)),
    ]);
    let o = origin(Proto::H2Tls, h);
    let mut p = proxy(o.addr, p256());
    let b = mitm_browser(&p, o.addr);
    assert_eq!(b.get("/before", &[]).0, 200);

    let hang = b.start_get("/hang");
    b.drive_until(|| o.requests().iter().any(|r| r.path == "/hang"));
    p.restart_server();
    match b.finish(hang) {
        Ok(r) => assert_eq!((r.0.as_u16(), xmq_error(&r)), (502, Some("upstream-reset"))),
        Err(e) => assert!(e.is_reset() && !e.is_go_away() && !e.is_io(), "{e}"),
    }

    let seen = Cell::new(false);
    wait_until("a 200 on the new tunnel", || {
        during_outage(&b, "/after", &seen) == Outage::Served
    });
    assert_eq!(p.join_both(), (0, 0));
}

// ---- opaque routes: the origin's own certificate, verified with the origin CA ----

// SP4 spec §7.3 route step 3: no `h2` in ALPN → opaque.
#[test]
fn opaque_no_h2_alpn() {
    let log = Logged::start("opaque(NoH2)");
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let b = browser(&p, o.addr, Path::new(ORIGIN_CA));
    assert_origin_chain(&b.tls_only(&[b"http/1.1"], "localhost"));
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.3 route step 4: an ignored host → opaque; h2 then runs with the origin.
#[test]
fn opaque_ignored_host() {
    let log = Logged::start("opaque(Ignored)");
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let p = proxy(
        o.addr,
        mitm_cfg("ca-p256", &["localhost"], MitmTuning::default()),
    );
    let b = browser(&p, o.addr, Path::new(ORIGIN_CA));
    assert_origin_chain(&b.tls_only(&[b"h2"], "localhost"));
    assert_eq!(b.get("/direct", &[]).0, 200);
    assert!(o.requests().iter().any(|r| r.path == "/direct"));
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.3 "Peek": bytes that are not TLS → opaque, relayed as they are.
#[test]
fn opaque_non_tls_bytes() {
    let log = Logged::start("opaque(NotTls)");
    let o = origin(Proto::H1Plain, Handler::Status(200));
    let p = proxy(o.addr, p256());
    let mut s = TcpStream::connect(p.mitm_addr()).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s.write_all(b"GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"), "{reply:?}");
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.3 route step 5: an SNI outside a NameConstraints CA's scope → opaque.
#[test]
fn opaque_out_of_scope_constrained_ca() {
    let log = Logged::start("opaque(OutOfCaScope)");
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let mitm = mitm_cfg("ca-dns-constraint", &[], MitmTuning::default());
    let p = proxy(o.addr, mitm);
    let b = browser(&p, o.addr, Path::new(ORIGIN_CA));
    assert_origin_chain(&b.tls_only(&[b"h2"], "localhost"));
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.3: no ClientHello within the peek deadline → opaque; a handshake started
// afterwards reaches the origin.
#[test]
fn opaque_peek_timeout() {
    let log = Logged::start("opaque(Timeout)");
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let tuning = MitmTuning {
        peek: Duration::from_millis(200),
        ..MitmTuning::default()
    };
    let p = proxy(o.addr, mitm_cfg("ca-p256", &[], tuning));
    let b = browser(&p, o.addr, Path::new(ORIGIN_CA));
    let tcp = TcpStream::connect(p.mitm_addr()).unwrap();
    log.wait();
    assert_origin_chain(&b.tls_on(tcp, &[b"h2"], "localhost"));
    assert_eq!(p.join_both(), (0, 0));
}

/// A plain TCP origin that reads to EOF, writes back what it read, and closes.
fn echo_to_eof() -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(T)).unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        s.write_all(&got).unwrap();
        got
    });
    (addr, t)
}

// SP4 spec §7.3 "EOF and errors while peeking": a half-close with bytes in rx → opaque;
// the relay carries the bytes and the EOF, and the answer still comes back.
#[test]
fn opaque_peek_eof_half_close() {
    let log = Logged::start("opaque(Eof)");
    let (addr, origin) = echo_to_eof();
    let p = proxy(addr, p256());
    let mut s = TcpStream::connect(p.mitm_addr()).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    // A TLS record header prefix: the peek waits for more, then sees the EOF.
    let sent = [0x16, 0x03, 0x01, 0x00];
    s.write_all(&sent).unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, sent);
    assert_eq!(origin.join().unwrap(), sent);
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}

// SP4 spec §7.3 "Accept" step 2: at `max_conns` (lowered to 1) a new flow goes opaque.
#[test]
fn opaque_at_capacity() {
    let log = Logged::start("opaque(AtCapacity)");
    let o = origin(Proto::H2Tls, Handler::Status(200));
    let tuning = MitmTuning {
        max_conns: 1,
        ..MitmTuning::default()
    };
    let p = proxy(o.addr, mitm_cfg("ca-p256", &[], tuning));
    // The one MITM conn, live.
    let held = mitm_browser(&p, o.addr);
    let b = browser(&p, o.addr, Path::new(ORIGIN_CA));
    assert_origin_chain(&b.tls_only(&[b"h2"], "localhost"));
    assert_eq!(held.get("/still", &[]).0, 200);
    log.wait();
    assert_eq!(p.join_both(), (0, 0));
}
