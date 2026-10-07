// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Harness for the MITM front tests (SP4 spec §7): `MH`, a
//! `Shard<ScriptedTransport, MitmHost>` whose `TRANSPARENT` accepts carry an
//! original destination, and `Browser`, a rustls client trusting `ca-p256`
//! with an `h2::client` over one end of a `pipe_pair`, all polled by hand.
//! Test files declare `mod common;` next to `mod mitm_harness;`.
#![allow(dead_code)]

use crate::common::{addr, meta};
use bytes::Bytes;
use h2::client::{ResponseFuture, SendRequest};
use h2::{Reason, RecvStream, SendStream};
use mq_proxy::client::TRANSPARENT;
use mq_proxy::client::mitm::Handoff;
use mq_proxy::client::mitm::MitmTuning;
use mq_proxy::client::mitm::ca::Ca;
use mq_proxy::client::mitm::host::MitmHost;
use mq_proxy::client::mitm::policy::IgnoreHosts;
use mq_proxy::config::MitmConfig;
use mq_proxy::tls_pipe::{Dirty, PipeIo, pipe_pair};
use mq_runtime::testing::{ScriptedHandle, ScriptedTransport};
use mq_runtime::{IoRequest, IoResult, ListenerId, Shard, TcpId};
use mq_transport_api::Time;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const TOKEN: &str = "secret";

fn fixtures() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/certs/rust-mitm"
    ))
}

/// A `MitmConfig` for fixture CA `name` (`ca-p256`, `ca-dns-constraint`, …)
/// with no IgnoreHosts and the default tuning. The key is copied into a
/// 0600 temp dir first, as `Ca::load` requires.
pub fn cfg(name: &str) -> MitmConfig {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("mq-mitm-h-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let (crt, key) = (format!("{name}.crt"), format!("{name}.key"));
    for f in [&crt, &key] {
        std::fs::copy(fixtures().join(f), d.join(f)).unwrap();
        std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let ca = Ca::load(&d.join(&crt), &d.join(&key)).expect("fixture CA");
    let _ = std::fs::remove_dir_all(&d);
    MitmConfig {
        ca: Arc::new(ca),
        ignore: IgnoreHosts::default(),
        tuning: MitmTuning::default(),
    }
}

/// One h2 PING frame (17 bytes) with payload `i`.
pub fn ping_frame(i: u64) -> Vec<u8> {
    let mut f = vec![0, 0, 8, 6, 0, 0, 0, 0, 0];
    f.extend_from_slice(&i.to_be_bytes());
    f
}

/// h2 frame types.
pub const SETTINGS: u8 = 0x4;
pub const GOAWAY: u8 = 0x7;

pub struct MH {
    pub sh: Shard<ScriptedTransport, MitmHost>,
    pub t: ScriptedHandle,
    pub now: Time,
    pub tproxy: ListenerId,
    io: Vec<IoRequest>,
}

impl MH {
    /// A MITM front for `cfg` started at t = 1 s.
    pub fn new(cfg: MitmConfig) -> MH {
        let (t, h) = ScriptedTransport::new();
        let mut sh = Shard::new(t, MitmHost::new(&cfg, TOKEN), addr(4433), 7);
        let tproxy = sh.add_listener(TRANSPARENT);
        let now = Time::from_micros(1_000_000);
        sh.start(now);
        MH {
            sh,
            t: h,
            now,
            tproxy,
            io: Vec::new(),
        }
    }

    /// `ca-p256`, default tuning.
    pub fn p256() -> MH {
        MH::new(cfg("ca-p256"))
    }

    pub fn drive(&mut self) {
        self.sh.drive(self.now);
    }

    pub fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
        self.drive();
    }

    /// A browser socket captured by `TRANSPARENT`, original dst 127.0.0.1:443.
    pub fn accept(&mut self) -> TcpId {
        let tcp = self
            .sh
            .on_accepted(self.now, self.tproxy, meta(Some(addr(443))));
        let tcp = tcp.expect("below the cap");
        self.drive();
        tcp
    }

    /// The driver's read: `bytes` in as many reads as the room allows.
    pub fn tcp_in(&mut self, tcp: TcpId, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            let buf = self.sh.tcp_rx_buf(tcp);
            let n = buf.len().min(rest.len());
            assert!(n > 0, "no receive room: the app did not consume");
            buf[..n].copy_from_slice(&rest[..n]);
            self.sh.tcp_rx_commit(self.now, tcp, IoResult::Bytes(n));
            rest = &rest[n..];
        }
        self.drive();
    }

    /// As much of `bytes` as the receive buffer takes; returns that count.
    pub fn tcp_in_some(&mut self, tcp: TcpId, bytes: &[u8]) -> usize {
        let mut fed = 0;
        loop {
            let buf = self.sh.tcp_rx_buf(tcp);
            let n = buf.len().min(bytes.len() - fed);
            if n == 0 {
                break;
            }
            buf[..n].copy_from_slice(&bytes[fed..fed + n]);
            self.sh.tcp_rx_commit(self.now, tcp, IoResult::Bytes(n));
            fed += n;
        }
        self.drive();
        fed
    }

    /// The driver's write: everything queued toward the socket, committed.
    pub fn tcp_out_all(&mut self, tcp: TcpId) -> Vec<u8> {
        let out = self.sh.tcp_tx_buf(tcp).to_vec();
        self.sh
            .tcp_tx_commit(self.now, tcp, IoResult::Bytes(out.len()));
        self.drive();
        out
    }

    /// Bytes queued toward the socket, not committed.
    pub fn tcp_queued(&self, tcp: TcpId) -> usize {
        self.sh.tcp_tx_buf(tcp).len()
    }

    pub fn tcp_eof(&mut self, tcp: TcpId) {
        self.sh.tcp_rx_commit(self.now, tcp, IoResult::Eof);
        self.drive();
    }

    pub fn tcp_error(&mut self, tcp: TcpId, kind: io::ErrorKind) {
        self.sh.on_tcp_error(self.now, tcp, kind);
        self.drive();
    }

    /// The socket's unconsumed received bytes.
    pub fn rx(&mut self, tcp: TcpId) -> Vec<u8> {
        self.sh.with_app(self.now, |_, cx| cx.tcp_rx(tcp).to_vec())
    }

    pub fn shutdown(&mut self) {
        self.sh.on_shutdown_signal(self.now);
        self.drive();
    }

    /// Every `IoRequest` the shard emitted so far.
    pub fn io(&mut self) -> &[IoRequest] {
        while let Some(r) = self.sh.poll_io_request() {
            self.io.push(r);
        }
        &self.io
    }

    /// The `TcpClose` of `tcp`: `Some(abort)`.
    pub fn close_of(&mut self, tcp: TcpId) -> Option<bool> {
        self.io().iter().rev().find_map(|r| match r {
            IoRequest::TcpClose { tcp: t, abort } if *t == tcp => Some(*abort),
            _ => None,
        })
    }

    pub fn handoffs(&self) -> Vec<Handoff> {
        self.sh.app().handoffs().to_vec()
    }

    pub fn metrics(&self) -> String {
        self.sh.app().mitm_metrics_line().unwrap_or_default()
    }

    pub fn conn_count(&self) -> usize {
        self.sh.app().conn_count()
    }

    /// One round of `flow`: pending events, the proxy's output to the
    /// browser, the browser's into whatever receive room there is (the rest
    /// stays in `pending`), then a due continuation. `true` when anything
    /// moved.
    pub fn flow_step(&mut self, b: &mut Browser, tcp: TcpId, pending: &mut Vec<u8>) -> bool {
        self.drive();
        let from = self.tcp_out_all(tcp);
        pending.extend(b.exchange(&from));
        let fed = if self.close_of(tcp).is_none() {
            self.tcp_in_some(tcp, pending)
        } else {
            pending.len()
        };
        pending.drain(..fed);
        let cont = self.sh.next_timeout() == Some(self.now);
        if cont {
            self.drive();
        }
        !from.is_empty() || fed > 0 || cont
    }

    /// `relay` for bulk transfers: the receive buffer may fill, and
    /// continuations (0-delay timers) fire, until nothing moves.
    pub fn flow(&mut self, b: &mut Browser, tcp: TcpId) {
        let mut pending = Vec::new();
        for _ in 0..100_000 {
            if !self.flow_step(b, tcp, &mut pending) {
                assert!(pending.is_empty(), "browser bytes stuck");
                return;
            }
        }
        panic!("flow did not settle");
    }

    /// Bytes both ways until neither side has anything to send.
    pub fn relay(&mut self, b: &mut Browser, tcp: TcpId) {
        for _ in 0..100 {
            let from = self.tcp_out_all(tcp);
            let to = b.exchange(&from);
            if !to.is_empty() && self.close_of(tcp).is_none() {
                self.tcp_in(tcp, &to);
            }
            if from.is_empty() && to.is_empty() {
                return;
            }
        }
        panic!("relay did not settle");
    }

    /// A browser socket, its ClientHello and the TLS + h2 handshakes.
    pub fn connect(&mut self, b: &mut Browser) -> TcpId {
        let tcp = self.accept();
        self.relay(b, tcp);
        tcp
    }
}

/// `WebPkiServerVerifier` offering only `schemes` in the ClientHello.
#[derive(Debug)]
struct Schemes {
    inner: Arc<WebPkiServerVerifier>,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for Schemes {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        mids: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(end, mids, name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

type Handshake = Pin<
    Box<
        dyn Future<
            Output = Result<(SendRequest<Bytes>, h2::client::Connection<PipeIo, Bytes>), h2::Error>,
        >,
    >,
>;

/// A request's progress, as the browser sees it.
struct BStream {
    resp: Option<ResponseFuture>,
    head: Option<http::response::Parts>,
    body: Option<RecvStream>,
    data: Vec<u8>,
    done: bool,
    err: Option<String>,
    reason: Option<Reason>,
    /// The request side, kept for more body or a reset.
    up: Option<SendStream<Bytes>>,
    /// Received bytes whose capacity is held back (`Browser::hold_capacity`).
    unreleased: usize,
}

impl BStream {
    fn fail(&mut self, e: h2::Error) {
        self.reason = e.reason();
        self.err = Some(e.to_string());
        self.done = true;
    }

    fn poll(&mut self, cx: &mut Context<'_>, hold: bool) {
        if let Some(f) = &mut self.resp {
            match Pin::new(f).poll(cx) {
                Poll::Pending => return,
                Poll::Ready(Ok(r)) => {
                    let (p, b) = r.into_parts();
                    self.done = b.is_end_stream();
                    self.head = Some(p);
                    self.body = Some(b);
                }
                Poll::Ready(Err(e)) => self.fail(e),
            }
            self.resp = None;
        }
        let Some(b) = &mut self.body else { return };
        while !self.done {
            match b.poll_data(cx) {
                Poll::Pending => return,
                Poll::Ready(Some(Ok(d))) => {
                    if hold {
                        self.unreleased += d.len();
                    } else {
                        let _ = b.flow_control().release_capacity(d.len());
                    }
                    self.data.extend_from_slice(&d);
                }
                Poll::Ready(Some(Err(e))) => return self.fail(e),
                Poll::Ready(None) => self.done = true,
            }
        }
    }
}

/// A browser request; `Browser::response` reads it.
#[derive(Clone, Copy, Debug)]
pub struct StreamHandle(usize);

pub struct Browser {
    pub tls: rustls::ClientConnection,
    sni: String,
    alpn: Vec<Vec<u8>>,
    schemes: Option<Vec<SignatureScheme>>,
    /// The TLS side of the pair; h2 holds the other end.
    io: PipeIo,
    hs: Option<Handshake>,
    send: Option<SendRequest<Bytes>>,
    conn: Option<h2::client::Connection<PipeIo, Bytes>>,
    /// The h2 client conn's result once it ended.
    pub conn_end: Option<Result<(), String>>,
    polling: bool,
    dirty: Arc<Dirty>,
    streams: Vec<BStream>,
    /// Every plaintext byte from the proxy, in order, polled or not.
    pub plain_rx: Vec<u8>,
    /// `plain_rx` bytes handed to h2.
    to_h2: usize,
    /// The proxy's close_notify arrived.
    pub close_notify: bool,
    eof_to_h2: bool,
    pub tls_error: Option<rustls::Error>,
    /// Received DATA capacity is not released (`hold_capacity`).
    hold: bool,
    /// Ciphertext toward the proxy, not yet returned by `exchange`.
    ct_out: Vec<u8>,
    /// Every plaintext byte toward the proxy, in order.
    pub plain_tx: Vec<u8>,
}

/// One h2 frame: type, flags, stream id, payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub ty: u8,
    pub flags: u8,
    pub sid: u32,
    pub payload: Vec<u8>,
}

/// The h2 frames in `b`, in order.
pub fn parse_frames(mut b: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    while b.len() >= 9 {
        let len = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
        let sid = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff;
        let end = (9 + len).min(b.len());
        out.push(Frame {
            ty: b[3],
            flags: b[4],
            sid,
            payload: b[9..end].to_vec(),
        });
        b = &b[end..];
    }
    out
}

impl Browser {
    /// SNI `sni` (an IP sends none), ALPN `h2`, rustls's default schemes.
    pub fn new(sni: &str) -> Browser {
        let (h2_end, io) = pipe_pair();
        let hs: Handshake = Box::pin(h2::client::handshake(h2_end));
        Browser {
            tls: Browser::client(sni, &[b"h2".to_vec()], None),
            sni: sni.to_owned(),
            alpn: vec![b"h2".to_vec()],
            schemes: None,
            io,
            hs: Some(hs),
            send: None,
            conn: None,
            conn_end: None,
            polling: true,
            dirty: Arc::default(),
            streams: Vec::new(),
            plain_rx: Vec::new(),
            to_h2: 0,
            close_notify: false,
            eof_to_h2: false,
            tls_error: None,
            hold: false,
            ct_out: Vec::new(),
            plain_tx: Vec::new(),
        }
    }

    /// The h2 client's receive windows (before the first `exchange`).
    pub fn windows(mut self, stream: u32, conn: u32) -> Browser {
        let (h2_end, io) = pipe_pair();
        let mut b = h2::client::Builder::new();
        b.initial_window_size(stream)
            .initial_connection_window_size(conn);
        self.hs = Some(Box::pin(b.handshake(h2_end)));
        self.io = io;
        self
    }

    /// While on, received DATA is kept but its capacity is not released,
    /// so the proxy's send window shrinks.
    pub fn hold_capacity(&mut self, on: bool) {
        self.hold = on;
    }

    /// Releases the capacity `hold_capacity` held back on `h`.
    pub fn release(&mut self, h: &StreamHandle) {
        let s = &mut self.streams[h.0];
        if let Some(b) = &mut s.body {
            let _ = b.flow_control().release_capacity(s.unreleased);
            s.unreleased = 0;
        }
        self.poll_h2();
    }

    fn client(
        sni: &str,
        alpn: &[Vec<u8>],
        schemes: Option<&[SignatureScheme]>,
    ) -> rustls::ClientConnection {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        let ca = CertificateDer::from_pem_file(fixtures().join("ca-p256.crt")).unwrap();
        roots.add(ca).unwrap();
        let roots = Arc::new(roots);
        let mut c = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        c.alpn_protocols = alpn.to_vec();
        if let Some(s) = schemes {
            let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .unwrap();
            let v = Schemes {
                inner,
                schemes: s.to_vec(),
            };
            c.dangerous().set_certificate_verifier(Arc::new(v));
        }
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        rustls::ClientConnection::new(Arc::new(c), name).unwrap()
    }

    fn rebuild(&mut self) {
        self.tls = Browser::client(&self.sni, &self.alpn, self.schemes.as_deref());
    }

    /// Offers these ALPN protocols instead (before the first `exchange`).
    pub fn alpn(mut self, protos: &[&[u8]]) -> Browser {
        self.alpn = protos.iter().map(|p| p.to_vec()).collect();
        self.rebuild();
        self
    }

    /// Offers only these signature schemes (before the first `exchange`).
    pub fn sigschemes(mut self, s: &[SignatureScheme]) -> Browser {
        self.schemes = Some(s.to_vec());
        self.rebuild();
        self
    }

    /// The h2 client is no longer polled: it sends nothing (not even its
    /// preface if called first) and answers nothing; TLS goes on.
    pub fn stop_polling_h2(&mut self) {
        self.polling = false;
    }

    /// The proxy's ciphertext in; the browser's ciphertext out.
    pub fn exchange(&mut self, from_proxy: &[u8]) -> Vec<u8> {
        let mut s = from_proxy;
        while !s.is_empty() && self.tls_error.is_none() {
            if self.tls.read_tls(&mut s).is_err() {
                break;
            }
            if let Err(e) = self.tls.process_new_packets() {
                self.tls_error = Some(e);
            }
            self.read_plain();
        }
        self.poll_h2();
        self.drain_tls();
        std::mem::take(&mut self.ct_out)
    }

    fn drain_tls(&mut self) {
        while self.tls.wants_write() {
            self.tls.write_tls(&mut self.ct_out).unwrap();
        }
    }

    /// Plaintext straight into TLS, around the h2 client.
    pub fn raw_plain(&mut self, b: &[u8]) {
        self.tls.writer().write_all(b).unwrap();
    }

    /// A request for `https://<sni><path>`; an empty `body` ends the stream
    /// on HEADERS.
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> StreamHandle {
        let h = self.open(method, path, headers, body.is_empty());
        if !body.is_empty() {
            self.send(&h, body, true);
        }
        h
    }

    /// A request whose body follows through `send`.
    pub fn request_streaming(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> StreamHandle {
        self.open(method, path, headers, false)
    }

    /// More request body for `h` (h2 buffers it past the window).
    pub fn send(&mut self, h: &StreamHandle, data: &[u8], fin: bool) {
        let up = self.streams[h.0].up.as_mut().expect("request side");
        up.send_data(Bytes::copy_from_slice(data), fin).unwrap();
        self.poll_h2();
    }

    /// RST_STREAM(CANCEL) on `h`.
    pub fn cancel(&mut self, h: &StreamHandle) {
        let up = self.streams[h.0].up.as_mut().expect("request side");
        up.send_reset(Reason::CANCEL);
        self.poll_h2();
    }

    fn open(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        end: bool,
    ) -> StreamHandle {
        self.poll_h2();
        let send = self.send.as_mut().expect("h2 client ready");
        let waker = Waker::from(self.dirty.clone());
        let ready = send.poll_ready(&mut Context::from_waker(&waker));
        assert!(matches!(ready, Poll::Ready(Ok(()))), "h2 client ready");
        let mut r = http::Request::builder()
            .method(method)
            .uri(format!("https://{}{path}", self.sni));
        for (n, v) in headers {
            r = r.header(*n, *v);
        }
        let (resp, up) = send
            .send_request(r.body(()).unwrap(), end)
            .expect("send_request");
        self.streams.push(BStream {
            resp: Some(resp),
            head: None,
            body: None,
            data: Vec::new(),
            done: false,
            err: None,
            reason: None,
            up: Some(up),
            unreleased: 0,
        });
        self.poll_h2();
        StreamHandle(self.streams.len() - 1)
    }

    /// The response head and whole body, once the body ended.
    pub fn response(&mut self, h: &StreamHandle) -> Option<(http::response::Parts, Vec<u8>)> {
        self.poll_h2();
        let s = &self.streams[h.0];
        match (&s.head, s.done) {
            (Some(p), true) => Some((p.clone(), s.data.clone())),
            _ => None,
        }
    }

    /// The stream's error (a reset, or the conn's end), if any.
    pub fn stream_error(&self, h: &StreamHandle) -> Option<String> {
        self.streams[h.0].err.clone()
    }

    /// The reset reason of the stream's error, if any.
    pub fn stream_reason(&self, h: &StreamHandle) -> Option<Reason> {
        self.streams[h.0].reason
    }

    /// The response head, once it arrived.
    pub fn head(&mut self, h: &StreamHandle) -> Option<http::response::Parts> {
        self.poll_h2();
        self.streams[h.0].head.clone()
    }

    /// Response body bytes received so far.
    pub fn received(&mut self, h: &StreamHandle) -> Vec<u8> {
        self.poll_h2();
        self.streams[h.0].data.clone()
    }

    /// The h2 frames the proxy sent, in order.
    pub fn frames(&self) -> Vec<Frame> {
        parse_frames(&self.plain_rx)
    }

    /// The h2 frames the browser sent, in order (after its 24-byte preface).
    pub fn sent_frames(&self) -> Vec<Frame> {
        parse_frames(self.plain_tx.get(24..).unwrap_or_default())
    }

    /// The types of the h2 frames the proxy sent, in order.
    pub fn frame_types(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = &self.plain_rx[..];
        while b.len() >= 9 {
            let len = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
            out.push(b[3]);
            b = &b[(9 + len).min(b.len())..];
        }
        out
    }

    fn read_plain(&mut self) {
        let mut buf = [0u8; 16384];
        loop {
            match self.tls.reader().read(&mut buf) {
                Ok(0) => return self.close_notify = true,
                Ok(n) => self.plain_rx.extend_from_slice(&buf[..n]),
                Err(_) => return,
            }
        }
    }

    fn poll_h2(&mut self) {
        if !self.polling {
            return;
        }
        let waker = Waker::from(self.dirty.clone());
        let mut cx = Context::from_waker(&waker);
        for _ in 0..64 {
            self.dirty.take();
            self.push_to_h2(&mut cx);
            if let Some(hs) = &mut self.hs
                && let Poll::Ready(r) = hs.as_mut().poll(&mut cx)
            {
                let (send, conn) = r.expect("h2 client handshake");
                (self.send, self.conn, self.hs) = (Some(send), Some(conn), None);
            }
            if let Some(c) = &mut self.conn
                && let Poll::Ready(r) = Pin::new(c).poll(&mut cx)
            {
                self.conn_end = Some(r.map_err(|e| e.to_string()));
                self.conn = None;
            }
            for s in &mut self.streams {
                s.poll(&mut cx, self.hold);
            }
            self.pull_from_h2(&mut cx);
            if !self.dirty.take() {
                return;
            }
        }
    }

    /// `plain_rx` → h2, then the EOF after a close_notify.
    fn push_to_h2(&mut self, cx: &mut Context<'_>) {
        while self.to_h2 < self.plain_rx.len() {
            match Pin::new(&mut self.io).poll_write(cx, &self.plain_rx[self.to_h2..]) {
                Poll::Ready(Ok(n)) if n > 0 => self.to_h2 += n,
                _ => return,
            }
        }
        if self.close_notify && !self.eof_to_h2 {
            self.eof_to_h2 = true;
            let _ = Pin::new(&mut self.io).poll_shutdown(cx);
        }
    }

    /// What h2 wrote → TLS.
    fn pull_from_h2(&mut self, cx: &mut Context<'_>) {
        let mut buf = [0u8; 16384];
        loop {
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) if !rb.filled().is_empty() => {
                    self.plain_tx.extend_from_slice(rb.filled());
                    self.tls.writer().write_all(rb.filled()).unwrap();
                    // rustls buffers at most 64 KiB of unsent ciphertext.
                    self.drain_tls();
                }
                _ => return,
            }
        }
    }
}
