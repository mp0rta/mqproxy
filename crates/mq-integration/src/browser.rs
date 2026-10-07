// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! `TestBrowser` (SP4 spec §11.3): a browser stand-in for the MITM pair tests. It speaks
//! rustls (client) + `h2::client` on a tokio current_thread runtime, driven by the calling
//! thread (`block_on`), over TCP to the proxy's `TRANSPARENT` listener only. TLS uses SNI
//! `localhost`; requests carry `:authority` `localhost:<origin port>`, which the server's
//! gateway dials (the origin certificate's SAN covers `localhost`). The h2 connection is
//! made at the first request and reused.

use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, StatusCode};
use mq_proxy::server::origin::install_ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::cell::RefCell;
use std::future::poll_fn;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

/// The SNI every `TestBrowser` connection sends.
pub const SNI: &str = "localhost";
/// Upload DATA frames are at most this big.
const CHUNK: usize = 16 * 1024;
/// The deadline of every blocking step.
const T: Duration = Duration::from_secs(20);

/// A request body.
pub enum Body {
    /// END_STREAM on HEADERS.
    Empty,
    /// DATA frames; `content-length` is sent when `known_len`.
    Data(Vec<u8>, bool),
}

/// A response as the browser saw it.
pub type Resp = (StatusCode, HeaderMap, Vec<u8>);

/// The trust roots in a PEM file.
pub fn roots(pem: &Path) -> RootCertStore {
    let mut r = RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(pem).expect("roots") {
        r.add(c.expect("root")).expect("root cert");
    }
    r
}

pub struct TestBrowser {
    proxy: SocketAddr,
    authority: String,
    roots: RootCertStore,
    rt: Runtime,
    h2: RefCell<Option<SendRequest<Bytes>>>,
}

impl TestBrowser {
    /// `authority` is `localhost:<origin port>`; `roots` verify what the proxy presents
    /// (the MITM CA, or the origin CA on opaque routes).
    pub fn new(proxy: SocketAddr, authority: String, roots: RootCertStore) -> TestBrowser {
        install_ring();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("browser runtime");
        TestBrowser {
            proxy,
            authority,
            roots,
            rt,
            h2: RefCell::new(None),
        }
    }

    fn tls_config(&self, alpn: &[&[u8]]) -> Arc<ClientConfig> {
        let mut c = ClientConfig::builder()
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(c)
    }

    /// The h2 connection, made on first use.
    fn conn(&self) -> SendRequest<Bytes> {
        if let Some(s) = self.h2.borrow().as_ref() {
            return s.clone();
        }
        let cfg = self.tls_config(&[b"h2"]);
        let proxy = self.proxy;
        let send = self.block_on(async move {
            let tcp = tokio::net::TcpStream::connect(proxy)
                .await
                .expect("connect");
            let name = ServerName::try_from(SNI).expect("sni");
            let tls = TlsConnector::from(cfg).connect(name, tcp).await;
            let tls = tls.expect("TLS handshake with the proxy");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let (send, conn) = h2::client::Builder::new()
                .initial_window_size(1 << 20)
                .initial_connection_window_size(4 << 20)
                .handshake::<_, Bytes>(tls)
                .await
                .expect("h2 handshake");
            tokio::spawn(async move {
                let _ = conn.await;
            });
            send
        });
        *self.h2.borrow_mut() = Some(send.clone());
        send
    }

    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.rt
            .block_on(async { tokio::time::timeout(T, f).await })
            .expect("browser step timed out")
    }

    /// One request: any `method` (case kept), `:authority` overridden by `uri_authority`.
    pub fn request(
        &self,
        method: &str,
        uri_authority: Option<&str>,
        path: &str,
        headers: &[(&str, &[u8])],
        body: Body,
    ) -> Result<Resp, h2::Error> {
        let authority = uri_authority.unwrap_or(&self.authority);
        let mut req = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("method"))
            .uri(format!("https://{authority}{path}"));
        for (n, v) in headers {
            req = req.header(*n, *v);
        }
        let (data, end) = match body {
            Body::Empty => (Vec::new(), true),
            Body::Data(d, known) => {
                if known {
                    req = req.header("content-length", d.len());
                }
                (d, false)
            }
        };
        let req = req.body(()).expect("request");
        let send = self.conn();
        self.block_on(async move {
            let mut send = send.ready().await?;
            let (resp, up) = send.send_request(req, end)?;
            let response = async move {
                let (parts, body) = resp.await?.into_parts();
                Ok((parts.status, parts.headers, read_all(body).await?))
            };
            let upload = async move {
                if !end {
                    let _ = upload(up, data).await;
                }
            };
            tokio::join!(response, upload).0
        })
    }

    pub fn get(&self, path: &str, headers: &[(&str, &[u8])]) -> Resp {
        let r = self.request("GET", None, path, headers, Body::Empty);
        r.unwrap_or_else(|e| panic!("GET {path}: {e}"))
    }

    pub fn post(
        &self,
        path: &str,
        headers: &[(&str, &[u8])],
        body: Vec<u8>,
        known_len: bool,
    ) -> Resp {
        let r = self.request("POST", None, path, headers, Body::Data(body, known_len));
        r.unwrap_or_else(|e| panic!("POST {path}: {e}"))
    }

    /// `n` concurrent GETs of `path` on the one connection.
    pub fn get_parallel(&self, n: usize, path: &str) -> Vec<Resp> {
        let all: Vec<_> = (0..n).map(|_| self.start_get(path)).collect();
        (all.into_iter())
            .map(|t| self.finish(t).expect("parallel GET"))
            .collect()
    }

    /// A GET spawned on the browser runtime; it progresses whenever the runtime is driven
    /// (`drive_until`, `finish`, any other call).
    pub fn start_get(&self, path: &str) -> JoinHandle<Result<Resp, h2::Error>> {
        let send = self.conn();
        let req = Request::get(format!("https://{}{path}", self.authority)).body(());
        let req = req.expect("request");
        self.rt.spawn(async move {
            let (resp, _) = send.ready().await?.send_request(req, true)?;
            let (parts, body) = resp.await?.into_parts();
            Ok((parts.status, parts.headers, read_all(body).await?))
        })
    }

    /// The outcome of a `start_get`.
    pub fn finish(&self, t: JoinHandle<Result<Resp, h2::Error>>) -> Result<Resp, h2::Error> {
        self.block_on(t).expect("request task")
    }

    /// Drives the browser runtime until `cond` holds.
    pub fn drive_until(&self, cond: impl Fn() -> bool) {
        self.block_on(async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    }

    /// A TLS handshake only, on a new connection: the certificate chain it verified.
    pub fn tls_only(&self, alpn: &[&[u8]], sni: &str) -> Vec<CertificateDer<'static>> {
        self.tls_on(TcpStream::connect(self.proxy).expect("connect"), alpn, sni)
    }

    /// `tls_only` over an already connected `tcp`.
    pub fn tls_on(
        &self,
        tcp: TcpStream,
        alpn: &[&[u8]],
        sni: &str,
    ) -> Vec<CertificateDer<'static>> {
        tcp.set_read_timeout(Some(T)).expect("timeout");
        let name = ServerName::try_from(sni.to_owned()).expect("sni");
        let conn = ClientConnection::new(self.tls_config(alpn), name).expect("client conn");
        let mut s = StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn
                .complete_io(&mut s.sock)
                .unwrap_or_else(|e| panic!("TLS handshake: {e}"));
        }
        let _ = s.flush();
        s.conn.peer_certificates().expect("peer chain").to_vec()
    }
}

async fn upload(mut s: SendStream<Bytes>, data: Vec<u8>) -> Result<(), h2::Error> {
    let mut data = Bytes::from(data);
    if data.is_empty() {
        return s.send_data(data, true);
    }
    while !data.is_empty() {
        s.reserve_capacity(data.len().min(CHUNK));
        let Some(n) = poll_fn(|cx| s.poll_capacity(cx)).await else {
            return Ok(()); // the stream ended (e.g. an early response)
        };
        let n = n?.min(data.len());
        if n > 0 {
            let chunk = data.split_to(n);
            s.send_data(chunk, data.is_empty())?;
        }
    }
    Ok(())
}

async fn read_all(mut body: RecvStream) -> Result<Vec<u8>, h2::Error> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
