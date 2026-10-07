// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Harness for the origin bridge tests (spec §7): `Shard<ScriptedTransport,
//! OriginHost>`, with dial results and socket bytes fed by hand as the driver
//! would, and `TlsPeer`, a hand-driven rustls server playing the origin.
#![allow(dead_code)]

use mq_http::headers::HttpVer;
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, OriginHost, StartSpec};
use mq_proxy::server::origin::{OriginCfg, build_client_config, install_ring};
use mq_runtime::testing::{ScriptedHandle, ScriptedTransport};
use mq_runtime::{Cx, DialError, DialOpId, IoRequest, IoResult, Shard, Target, TcpId};
use mq_transport_api::{H3ReqId, Time};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub const ORIGIN_CA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/certs/origin-ca.crt"
);
/// Leaf (CA:FALSE), SAN IP:127.0.0.1 and DNS:localhost.
pub const ORIGIN_CRT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/origin.crt");
pub const ORIGIN_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/origin.key");

/// 10 s connect deadline (the production default), 200 ms sweep.
pub fn cfg() -> OriginCfg {
    OriginCfg {
        connect_timeout: Duration::from_secs(10),
        sweep: Duration::from_millis(200),
    }
}

/// A client config trusting the test origin CA only.
pub fn tls() -> Arc<rustls::ClientConfig> {
    build_client_config(Some(ORIGIN_CA.as_ref()), &Vec::new).expect("origin CA")
}

/// A bodiless GET of `url` with the default protocol preference.
pub fn get(url: &str) -> StartSpec {
    StartSpec {
        method: "GET",
        url: url.into(),
        headers: Vec::new(),
        ver: HttpVer::Default,
        body: BodySpec::None,
    }
}

pub struct OH {
    pub sh: Shard<ScriptedTransport, OriginHost>,
    pub t: ScriptedHandle,
    pub now: Time,
    /// Every `IoRequest` polled so far, in order.
    io: Vec<IoRequest>,
    /// `Dial` requests already returned by `dial()`.
    dials_taken: usize,
}

impl OH {
    /// An origin bridge started at t = 1 s.
    pub fn new(cfg: OriginCfg, tls: Arc<rustls::ClientConfig>) -> OH {
        let (t, h) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, OriginHost::new(cfg, tls), addr, 7);
        let now = Time::from_micros(1_000_000);
        sh.start(now);
        OH {
            sh,
            t: h,
            now,
            io: Vec::new(),
            dials_taken: 0,
        }
    }

    pub fn drive(&mut self) {
        self.sh.drive(self.now);
    }

    pub fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
        self.drive();
    }

    pub fn with_host<R>(&mut self, f: impl FnOnce(&mut OriginHost, &mut Cx<'_>) -> R) -> R {
        self.sh.with_app(self.now, f)
    }

    /// `OriginHost::start` (start + pump).
    pub fn start(&mut self, spec: StartSpec) -> H3ReqId {
        self.with_host(|h, cx| h.start(cx, spec))
    }

    /// `OriginHost::cancel` (`H3Closed` + pump).
    pub fn cancel(&mut self, h3: H3ReqId) {
        self.with_host(|h, cx| h.cancel(cx, h3));
    }

    pub fn events(&self) -> Vec<BridgeEv> {
        self.sh.app().events().to_vec()
    }

    /// Every `IoRequest` the shard emitted so far.
    pub fn io(&mut self) -> &[IoRequest] {
        while let Some(r) = self.sh.poll_io_request() {
            self.io.push(r);
        }
        &self.io
    }

    /// The next `IoRequest::Dial` not returned yet.
    pub fn dial(&mut self) -> Option<(DialOpId, Target, Duration)> {
        let skip = self.dials_taken;
        let d = self
            .io()
            .iter()
            .filter_map(|r| match r {
                IoRequest::Dial {
                    op,
                    target,
                    deadline,
                } => Some((*op, target.clone(), *deadline)),
                _ => None,
            })
            .nth(skip);
        self.dials_taken += usize::from(d.is_some());
        d
    }

    pub fn dial_ok(&mut self, op: DialOpId) -> TcpId {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
        let tcp = self.sh.on_dial_result(self.now, op, Ok(addr)).unwrap();
        self.drive();
        tcp
    }

    pub fn dial_err(&mut self, op: DialOpId, e: DialError) {
        assert!(self.sh.on_dial_result(self.now, op, Err(e)).is_none());
        self.drive();
    }

    /// The driver's read: `bytes` into the receive buffer, in as many reads
    /// as its room allows (the app must consume between them).
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

    /// The driver's read under backpressure: as much of `bytes` as the
    /// receive buffer takes; returns that count.
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

    pub fn tcp_eof(&mut self, tcp: TcpId) {
        self.sh.tcp_rx_commit(self.now, tcp, IoResult::Eof);
        self.drive();
    }

    pub fn tcp_error(&mut self, tcp: TcpId, kind: io::ErrorKind) {
        self.sh.on_tcp_error(self.now, tcp, kind);
        self.drive();
    }

    /// Whether the app reset `tcp` (`tcp_abort`; also the shard's own close
    /// after a socket error).
    pub fn aborted(&mut self, tcp: TcpId) -> bool {
        let want = IoRequest::TcpClose { tcp, abort: true };
        self.io().contains(&want)
    }

    /// Whether `tcp` was closed in any way.
    pub fn closed(&mut self, tcp: TcpId) -> bool {
        self.io()
            .iter()
            .any(|r| matches!(r, IoRequest::TcpClose { tcp: t, .. } if *t == tcp))
    }
}

/// A hand-driven rustls server playing the origin's TLS side.
pub struct TlsPeer {
    pub conn: rustls::ServerConnection,
}

impl TlsPeer {
    /// `cert`/`key` are PEM paths (`ORIGIN_CRT`, `ORIGIN_KEY`).
    pub fn new(cert: &str, key: &str, alpn: &[&[u8]]) -> TlsPeer {
        TlsPeer::from_config(TlsPeer::config(cert, key, alpn))
    }

    /// A peer from a config built by `config` and adjusted by the test.
    pub fn from_config(c: rustls::ServerConfig) -> TlsPeer {
        TlsPeer {
            conn: rustls::ServerConnection::new(Arc::new(c)).unwrap(),
        }
    }

    /// The server config `new` uses.
    pub fn config(cert: &str, key: &str, alpn: &[&[u8]]) -> rustls::ServerConfig {
        install_ring();
        let certs = CertificateDer::pem_file_iter(cert)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(key).unwrap();
        let mut c = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        c
    }

    /// The test origin with ALPN `http/1.1` only.
    pub fn h1() -> TlsPeer {
        TlsPeer::new(ORIGIN_CRT, ORIGIN_KEY, &[b"http/1.1"])
    }

    /// One exchange: what the bridge wrote to `tcp` → rustls → what rustls
    /// has to send (handshake records, plaintext from `write_plain`) → `tcp`.
    pub fn pump(&mut self, oh: &mut OH, tcp: TcpId) {
        let out = oh.tcp_out_all(tcp);
        let mut s = &out[..];
        while !s.is_empty() {
            self.conn.read_tls(&mut s).unwrap();
            self.conn
                .process_new_packets()
                .expect("the bridge's TLS bytes");
        }
        let mut b = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut b).unwrap();
        }
        if !b.is_empty() {
            oh.tcp_in(tcp, &b);
        }
    }

    /// Application bytes, sent encrypted by the next `pump`.
    pub fn write_plain(&mut self, b: &[u8]) {
        self.conn.writer().write_all(b).unwrap();
    }

    /// Raw bytes on the socket, bypassing TLS. After the handshake a
    /// plaintext record fails to decrypt (`DecryptError`, fatal and sticky);
    /// the alert bytes `15 03 03 00 02 02 28` are only decoration.
    pub fn write_raw(&mut self, oh: &mut OH, tcp: TcpId, b: &[u8]) {
        oh.tcp_in(tcp, b);
    }
}
