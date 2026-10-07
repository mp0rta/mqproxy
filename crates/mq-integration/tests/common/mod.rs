// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Rigs for the driver tests with the real apps (spec §8.1 "Driver", rerun
//! with the real `Client`/`Server`): the production `Driver` on its own
//! thread, a `ScriptedTransport` in polling mode (so events the test injects
//! from its own thread are picked up within 1 ms), and real loopback sockets.
#![allow(dead_code)]

use mq_integration::driver_harness::{DriverThread, ResolverControl, chan_resolver};
use mq_proxy::client::{Client, HTTP_CONNECT, SOCKS5};
use mq_proxy::config::{ClientConfig, ServerConfig};
use mq_proxy::server::Server;
use mq_runtime::driver::DriverConfig;
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_runtime::{ListenKind, Shard};
use mq_transport_api::{ConnId, ConnProto, Event, StreamId, StreamInfo, StreamKind};
use mq_wire::frames::{AuthReq, AuthResp, ConnectTcpResp, FEAT_UDP_RELAY};
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const T: Duration = Duration::from_secs(5);

/// Polls `f` every 2 ms until it holds or `timeout` passes.
pub fn wait(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// Stream type 0x01 then a `CONNECT_TCP_REQUEST` for example.com:443.
pub const CONNECT_REQ_C: &[u8] = &[
    0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
    0xBB, 0x00,
];

/// An `AUTH_RESPONSE` without capabilities (what a no-UDP server sends the client under test).
pub fn auth_resp(status: u8, code: u64) -> Vec<u8> {
    auth_resp_features(status, code, 0)
}

pub fn auth_resp_features(status: u8, code: u64, features: u64) -> Vec<u8> {
    let mut b = [0u8; 512];
    let n = AuthResp {
        status,
        error_code: code,
        server_id: b"mqproxy-server",
        features,
    }
    .encode(&mut b)
    .unwrap();
    b[..n].to_vec()
}

pub fn auth_req(token: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 512];
    let n = AuthReq {
        version: 1,
        client_id: b"mqproxy",
        auth_token: token,
        features: 0,
    }
    .encode(&mut b)
    .unwrap();
    b[..n].to_vec()
}

pub fn connect_resp(status: u8, code: u64) -> Vec<u8> {
    let mut b = [0u8; 512];
    let n = ConnectTcpResp {
        status,
        error_code: code,
        message: b"",
    }
    .encode(&mut b)
    .unwrap();
    b[..n].to_vec()
}

fn driver_cfg() -> (DriverConfig, ResolverControl) {
    let (resolver, control) = chan_resolver();
    let cfg = DriverConfig {
        resolver,
        emfile_retry: Duration::from_millis(100),
        shutdown_cap: Duration::from_secs(2),
        install_signal_handlers: false,
    };
    (cfg, control)
}

/// Queue `bytes` (+ FIN) on `s` and signal readability.
pub fn feed(t: &ScriptedHandle, s: StreamId, bytes: &[u8], fin: bool) {
    t.expect_stream_recv(s, Ok((bytes.to_vec(), fin)));
    t.push_event(Event::StreamReadable(s));
}

/// Whether some `stream_send` on `s` carried FIN.
pub fn sent_fin(t: &ScriptedHandle, s: StreamId) -> bool {
    t.log()
        .iter()
        .any(|c| matches!(c, Call::StreamSend { s: x, fin: true, .. } if *x == s))
}

pub fn was_reset(t: &ScriptedHandle, s: StreamId) -> bool {
    t.log().contains(&Call::StreamReset(s))
}

/// Reads until EOF (or the read timeout); the bytes before it.
pub fn read_to_eof(c: &mut TcpStream) -> Vec<u8> {
    c.set_read_timeout(Some(T)).unwrap();
    let mut v = Vec::new();
    c.read_to_end(&mut v).expect("EOF within the timeout");
    v
}

pub fn read_n(c: &mut TcpStream, n: usize) -> Vec<u8> {
    c.set_read_timeout(Some(T)).unwrap();
    let mut v = vec![0; n];
    c.read_exact(&mut v).unwrap();
    v
}

/// The real `Client` with a SOCKS5 (`listen_addrs[0]`) and an HTTP CONNECT
/// (`listen_addrs[1]`) listener. The transport answers `connect` with a fresh
/// connection (established at once when `establish`), hands out data streams
/// with their `StreamInfo`, and answers the `AUTH_REQUEST` on the control
/// stream with an OK `AUTH_RESPONSE`. Data streams are answered by the test.
pub struct ClientRig {
    pub d: DriverThread<ScriptedHandle>,
    pub t: ScriptedHandle,
    /// Streams in `open_stream` order: the control stream first.
    opened: Arc<Mutex<Vec<StreamId>>>,
}

impl ClientRig {
    pub fn spawn(establish: bool) -> ClientRig {
        let (cfg, _resolver) = driver_cfg(); // the client never resolves
        let opened: Arc<Mutex<Vec<StreamId>>> = Arc::default();
        let op = opened.clone();
        let listeners = vec![
            (ListenKind::Plain, SOCKS5),
            (ListenKind::Plain, HTTP_CONNECT),
        ];
        let mut d = DriverThread::spawn_with(cfg, listeners, move |local| {
            let (tr, t) = ScriptedTransport::new();
            t.set_polling(true);
            t.on_connect(move |h| {
                let c = h.new_conn_id();
                if establish {
                    h.push_event(Event::ConnEstablished(c));
                }
                Ok(c)
            });
            let o = op.clone();
            t.on_open_stream(move |h, conn: ConnId| {
                let s = h.new_stream_id();
                let mut o = o.lock().unwrap();
                let quic_id = 4 * o.len() as u64;
                h.set_stream_info(
                    s,
                    StreamInfo {
                        conn,
                        quic_id,
                        kind: StreamKind::Bidi,
                    },
                );
                o.push(s);
                Ok(s)
            });
            let o = op.clone();
            t.on_stream_send(move |h, s, data, _fin| {
                // The control stream's only send is the AUTH_REQUEST.
                if o.lock().unwrap().first() == Some(&s) {
                    feed(h, s, &auth_resp(0, 0), false);
                }
                Ok(data.len())
            });
            let cfg = ClientConfig {
                token: "secret".into(),
                ..ClientConfig::default()
            };
            (Shard::new(tr, Client::new(cfg), local, 7), t)
        });
        d.start();
        let t = d.handle.clone();
        ClientRig { d, t, opened }
    }

    /// Started and authenticated (`Serving`): the control stream was read for
    /// the `AUTH_RESPONSE` and then drained to `Blocked`.
    pub fn serving() -> ClientRig {
        let r = ClientRig::spawn(true);
        let ctrl = r.stream(0);
        let recvs = |t: &ScriptedHandle| {
            (t.log().iter())
                .filter(|c| matches!(c, Call::StreamRecv { s, .. } if *s == ctrl))
                .count()
        };
        assert!(wait(T, || recvs(&r.t) >= 2), "not serving: {:?}", r.t.log());
        r
    }

    pub fn socks(&self) -> SocketAddr {
        self.d.listen_addrs[0]
    }
    pub fn http(&self) -> SocketAddr {
        self.d.listen_addrs[1]
    }

    /// The `i`-th stream opened (0 = control), waiting for it.
    pub fn stream(&self, i: usize) -> StreamId {
        assert!(
            wait(T, || self.opened.lock().unwrap().len() > i),
            "stream {i} never opened"
        );
        self.opened.lock().unwrap()[i]
    }

    pub fn opened(&self) -> usize {
        self.opened.lock().unwrap().len()
    }

    /// Waits until exactly `want` was accepted on `s`.
    pub fn wait_sent(&self, s: StreamId, want: &[u8]) {
        assert!(
            wait(T, || self.t.sent_bytes(s) == want),
            "sent on {s:?}: {:?}, want {want:?}",
            self.t.sent_bytes(s)
        );
    }

    pub fn stop(mut self) {
        self.d.shutdown.trigger();
        assert_eq!(self.d.join_timeout(T), Some(0));
    }
}

/// The real `Server` with a resolver the test answers.
pub struct ServerRig {
    pub d: DriverThread<ScriptedHandle>,
    pub t: ScriptedHandle,
    pub resolver: ResolverControl,
}

impl ServerRig {
    pub fn spawn(dial_deadline: Duration) -> ServerRig {
        let (cfg, resolver) = driver_cfg();
        let mut d = DriverThread::spawn_with(cfg, Vec::new(), move |local| {
            let (tr, t) = ScriptedTransport::new();
            t.set_polling(true);
            let cfg = ServerConfig {
                token: "secret".into(),
                dial_deadline,
                ..ServerConfig::default()
            };
            (Shard::new(tr, Server::new(cfg), local, 7), t)
        });
        d.start();
        let t = d.handle.clone();
        ServerRig { d, t, resolver }
    }

    fn push_stream(&self, conn: ConnId, quic_id: u64) -> StreamId {
        let s = self.t.new_stream_id();
        let info = StreamInfo {
            conn,
            quic_id,
            kind: StreamKind::Bidi,
        };
        self.t.set_stream_info(s, info);
        self.t.push_event(Event::NewStream(conn, s, info));
        s
    }

    /// `NewConn` + the control stream with a good `AUTH_REQUEST`; waits for the OK.
    pub fn authed(&self) -> ConnId {
        let c = self.t.new_conn_id();
        self.t.push_event(Event::NewConn(c, ConnProto::Raw));
        let ctrl = self.push_stream(c, 0);
        feed(&self.t, ctrl, &auth_req(b"secret"), false);
        let ok = auth_resp_features(0, 0, FEAT_UDP_RELAY); // the default server config
        assert!(
            wait(T, || self.t.sent_bytes(ctrl) == ok),
            "not authenticated: {:?}",
            self.t.log()
        );
        c
    }

    /// A data stream carrying CONNECT `host`:`port`.
    pub fn request(&self, conn: ConnId, host: &str, port: u16) -> StreamId {
        let s = self.push_stream(conn, 4);
        let mut b = vec![0x01, 0x00, 0x03, host.len() as u8];
        b.extend_from_slice(host.as_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b.push(0x00); // padding_length
        feed(&self.t, s, &b, false);
        s
    }

    pub fn stop(mut self) {
        self.d.shutdown.trigger();
        assert_eq!(self.d.join_timeout(T), Some(0));
    }
}
