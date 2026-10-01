//! Harness for the server tests (spec §6.3): `Shard<ScriptedTransport, Server>`,
//! with dial completions fed by hand as the driver would.
#![allow(dead_code)]

use mq_proxy::config::ServerConfig;
use mq_proxy::server::Server;
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_runtime::{DialError, DialOpId, IoRequest, Shard, Target, TcpId};
use mq_transport_api::{
    CloseReason, ConnId, ErrType, Event, StreamId, StreamInfo, StreamKind, Time,
};
use mq_wire::frames::{AuthReq, ConnectTcpResp};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Stream type 0x01 then C `mq_encode_connect_tcp_req` for example.com:443.
pub const CONNECT_REQ_C: &[u8] = &[
    0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01,
    0xBB, 0x00,
];

/// C `mq_encode_auth_resp` for OK / ERROR+AUTH_FAILED, server_id "mqproxy-server", features 0.
pub const AUTH_OK_C: &[u8] = &[
    0x00, 0x00, 14, b'm', b'q', b'p', b'r', b'o', b'x', b'y', b'-', b's', b'e', b'r', b'v', b'e',
    b'r', 0x00, 0x00,
];
pub const AUTH_FAILED_C: &[u8] = &[
    0x01, 0x01, 14, b'm', b'q', b'p', b'r', b'o', b'x', b'y', b'-', b's', b'e', b'r', b'v', b'e',
    b'r', 0x00, 0x00,
];

pub fn cfg() -> ServerConfig {
    ServerConfig {
        token: "secret".into(),
        ..ServerConfig::default()
    }
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

pub fn origin() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 80))
}

pub fn closed_reason() -> CloseReason {
    CloseReason {
        err_type: ErrType::Unknown,
        code: 0,
    }
}

pub struct H {
    pub sh: Shard<ScriptedTransport, Server>,
    pub t: ScriptedHandle,
    pub now: Time,
    next_quic: u64,
}

impl H {
    /// A server started at t = 1 s.
    pub fn new(cfg: ServerConfig) -> H {
        let (transport, t) = ScriptedTransport::new();
        let mut sh = Shard::new(
            transport,
            Server::new(cfg),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
            7,
        );
        let now = Time::from_micros(1_000_000);
        sh.start(now);
        H {
            sh,
            t,
            now,
            next_quic: 4,
        }
    }

    pub fn drive(&mut self) {
        self.sh.drive(self.now);
    }
    pub fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
        self.drive();
    }
    pub fn event(&mut self, e: Event) {
        self.t.push_event(e);
        self.drive();
    }
    pub fn log(&self) -> Vec<Call> {
        self.t.log()
    }
    pub fn count(&self, f: impl Fn(&Call) -> bool) -> usize {
        self.log().iter().filter(|c| f(c)).count()
    }
    pub fn reqs(&mut self) -> Vec<IoRequest> {
        std::iter::from_fn(|| self.sh.poll_io_request()).collect()
    }
    pub fn reset(&self, s: StreamId) -> bool {
        self.log().contains(&Call::StreamReset(s))
    }
    pub fn close_conn_count(&self, c: ConnId) -> usize {
        self.count(|x| *x == Call::CloseConn(c))
    }
    pub fn recv_caps(&self, s: StreamId) -> Vec<usize> {
        self.log()
            .iter()
            .filter_map(|c| match c {
                Call::StreamRecv { s: x, cap } if *x == s => Some(*cap),
                _ => None,
            })
            .collect()
    }
    /// The `fin` flag of every `stream_send` on `s`.
    pub fn send_fins(&self, s: StreamId) -> Vec<bool> {
        self.log()
            .iter()
            .filter_map(|c| match c {
                Call::StreamSend { s: x, fin, .. } if *x == s => Some(*fin),
                _ => None,
            })
            .collect()
    }

    /// `NewConn`.
    pub fn conn(&mut self) -> ConnId {
        let c = self.t.new_conn_id();
        self.event(Event::NewConn(c));
        c
    }

    /// A peer stream with QUIC id `quic_id`, queued (not yet driven).
    pub fn push_stream(&mut self, conn: ConnId, quic_id: u64, kind: StreamKind) -> StreamId {
        let s = self.t.new_stream_id();
        let info = StreamInfo {
            conn,
            quic_id,
            kind,
        };
        self.t.set_stream_info(s, info);
        self.t.push_event(Event::NewStream(conn, s, info));
        s
    }
    pub fn stream(&mut self, conn: ConnId, quic_id: u64, kind: StreamKind) -> StreamId {
        let s = self.push_stream(conn, quic_id, kind);
        self.drive();
        s
    }
    /// The next client-initiated bidirectional data stream (queued).
    pub fn push_data(&mut self, conn: ConnId) -> StreamId {
        let q = self.next_quic;
        self.next_quic += 4;
        self.push_stream(conn, q, StreamKind::Bidi)
    }
    pub fn data(&mut self, conn: ConnId) -> StreamId {
        let s = self.push_data(conn);
        self.drive();
        s
    }

    /// The control stream (QUIC id 0) carrying `bytes`.
    pub fn ctrl(&mut self, conn: ConnId, bytes: &[u8], fin: bool) -> StreamId {
        let s = self.stream(conn, 0, StreamKind::Bidi);
        self.feed(s, bytes, fin);
        s
    }
    /// A new authenticated connection; returns it and its control stream.
    pub fn authed(&mut self) -> (ConnId, StreamId) {
        let c = self.conn();
        let s = self.ctrl(c, &auth_req(b"secret"), false);
        assert_eq!(self.t.sent_bytes(s), AUTH_OK_C, "authenticated");
        (c, s)
    }
    /// Queue `bytes` on `s` and signal readability.
    pub fn feed(&mut self, s: StreamId, bytes: &[u8], fin: bool) {
        self.t.expect_stream_recv(s, Ok((bytes.to_vec(), fin)));
        self.event(Event::StreamReadable(s));
    }
    /// A data stream that sent CONNECT example.com:443 + `extra`; returns the dial.
    pub fn request(&mut self, conn: ConnId, extra: &[u8]) -> (StreamId, DialOpId) {
        let s = self.data(conn);
        let mut b = CONNECT_REQ_C.to_vec();
        b.extend_from_slice(extra);
        self.feed(s, &b, false);
        let (op, _, _) = self.dial().expect("a dial");
        (s, op)
    }
    /// The single dial requested since the last `reqs`.
    pub fn dial(&mut self) -> Option<(DialOpId, Target, Duration)> {
        let mut d: Vec<_> = self
            .reqs()
            .into_iter()
            .filter_map(|r| match r {
                IoRequest::Dial {
                    op,
                    target,
                    deadline,
                } => Some((op, target, deadline)),
                _ => None,
            })
            .collect();
        assert!(d.len() <= 1, "{d:?}");
        d.pop()
    }
    pub fn dial_ok(&mut self, op: DialOpId) -> TcpId {
        let tcp = self.sh.on_dial_result(self.now, op, Ok(origin())).unwrap();
        self.drive();
        tcp
    }
    pub fn dial_err(&mut self, op: DialOpId, e: DialError) {
        assert!(self.sh.on_dial_result(self.now, op, Err(e)).is_none());
        self.drive();
    }
    /// Bytes queued toward the origin socket (a relay's preread lands here).
    pub fn tcp_out(&mut self, tcp: TcpId) -> Vec<u8> {
        self.sh.tcp_tx_buf(tcp).to_vec()
    }
    /// `n` data streams on `conn` that never send their request, in one drive.
    pub fn idle_streams(&mut self, conn: ConnId, n: usize) -> Vec<StreamId> {
        let v = (0..n).map(|_| self.push_data(conn)).collect();
        self.drive();
        v
    }
    pub fn closed(&mut self, c: ConnId) {
        self.event(Event::ConnClosed(c, closed_reason()));
    }
}

/// `frame` (ending in `padding_length = 0`) re-padded to exactly `total` bytes.
pub fn pad_to(frame: &[u8], total: usize) -> Vec<u8> {
    let mut b = frame[..frame.len() - 1].to_vec();
    let p = total - b.len() - 2;
    assert!((64..16384).contains(&p), "2-byte varint padding");
    b.extend_from_slice(&[0x40 | (p >> 8) as u8, p as u8]);
    b.resize(total, 0);
    b
}
