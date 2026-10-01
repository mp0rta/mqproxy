//! Harness for the client tests (spec §6.2): `Shard<ScriptedTransport, Client>`,
//! driven by hand on the socket side as the driver would.
#![allow(dead_code)]

use mq_proxy::client::{Client, HTTP_CONNECT, SOCKS5, TRANSPARENT};
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_runtime::{AcceptMeta, IoRequest, IoResult, ListenerId, Shard, TcpId};
use mq_transport_api::{ConnId, Event, StreamId, StreamInfo, StreamKind, Time};
use mq_wire::frames::{AuthResp, ConnectTcpResp};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const SEED: u64 = 7;

/// C `mq_encode_auth_req` for client_id "mqproxy", token "secret".
pub const AUTH_REQ_C: &[u8] = &[
    0x01, // version
    0x07, b'm', b'q', b'p', b'r', b'o', b'x', b'y', // client_id
    0x06, b's', b'e', b'c', b'r', b'e', b't', // auth_token
    0x00, // features
    0x00, // padding_length
];

/// SOCKS5 greeting (no-auth) and CONNECT example.com:443.
pub const SOCKS_GREETING: &[u8] = &[0x05, 0x01, 0x00];
pub const SOCKS_CONNECT: &[u8] = &[
    0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
    0x01, 0xBB,
];
/// Stream type 0x01 then C `mq_encode_connect_tcp_req` for example.com:443.
pub const CONNECT_REQ_C: &[u8] = &[
    0x01, // MQ_STREAM_TYPE_CONNECT_TCP
    0x00, // flags
    0x03, // address_type = domain
    11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', // host
    0x01, 0xBB, // port 443
    0x00, // padding_length
];
pub const SOCKS_OK: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
pub const SOCKS_REFUSED: [u8; 10] = [5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
pub const SOCKS_TIMEOUT: [u8; 10] = [5, 6, 0, 1, 0, 0, 0, 0, 0, 0];

pub fn cfg() -> ClientConfig {
    ClientConfig {
        token: "secret".into(),
        ..ClientConfig::default()
    }
}

pub fn auth_resp(status: u8, code: u64) -> Vec<u8> {
    let mut b = [0u8; 512];
    let n = AuthResp {
        status,
        error_code: code,
        server_id: b"mqproxy-server",
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

pub fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

pub fn meta(original_dst: Option<SocketAddr>) -> AcceptMeta {
    AcceptMeta {
        peer: addr(5000),
        original_dst,
    }
}

pub struct H {
    pub sh: Shard<ScriptedTransport, Client>,
    pub t: ScriptedHandle,
    pub now: Time,
    pub socks: ListenerId,
    pub http: ListenerId,
    pub tproxy: ListenerId,
    /// The connection the next `connect` returns (scripted at setup).
    pub conn: ConnId,
}

impl H {
    /// A client whose first `connect` returns `self.conn`; started at t = 1 s.
    pub fn new(cfg: ClientConfig) -> H {
        let (transport, t) = ScriptedTransport::new();
        let conn = t.new_conn_id();
        t.expect_connect(Ok(conn));
        let mut sh = Shard::new(transport, Client::new(cfg), addr(4433), SEED);
        let socks = sh.add_listener(SOCKS5);
        let http = sh.add_listener(HTTP_CONNECT);
        let tproxy = sh.add_listener(TRANSPARENT);
        let now = Time::from_micros(1_000_000);
        sh.start(now);
        H {
            sh,
            t,
            now,
            socks,
            http,
            tproxy,
            conn,
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

    /// A stream id of `conn` that the next `open_stream` returns.
    pub fn next_stream(&self, conn: ConnId) -> StreamId {
        let s = self.t.new_stream_id();
        self.t.set_stream_info(
            s,
            StreamInfo {
                conn,
                quic_id: 0,
                kind: StreamKind::Bidi,
            },
        );
        self.t.expect_open_stream(Ok(s));
        s
    }

    /// `ConnEstablished`; returns the control stream.
    pub fn establish(&mut self) -> StreamId {
        let ctrl = self.next_stream(self.conn);
        self.event(Event::ConnEstablished(self.conn));
        ctrl
    }

    /// Established and authenticated; returns the control stream.
    pub fn serving(&mut self) -> StreamId {
        let ctrl = self.establish();
        self.t
            .expect_stream_recv(ctrl, Ok((auth_resp(0, 0), false)));
        self.event(Event::StreamReadable(ctrl));
        ctrl
    }

    pub fn accept(&mut self, l: ListenerId, m: AcceptMeta) -> TcpId {
        self.sh.on_accepted(self.now, l, m).expect("below the cap")
    }
    /// The driver's read: copy into `tcp_rx_buf`, commit.
    pub fn rx(&mut self, tcp: TcpId, bytes: &[u8]) {
        let buf = self.sh.tcp_rx_buf(tcp);
        assert!(buf.len() >= bytes.len(), "rx buffer room");
        buf[..bytes.len()].copy_from_slice(bytes);
        self.sh
            .tcp_rx_commit(self.now, tcp, IoResult::Bytes(bytes.len()));
    }
    /// The driver's write: everything queued for TCP, committed.
    pub fn tx_all(&mut self, tcp: TcpId) -> Vec<u8> {
        let out = self.sh.tcp_tx_buf(tcp).to_vec();
        self.sh
            .tcp_tx_commit(self.now, tcp, IoResult::Bytes(out.len()));
        out
    }

    /// A SOCKS5 client that sent greeting + CONNECT example.com:443 (+ `extra`);
    /// the method reply `[5, 0]` stays queued in front of anything that follows.
    pub fn socks_request(&mut self, extra: &[u8]) -> TcpId {
        let tcp = self.accept(self.socks, meta(None));
        let mut b = SOCKS_GREETING.to_vec();
        b.extend_from_slice(SOCKS_CONNECT);
        b.extend_from_slice(extra);
        self.rx(tcp, &b);
        tcp
    }

    /// What the socket was sent after the SOCKS5 method reply.
    pub fn reply(&mut self, tcp: TcpId) -> Vec<u8> {
        let out = self.tx_all(tcp);
        assert_eq!(out[..2], [5, 0], "method reply");
        out[2..].to_vec()
    }

    pub fn closed(reqs: &[IoRequest], tcp: TcpId) -> bool {
        reqs.iter()
            .any(|r| matches!(r, IoRequest::TcpClose { tcp: t, .. } if *t == tcp))
    }
    pub fn reset(&self, s: StreamId) -> bool {
        self.log().contains(&Call::StreamReset(s))
    }
    pub fn close_conn_count(&self, c: ConnId) -> usize {
        self.count(|x| *x == Call::CloseConn(c))
    }
    pub fn connects(&self) -> usize {
        self.count(|x| *x == Call::Connect)
    }
    pub fn opens(&self) -> usize {
        self.count(|x| matches!(x, Call::OpenStream(_)))
    }
}
