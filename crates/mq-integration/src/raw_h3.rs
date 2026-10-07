// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! The raw-H3 peer (adoption spec §6.2): HTTP/3 as fixed bytes on raw streams, for the
//! malformed input a compliant H3 send API cannot produce.

use mq_runtime::{
    AcceptMeta, App, Cx, DialError, DialOpId, ListenerTag, SocketOpId, TcpEnd, TcpId, TimerId,
    UdpSocketId,
};
use mq_transport_api::{CloseReason, ConnConfig, ConnId, ConnProto, Event, StreamId, StreamKind};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

/// The peer's control stream: stream type 0x00, then an empty SETTINGS frame (RFC 9114 §6.2.1).
const CONTROL: [u8; 3] = [0x00, 0x04, 0x00];

/// What the peer saw.
#[derive(Debug, Default)]
pub struct RawH3Seen {
    /// Every `ConnClosed` reason.
    pub closed: Vec<CloseReason>,
    /// Every `StreamPeerReset`: the stream and its code.
    pub resets: Vec<(StreamId, u64)>,
    /// The bytes read on request streams (the one a client opened, every one opened to a
    /// server), and whether a FIN ended one.
    pub read: Vec<u8>,
    pub fin: bool,
}

/// `Clone + Send` view of a peer's `RawH3Seen`.
#[derive(Clone, Debug, Default)]
pub struct RawH3Handle(Arc<Mutex<RawH3Seen>>);

impl RawH3Handle {
    pub fn lock(&self) -> MutexGuard<'_, RawH3Seen> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct RawH3Script {
    /// Client role: the request stream's bytes and FIN. Server role: written as the response
    /// to every request stream the peer opens.
    pub stream: Vec<u8>,
    pub fin: bool,
}

/// A peer that speaks HTTP/3 by writing fixed bytes on raw streams (spec §6.2): no H3 stack,
/// so it can send what no compliant stack sends. Runs on the raw `Transport` with ALPN `h3` enabled
/// (`loopback::raw_h3_transport`).
pub struct RawH3Peer {
    /// Client role: the server to connect to.
    server: Option<SocketAddr>,
    s: RawH3Script,
    h: RawH3Handle,
    /// Request streams.
    reqs: HashSet<StreamId>,
    /// Streams with bytes (or the FIN) still unsent: the bytes, how many were sent, the FIN.
    out: HashMap<StreamId, (Vec<u8>, usize, bool)>,
}

impl RawH3Peer {
    pub fn client(server: SocketAddr, s: RawH3Script) -> (RawH3Peer, RawH3Handle) {
        Self::make(Some(server), s)
    }

    pub fn server(s: RawH3Script) -> (RawH3Peer, RawH3Handle) {
        Self::make(None, s)
    }

    fn make(server: Option<SocketAddr>, s: RawH3Script) -> (RawH3Peer, RawH3Handle) {
        let h = RawH3Handle::default();
        let p = RawH3Peer {
            server,
            s,
            h: h.clone(),
            reqs: HashSet::new(),
            out: HashMap::new(),
        };
        (p, h)
    }

    fn control(&mut self, cx: &mut Cx<'_>, c: ConnId) {
        let s = cx.open_uni(c).expect("open_uni");
        self.write(cx, s, CONTROL.to_vec(), false);
    }

    /// Starts writing the script on request stream `s`.
    fn respond(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        self.reqs.insert(s);
        self.write(cx, s, self.s.stream.clone(), self.s.fin);
    }

    /// Writes `bytes` (+ `fin`) on `s`; what is not accepted follows on `StreamWritable`.
    fn write(&mut self, cx: &mut Cx<'_>, s: StreamId, bytes: Vec<u8>, fin: bool) {
        self.out.insert(s, (bytes, 0, fin));
        self.push(cx, s);
    }

    fn push(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let Some((bytes, sent, fin)) = self.out.get_mut(&s) else {
            return;
        };
        let rest = &bytes[*sent..];
        let done = match cx.stream_send(s, rest, *fin) {
            Ok(n) => {
                *sent += n;
                n == rest.len()
            }
            Err(e) => e != mq_transport_api::StreamError::Blocked,
        };
        if done {
            self.out.remove(&s);
        }
    }

    /// Reads everything `s` has; request-stream bytes are recorded, the rest discarded.
    fn read(&mut self, cx: &mut Cx<'_>, s: StreamId) {
        let mut buf = [0u8; 16 * 1024];
        let req = self.reqs.contains(&s);
        while let Ok((n, fin)) = cx.stream_recv(s, &mut buf) {
            if req {
                let mut seen = self.h.lock();
                seen.read.extend_from_slice(&buf[..n]);
                seen.fin |= fin;
            }
            if fin || n == 0 {
                break;
            }
        }
    }
}

impl App for RawH3Peer {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        if let Some(peer) = self.server {
            let cfg = ConnConfig {
                peer,
                sni: "mqproxy",
                idle_timeout: None,
                proto: ConnProto::H3,
            };
            cx.connect(&cfg).expect("connect");
        }
    }

    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        match ev {
            Event::ConnEstablished(c) if self.server.is_some() => {
                self.control(cx, c);
                let s = cx.open_stream(c).expect("open_stream");
                self.respond(cx, s);
            }
            Event::NewConn(c, _) => self.control(cx, c),
            Event::NewStream(_, s, info) => {
                if info.kind == StreamKind::Bidi {
                    self.respond(cx, s);
                }
                self.read(cx, s);
            }
            Event::StreamReadable(s) => self.read(cx, s),
            Event::StreamWritable(s) => self.push(cx, s),
            Event::StreamPeerReset(s, code) => {
                self.h.lock().resets.push((s, code));
                self.read(cx, s); // the retirement probe (adoption spec §3)
            }
            Event::ConnClosed(_, why) => self.h.lock().closed.push(why),
            _ => {}
        }
    }

    fn on_timer(&mut self, _: &mut Cx<'_>, _: TimerId) {}
    crate::h3_apps::no_io!();
}

/// A HEADERS frame of `fields` (static-table QPACK), unvalidated: on h3wire's hidden
/// `qpack::encoder::encode_field_section` and `frame::encode_header`.
pub fn headers_frame(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let fs: Vec<h3wire::FieldRef> = fields
        .iter()
        .map(|&(n, v)| h3wire::FieldRef::new(n, v))
        .collect();
    let mut section = Vec::new();
    h3wire::qpack::encoder::encode_field_section(&fs, &mut section);
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x01, section.len() as u64, &mut out);
    out.extend_from_slice(&section);
    out
}

/// A DATA frame header declaring `declared` bytes, then `payload` (`declared` may exceed it:
/// a cut frame).
pub fn data_frame(declared: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    h3wire::frame::encode_header(0x00, declared, &mut out);
    out.extend_from_slice(payload);
    out
}

/// The value of `name` in the first HEADERS frame of `bytes` (a request stream as read raw);
/// on h3wire's hidden `varint` and `qpack::decoder`.
pub fn field(bytes: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    use h3wire::qpack::decoder::{Span, decode_field_section};
    let mut b = bytes;
    while !b.is_empty() {
        let (ty, n) = h3wire::varint::decode(b)?;
        let (len, m) = h3wire::varint::decode(&b[n..])?;
        let payload = b.get(n + m..n + m + len as usize)?;
        b = &b[n + m + len as usize..];
        if ty != 0x01 {
            continue; // DATA or a reserved frame
        }
        let (mut arena, mut fields) = (Vec::new(), Vec::new());
        decode_field_section(payload, &mut arena, &mut fields).ok()?;
        let get = |s: Span| match s {
            Span::Static(v) => v.to_vec(),
            Span::Arena(a, z) => arena[a as usize..z as usize].to_vec(),
        };
        return fields
            .iter()
            .find(|f| get(f.name) == name)
            .map(|f| get(f.value));
    }
    None
}
