// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! A connected client/server pair over the lockstep harness, with virtual-time stepping and
//! an event log per side.

use super::lockstep::{Datagram, Peer, cfg, server_role};
use mq_transport_api::{
    ConnConfig, ConnId, ConnProto, Event, PathError, PathId, Role, StreamError, StreamId,
    StreamInfo, Time, TransportConfig, TransportOps,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub const T0: Time = Time(1_000_000);
pub const MS: Duration = Duration::from_millis(1);
pub const ACTIVE: u32 = 2; // XQC_PATH_STATE_ACTIVE

pub fn srv_addr() -> SocketAddr {
    "10.0.0.1:4433".parse().unwrap()
}

/// Client path `k` sends from this address.
pub fn cli_addr(k: usize) -> SocketAddr {
    SocketAddr::from(([10, 0, 1, 2 + k as u8], 50000))
}

pub fn conn_cfg(idle: Option<Duration>) -> ConnConfig {
    ConnConfig {
        peer: srv_addr(),
        sni: "mqproxy",
        idle_timeout: idle,
        proto: ConnProto::Raw,
    }
}

pub struct Opts {
    pub server: TransportConfig,
    pub client: TransportConfig,
    /// Client local addresses (path k uses `cli_addr(k)`).
    pub paths: usize,
    pub idle: Option<Duration>,
    /// Client qlog directory, opened at creation.
    pub qlog: Option<PathBuf>,
    /// Client connection protocol.
    pub proto: ConnProto,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            server: cfg(server_role()),
            client: cfg(Role::Client),
            paths: 1,
            idle: None,
            qlog: None,
            proto: ConnProto::Raw,
        }
    }
}

pub struct Pair {
    pub client: Peer,
    pub server: Peer,
    pub conn: ConnId,
    pub srv_conn: ConnId,
    pub now: Time,
    /// Events drained so far, per side (appended by every `exchange`).
    pub cev: Vec<Event>,
    pub sev: Vec<Event>,
    /// When set, every moved datagram is appended to `wire`.
    pub record: bool,
    pub wire: Vec<Datagram>,
    /// When set, datagrams are lost in both directions.
    pub lose: bool,
}

impl Pair {
    pub fn new() -> Pair {
        Pair::with(Opts::default())
    }

    /// Spawns both peers and completes the handshake at `T0`.
    pub fn with(o: Opts) -> Pair {
        let server = Peer::spawn(o.server, vec![srv_addr()]);
        let client = Peer::spawn(
            TransportConfig {
                qlog: o.qlog,
                ..o.client
            },
            (0..o.paths).map(cli_addr).collect(),
        );
        let mut cc = conn_cfg(o.idle);
        cc.proto = o.proto;
        let conn = client
            .call(T0, move |t, now| t.connect(now, &cc))
            .expect("connect");
        let mut p = Pair {
            client,
            server,
            conn,
            srv_conn: conn, // replaced below
            now: T0,
            cev: Vec::new(),
            sev: Vec::new(),
            record: false,
            wire: Vec::new(),
            lose: false,
        };
        assert!(p.exchange() > 0);
        p.srv_conn = p
            .sev
            .iter()
            .find_map(|e| match e {
                Event::NewConn(c, _) => Some(*c),
                _ => None,
            })
            .expect("server NewConn");
        assert!(
            p.sev.contains(&Event::ConnEstablished(p.srv_conn)),
            "{:?}",
            p.sev
        );
        assert!(p.cev.contains(&Event::ConnEstablished(conn)), "{:?}", p.cev);
        p
    }

    pub fn collect(&mut self) {
        self.cev.extend(self.client.drain_events());
        self.sev.extend(self.server.drain_events());
    }

    /// Moves datagrams both ways, driving each receiver after a delivery, until neither side
    /// has anything to send; then drains events. Returns the number of datagrams moved.
    pub fn exchange(&mut self) -> usize {
        let mut moved = 0;
        loop {
            let mut progress = false;
            for to_server in [true, false] {
                let (src, dst) = if to_server {
                    (&self.client, &self.server)
                } else {
                    (&self.server, &self.client)
                };
                let out = src.pump_out(self.now);
                if out.is_empty() {
                    continue;
                }
                progress = true;
                moved += out.len();
                if self.lose {
                    continue;
                }
                for d in out {
                    assert!(dst.owns(d.to), "datagram to unknown address {}", d.to);
                    if self.record {
                        self.wire.push(d.clone());
                    }
                    dst.deliver(self.now, d.to, d.from, d.data);
                }
                dst.drive(self.now);
            }
            if !progress {
                break;
            }
        }
        self.collect();
        moved
    }

    /// Advances virtual time by `dt`, drives both sides and exchanges.
    pub fn tick(&mut self, dt: Duration) {
        self.now = self.now + dt;
        self.client.drive(self.now);
        self.server.drive(self.now);
        self.exchange();
    }

    /// Ticks by `dt` until `cond` holds (checked first), at most `max_steps` ticks.
    pub fn pump_until(
        &mut self,
        dt: Duration,
        max_steps: usize,
        mut cond: impl FnMut(&mut Pair) -> bool,
    ) -> bool {
        for _ in 0..max_steps {
            if cond(self) {
                return true;
            }
            self.tick(dt);
        }
        cond(self)
    }

    /// Jumps to the earlier of both sides' `next_timeout()` (never backwards), drives both
    /// and exchanges. Returns false when neither side has a deadline.
    pub fn follow_timeout(&mut self) -> bool {
        let next = [self.client.next_timeout(), self.server.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        let Some(at) = next else { return false };
        self.now = self.now.max(at);
        self.client.drive(self.now);
        self.server.drive(self.now);
        self.exchange();
        true
    }

    pub fn client_closed(&self) -> Option<mq_transport_api::CloseReason> {
        closed(&self.cev, self.conn)
    }

    pub fn server_closed(&self) -> Option<mq_transport_api::CloseReason> {
        closed(&self.sev, self.srv_conn)
    }

    pub fn open(&self) -> StreamId {
        let c = self.conn;
        self.client
            .call(self.now, move |t, now| t.open_stream(now, c))
            .expect("open_stream")
    }
}

pub fn mp_ready_count(p: &Pair) -> usize {
    p.cev
        .iter()
        .filter(|e| **e == Event::MpReady(p.conn))
        .count()
}

pub fn add_path(p: &Pair) -> Result<PathId, PathError> {
    let c = p.conn;
    p.client
        .call(p.now, move |t, now| t.add_path(now, c, false))
}

pub fn path_state(p: &Pair, id: u64) -> Option<u32> {
    let c = p.conn;
    let st = p.client.call(p.now, move |t, _| t.conn_stats(c)).unwrap();
    st.paths.iter().find(|x| x.id == id).map(|x| x.state)
}

pub fn closed(ev: &[Event], c: ConnId) -> Option<mq_transport_api::CloseReason> {
    ev.iter().find_map(|e| match e {
        Event::ConnClosed(x, r) if *x == c => Some(*r),
        _ => None,
    })
}

/// The peer streams announced in `ev`, in order.
pub fn new_streams(ev: &[Event]) -> Vec<(StreamId, StreamInfo)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::NewStream(_, s, i) => Some((*s, *i)),
            _ => None,
        })
        .collect()
}

/// Events in `ev` about stream `s`.
pub fn stream_events(ev: &[Event], s: StreamId) -> Vec<Event> {
    ev.iter()
        .filter(|e| match e {
            Event::NewStream(_, x, _)
            | Event::StreamReadable(x)
            | Event::StreamWritable(x)
            | Event::StreamClosed(x) => *x == s,
            _ => false,
        })
        .cloned()
        .collect()
}

pub fn send(
    p: &Peer,
    now: Time,
    s: StreamId,
    data: Vec<u8>,
    fin: bool,
) -> Result<usize, StreamError> {
    p.call(now, move |t, now| t.stream_send(now, s, &data, fin))
}

/// Reads until `Blocked`, FIN or an error. `Ok((bytes, fin))`; an error after some bytes
/// were read is returned as the error.
pub fn read_all(p: &Peer, now: Time, s: StreamId) -> Result<(Vec<u8>, bool), StreamError> {
    p.call(now, move |t, now| {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match t.stream_recv(now, s, &mut buf) {
                Ok((n, fin)) => {
                    out.extend_from_slice(&buf[..n]);
                    if fin {
                        return Ok((out, true));
                    }
                    if n == 0 {
                        return Ok((out, false));
                    }
                }
                Err(StreamError::Blocked) => return Ok((out, false)),
                Err(e) => return Err(e),
            }
        }
    })
}

pub fn recv(p: &Peer, now: Time, s: StreamId, cap: usize) -> Result<(Vec<u8>, bool), StreamError> {
    p.call(now, move |t, now| {
        let mut buf = vec![0u8; cap];
        t.stream_recv(now, s, &mut buf)
            .map(|(n, f)| (buf[..n].to_vec(), f))
    })
}

pub fn stream_count(p: &Peer, c: ConnId) -> u32 {
    p.call(Time::ZERO, move |t, _| t.stream_count(c))
}
