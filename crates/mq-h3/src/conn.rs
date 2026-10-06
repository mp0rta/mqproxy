//! One `h3wire::Connection` per H3 conn, and the raw events it consumes (adoption spec §4.2,
//! §4.4).

use crate::req::{Req, req_id};
use crate::{BOOT_READ, H3Wire};
use h3wire::{Config, Connection, H3Code, Role, StreamId as Q};
use mq_transport_api::{ConnId, ConnProto, Event, StreamError, StreamId, Time, TransportOps};
use std::collections::{HashMap, HashSet};

/// Equals `mq_transport::H3_FIELD_SECTION_MAX`; mq-h3 does not depend on mq-transport.
const FIELD_SECTION_MAX: usize = 64 * 1024;

/// adoption spec §4.2.
pub(crate) fn h3_config() -> Config {
    let mut c = Config::default();
    c.max_encoded_field_section_size = FIELD_SECTION_MAX;
    c.max_field_section_size = Some(FIELD_SECTION_MAX as u64);
    c.grease = true;
    c.enable_connect_protocol = false;
    c.h3_datagram = false;
    c
}

pub(crate) struct H3Conn {
    pub(crate) h3: Connection,
    pub(crate) client: bool,
    /// The mq id of each quic id: local and peer uni streams, request streams.
    pub(crate) mq: HashMap<u64, StreamId>,
    /// Peer uni streams read to FIN or reset: never fed again, since h3wire would take
    /// further bytes for a new stream's type.
    pub(crate) uni_done: HashSet<StreamId>,
    /// We closed the transport; h3wire's actions and bytes are dropped from then on.
    pub(crate) closing: bool,
}

impl H3Conn {
    pub(crate) fn is_local(&self, q: Q) -> bool {
        q.is_client_initiated() == self.client
    }
}

impl<T: TransportOps> H3Wire<T> {
    pub(crate) fn add_conn(&mut self, now: Time, c: ConnId, role: Role) {
        let conn = H3Conn {
            h3: Connection::new(role, h3_config()),
            client: role == Role::Client,
            mq: HashMap::new(),
            uni_done: HashSet::new(),
            closing: false,
        };
        self.conns.insert(c, conn);
        self.service(now, c);
    }

    /// An inner event, active mode. Returns it if it passes through; the raw stream events
    /// of H3 conns are consumed here (adoption spec §4.1).
    pub(crate) fn on_event(&mut self, now: Time, e: Event) -> Option<Event> {
        match e {
            Event::NewConn(c, proto) => {
                self.server = true;
                if proto == ConnProto::H3 {
                    self.add_conn(now, c, Role::Server);
                }
            }
            // ponytail: C2 drops the conn outright; Task C5 adds the request fan-out.
            Event::ConnClosed(c, _) => {
                if let Some(conn) = self.conns.remove(&c) {
                    for s in conn.mq.values() {
                        self.streams.remove(s);
                    }
                }
            }
            Event::NewStream(c, s, info) => {
                let Some(conn) = self.conns.get_mut(&c) else {
                    return Some(e);
                };
                conn.mq.insert(info.quic_id, s);
                self.streams.insert(s, (c, Q(info.quic_id)));
                // A peer request stream (server): h3wire holds its state from the first
                // sight; the gateway learns of it at its HEADERS (adoption spec §4.3).
                if Q(info.quic_id).is_request() && !conn.client {
                    let req = Req::new(c, s, info.quic_id, false);
                    self.reqs.insert(req_id(s), req);
                }
                return None;
            }
            Event::StreamReadable(s)
            | Event::StreamWritable(s)
            | Event::StreamPeerReset(s, _)
            | Event::StreamStopSending(s, _)
            | Event::StreamCloseStats(s, _)
            | Event::StreamClosed(s) => {
                let Some(&(c, q)) = self.streams.get(&s) else {
                    return Some(e);
                };
                self.on_stream_event(now, c, s, q, e);
                self.service(now, c);
                return None;
            }
            _ => {}
        }
        Some(e)
    }

    fn on_stream_event(&mut self, now: Time, c: ConnId, s: StreamId, q: Q, e: Event) {
        if q.is_request() && self.on_req_event(now, c, s, q, &e) {
            return;
        }
        let conn = self
            .conns
            .get_mut(&c)
            .expect("streams only name live conns");
        let peer_uni = q.is_uni() && !conn.is_local(q);
        match e {
            Event::StreamReadable(_) if peer_uni => self.read_uni(now, c, s, q),
            Event::StreamPeerReset(_, code) => {
                if peer_uni && conn.uni_done.insert(s) {
                    log_closed(conn.h3.stream_reset_received(q, H3Code(code)));
                }
                // Retirement probe (adoption spec §3).
                if peer_uni {
                    self.read_uni(now, c, s, q);
                }
            }
            Event::StreamStopSending(_, code) => {
                log_closed(conn.h3.stop_sending_received(q, H3Code(code)));
            }
            Event::StreamClosed(_) => {
                conn.mq.remove(&q.0);
                conn.uni_done.remove(&s);
                self.streams.remove(&s);
            }
            // Writable: `service` flushes. CloseStats of a non-request stream: ignored.
            _ => {}
        }
    }

    /// Reads a peer uni stream eagerly to the transport's end (adoption spec §4.4).
    fn read_uni(&mut self, now: Time, c: ConnId, s: StreamId, q: Q) {
        let mut buf = [0u8; BOOT_READ];
        loop {
            let r = self.inner.stream_recv(now, s, &mut buf);
            let conn = self
                .conns
                .get_mut(&c)
                .expect("streams only name live conns");
            match r {
                Ok((n, fin)) => {
                    if !conn.uni_done.contains(&s) {
                        // A uni stream always consumes everything.
                        log_closed(conn.h3.recv(q, &buf[..n], fin).map(drop));
                    }
                    if fin {
                        conn.uni_done.insert(s);
                    }
                    if fin || n == 0 {
                        return;
                    }
                }
                Err(StreamError::Reset) => {
                    // adoption spec §4.4: a deliberate uni-only shortcut. The code only matters
                    // on a critical stream, which closes the conn whatever it is, so the reset
                    // is passed now with REQUEST_CANCELLED. Request streams instead follow the
                    // deferred "reset, code pending" rule (Task C3).
                    if conn.uni_done.insert(s) {
                        log_closed(conn.h3.stream_reset_received(q, H3Code::REQUEST_CANCELLED));
                    }
                    return;
                }
                Err(_) => return,
            }
        }
    }
}

/// `ConnectionError` is a state notification; the wire effect is a queued action
/// (adoption spec §5.1).
pub(crate) fn log_closed(r: Result<(), h3wire::ConnectionError>) {
    if let Err(e) = r {
        log::debug!("h3wire: {e}");
    }
}
