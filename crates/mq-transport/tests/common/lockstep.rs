// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Lockstep fabric harness (spec §8.1 "Fabric"): one `Transport` per thread (spec §4.6). The
//! test sends one command at a time and waits for the reply, so only one side runs at a time.
//! Each command carries `now`; there is no shared clock. Path k sends from `local_addrs[k]`
//! (from the last address when there are fewer addresses than paths, as a one-socket server).

use mq_transport::Transport;
use mq_transport_api::{CongestionControl, Event, Role, Scheduler, Time, TransportConfig};
use mq_transport_api::{TransportOps, TxKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

pub const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/test.crt");
pub const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/test.key");

pub fn cfg(role: Role) -> TransportConfig {
    TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns: 0,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
        h3: false,
        qlog: None,
    }
}

pub fn server_role() -> Role {
    Role::Server {
        cert: PathBuf::from(CERT),
        key: PathBuf::from(KEY),
    }
}

type Cmd = Box<dyn FnOnce(&mut Transport) + Send>;

/// One datagram on the wire.
#[derive(Clone, Debug)]
pub struct Datagram {
    /// The transmit queue it came from.
    pub key: TxKey,
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

pub struct Peer {
    tx: Option<mpsc::Sender<Cmd>>,
    thread: Option<thread::JoinHandle<()>>,
    pub local_addrs: Vec<SocketAddr>,
    /// Keys whose "socket" is unwritable: `pump_out` leaves their queues untouched.
    pub blocked: HashSet<TxKey>,
    /// Path id -> index into `local_addrs`, overriding the default "path k sends from
    /// `local_addrs[k]`" (a re-added path takes a fresh id but reuses an address).
    pub path_addr: HashMap<u64, usize>,
}

impl Peer {
    pub fn spawn(cfg: TransportConfig, local_addrs: Vec<SocketAddr>) -> Peer {
        let (tx, rx) = mpsc::channel::<Cmd>();
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut t = Transport::new(cfg).expect("Transport::new");
            ready_tx.send(()).unwrap();
            while let Ok(cmd) = rx.recv() {
                cmd(&mut t);
            }
        });
        ready_rx
            .recv()
            .expect("peer thread failed to create its transport");
        Peer {
            tx: Some(tx),
            thread: Some(thread),
            local_addrs,
            blocked: HashSet::new(),
            path_addr: HashMap::new(),
        }
    }

    /// Runs `f(transport, now)` on the peer's thread and returns its result.
    pub fn call<R: Send + 'static>(
        &self,
        now: Time,
        f: impl FnOnce(&mut Transport, Time) -> R + Send + 'static,
    ) -> R {
        let (rtx, rrx) = mpsc::channel();
        let cmd: Cmd = Box::new(move |t| {
            let _ = rtx.send(f(t, now));
        });
        self.tx.as_ref().unwrap().send(cmd).unwrap();
        rrx.recv().expect("peer thread panicked")
    }

    /// Drains every key not in `blocked` into datagrams and commits them. Sending takes no
    /// time; `now` only orders the command with the others.
    pub fn pump_out(&self, now: Time) -> Vec<Datagram> {
        let blocked = self.blocked.clone();
        let addrs = self.local_addrs.clone();
        let path_addr = self.path_addr.clone();
        self.call(now, move |t, _| {
            let mut keys = Vec::new();
            t.pending_transmit(&mut keys);
            let mut out = Vec::new();
            for key in keys.into_iter().filter(|k| !blocked.contains(k)) {
                // A server has one socket for every path.
                let k = path_addr.get(&key.1.0).copied().unwrap_or(key.1.0 as usize);
                let from = addrs[k.min(addrs.len() - 1)];
                while let Some(tx) = t.peek_transmit(key) {
                    let before = out.len();
                    out.extend(tx.payload.chunks(tx.segment_size).map(|d| Datagram {
                        key,
                        from,
                        to: tx.dst,
                        data: d.to_vec(),
                    }));
                    let n = out.len() - before;
                    t.transmit_done(key, n);
                }
            }
            out
        })
    }

    pub fn deliver(&self, now: Time, local: SocketAddr, peer: SocketAddr, data: Vec<u8>) {
        self.call(now, move |t, now| t.recv_datagram(now, local, peer, &data));
    }

    pub fn drive(&self, now: Time) {
        self.call(now, |t, now| t.drive(now));
    }

    pub fn next_timeout(&self) -> Option<Time> {
        self.call(Time::ZERO, |t, _| t.next_timeout())
    }

    pub fn drain_events(&self) -> Vec<Event> {
        self.call(Time::ZERO, |t, _| {
            std::iter::from_fn(|| t.poll_event()).collect()
        })
    }

    pub fn owns(&self, a: SocketAddr) -> bool {
        self.local_addrs.contains(&a)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        drop(self.tx.take()); // ends the command loop; the transport drops on its own thread
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `exchange` for any number of peers: datagrams go to the peer owning their destination
/// (to nobody if none does).
pub fn exchange_many(now: Time, peers: &[&Peer]) -> usize {
    let mut moved = 0;
    loop {
        let mut progress = false;
        for src in peers {
            for d in src.pump_out(now) {
                progress = true;
                moved += 1;
                if let Some(dst) = peers.iter().find(|p| p.owns(d.to)) {
                    dst.deliver(now, d.to, d.from, d.data);
                    dst.drive(now);
                }
            }
        }
        if !progress {
            return moved;
        }
    }
}

/// Moves datagrams between `a` and `b`, driving each receiver after a delivery, until
/// neither has anything to send. Returns the number of datagrams moved.
pub fn exchange(now: Time, a: &Peer, b: &Peer) -> usize {
    let mut moved = 0;
    loop {
        let mut progress = false;
        for (src, dst) in [(a, b), (b, a)] {
            let out = src.pump_out(now);
            if out.is_empty() {
                continue;
            }
            progress = true;
            moved += out.len();
            for d in out {
                assert!(dst.owns(d.to), "datagram to unknown address {}", d.to);
                dst.deliver(now, d.to, d.from, d.data);
            }
            dst.drive(now);
        }
        if !progress {
            return moved;
        }
    }
}
