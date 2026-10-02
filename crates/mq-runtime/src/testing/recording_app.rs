//! `RecordingApp`: an `App` that records every callback and runs test
//! closures against `Cx` from inside callbacks (spec §8.1).

use crate::app::{AcceptMeta, App, Cx, DialError, ListenerTag, TcpEnd};
use crate::ids::{DialOpId, SocketOpId, TcpId, TimerId, UdpSocketId};
use mq_transport_api::Event;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

/// One `App` callback, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    Start,
    TransportEvent(Event),
    Accepted {
        l: ListenerTag,
        tcp: TcpId,
        meta: AcceptMeta,
    },
    TcpData(TcpId),
    TcpEnd(TcpId, TcpEnd),
    DialResult(DialOpId, Result<TcpId, DialError>),
    UdpSocket(SocketOpId, Result<(UdpSocketId, SocketAddr), io::ErrorKind>),
    UdpRx {
        sock: UdpSocketId,
        peer: SocketAddr,
        data: Vec<u8>,
    },
    Timer(TimerId),
    Shutdown,
}

type Reaction = Box<dyn FnMut(&Recorded, &mut Cx<'_>) + Send>;

#[derive(Default)]
struct Inner {
    log: Vec<Recorded>,
    reactions: Vec<Reaction>,
}

/// The test's side of a `RecordingApp`; `Clone + Send`.
#[derive(Clone, Default)]
pub struct RecordHandle(Arc<Mutex<Inner>>);

impl RecordHandle {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Every callback so far.
    pub fn records(&self) -> Vec<Recorded> {
        self.lock().log.clone()
    }
    /// Returns and clears the callbacks so far.
    pub fn take(&self) -> Vec<Recorded> {
        std::mem::take(&mut self.lock().log)
    }
    /// Runs `f` inside every later callback, after the callback is recorded.
    pub fn on(&self, f: impl FnMut(&Recorded, &mut Cx<'_>) + Send + 'static) {
        self.lock().reactions.push(Box::new(f));
    }
}

/// An `App` that records each callback into its `RecordHandle`.
#[derive(Default)]
pub struct RecordingApp {
    h: RecordHandle,
}

impl RecordingApp {
    pub fn new() -> (RecordingApp, RecordHandle) {
        let h = RecordHandle::default();
        (RecordingApp { h: h.clone() }, h)
    }
    pub fn handle(&self) -> &RecordHandle {
        &self.h
    }

    /// Records, then runs the reactions outside the lock (they may use the handle).
    fn rec(&mut self, cx: &mut Cx<'_>, r: Recorded) {
        let mut reactions = {
            let mut g = self.h.lock();
            g.log.push(r.clone());
            std::mem::take(&mut g.reactions)
        };
        for f in &mut reactions {
            f(&r, cx);
        }
        let mut g = self.h.lock();
        reactions.append(&mut g.reactions);
        g.reactions = reactions;
    }
}

impl App for RecordingApp {
    fn on_start(&mut self, cx: &mut Cx<'_>) {
        self.rec(cx, Recorded::Start)
    }
    fn on_transport_event(&mut self, cx: &mut Cx<'_>, ev: Event) {
        self.rec(cx, Recorded::TransportEvent(ev))
    }
    fn on_accepted(&mut self, cx: &mut Cx<'_>, l: ListenerTag, tcp: TcpId, meta: AcceptMeta) {
        self.rec(cx, Recorded::Accepted { l, tcp, meta })
    }
    fn on_tcp_data(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        self.rec(cx, Recorded::TcpData(tcp))
    }
    fn on_tcp_end(&mut self, cx: &mut Cx<'_>, tcp: TcpId, end: TcpEnd) {
        self.rec(cx, Recorded::TcpEnd(tcp, end))
    }
    fn on_dial_result(&mut self, cx: &mut Cx<'_>, op: DialOpId, r: Result<TcpId, DialError>) {
        self.rec(cx, Recorded::DialResult(op, r))
    }
    fn on_udp_socket(
        &mut self,
        cx: &mut Cx<'_>,
        op: SocketOpId,
        r: Result<(UdpSocketId, SocketAddr), io::ErrorKind>,
    ) {
        self.rec(cx, Recorded::UdpSocket(op, r))
    }
    fn on_udp_rx(&mut self, cx: &mut Cx<'_>, sock: UdpSocketId, peer: SocketAddr, data: &[u8]) {
        let data = data.to_vec();
        self.rec(cx, Recorded::UdpRx { sock, peer, data })
    }
    fn on_timer(&mut self, cx: &mut Cx<'_>, id: TimerId) {
        self.rec(cx, Recorded::Timer(id))
    }
    fn on_shutdown(&mut self, cx: &mut Cx<'_>) {
        self.rec(cx, Recorded::Shutdown)
    }
}
