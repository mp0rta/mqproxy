//! `FakeIo`: an `Io` on virtual time with scripted sockets, resolutions and
//! connects (spec §8.1 "Scripted"). Never sleeps: with `auto_advance` on, a
//! `wait(Until(t))` with nothing pending moves the clock to `t`.

use crate::app::{AcceptMeta, IoResult};
use crate::driver::{
    Io, IoEvent, ListenerKey, RecvBatch, RecvStop, SockKey, TcpSock, UdpSock, Wait,
};
use crate::ids::DialOpId;
use mq_linux::RecvMeta;
use mq_transport_api::{Time, Transmit};
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// One `Io` call, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Wait(Wait),
    Accept(ListenerKey),
    /// Buffer length offered.
    Read(TcpSock, usize),
    /// Bytes offered.
    Write(TcpSock, usize),
    /// Budget.
    RecvUdp(UdpSock, usize),
    /// Datagrams offered.
    SendUdp(UdpSock, usize),
    StartResolve(DialOpId, String, u16),
    StartConnect(DialOpId, SocketAddr),
    CancelConnect(DialOpId),
    OpenUdp(IpAddr),
    ShutdownWrite(TcpSock),
    CloseTcp(TcpSock, bool),
    CloseUdp(UdpSock),
    SocketError(TcpSock),
}

#[derive(Default)]
struct FakeTcp {
    rx: VecDeque<u8>,
    eof: bool,
    read_err: Option<ErrorKind>,
    read_chunk: Option<usize>,
    /// Bytes writes accept before `WouldBlock`; `None` = unlimited.
    write_room: Option<usize>,
    write_err: Option<ErrorKind>,
    written: Vec<u8>,
    sock_err: Option<ErrorKind>,
    closed: Option<bool>,
}

struct FakeUdp {
    local: SocketAddr,
    rx: VecDeque<(SocketAddr, Vec<u8>)>,
    unwritable: bool,
    send_script: VecDeque<io::Result<usize>>,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    closed: bool,
}

/// Scripted `Io` on virtual time.
pub struct FakeIo {
    now: Time,
    auto_advance: bool,
    next_key: u64,
    events: VecDeque<IoEvent>,
    pending_work: usize,
    ops: Vec<Op>,
    tcp: HashMap<TcpSock, FakeTcp>,
    udp: HashMap<UdpSock, FakeUdp>,
    accepts: HashMap<ListenerKey, VecDeque<io::Result<(TcpSock, AcceptMeta)>>>,
    sync_connect_fail: HashMap<SocketAddr, ErrorKind>,
    open_udp_script: VecDeque<io::Result<SocketAddr>>,
}

impl Default for FakeIo {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIo {
    /// Clock at zero, `auto_advance` on.
    pub fn new() -> FakeIo {
        FakeIo {
            now: Time::ZERO,
            auto_advance: true,
            next_key: 0,
            events: VecDeque::new(),
            pending_work: 0,
            ops: Vec::new(),
            tcp: HashMap::new(),
            udp: HashMap::new(),
            accepts: HashMap::new(),
            sync_connect_fail: HashMap::new(),
            open_udp_script: VecDeque::new(),
        }
    }

    fn key(&mut self) -> SockKey {
        self.next_key += 1;
        SockKey(self.next_key)
    }
    fn new_tcp(&mut self) -> TcpSock {
        let s = TcpSock(self.key());
        self.tcp.insert(s, FakeTcp::default());
        s
    }
    fn tcp_mut(&mut self, s: TcpSock) -> &mut FakeTcp {
        self.tcp.get_mut(&s).expect("known fake TCP socket")
    }
    fn udp_mut(&mut self, s: UdpSock) -> &mut FakeUdp {
        self.udp.get_mut(&s).expect("known fake UDP socket")
    }

    // --- Clock ---

    pub fn set_now(&mut self, t: Time) {
        self.now = t;
    }
    pub fn advance(&mut self, d: Duration) {
        self.now = self.now + d;
    }
    /// On: `wait(Until(t))` with nothing pending advances to `t` and returns
    /// `Timer`. Off: it returns what is pending (maybe nothing) at once.
    pub fn set_auto_advance(&mut self, on: bool) {
        self.auto_advance = on;
    }

    // --- Events ---

    /// Queues any event for the next `wait`.
    pub fn push_event(&mut self, e: IoEvent) {
        self.events.push_back(e);
    }
    pub fn inject_shutdown(&mut self) {
        self.push_event(IoEvent::Shutdown);
    }
    /// `has_pending_work` is true for the next `n` waits.
    pub fn set_pending_work(&mut self, n: usize) {
        self.pending_work = n;
    }

    // --- Log ---

    pub fn ops(&self) -> &[Op] {
        &self.ops
    }
    pub fn take_ops(&mut self) -> Vec<Op> {
        std::mem::take(&mut self.ops)
    }
    pub fn waits(&self) -> Vec<Wait> {
        self.ops
            .iter()
            .filter_map(|o| match o {
                Op::Wait(w) => Some(*w),
                _ => None,
            })
            .collect()
    }

    // --- Listeners ---

    pub fn add_listener(&mut self) -> ListenerKey {
        let l = ListenerKey(self.key());
        self.accepts.insert(l, VecDeque::new());
        l
    }
    /// Queues a connection on `l` (and its readable edge); returns its socket.
    pub fn push_accept(&mut self, l: ListenerKey, meta: AcceptMeta) -> TcpSock {
        let s = self.new_tcp();
        self.accepts
            .get_mut(&l)
            .expect("known listener")
            .push_back(Ok((s, meta)));
        self.push_event(IoEvent::Readable(l.0));
        s
    }
    /// Queues an accept failure (e.g. `EMFILE`) and a readable edge.
    pub fn push_accept_err(&mut self, l: ListenerKey, e: io::Error) {
        self.accepts
            .get_mut(&l)
            .expect("known listener")
            .push_back(Err(e));
        self.push_event(IoEvent::Readable(l.0));
    }

    // --- TCP endpoints ---

    /// Bytes for the socket to read, with a readable edge.
    pub fn tcp_feed(&mut self, s: TcpSock, data: &[u8]) {
        self.tcp_mut(s).rx.extend(data);
        self.push_event(IoEvent::Readable(s.0));
    }
    /// Reads return `Eof` once the fed bytes are gone; a readable edge.
    pub fn tcp_eof(&mut self, s: TcpSock) {
        self.tcp_mut(s).eof = true;
        self.push_event(IoEvent::Readable(s.0));
    }
    /// Reads fail with `kind`; a readable edge.
    pub fn tcp_read_error(&mut self, s: TcpSock, kind: ErrorKind) {
        self.tcp_mut(s).read_err = Some(kind);
        self.push_event(IoEvent::Readable(s.0));
    }
    /// Each read returns at most `n` bytes.
    pub fn tcp_read_chunk(&mut self, s: TcpSock, n: usize) {
        self.tcp_mut(s).read_chunk = Some(n);
    }
    /// Writes accept `n` more bytes in total, then return `WouldBlock`.
    pub fn would_block_after(&mut self, s: TcpSock, n: usize) {
        self.tcp_mut(s).write_room = Some(n);
    }
    /// Writes fail with `kind`.
    pub fn tcp_write_error(&mut self, s: TcpSock, kind: ErrorKind) {
        self.tcp_mut(s).write_err = Some(kind);
    }
    /// `EPOLLERR` with `SO_ERROR` = `kind`.
    pub fn fail_socket(&mut self, s: TcpSock, kind: ErrorKind) {
        self.tcp_mut(s).sock_err = Some(kind);
        self.push_event(IoEvent::Error(s.0));
    }
    pub fn tcp_written(&self, s: TcpSock) -> Vec<u8> {
        self.tcp
            .get(&s)
            .map(|t| t.written.clone())
            .unwrap_or_default()
    }
    /// Bytes still unread.
    pub fn tcp_unread(&self, s: TcpSock) -> usize {
        self.tcp.get(&s).map_or(0, |t| t.rx.len())
    }
    /// `Some(abort)` once closed.
    pub fn tcp_closed(&self, s: TcpSock) -> Option<bool> {
        self.tcp.get(&s).and_then(|t| t.closed)
    }

    // --- Dials ---

    /// Completes a resolution.
    pub fn resolve(&mut self, op: DialOpId, r: io::Result<Vec<SocketAddr>>) {
        self.push_event(IoEvent::Resolved { op, r });
    }
    /// Completes a connect; returns the new socket.
    pub fn connect_ok(&mut self, op: DialOpId) -> TcpSock {
        let s = self.new_tcp();
        self.push_event(IoEvent::Connected { op, r: Ok(s) });
        s
    }
    pub fn connect_err(&mut self, op: DialOpId, kind: ErrorKind) {
        self.push_event(IoEvent::Connected {
            op,
            r: Err(kind.into()),
        });
    }
    /// A connect to `addr` fails synchronously, reported through the completions.
    pub fn fail_connect_sync(&mut self, addr: SocketAddr, kind: ErrorKind) {
        self.sync_connect_fail.insert(addr, kind);
    }

    // --- UDP ---

    pub fn add_udp(&mut self, local: SocketAddr) -> UdpSock {
        let s = UdpSock(self.key());
        self.udp.insert(
            s,
            FakeUdp {
                local,
                rx: VecDeque::new(),
                unwritable: false,
                send_script: VecDeque::new(),
                sent: Vec::new(),
                closed: false,
            },
        );
        s
    }
    /// A datagram from `from`, with a readable edge.
    pub fn inject_udp(&mut self, s: UdpSock, from: SocketAddr, data: &[u8]) {
        self.udp_mut(s).rx.push_back((from, data.to_vec()));
        self.push_event(IoEvent::Readable(s.0));
    }
    /// Unwritable: sends return `WouldBlock`. Writable again: a writable edge.
    pub fn mark_udp_unwritable(&mut self, s: UdpSock, on: bool) {
        self.udp_mut(s).unwritable = on;
        if !on {
            self.push_event(IoEvent::Writable(s.0));
        }
    }
    /// The next `send_udp` on `s` returns `r` (`Ok(n)` sends the first `n` datagrams).
    pub fn script_send(&mut self, s: UdpSock, r: io::Result<usize>) {
        self.udp_mut(s).send_script.push_back(r);
    }
    /// Datagrams sent so far (destination, payload); clears them.
    pub fn take_sent_udp(&mut self, s: UdpSock) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.udp_mut(s).sent)
    }
    /// The next `open_udp` returns `r` (default: `Ok` on an ephemeral port).
    pub fn script_open_udp(&mut self, r: io::Result<SocketAddr>) {
        self.open_udp_script.push_back(r);
    }
    pub fn udp_closed(&self, s: UdpSock) -> bool {
        self.udp.get(&s).is_some_and(|u| u.closed)
    }
}

impl Io for FakeIo {
    fn now(&self) -> Time {
        self.now
    }

    fn wait(&mut self, w: Wait) -> Vec<IoEvent> {
        self.ops.push(Op::Wait(w));
        self.pending_work = self.pending_work.saturating_sub(1);
        if !self.events.is_empty() {
            return self.events.drain(..).collect();
        }
        match w {
            Wait::Until(t) if self.auto_advance => {
                self.now = self.now.max(t);
                vec![IoEvent::Timer]
            }
            _ => Vec::new(),
        }
    }

    fn has_pending_work(&self) -> bool {
        self.pending_work > 0
    }

    fn accept(&mut self, l: ListenerKey) -> io::Result<(TcpSock, AcceptMeta)> {
        self.ops.push(Op::Accept(l));
        self.accepts
            .get_mut(&l)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| Err(ErrorKind::WouldBlock.into()))
    }

    fn read(&mut self, s: TcpSock, buf: &mut [u8]) -> IoResult {
        assert!(!buf.is_empty(), "zero-length read");
        self.ops.push(Op::Read(s, buf.len()));
        let t = self.tcp_mut(s);
        if let Some(k) = t.read_err {
            return IoResult::Error(k);
        }
        if t.rx.is_empty() {
            return if t.eof {
                IoResult::Eof
            } else {
                IoResult::WouldBlock
            };
        }
        let n = buf
            .len()
            .min(t.rx.len())
            .min(t.read_chunk.unwrap_or(usize::MAX));
        for (b, x) in buf.iter_mut().zip(t.rx.drain(..n)) {
            *b = x;
        }
        IoResult::Bytes(n)
    }

    fn write(&mut self, s: TcpSock, buf: &[u8]) -> IoResult {
        self.ops.push(Op::Write(s, buf.len()));
        let t = self.tcp_mut(s);
        if let Some(k) = t.write_err {
            return IoResult::Error(k);
        }
        let n = buf.len().min(t.write_room.unwrap_or(usize::MAX));
        if n == 0 {
            return IoResult::WouldBlock;
        }
        if let Some(r) = &mut t.write_room {
            *r -= n;
        }
        t.written.extend_from_slice(&buf[..n]);
        IoResult::Bytes(n)
    }

    fn recv_udp(&mut self, s: UdpSock, out: &mut RecvBatch, budget: usize) -> io::Result<RecvStop> {
        self.ops.push(Op::RecvUdp(s, budget));
        let u = self.udp_mut(s);
        let mut used = 0;
        loop {
            if u.rx.is_empty() {
                return Ok(RecvStop::Drained);
            }
            if used >= budget {
                return Ok(RecvStop::Budget);
            }
            let (src, d) = u.rx.pop_front().expect("non-empty");
            let start = out.buf.len();
            out.buf.extend_from_slice(&d);
            out.metas.push(RecvMeta {
                src,
                local: u.local,
                range: start..out.buf.len(),
            });
            used += d.len();
        }
    }

    fn send_udp(&mut self, s: UdpSock, t: &Transmit<'_>) -> io::Result<usize> {
        let dgrams: Vec<Vec<u8>> = t
            .payload
            .chunks(t.segment_size)
            .map(<[u8]>::to_vec)
            .collect();
        self.ops.push(Op::SendUdp(s, dgrams.len()));
        let u = self.udp_mut(s);
        let r = match u.send_script.pop_front() {
            Some(r) => r,
            None if u.unwritable => Err(ErrorKind::WouldBlock.into()),
            None => Ok(dgrams.len()),
        };
        if let Ok(n) = r {
            u.sent
                .extend(dgrams.into_iter().take(n).map(|d| (t.dst, d)));
        }
        r
    }

    fn start_resolve(&mut self, op: DialOpId, host: String, port: u16) {
        self.ops.push(Op::StartResolve(op, host, port));
    }

    fn start_connect(&mut self, op: DialOpId, addr: SocketAddr) {
        self.ops.push(Op::StartConnect(op, addr));
        if let Some(&k) = self.sync_connect_fail.get(&addr) {
            self.connect_err(op, k);
        }
    }

    fn cancel_connect(&mut self, op: DialOpId) {
        self.ops.push(Op::CancelConnect(op));
    }

    fn open_udp(&mut self, local_ip: IpAddr) -> io::Result<(UdpSock, SocketAddr)> {
        self.ops.push(Op::OpenUdp(local_ip));
        let port = 40000 + self.next_key as u16;
        let local = self
            .open_udp_script
            .pop_front()
            .unwrap_or(Ok(SocketAddr::new(local_ip, port)))?;
        Ok((self.add_udp(local), local))
    }

    fn shutdown_write(&mut self, s: TcpSock) -> io::Result<()> {
        self.ops.push(Op::ShutdownWrite(s));
        Ok(())
    }

    fn close_tcp(&mut self, s: TcpSock, abort: bool) {
        self.ops.push(Op::CloseTcp(s, abort));
        self.tcp_mut(s).closed = Some(abort);
    }

    fn close_udp(&mut self, s: UdpSock) {
        self.ops.push(Op::CloseUdp(s));
        self.udp_mut(s).closed = true;
    }

    fn socket_error(&mut self, s: TcpSock) -> ErrorKind {
        self.ops.push(Op::SocketError(s));
        self.tcp_mut(s)
            .sock_err
            .unwrap_or(ErrorKind::ConnectionReset)
    }
}
