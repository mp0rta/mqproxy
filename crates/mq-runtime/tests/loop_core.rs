//! spec §5.3 loop core, §5.5 one loop iteration: `LoopCore` over `FakeIo`
//! (virtual time), with a `ScriptedTransport` and a `RecordingApp`.

use mq_runtime::driver::{
    Io, Latch, ListenerKey, LoopConfig, LoopCore, Next, RESOLVER_SLOTS, SockKey, TcpSock, UdpSock,
    Wait,
};
use mq_runtime::testing::{
    Call, FakeIo, Op, RecordHandle, Recorded, RecordingApp, ScriptedHandle, ScriptedTransport,
};
use mq_runtime::{
    AcceptMeta, Cx, DialError, DialOpId, Host, ListenerTag, Shard, Target, TcpEnd, TcpId,
};
use mq_transport_api::{PathId, Time, TxKey};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Core = LoopCore<FakeIo, ScriptedTransport, RecordingApp>;

const SEC: Duration = Duration::from_secs(1);
const KEY: TxKey = (None, PathId(0));
const BOTH: Latch = Latch {
    readable: true,
    writable: true,
};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
fn meta() -> AcceptMeta {
    AcceptMeta {
        peer: addr(5000),
        local: addr(1080),
        original_dst: None,
    }
}
fn domain(name: &str) -> Target {
    Target {
        host: Host::Domain(name.into()),
        port: 443,
    }
}
fn ip(a: [u8; 4], port: u16) -> Target {
    Target {
        host: Host::Ip(IpAddr::from(a)),
        port,
    }
}

struct H {
    c: Core,
    t: ScriptedHandle,
    app: RecordHandle,
    l: ListenerKey,
    udp: UdpSock,
}

/// Core with a listener and the primary UDP socket attached, started, no iteration yet.
fn setup_raw() -> H {
    let (transport, t) = ScriptedTransport::new();
    let (app, rec) = RecordingApp::new();
    let mut sh = Shard::new(transport, app, addr(4433), 1);
    let lid = sh.add_listener(ListenerTag(1));
    let prim = sh.primary_udp();
    let mut io = FakeIo::new();
    let l = io.add_listener();
    let udp = io.add_udp(addr(4433));
    let mut c = LoopCore::new(io, sh, LoopConfig::default());
    c.attach_listener(l, lid);
    c.attach_primary_udp(udp, prim);
    c.start();
    rec.take();
    H {
        c,
        t,
        app: rec,
        l,
        udp,
    }
}

/// `setup_raw` plus one idle iteration: the initial latches are consumed.
fn setup() -> H {
    let mut h = setup_raw();
    assert_eq!(h.it(), Next::Continue);
    h.ops();
    h
}

impl H {
    fn io(&mut self) -> &mut FakeIo {
        self.c.io_mut()
    }
    fn it(&mut self) -> Next {
        self.c.iteration()
    }
    fn now(&self) -> Time {
        self.c.io().now()
    }
    fn ops(&mut self) -> Vec<Op> {
        self.io().take_ops()
    }
    fn act<R>(&mut self, f: impl FnOnce(&mut Cx<'_>) -> R) -> R {
        let now = self.now();
        self.c.shard_mut().with_app(now, |_, cx| f(cx))
    }
    fn dial(&mut self, t: Target, deadline: Duration) -> DialOpId {
        self.act(|cx| cx.dial(t, deadline))
    }
    fn latch(&self, k: SockKey) -> Latch {
        self.c.latch(k).expect("registered socket")
    }
    fn accept(&mut self) -> (TcpSock, TcpId) {
        let l = self.l;
        let s = self.io().push_accept(l, meta());
        self.it();
        let tcp = self
            .app
            .records()
            .iter()
            .rev()
            .find_map(|r| match r {
                Recorded::Accepted { tcp, .. } => Some(*tcp),
                _ => None,
            })
            .expect("accepted");
        (s, tcp)
    }
    fn dial_results(&self) -> Vec<(DialOpId, Result<TcpId, DialError>)> {
        self.app
            .records()
            .into_iter()
            .filter_map(|r| match r {
                Recorded::DialResult(op, r) => Some((op, r)),
                _ => None,
            })
            .collect()
    }
    fn tlog(&self) -> Vec<Call> {
        self.t.log()
    }
    fn datagrams_in(&self) -> usize {
        self.tlog()
            .iter()
            .filter(|c| matches!(c, Call::RecvDatagram { .. }))
            .count()
    }
}

fn count(ops: &[Op], f: impl Fn(&Op) -> bool) -> usize {
    ops.iter().filter(|o| f(o)).count()
}
fn resolves(ops: &[Op]) -> Vec<DialOpId> {
    ops.iter()
        .filter_map(|o| match o {
            Op::StartResolve(op, ..) => Some(*op),
            _ => None,
        })
        .collect()
}
fn connects(ops: &[Op]) -> Vec<(DialOpId, SocketAddr)> {
    ops.iter()
        .filter_map(|o| match o {
            Op::StartConnect(op, a) => Some((*op, *a)),
            _ => None,
        })
        .collect()
}

// --- Step order ---

#[test]
fn udp_rx_before_tcp_io() {
    let mut h = setup();
    let (s, _) = h.accept();
    h.ops();
    h.io().tcp_feed(s, b"hello");
    let udp = h.udp;
    h.io().inject_udp(udp, addr(9), b"dgram");
    h.it();
    let ops = h.ops();
    let ru = ops
        .iter()
        .position(|o| matches!(o, Op::RecvUdp(u, _) if *u == udp))
        .expect("udp read");
    let rd = ops
        .iter()
        .position(|o| matches!(o, Op::Read(x, _) if *x == s))
        .expect("tcp read");
    assert!(ru < rd, "{ops:?}");
    assert!(
        h.tlog()
            .iter()
            .any(|c| matches!(c, Call::RecvDatagram { data, .. } if data == b"dgram"))
    );
}

// --- Step 5: TCP I/O ---

#[test]
fn latched_readable_survives_budget_cut() {
    let mut h = setup();
    let (s, tcp) = h.accept();
    h.app.on(move |r, cx| {
        if *r == Recorded::TcpData(tcp) {
            let n = cx.tcp_rx(tcp).len();
            cx.tcp_consume(tcp, n);
        }
    });
    h.io().tcp_feed(s, &vec![7u8; 300 * 1024]);
    h.it();
    // 256 KiB per socket per direction per iteration.
    assert_eq!(h.c.io().tcp_unread(s), 44 * 1024);
    assert!(h.latch(s.0).readable, "budget cut keeps the latch");
    assert_eq!(h.c.next_wait(), Wait::Yield);
    h.ops();
    h.it(); // no new edge
    assert_eq!(h.c.io().tcp_unread(s), 0);
    assert!(!h.latch(s.0).readable, "WouldBlock clears it");
}

#[test]
fn interest_rechecked_between_reads_and_no_zero_length_read() {
    let mut h = setup();
    // The buffer fills: interest drops, no read into an empty slice
    // (FakeIo panics on a zero-length read).
    let (s, _) = h.accept();
    h.ops();
    h.io().tcp_feed(s, &vec![1u8; 100 * 1024]);
    h.it();
    let ops = h.ops();
    assert_eq!(
        ops.iter()
            .filter(|o| matches!(o, Op::Read(x, _) if *x == s))
            .collect::<Vec<_>>(),
        vec![&Op::Read(s, 64 * 1024)]
    );
    // The app turns reading off after the first chunk: no second read.
    let (s2, tcp2) = h.accept();
    h.ops();
    h.app.on(move |r, cx| {
        if *r == Recorded::TcpData(tcp2) {
            cx.tcp_set_read(tcp2, false);
        }
    });
    h.io().tcp_read_chunk(s2, 10);
    h.io().tcp_feed(s2, &[2u8; 100]);
    h.it();
    let ops = h.ops();
    assert_eq!(count(&ops, |o| matches!(o, Op::Read(x, _) if *x == s2)), 1);
    assert_eq!(h.c.io().tcp_unread(s2), 90);
}

#[test]
fn eof_and_error_end_the_io_loop() {
    let mut h = setup();
    let (a, ta) = h.accept();
    let (b, tb) = h.accept();
    let (c, tc) = h.accept();
    h.ops();
    h.app.take();
    h.io().tcp_eof(a);
    h.io().tcp_read_error(b, ErrorKind::ConnectionReset);
    h.io().tcp_write_error(c, ErrorKind::BrokenPipe);
    h.act(|cx| cx.tcp_write(tc, b"x")).unwrap();
    h.it();
    let ops = h.ops();
    assert_eq!(count(&ops, |o| matches!(o, Op::Read(x, _) if *x == a)), 1);
    assert_eq!(count(&ops, |o| matches!(o, Op::Read(x, _) if *x == b)), 1);
    assert_eq!(count(&ops, |o| matches!(o, Op::Write(x, _) if *x == c)), 1);
    let recs = h.app.records();
    assert!(recs.contains(&Recorded::TcpEnd(ta, TcpEnd::ReadEof)));
    assert!(recs.contains(&Recorded::TcpEnd(
        tb,
        TcpEnd::Error(ErrorKind::ConnectionReset)
    )));
    assert!(recs.contains(&Recorded::TcpEnd(tc, TcpEnd::Error(ErrorKind::BrokenPipe))));
    // The errored sockets are closed by step 8 of the same iteration.
    assert!(ops.contains(&Op::CloseTcp(b, true)));
    assert!(ops.contains(&Op::CloseTcp(c, true)));
}

#[test]
fn no_write_call_when_tx_empty() {
    let mut h = setup();
    let (s, tcp) = h.accept();
    h.it();
    let ops = h.ops();
    assert_eq!(count(&ops, |o| matches!(o, Op::Write(..))), 0);
    assert!(h.latch(s.0).writable);
    h.act(|cx| cx.tcp_write(tcp, b"hi")).unwrap();
    h.it();
    h.it();
    let ops = h.ops();
    assert_eq!(
        ops.iter()
            .filter(|o| matches!(o, Op::Write(..)))
            .collect::<Vec<_>>(),
        vec![&Op::Write(s, 2)]
    );
    assert_eq!(h.c.io().tcp_written(s), b"hi");
}

// --- Step 2: UDP receive ---

#[test]
fn recv_stop_drained_clears_latch_budget_keeps_it() {
    let mut h = setup();
    let udp = h.udp;
    h.io().inject_udp(udp, addr(9), b"one");
    h.it();
    assert!(!h.latch(udp.0).readable);
    assert_ne!(h.c.next_wait(), Wait::Yield);
    for _ in 0..20 {
        h.io().inject_udp(udp, addr(9), &[0u8; 60000]);
    }
    h.it();
    assert!(h.latch(udp.0).readable);
    assert_eq!(h.c.next_wait(), Wait::Yield);
}

#[test]
fn udp_receive_budget_1mib_per_socket() {
    let mut h = setup();
    let udp = h.udp;
    for _ in 0..20 {
        h.io().inject_udp(udp, addr(9), &[0u8; 60000]);
    }
    let before = h.datagrams_in();
    h.it();
    assert!(h.ops().contains(&Op::RecvUdp(udp, 1 << 20)));
    // 1 MiB = 17.5 datagrams: the 18th crosses the budget.
    assert_eq!(h.datagrams_in() - before, 18);
    h.it();
    assert_eq!(h.datagrams_in() - before, 20);
}

// --- Latches ---

#[test]
fn new_sockets_start_with_both_latches() {
    let mut h = setup_raw();
    assert_eq!(h.latch(h.l.0), BOTH);
    assert_eq!(h.latch(h.udp.0), BOTH);
    h.it();
    h.ops();
    // Accepted: read without any readable edge of its own.
    let (s, _) = h.accept();
    let ops = h.ops();
    assert!(ops.contains(&Op::Read(s, 64 * 1024)), "{ops:?}");
    assert!(h.latch(s.0).writable);
    // Dialled.
    let op = h.dial(ip([10, 0, 0, 1], 80), SEC);
    h.it();
    let s2 = h.io().connect_ok(op);
    h.it();
    assert!(h.ops().contains(&Op::Read(s2, 64 * 1024)));
    assert!(h.latch(s2.0).writable);
    // Opened UDP socket.
    h.act(|cx| cx.open_udp_socket(IpAddr::from([127, 0, 0, 1])));
    h.it(); // step 8 opens
    h.it(); // step 3 delivers (after this iteration's step 2)
    h.it(); // step 2 reads it
    let id = h
        .app
        .records()
        .into_iter()
        .find_map(|r| match r {
            Recorded::UdpSocket(_, Ok((id, _))) => Some(id),
            _ => None,
        })
        .expect("opened");
    let u2 = h.c.udp_sock(id).expect("mapped");
    assert!(h.ops().contains(&Op::RecvUdp(u2, 1 << 20)));
    assert!(h.latch(u2.0).writable);
}

// --- Step 10: the wait decision ---

#[test]
fn io_pending_work_forces_yield_until_drained() {
    let mut h = setup();
    assert_eq!(h.c.next_wait(), Wait::Forever);
    h.io().set_pending_work(3);
    h.it();
    h.it();
    h.it();
    h.it();
    assert_eq!(
        h.c.io().waits(),
        vec![Wait::Forever, Wait::Yield, Wait::Yield, Wait::Forever]
    );
}

#[test]
fn no_wait_while_runnable_but_yield_collects_completions() {
    let mut h = setup();
    h.t.set_resume_pending(true); // runnable work
    let op = h.dial(domain("a.example"), 10 * SEC);
    h.it();
    assert_eq!(resolves(h.c.io().ops()), vec![op]);
    assert_eq!(h.c.next_wait(), Wait::Yield);
    h.io().resolve(op, Err(ErrorKind::NotFound.into()));
    h.it();
    assert_eq!(h.c.io().waits(), vec![Wait::Forever, Wait::Yield]);
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Dns))]);
    assert_eq!(h.now(), Time::ZERO, "never slept");
}

#[test]
fn wait_arms_min_of_shard_and_driver_deadlines() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    h.t.set_next_timeout(Some(Time::ZERO + 5 * SEC));
    h.it();
    assert_eq!(h.c.next_wait(), Wait::Until(Time::ZERO + 5 * SEC));
    h.dial(domain("a.example"), 2 * SEC);
    h.it();
    assert_eq!(h.c.earliest_deadline(), Some(Time::ZERO + 2 * SEC));
    assert_eq!(h.c.next_wait(), Wait::Until(Time::ZERO + 2 * SEC));
    h.t.set_next_timeout(Some(Time::ZERO + SEC));
    h.it();
    assert_eq!(h.c.next_wait(), Wait::Until(Time::ZERO + SEC));
}

#[test]
fn blocked_udp_socket_without_writable_latch_does_not_spin() {
    let mut h = setup();
    let udp = h.udp;
    h.t.set_transmit(KEY, addr(9), vec![vec![1; 100]]);
    h.io().mark_udp_unwritable(udp, true);
    h.it();
    assert_eq!(count(&h.ops(), |o| matches!(o, Op::SendUdp(..))), 1);
    assert!(!h.latch(udp.0).writable);
    assert_eq!(h.c.next_wait(), Wait::Forever);
    h.it();
    h.it();
    assert_eq!(count(&h.ops(), |o| matches!(o, Op::SendUdp(..))), 0);
}

// --- Dials and the resolver ---

#[test]
fn sync_connect_failure_arrives_as_connected_err() {
    let mut h = setup();
    h.io()
        .fail_connect_sync(addr(80), ErrorKind::ConnectionRefused);
    let op = h.dial(ip([127, 0, 0, 1], 80), 10 * SEC);
    h.it();
    assert_eq!(connects(h.c.io().ops()), vec![(op, addr(80))]);
    assert!(h.dial_results().is_empty());
    h.it();
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Refused))]);
}

#[test]
fn dial_deadline_reports_timeout_while_resolve_running_and_cancels_connect() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    let a = h.dial(domain("slow.example"), SEC);
    let b = h.dial(ip([10, 0, 0, 1], 80), SEC);
    h.it();
    let ops = h.ops();
    assert_eq!(resolves(&ops), vec![a]);
    assert_eq!(
        connects(&ops),
        vec![(b, SocketAddr::from(([10, 0, 0, 1], 80)))]
    );
    h.io().set_now(Time::ZERO + SEC);
    h.it();
    let mut res = h.dial_results();
    res.sort_by_key(|x| x.0);
    let mut want = vec![(a, Err(DialError::Timeout)), (b, Err(DialError::Timeout))];
    want.sort_by_key(|x| x.0);
    assert_eq!(res, want);
    let ops = h.ops();
    assert!(ops.contains(&Op::CancelConnect(b)));
    // The running resolution keeps its slot until it returns; its result is dropped.
    assert_eq!(h.c.resolver().running(), 1);
    h.io().resolve(a, Ok(vec![addr(443)]));
    h.it();
    assert_eq!(h.c.resolver().running(), 0);
    assert!(connects(&h.ops()).is_empty());
    assert_eq!(h.dial_results().len(), 2);
}

#[test]
fn ip_target_bypasses_resolver() {
    let mut h = setup();
    let op = h.dial(ip([1, 2, 3, 4], 443), SEC);
    h.it();
    let ops = h.ops();
    assert!(resolves(&ops).is_empty());
    assert_eq!(
        connects(&ops),
        vec![(op, SocketAddr::from(([1, 2, 3, 4], 443)))]
    );
    assert_eq!(h.c.resolver().running(), 0);
}

#[test]
fn dial_uses_first_address_only() {
    let mut h = setup();
    let op = h.dial(domain("two.example"), 10 * SEC);
    h.it();
    let (a1, a2) = (addr(1001), addr(1002));
    h.io().resolve(op, Ok(vec![a1, a2]));
    h.it();
    assert_eq!(connects(&h.ops()), vec![(op, a1)]);
    h.io().connect_err(op, ErrorKind::ConnectionRefused);
    h.it();
    assert!(connects(&h.ops()).is_empty());
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Refused))]);
}

#[test]
fn resolver_cap_64_and_fifo() {
    let mut h = setup();
    let ops: Vec<DialOpId> = (0..70)
        .map(|i| h.dial(domain(&format!("h{i}.example")), 60 * SEC))
        .collect();
    h.it();
    assert_eq!(resolves(&h.ops()), ops[..RESOLVER_SLOTS].to_vec());
    assert_eq!(RESOLVER_SLOTS, 64);
    assert_eq!(h.c.resolver().waiting(), 6);
    h.io().resolve(ops[3], Err(ErrorKind::NotFound.into()));
    h.it();
    assert_eq!(resolves(&h.ops()), vec![ops[64]]);
    h.io().resolve(ops[10], Err(ErrorKind::NotFound.into()));
    h.it();
    assert_eq!(resolves(&h.ops()), vec![ops[65]]);
    assert_eq!(h.c.resolver().running(), 64);
    assert_eq!(h.c.resolver().waiting(), 4);
}

#[test]
fn cancel_queued_dial_removes_it() {
    let mut h = setup();
    let ops: Vec<DialOpId> = (0..65)
        .map(|i| h.dial(domain(&format!("h{i}.example")), 60 * SEC))
        .collect();
    h.it();
    assert_eq!(h.c.resolver().waiting(), 1);
    h.act(|cx| cx.cancel_dial(ops[64]));
    h.it();
    assert_eq!(h.c.resolver().waiting(), 0);
    h.ops();
    h.io().resolve(ops[0], Err(ErrorKind::NotFound.into()));
    h.it();
    assert!(resolves(&h.ops()).is_empty());
    assert_eq!(h.c.resolver().running(), 63);
    assert!(h.dial_results().iter().all(|(op, _)| *op != ops[64]));
}

#[test]
fn late_connect_for_cancelled_op_closed() {
    let mut h = setup();
    let op = h.dial(ip([10, 0, 0, 1], 80), 10 * SEC);
    h.it();
    h.act(|cx| cx.cancel_dial(op));
    h.it();
    assert!(h.ops().contains(&Op::CancelConnect(op)));
    let s = h.io().connect_ok(op);
    h.it();
    assert!(h.ops().contains(&Op::CloseTcp(s, false)));
    assert!(h.dial_results().is_empty());
}

#[test]
fn dial_deadline_beats_same_iteration_success() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    let op = h.dial(ip([10, 0, 0, 1], 80), SEC);
    h.it();
    h.ops();
    // The deadline passes and the successful connect lands in the same wait.
    h.io().set_now(Time::ZERO + SEC);
    let s = h.io().connect_ok(op);
    h.it();
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Timeout))]);
    let ops = h.ops();
    assert!(ops.contains(&Op::CancelConnect(op)));
    assert!(ops.contains(&Op::CloseTcp(s, false)));
    h.it();
    assert_eq!(h.dial_results().len(), 1);
}

#[test]
fn dial_deadline_beats_same_iteration_resolve() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    let op = h.dial(domain("slow.example"), SEC);
    h.it();
    h.ops();
    h.io().set_now(Time::ZERO + SEC);
    h.io().resolve(op, Ok(vec![addr(443)]));
    h.it();
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Timeout))]);
    assert!(connects(&h.ops()).is_empty());
    assert_eq!(h.c.resolver().running(), 0);
    h.it();
    assert_eq!(h.dial_results().len(), 1);
}

// --- Resolve-only requests (SP2 spec §4.2) ---

impl H {
    fn resolve_results(&self) -> Vec<(DialOpId, Result<SocketAddr, DialError>)> {
        self.app
            .records()
            .into_iter()
            .filter_map(|r| match r {
                Recorded::ResolveResult(op, r) => Some((op, r)),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn resolve_domain_round_trip() {
    let mut h = setup();
    let op = h.act(|cx| cx.resolve(domain("name.example"), 10 * SEC));
    h.it();
    assert_eq!(resolves(&h.ops()), vec![op]);
    assert!(h.c.earliest_deadline().is_some());
    let (a1, a2) = (addr(1001), addr(1002));
    h.io().resolve(op, Ok(vec![a1, a2]));
    h.it();
    // The first address, and no connect: the op ends here.
    assert_eq!(h.resolve_results(), vec![(op, Ok(a1))]);
    assert!(connects(&h.ops()).is_empty());
    assert_eq!(h.c.resolver().running(), 0);
    assert_eq!(h.c.earliest_deadline(), None, "deadline cancelled");
    assert!(h.dial_results().is_empty());
}

#[test]
fn resolve_ip_target_completes_in_next_iteration() {
    let mut h = setup();
    let op = h.act(|cx| cx.resolve(ip([10, 0, 0, 1], 53), 10 * SEC));
    h.it();
    assert_eq!(
        h.resolve_results(),
        vec![(op, Ok(SocketAddr::from(([10, 0, 0, 1], 53))))]
    );
    let ops = h.ops();
    assert!(resolves(&ops).is_empty() && connects(&ops).is_empty());
    assert_eq!(h.c.earliest_deadline(), None);
}

#[test]
fn resolve_dns_error() {
    let mut h = setup();
    let (a, b) = (
        h.act(|cx| cx.resolve(domain("a.example"), 10 * SEC)),
        h.act(|cx| cx.resolve(domain("b.example"), 10 * SEC)),
    );
    h.it();
    h.ops();
    h.io().resolve(a, Err(ErrorKind::NotFound.into()));
    h.io().resolve(b, Ok(vec![])); // an empty answer is a failure too
    h.it();
    let mut res = h.resolve_results();
    res.sort_by_key(|x| x.0);
    let mut want = vec![(a, Err(DialError::Dns)), (b, Err(DialError::Dns))];
    want.sort_by_key(|x| x.0);
    assert_eq!(res, want);
    assert_eq!(h.c.resolver().running(), 0);
    assert_eq!(h.c.earliest_deadline(), None);
}

#[test]
fn resolve_timeout() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    let op = h.act(|cx| cx.resolve(domain("slow.example"), SEC));
    h.it();
    h.ops();
    h.io().set_now(Time::ZERO + SEC);
    h.it();
    assert_eq!(h.resolve_results(), vec![(op, Err(DialError::Timeout))]);
    // The running resolution keeps its slot until it returns; its result is dropped.
    assert_eq!(h.c.resolver().running(), 1);
    h.io().resolve(op, Ok(vec![addr(443)]));
    h.it();
    assert_eq!(h.c.resolver().running(), 0);
    assert_eq!(h.resolve_results().len(), 1);
    assert!(connects(&h.ops()).is_empty());
}

#[test]
fn resolve_cancelled_never_delivers() {
    let mut h = setup();
    let op = h.act(|cx| cx.resolve(domain("gone.example"), 10 * SEC));
    h.it();
    h.ops();
    h.act(|cx| cx.cancel_resolve(op));
    h.it();
    assert_eq!(h.c.earliest_deadline(), None, "deadline cancelled");
    // The abandoned resolution frees its slot when it returns; nothing is delivered.
    assert_eq!(h.c.resolver().running(), 1);
    h.io().resolve(op, Ok(vec![addr(443)]));
    h.it();
    assert_eq!(h.c.resolver().running(), 0);
    assert!(h.resolve_results().is_empty());
    assert!(connects(&h.ops()).is_empty());
}

#[test]
fn queued_resolve_shares_the_dial_resolver_slots() {
    let mut h = setup();
    let ops: Vec<DialOpId> = (0..RESOLVER_SLOTS)
        .map(|i| h.dial(domain(&format!("h{i}.example")), 60 * SEC))
        .collect();
    let r = h.act(|cx| cx.resolve(domain("late.example"), 60 * SEC));
    h.it();
    assert_eq!(h.c.resolver().waiting(), 1);
    h.ops();
    h.io().resolve(ops[0], Err(ErrorKind::NotFound.into()));
    h.it();
    assert_eq!(resolves(&h.ops()), vec![r]);
    h.act(|cx| cx.cancel_resolve(r));
    h.io().resolve(r, Ok(vec![addr(1)]));
    h.it();
    assert!(h.resolve_results().is_empty());
}

// --- Listeners ---

#[test]
fn emfile_pauses_listener_and_retries_after_100ms() {
    let mut h = setup();
    let l = h.l;
    h.io().push_accept_err(l, io::Error::from_raw_os_error(24)); // EMFILE
    h.io().push_accept(l, meta());
    h.it();
    assert_eq!(count(&h.ops(), |o| matches!(o, Op::Accept(_))), 1);
    assert!(!h.latch(l.0).readable);
    let retry = Time::ZERO + Duration::from_millis(100);
    assert_eq!(h.c.earliest_deadline(), Some(retry));
    assert_eq!(h.c.next_wait(), Wait::Until(retry));
    assert!(h.app.records().is_empty());
    h.it(); // sleeps to the retry
    assert_eq!(h.now(), retry);
    assert!(
        h.app
            .records()
            .iter()
            .any(|r| matches!(r, Recorded::Accepted { .. }))
    );
}

// --- Step 6/7: UDP send ---

#[test]
fn app_udp_socket_echoes_through_the_loop() {
    // SP2 spec §4.1: step 2 hands the datagram to the app; step 6 sends its record.
    let mut h = setup();
    h.app.on(|r, cx| {
        if let Recorded::UdpRx { sock, peer, data } = r {
            cx.udp_send(*sock, *peer, data).unwrap();
        }
    });
    h.act(|cx| cx.open_app_udp_socket(IpAddr::from([127, 0, 0, 1])));
    h.it(); // step 8 opens
    h.it(); // step 3 delivers
    let id = h
        .app
        .records()
        .into_iter()
        .find_map(|r| match r {
            Recorded::UdpSocket(_, Ok((id, _))) => Some(id),
            _ => None,
        })
        .expect("opened");
    let u = h.c.udp_sock(id).expect("mapped");
    h.io().inject_udp(u, addr(9), b"ping");
    h.it();
    assert_eq!(h.io().take_sent_udp(u), [(addr(9), b"ping".to_vec())]);
    assert_eq!(h.c.shard().pending_transmit().count(), 0);
    assert!(
        !h.tlog()
            .iter()
            .any(|c| matches!(c, Call::RecvDatagram { .. }))
    );
}

#[test]
fn udp_error_drops_and_commits() {
    let mut h = setup();
    let udp = h.udp;
    h.t.set_transmit(KEY, addr(9), vec![vec![1; 100]; 3]);
    h.io()
        .script_send(udp, Err(io::Error::from_raw_os_error(1))); // EPERM
    h.it();
    assert!(h.tlog().contains(&Call::TransmitDone { key: KEY, n: 3 }));
    assert_eq!(h.c.udp_send_errors(), 1);
    assert!(h.latch(udp.0).writable);
    assert_eq!(h.c.shard().pending_transmit().count(), 0);
}

#[test]
fn send_udp_partial_keeps_rest_queued() {
    let mut h = setup();
    let udp = h.udp;
    h.t.set_transmit(KEY, addr(9), vec![vec![1; 100]; 3]);
    h.io().script_send(udp, Ok(1));
    h.it();
    assert!(h.tlog().contains(&Call::TransmitDone { key: KEY, n: 1 }));
    assert!(!h.latch(udp.0).writable);
    assert_eq!(h.c.shard().pending_transmit().count(), 1);
    assert_ne!(h.c.next_wait(), Wait::Yield);
    h.io().mark_udp_unwritable(udp, false); // writable edge
    h.it();
    assert!(h.tlog().contains(&Call::TransmitDone { key: KEY, n: 2 }));
    assert_eq!(h.io().take_sent_udp(udp).len(), 3);
    // Never a zero commit.
    assert!(
        !h.tlog()
            .iter()
            .any(|c| matches!(c, Call::TransmitDone { n: 0, .. }))
    );
}

#[test]
fn resume_pending_triggers_second_drive_and_send() {
    let mut h = setup();
    let udp = h.udp;
    let drives = Arc::new(AtomicUsize::new(0));
    let d = drives.clone();
    h.t.on_drive(move |t, _| {
        if d.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
            t.set_transmit(KEY, addr(9), vec![vec![7; 50]]);
            t.set_resume_pending(false);
        }
    });
    h.t.set_resume_pending(true);
    let start = h.tlog().len();
    h.it();
    let tail: Vec<Call> = h.tlog()[start..]
        .iter()
        .filter(|c| {
            matches!(
                c,
                Call::Drive(_) | Call::PeekTransmit(_) | Call::TransmitDone { .. }
            )
        })
        .cloned()
        .collect();
    let t0 = h.now();
    assert_eq!(
        tail,
        vec![
            Call::Drive(t0),
            Call::Drive(t0),
            Call::Drive(t0),
            Call::PeekTransmit(KEY),
            Call::TransmitDone { key: KEY, n: 1 },
        ]
    );
    assert_eq!(h.io().take_sent_udp(udp), vec![(addr(9), vec![7; 50])]);
    // Without resume_pending: two drives only.
    drives.store(100, Ordering::SeqCst);
    let start = h.tlog().len();
    h.it();
    assert_eq!(
        h.tlog()[start..]
            .iter()
            .filter(|c| matches!(c, Call::Drive(_)))
            .count(),
        2
    );
}

// --- Driver deadlines ---

#[test]
fn driver_deadlines_expire_on_non_sleeping_iterations() {
    let mut h = setup();
    h.io().set_auto_advance(false);
    h.t.set_resume_pending(true); // always runnable: every wait is a Yield
    let op = h.dial(domain("slow.example"), SEC);
    h.it();
    h.io().set_now(Time::ZERO + SEC);
    h.ops();
    h.it();
    assert_eq!(h.c.io().waits(), vec![Wait::Yield]);
    assert_eq!(h.dial_results(), vec![(op, Err(DialError::Timeout))]);
}

// --- Shutdown and exit ---

#[test]
fn shutdown_then_hook_then_cap_exits_0() {
    let mut h = setup();
    let seen = Arc::new(Mutex::new(None));
    let (s2, app) = (seen.clone(), h.app.clone());
    h.c.on_shutdown(move || {
        *s2.lock().unwrap() = Some(app.records().contains(&Recorded::Shutdown));
    });
    h.io().inject_shutdown();
    assert_eq!(h.it(), Next::Continue);
    assert!(h.app.records().contains(&Recorded::Shutdown));
    assert_eq!(*seen.lock().unwrap(), Some(true), "hook after on_shutdown");
    assert_eq!(h.c.earliest_deadline(), Some(Time::ZERO + 2 * SEC));
    let mut exit = None;
    for _ in 0..10 {
        if let Next::Exit(c) = h.it() {
            exit = Some(c);
            break;
        }
    }
    assert_eq!(exit, Some(0));
    assert_eq!(h.now(), Time::ZERO + 2 * SEC);
}

#[test]
fn exit_status_stops_loop() {
    let mut h = setup();
    h.act(|cx| cx.request_exit(3));
    assert_eq!(h.it(), Next::Exit(3));

    // `run` starts the shard, then loops until the exit status.
    let (transport, _t) = ScriptedTransport::new();
    let (app, rec) = RecordingApp::new();
    rec.on(|r, cx| {
        if *r == Recorded::Start {
            cx.request_exit(5);
        }
    });
    let sh = Shard::new(transport, app, addr(4433), 1);
    let c = LoopCore::new(FakeIo::new(), sh, LoopConfig::default());
    let (code, _shard) = c.run();
    assert_eq!(code, 5);
    assert_eq!(rec.records()[0], Recorded::Start);
}

// --- UDP socket open/cancel ---

#[test]
fn cancel_udp_socket_already_opened_is_closed() {
    let mut h = setup();
    // Opened and cancelled in the same step 8.
    h.act(|cx| {
        let op = cx.open_udp_socket(IpAddr::from([127, 0, 0, 1]));
        cx.cancel_udp_socket(op);
    });
    h.it();
    let ops = h.ops();
    let closed: Vec<UdpSock> = ops
        .iter()
        .filter_map(|o| match o {
            Op::CloseUdp(s) => Some(*s),
            _ => None,
        })
        .collect();
    assert_eq!(closed.len(), 1, "{ops:?}");
    assert!(h.c.io().udp_closed(closed[0]));
    // Opened, then cancelled before delivery.
    let op = h.act(|cx| cx.open_udp_socket(IpAddr::from([127, 0, 0, 1])));
    h.it();
    h.act(|cx| cx.cancel_udp_socket(op));
    h.it();
    assert_eq!(count(&h.ops(), |o| matches!(o, Op::CloseUdp(_))), 1);
    assert!(
        !h.app
            .records()
            .iter()
            .any(|r| matches!(r, Recorded::UdpSocket(..)))
    );
}
