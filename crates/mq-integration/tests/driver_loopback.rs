//! Driver tests (spec §8.1 "Driver"): the production driver over real
//! loopback sockets with a `RecordingApp`.

use mq_integration::driver_harness::{DriverHarness, HarnessConfig, install_echo, syn_sent_to};
use mq_runtime::driver::{AlreadyAttached, Driver, DriverConfig};
use mq_runtime::testing::{Recorded, RecordingApp, ScriptedTransport};
use mq_runtime::{DialError, DialOpId, Host, Shard, Target, TcpEnd};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);

fn ip(port: u16) -> Target {
    Target {
        host: Host::Ip(Ipv4Addr::LOCALHOST.into()),
        port,
    }
}

fn domain(name: &str, port: u16) -> Target {
    Target {
        host: Host::Domain(name.into()),
        port,
    }
}

fn harness() -> DriverHarness {
    DriverHarness::spawn(HarnessConfig::default())
}

fn stop(mut h: DriverHarness) {
    h.record.on(|r, cx| {
        if *r == Recorded::Shutdown {
            cx.request_exit(0);
        }
    });
    h.start();
    h.shutdown.trigger();
    assert_eq!(h.join(), 0);
}

fn dial_results(h: &DriverHarness) -> Vec<Recorded> {
    h.record
        .records()
        .into_iter()
        .filter(|r| matches!(r, Recorded::DialResult(..)))
        .collect()
}

fn echo_roundtrip(addr: SocketAddr, len: usize) {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(T)).unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    c.write_all(&data).unwrap();
    let mut back = vec![0; len];
    c.read_exact(&mut back).unwrap();
    assert_eq!(back, data);
}

/// Echo over loopback; also the spin check (spec §11): polling off, no app
/// timer, so an idle driver must sleep.
#[test]
fn driver_echo_loopback() {
    let mut h = harness();
    install_echo(&h.record);
    h.start();
    let mut c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    c.set_read_timeout(Some(T)).unwrap();
    for i in 0..128u32 {
        let chunk: Vec<u8> = (0..8192u32).map(|j| (i + j) as u8).collect();
        c.write_all(&chunk).unwrap();
        let mut back = vec![0; chunk.len()];
        c.read_exact(&mut back).unwrap();
        assert_eq!(back, chunk);
    }
    let after_transfer = h.stats.iterations();
    thread::sleep(Duration::from_millis(50)); // settle
    let before = h.stats.iterations();
    thread::sleep(Duration::from_millis(300));
    let idle = h.stats.iterations() - before;
    let empty = h.stats.max_consecutive_empty_drains();
    eprintln!(
        "spin check: transfer iterations={after_transfer} idle(300ms) iterations={idle} \
         max_consecutive_empty_drains={empty}"
    );
    assert!(idle <= 3, "idle driver iterated {idle} times in 300 ms");
    assert!(empty <= 2, "max_consecutive_empty_drains = {empty}");
    drop(c);
    h.shutdown.trigger();
    assert_eq!(h.join(), 0);
}

#[test]
fn driver_connect_timeout_with_full_backlog() {
    let l = mq_linux::TcpListenerBuilder::new("127.0.0.1:0".parse().unwrap())
        .backlog(1)
        .build()
        .unwrap();
    let addr = l.local_addr().unwrap();
    // Fill the accept queue: further SYNs are dropped.
    let mut fill = Vec::new();
    while fill.len() < 8 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(s) => fill.push(s),
            Err(_) => break,
        }
    }
    assert!(fill.len() < 8, "the backlog never filled");
    assert_eq!(syn_sent_to(addr.port()), 0);

    let mut h = harness();
    let started = Arc::new(Mutex::new(None));
    let st = started.clone();
    h.record.on(move |r, cx| {
        if *r == Recorded::Start {
            *st.lock().unwrap() = Some(Instant::now());
            for _ in 0..3 {
                cx.dial(ip(addr.port()), Duration::from_millis(500));
            }
        }
    });
    h.start();
    // The three connects are pending (SYN_SENT) before the deadline.
    let end = Instant::now() + Duration::from_millis(400);
    let mut seen = 0;
    while Instant::now() < end && seen < 3 {
        seen = syn_sent_to(addr.port());
    }
    assert_eq!(seen, 3, "three pending connects");
    let end = Instant::now() + T;
    while dial_results(&h).len() < 3 && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    let elapsed = started.lock().unwrap().unwrap().elapsed();
    let res = dial_results(&h);
    assert_eq!(res.len(), 3, "{res:?}");
    for r in &res {
        assert!(
            matches!(r, Recorded::DialResult(_, Err(DialError::Timeout))),
            "{r:?}"
        );
    }
    assert!(elapsed >= Duration::from_millis(500), "{elapsed:?}");
    // cancel_connect closed the sockets.
    let end = Instant::now() + Duration::from_secs(1);
    while syn_sent_to(addr.port()) > 0 && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(syn_sent_to(addr.port()), 0, "cancelled connects left open");
    stop(h);
    drop(fill);
}

#[test]
fn driver_refused_connect_reports_err_not_error_event() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port(); // closed again: connects are refused
    let mut h = harness();
    h.record.on(move |r, cx| {
        if *r == Recorded::Start {
            cx.dial(ip(port), Duration::from_secs(5));
        }
    });
    h.start();
    let r = h
        .wait_for(T, |r| matches!(r, Recorded::DialResult(..)))
        .expect("dial result");
    assert!(
        matches!(r, Recorded::DialResult(_, Err(DialError::Refused))),
        "{r:?}"
    );
    thread::sleep(Duration::from_millis(50));
    assert_eq!(h.record.records().len(), 2, "{:?}", h.record.records());
    stop(h);
}

#[test]
fn driver_late_resolve_after_cancel_starts_no_connect() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let addr = target.local_addr().unwrap();
    let mut h = harness();
    let op: Arc<Mutex<Option<DialOpId>>> = Arc::default();
    let o = op.clone();
    h.record.on(move |r, cx| match r {
        Recorded::Start => {
            *o.lock().unwrap() = Some(cx.dial(domain("held.test", addr.port()), T));
            cx.set_timer(Duration::from_millis(50));
        }
        Recorded::Timer(_) => cx.cancel_dial(o.lock().unwrap().unwrap()),
        _ => {}
    });
    h.start();
    let req = h.resolver.next(T).expect("resolution started");
    assert_eq!(req.host, "held.test");
    // The timer callback cancels the dial; its requests run in the same iteration.
    h.wait_for(T, |r| matches!(r, Recorded::Timer(_)))
        .expect("timer");
    req.answer(Ok(vec![addr]));
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        target.accept().map(|_| ()).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "a connect was started"
    );
    assert!(dial_results(&h).is_empty(), "{:?}", h.record.records());
    stop(h);
}

#[test]
fn driver_connected_for_cancelled_op_is_closed() {
    let mut h = harness();
    let port = h.listen_addrs[0].port();
    let op: Arc<Mutex<Option<DialOpId>>> = Arc::default();
    let o = op.clone();
    h.record.on(move |r, cx| match r {
        Recorded::Start => *o.lock().unwrap() = Some(cx.dial(ip(port), T)),
        // Step 3 delivers accepts before dial results.
        Recorded::Accepted { .. } => {
            if let Some(op) = o.lock().unwrap().take() {
                cx.cancel_dial(op);
            }
        }
        _ => {}
    });
    h.start();
    let Some(Recorded::Accepted { tcp, .. }) =
        h.wait_for(T, |r| matches!(r, Recorded::Accepted { .. }))
    else {
        panic!("no accept");
    };
    // The dialled end was closed: the accepted end reads EOF.
    h.wait_for(T, |r| *r == Recorded::TcpEnd(tcp, TcpEnd::ReadEof))
        .expect("dialled socket closed");
    assert!(dial_results(&h).is_empty(), "{:?}", h.record.records());
    stop(h);
}

#[test]
fn driver_resolver_answers_on_command() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let addr = target.local_addr().unwrap();
    let mut h = harness();
    h.record.on(move |r, cx| {
        if *r == Recorded::Start {
            cx.dial(domain("example.test", addr.port()), T);
        }
    });
    h.start();
    let req = h.resolver.next(T).expect("resolution started");
    assert_eq!((req.host.as_str(), req.port), ("example.test", addr.port()));
    thread::sleep(Duration::from_millis(100));
    assert!(dial_results(&h).is_empty(), "nothing before the answer");
    req.answer(Ok(vec![addr]));
    let r = h
        .wait_for(T, |r| matches!(r, Recorded::DialResult(..)))
        .expect("dial result");
    assert!(matches!(r, Recorded::DialResult(_, Ok(_))), "{r:?}");
    target.accept().expect("connected to the resolved address");
    stop(h);
}

/// Reactions: accepted sockets start with read interest off; a timer turns it on.
fn read_after(h: &DriverHarness, delay: Duration, got: Arc<Mutex<Vec<u8>>>) {
    let timers = Mutex::new(HashMap::new());
    h.record.on(move |r, cx| match r {
        Recorded::Accepted { tcp, .. } => {
            cx.tcp_set_read(*tcp, false);
            timers.lock().unwrap().insert(cx.set_timer(delay), *tcp);
        }
        Recorded::Timer(id) => {
            if let Some(tcp) = timers.lock().unwrap().remove(id) {
                cx.tcp_set_read(tcp, true);
            }
        }
        Recorded::TcpData(tcp) => {
            let n = {
                let b = cx.tcp_rx(*tcp);
                got.lock().unwrap().extend_from_slice(b);
                b.len()
            };
            cx.tcp_consume(*tcp, n);
        }
        _ => {}
    });
}

#[test]
fn driver_peer_shutdown_with_queued_bytes() {
    let mut h = harness();
    let got = Arc::new(Mutex::new(Vec::new()));
    read_after(&h, Duration::from_millis(200), got.clone());
    h.start();
    let mut c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    c.write_all(b"hello").unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    h.wait_for(T, |r| matches!(r, Recorded::TcpEnd(_, TcpEnd::ReadEof)))
        .expect("read EOF");
    assert_eq!(&*got.lock().unwrap(), b"hello");
    let recs = h.record.records();
    let pos = |f: &dyn Fn(&Recorded) -> bool| recs.iter().position(f).unwrap();
    let timer = pos(&|r| matches!(r, Recorded::Timer(_)));
    let data = pos(&|r| matches!(r, Recorded::TcpData(_)));
    let eof = pos(&|r| matches!(r, Recorded::TcpEnd(..)));
    assert!(timer < data && data < eof, "{recs:?}");
    stop(h);
}

#[test]
fn driver_edge_latch_survives_budget() {
    let mut h = harness();
    let got = Arc::new(Mutex::new(Vec::new()));
    read_after(&h, Duration::from_millis(300), got.clone());
    h.start();
    let mut c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    c.set_nonblocking(true).unwrap();
    // Fill the kernel buffers while the app is not reading; then stop
    // writing, so no further edge comes from this peer's writes.
    let chunk = vec![0x5a; 64 * 1024];
    let mut sent = 0;
    let end = Instant::now() + Duration::from_millis(250);
    while Instant::now() < end {
        match c.write(&chunk) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(sent > mq_runtime::TCP_BUF * 4, "only {sent} bytes queued");
    let end = Instant::now() + T;
    while got.lock().unwrap().len() < sent && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(got.lock().unwrap().len(), sent);
    stop(h);
}

#[test]
fn driver_abort_close_resets_peer() {
    let mut h = harness();
    h.record.on(|r, cx| {
        if let Recorded::Accepted { tcp, .. } = r {
            cx.tcp_abort(*tcp);
        }
    });
    h.start();
    let mut c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    c.set_read_timeout(Some(T)).unwrap();
    let e = c.read(&mut [0u8; 16]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionReset);
    stop(h);
}

#[test]
fn driver_original_dst_absent_on_plain_listener() {
    let mut h = harness();
    h.start();
    let c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    let Some(Recorded::Accepted { meta, .. }) =
        h.wait_for(T, |r| matches!(r, Recorded::Accepted { .. }))
    else {
        panic!("no accept");
    };
    assert_eq!(meta.original_dst, None);
    assert_eq!(meta.peer, c.local_addr().unwrap());
    stop(h);
}

#[test]
fn accept_meta_has_local() {
    let mut h = harness();
    h.start();
    let _c = TcpStream::connect(h.listen_addrs[0]).unwrap();
    let Some(Recorded::Accepted { meta, .. }) =
        h.wait_for(T, |r| matches!(r, Recorded::Accepted { .. }))
    else {
        panic!("no accept");
    };
    assert_eq!(meta.local, h.listen_addrs[0]);
    stop(h);
}

#[test]
fn driver_path_bind() {
    let mut d = Driver::new(DriverConfig {
        install_signal_handlers: false,
        ..DriverConfig::default()
    })
    .unwrap();
    let u = d.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_ne!(u.local_addr().port(), 0);
    let e = d.bind_udp("192.0.2.1:0".parse().unwrap()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::AddrNotAvailable);
    let (t, _) = ScriptedTransport::new();
    let (app, _) = RecordingApp::new();
    let shard = Shard::new(t, app, u.local_addr(), 0);
    let id = shard.primary_udp();
    assert_eq!(d.attach_primary_udp(u, id), Ok(()));
    let u2 = d.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    assert_eq!(d.attach_primary_udp(u2, id), Err(AlreadyAttached));
}

#[test]
fn driver_shutdown_handle_stops_one_driver_only() {
    let mut a = harness();
    let mut b = harness();
    install_echo(&a.record);
    install_echo(&b.record);
    a.start();
    b.start();
    a.shutdown.trigger();
    assert_eq!(a.join(), 0);
    echo_roundtrip(b.listen_addrs[0], 1000);
    assert!(!b.record.records().contains(&Recorded::Shutdown));
    b.shutdown.trigger();
    assert_eq!(b.join(), 0);
}

#[test]
fn driver_sustained_udp_readiness_does_not_starve_deadlines() {
    let mut h = harness();
    let started = Arc::new(Mutex::new(None));
    let st = started.clone();
    h.record.on(move |r, cx| {
        if *r == Recorded::Start {
            *st.lock().unwrap() = Some(Instant::now());
            // Held by the resolver: only the driver deadline can end it.
            cx.dial(domain("held.test", 9), Duration::from_millis(200));
        }
    });
    let stop_flood = Arc::new(AtomicBool::new(false));
    let flood = {
        let (stop_flood, dst) = (stop_flood.clone(), h.udp_addr);
        thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut n = 0u64;
            while !stop_flood.load(Ordering::Relaxed) {
                if s.send_to(&[0u8; 1200], dst).is_ok() {
                    n += 1;
                }
            }
            n
        })
    };
    thread::sleep(Duration::from_millis(50)); // the flood is running
    h.start();
    let req = h.resolver.next(T).expect("resolution started");
    let r = h
        .wait_for(T, |r| matches!(r, Recorded::DialResult(..)))
        .expect("dial result");
    let elapsed = started.lock().unwrap().unwrap().elapsed();
    stop_flood.store(true, Ordering::Relaxed);
    let sent = flood.join().unwrap();
    assert!(
        matches!(r, Recorded::DialResult(_, Err(DialError::Timeout))),
        "{r:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(200) && elapsed < Duration::from_millis(1000),
        "deadline expired after {elapsed:?}"
    );
    let rx = h
        .scripted
        .log()
        .iter()
        .filter(|c| matches!(c, mq_runtime::testing::Call::RecvDatagram { .. }))
        .count();
    eprintln!(
        "flood: {sent} sent, {rx} received by the shard in {} iterations, deadline after {elapsed:?}",
        h.stats.iterations()
    );
    assert!(rx > 1000, "the flood did not reach the shard ({rx})");
    drop(req);
    stop(h);
}

#[test]
fn driver_stress_many_short_transfers_with_idle_gaps() {
    let mut h = harness();
    install_echo(&h.record);
    h.start();
    let addr = h.listen_addrs[0];
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for i in 0..300 {
            echo_roundtrip(addr, 1 + (i * 37) % 4096);
            if i % 25 == 24 {
                thread::sleep(Duration::from_millis(30)); // idle gap
            }
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(60))
        .expect("transfers did not finish (or the client panicked)");
    let accepted = h
        .record
        .records()
        .iter()
        .filter(|r| matches!(r, Recorded::Accepted { .. }))
        .count();
    assert_eq!(accepted, 300);
    h.shutdown.trigger();
    assert_eq!(h.join(), 0);
}
