//! The driver harness (spec §8.1 "Driver"): the production `Driver` on its
//! own thread over a `ScriptedTransport` and a `RecordingApp`, real loopback
//! sockets, and a resolver the test answers on command.

use mq_runtime::driver::{Driver, DriverConfig, Resolver, ShutdownHandle, Stats};
use mq_runtime::testing::{
    RecordHandle, Recorded, RecordingApp, ScriptedHandle, ScriptedTransport,
};
use mq_runtime::{ListenKind, ListenerTag, Shard, TcpEnd};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// One resolution the driver is blocked on; answer it with `answer`.
/// Dropping it unanswered fails the resolution.
pub struct ResolveRequest {
    pub host: String,
    pub port: u16,
    reply: Sender<io::Result<Vec<SocketAddr>>>,
}

impl ResolveRequest {
    pub fn answer(self, r: io::Result<Vec<SocketAddr>>) {
        let _ = self.reply.send(r);
    }
}

/// The test's side of the channel-backed resolver.
pub struct ResolverControl(Receiver<ResolveRequest>);

impl ResolverControl {
    /// The next resolution the driver started, if one comes within `timeout`.
    pub fn next(&self, timeout: Duration) -> Option<ResolveRequest> {
        self.0.recv_timeout(timeout).ok()
    }
}

struct ChanResolver(Sender<ResolveRequest>);

impl Resolver for ChanResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let (reply, rx) = mpsc::channel();
        let req = ResolveRequest {
            host: host.to_owned(),
            port,
            reply,
        };
        let gone = || io::Error::other("resolver control dropped");
        self.0.send(req).map_err(|_| gone())?;
        rx.recv().map_err(|_| gone())?
    }
}

/// What the harness sets up; `Default`: one plain listener, 100 ms retry, 2 s cap.
pub struct HarnessConfig {
    /// Listener `i` reports `ListenerTag(i)`.
    pub listeners: Vec<ListenKind>,
    pub emfile_retry: Duration,
    pub shutdown_cap: Duration,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        HarnessConfig {
            listeners: vec![ListenKind::Plain],
            emfile_retry: Duration::from_millis(100),
            shutdown_cap: Duration::from_secs(2),
        }
    }
}

struct Ready {
    scripted: ScriptedHandle,
    record: RecordHandle,
    udp: SocketAddr,
    listeners: Vec<SocketAddr>,
    shutdown: ShutdownHandle,
    stats: Stats,
}

/// A driver on its own thread. Built and bound by `spawn`; `run` starts
/// only at `start`, so reactions can be installed before `on_start`.
pub struct DriverHarness {
    pub scripted: ScriptedHandle,
    pub record: RecordHandle,
    pub resolver: ResolverControl,
    /// The primary UDP socket.
    pub udp_addr: SocketAddr,
    pub listen_addrs: Vec<SocketAddr>,
    pub shutdown: ShutdownHandle,
    pub stats: Stats,
    go: Option<Sender<()>>,
    done: Receiver<i32>,
    thread: Option<JoinHandle<()>>,
}

impl DriverHarness {
    pub fn spawn(cfg: HarnessConfig) -> DriverHarness {
        let (req_tx, req_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (done_tx, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut d = Driver::new(DriverConfig {
                resolver: Arc::new(ChanResolver(req_tx)),
                emfile_retry: cfg.emfile_retry,
                shutdown_cap: cfg.shutdown_cap,
                install_signal_handlers: false,
            })
            .expect("driver");
            let udp = d.bind_udp(loopback()).expect("bind_udp");
            // `Transport`/`Shard` are `!Send`: built here, on the driver thread.
            let (t, scripted) = ScriptedTransport::new();
            let (app, record) = RecordingApp::new();
            let mut shard = Shard::new(t, app, udp.local_addr(), 1);
            let udp_addr = udp.local_addr();
            d.attach_primary_udp(udp, shard.primary_udp())
                .expect("first attach");
            let mut listeners = Vec::new();
            for (i, kind) in cfg.listeners.into_iter().enumerate() {
                let l = d.listen(loopback(), kind).expect("listen");
                listeners.push(l.local_addr());
                d.attach_listener(l, shard.add_listener(ListenerTag(i as u32)));
            }
            let _ = ready_tx.send(Ready {
                scripted,
                record,
                udp: udp_addr,
                listeners,
                shutdown: d.shutdown_handle(),
                stats: d.stats(),
            });
            if go_rx.recv().is_err() {
                return;
            }
            let (code, _shard) = d.run(shard);
            let _ = done_tx.send(code);
        });
        let r = ready_rx.recv().expect("driver thread failed during setup");
        DriverHarness {
            scripted: r.scripted,
            record: r.record,
            resolver: ResolverControl(req_rx),
            udp_addr: r.udp,
            listen_addrs: r.listeners,
            shutdown: r.shutdown,
            stats: r.stats,
            go: Some(go_tx),
            done,
            thread: Some(thread),
        }
    }

    /// Starts `Driver::run` (and so `on_start`).
    pub fn start(&mut self) {
        if let Some(go) = self.go.take() {
            go.send(()).expect("driver thread alive");
        }
    }

    /// Waits for a callback matching `pred` (searching everything recorded).
    pub fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&Recorded) -> bool,
    ) -> Option<Recorded> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(r) = self.record.records().into_iter().find(&pred) {
                return Some(r);
            }
            if Instant::now() >= end {
                return None;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// The exit status, if the driver exits within `timeout`.
    pub fn join_timeout(&mut self, timeout: Duration) -> Option<i32> {
        let code = match self.done.recv_timeout(timeout) {
            Ok(c) => c,
            Err(RecvTimeoutError::Timeout) => return None,
            Err(RecvTimeoutError::Disconnected) => panic!("driver thread panicked"),
        };
        if let Some(t) = self.thread.take() {
            t.join().expect("driver thread");
        }
        Some(code)
    }

    /// The exit status; panics if the driver does not exit within 10 s.
    pub fn join(mut self) -> i32 {
        self.join_timeout(Duration::from_secs(10))
            .expect("driver did not exit")
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Reactions of an echo app: every received byte is written back, a read
/// EOF closes the socket, and a shutdown signal exits 0.
pub fn install_echo(record: &RecordHandle) {
    record.on(|r, cx| match r {
        Recorded::TcpData(tcp) => {
            let data = cx.tcp_rx(*tcp).to_vec();
            if cx.tcp_write(*tcp, &data).is_ok() {
                cx.tcp_consume(*tcp, data.len());
            }
        }
        Recorded::TcpEnd(tcp, TcpEnd::ReadEof) => cx.tcp_close(*tcp),
        Recorded::Shutdown => cx.request_exit(0),
        _ => {}
    });
}

/// IPv4 sockets in `SYN_SENT` towards `port` (from `/proc/net/tcp`).
pub fn syn_sent_to(port: u16) -> usize {
    let tab = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let port = format!(":{port:04X}");
    tab.lines()
        .skip(1)
        .filter(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3 && f[2].ends_with(&port) && f[3] == "02"
        })
        .count()
}
