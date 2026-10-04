//! The driver harness (spec §8.1 "Driver"): the production `Driver` on its
//! own thread over a `ScriptedTransport` and a `RecordingApp`, real loopback
//! sockets, and a resolver the test answers on command. `DriverThread` is
//! the generic part: any shard, built by a factory on the driver thread.

use mq_runtime::driver::{Driver, DriverConfig, Resolver, ShutdownHandle, Stats};
use mq_runtime::testing::{
    RecordHandle, Recorded, RecordingApp, ScriptedHandle, ScriptedTransport,
};
use mq_runtime::{App, ListenKind, ListenerTag, Shard, TcpEnd};
use mq_transport_api::TransportOps;
use std::io;
use std::net::{IpAddr, SocketAddr};
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

/// A resolver for `DriverConfig::resolver` that blocks until the test answers
/// through the returned control.
pub fn chan_resolver() -> (Arc<dyn Resolver>, ResolverControl) {
    let (tx, rx) = mpsc::channel();
    (Arc::new(ChanResolver(tx)), ResolverControl(rx))
}

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

struct Ready<H> {
    handle: H,
    udp: SocketAddr,
    listeners: Vec<SocketAddr>,
    shutdown: ShutdownHandle,
    stats: Stats,
}

/// A production `Driver` on its own thread over a shard built by a factory
/// on that thread (`Transport` and `Shard` are `!Send`). Built and bound by
/// `spawn_with`; `run` starts only at `start`, so reactions can be installed
/// before `on_start`.
pub struct DriverThread<H> {
    /// What the factory handed back to the test (e.g. a `RecordHandle`).
    pub handle: H,
    /// The primary UDP socket.
    pub udp_addr: SocketAddr,
    pub listen_addrs: Vec<SocketAddr>,
    pub shutdown: ShutdownHandle,
    pub stats: Stats,
    go: Option<Sender<()>>,
    done: Receiver<i32>,
    thread: Option<JoinHandle<()>>,
}

impl<H: Send + 'static> DriverThread<H> {
    /// Binds the primary UDP socket on `127.0.0.1:0`, builds the shard with
    /// `factory(primary_local)` on the driver thread, then binds one loopback
    /// listener per `(kind, tag)`.
    pub fn spawn_with<T, A, F>(
        cfg: DriverConfig,
        listeners: Vec<(ListenKind, ListenerTag)>,
        factory: F,
    ) -> DriverThread<H>
    where
        T: TransportOps + 'static,
        A: App + 'static,
        F: FnOnce(SocketAddr) -> (Shard<T, A>, H) + Send + 'static,
    {
        Self::spawn_on(loopback().ip(), cfg, listeners, factory)
    }

    /// `spawn_with` with the primary UDP socket on `udp_ip` (port 0).
    pub fn spawn_on<T, A, F>(
        udp_ip: IpAddr,
        cfg: DriverConfig,
        listeners: Vec<(ListenKind, ListenerTag)>,
        factory: F,
    ) -> DriverThread<H>
    where
        T: TransportOps + 'static,
        A: App + 'static,
        F: FnOnce(SocketAddr) -> (Shard<T, A>, H) + Send + 'static,
    {
        Self::spawn_on_addr(SocketAddr::new(udp_ip, 0), cfg, listeners, factory)
    }

    /// `spawn_with` with the primary UDP socket bound to exactly `udp` (a
    /// restarted server keeps its address).
    pub fn spawn_on_addr<T, A, F>(
        udp: SocketAddr,
        cfg: DriverConfig,
        listeners: Vec<(ListenKind, ListenerTag)>,
        factory: F,
    ) -> DriverThread<H>
    where
        T: TransportOps + 'static,
        A: App + 'static,
        F: FnOnce(SocketAddr) -> (Shard<T, A>, H) + Send + 'static,
    {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (done_tx, done) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut d = Driver::new(cfg).expect("driver");
            let udp = d.bind_udp(udp).expect("bind_udp");
            let udp_addr = udp.local_addr();
            let (mut shard, handle) = factory(udp_addr);
            d.attach_primary_udp(udp, shard.primary_udp())
                .expect("first attach");
            let mut addrs = Vec::new();
            for (kind, tag) in listeners {
                let l = d.listen(loopback(), kind).expect("listen");
                addrs.push(l.local_addr());
                d.attach_listener(l, shard.add_listener(tag));
            }
            let _ = ready_tx.send(Ready {
                handle,
                udp: udp_addr,
                listeners: addrs,
                shutdown: d.shutdown_handle(),
                stats: d.stats(),
            });
            if go_rx.recv().is_err() {
                return;
            }
            // The shard, and its transport, drop here on their own thread.
            let (code, _shard) = d.run(shard);
            let _ = done_tx.send(code);
        });
        let r = ready_rx.recv().expect("driver thread failed during setup");
        DriverThread {
            handle: r.handle,
            udp_addr: r.udp,
            listen_addrs: r.listeners,
            shutdown: r.shutdown,
            stats: r.stats,
            go: Some(go_tx),
            done,
            thread: Some(thread),
        }
    }
}

impl<H> DriverThread<H> {
    /// Starts `Driver::run` (and so `on_start`).
    pub fn start(&mut self) {
        if let Some(go) = self.go.take() {
            go.send(()).expect("driver thread alive");
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

/// `DriverThread` over a `ScriptedTransport` and a `RecordingApp`, with the
/// channel-backed resolver. Derefs to the `DriverThread` for the addresses,
/// handles, `start` and `join_timeout`.
pub struct DriverHarness {
    pub scripted: ScriptedHandle,
    pub record: RecordHandle,
    pub resolver: ResolverControl,
    d: DriverThread<(ScriptedHandle, RecordHandle)>,
}

impl std::ops::Deref for DriverHarness {
    type Target = DriverThread<(ScriptedHandle, RecordHandle)>;
    fn deref(&self) -> &Self::Target {
        &self.d
    }
}

impl std::ops::DerefMut for DriverHarness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.d
    }
}

impl DriverHarness {
    pub fn spawn(cfg: HarnessConfig) -> DriverHarness {
        let (resolver, control) = chan_resolver();
        let dcfg = DriverConfig {
            resolver,
            emfile_retry: cfg.emfile_retry,
            shutdown_cap: cfg.shutdown_cap,
            install_signal_handlers: false,
        };
        let listeners = (cfg.listeners.into_iter().enumerate())
            .map(|(i, kind)| (kind, ListenerTag(i as u32)))
            .collect();
        let d = DriverThread::spawn_with(dcfg, listeners, |local| {
            let (t, scripted) = ScriptedTransport::new();
            let (app, record) = RecordingApp::new();
            (Shard::new(t, app, local, 1), (scripted, record))
        });
        DriverHarness {
            scripted: d.handle.0.clone(),
            record: d.handle.1.clone(),
            resolver: control,
            d,
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

    /// The exit status; panics if the driver does not exit within 10 s.
    pub fn join(self) -> i32 {
        self.d.join()
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
