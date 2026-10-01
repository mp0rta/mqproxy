//! `Driver`: the setup API around `LoopCore<MioIo, ..>` (spec §5.3 "Setup").

use super::core::{LoopConfig, LoopCore};
use super::io::{ListenerKey, Resolver, StdResolver, UdpSock};
use super::mio_io::{MioIo, ShutdownHandle, Stats};
use crate::app::{App, ListenKind};
use crate::ids::{ListenerId, UdpSocketId};
use crate::shard::Shard;
use mq_linux::TcpListenerBuilder;
use mq_transport_api::TransportOps;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// spec §5.3: what the driver tests (§8.1) replace.
#[derive(Clone)]
pub struct DriverConfig {
    pub resolver: Arc<dyn Resolver>,
    /// After `EMFILE`/`ENFILE` on accept (100 ms).
    pub emfile_retry: Duration,
    /// From a shutdown signal to exit 0 (2 s).
    pub shutdown_cap: Duration,
    /// SIGTERM/SIGINT → shutdown; off in tests so Ctrl-C still kills them.
    pub install_signal_handlers: bool,
}

impl Default for DriverConfig {
    fn default() -> Self {
        let l = LoopConfig::default();
        DriverConfig {
            resolver: Arc::new(StdResolver),
            emfile_retry: l.emfile_retry,
            shutdown_cap: l.shutdown_cap,
            install_signal_handlers: true,
        }
    }
}

/// A bound UDP socket, not yet attached.
#[derive(Debug)]
pub struct BoundUdp {
    sock: UdpSock,
    local: SocketAddr,
}

impl BoundUdp {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// A listening socket, not yet attached.
#[derive(Debug)]
pub struct BoundListener {
    key: ListenerKey,
    local: SocketAddr,
}

impl BoundListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// `attach_primary_udp` was called twice.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AlreadyAttached;

/// spec §5.3: the production driver.
pub struct Driver {
    io: MioIo,
    cfg: LoopConfig,
    primary: Option<(UdpSock, UdpSocketId)>,
    listeners: Vec<(ListenerKey, ListenerId)>,
    hook: Option<Box<dyn FnOnce()>>,
}

impl Driver {
    pub fn new(cfg: DriverConfig) -> io::Result<Driver> {
        Ok(Driver {
            io: MioIo::new(cfg.resolver, cfg.install_signal_handlers)?,
            cfg: LoopConfig {
                emfile_retry: cfg.emfile_retry,
                shutdown_cap: cfg.shutdown_cap,
            },
            primary: None,
            listeners: Vec::new(),
            hook: None,
        })
    }

    /// `AddrNotAvailable` for an address not on the host.
    pub fn bind_udp(&mut self, addr: SocketAddr) -> io::Result<BoundUdp> {
        let (sock, local) = self.io.bind_udp(addr)?;
        Ok(BoundUdp { sock, local })
    }

    /// spec §5.3: IPv4, `SO_REUSEADDR`, backlog 64; `IP_TRANSPARENT` for `Tproxy`.
    pub fn listen(&mut self, addr: SocketAddr, kind: ListenKind) -> io::Result<BoundListener> {
        let SocketAddr::V4(v4) = addr else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "listeners are IPv4",
            ));
        };
        let l = TcpListenerBuilder::new(v4)
            .transparent(kind == ListenKind::Tproxy)
            .build()?;
        let local = l.local_addr()?;
        let key = self.io.add_listener(l, kind)?;
        Ok(BoundListener { key, local })
    }

    pub fn attach_primary_udp(
        &mut self,
        u: BoundUdp,
        id: UdpSocketId,
    ) -> Result<(), AlreadyAttached> {
        if self.primary.is_some() {
            return Err(AlreadyAttached);
        }
        self.primary = Some((u.sock, id));
        Ok(())
    }

    pub fn attach_listener(&mut self, l: BoundListener, id: ListenerId) {
        self.listeners.push((l.key, id));
    }

    /// spec §5.3: runs right after `on_shutdown_signal`.
    pub fn on_shutdown(&mut self, hook: impl FnOnce() + 'static) {
        self.hook = Some(Box::new(hook));
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.io.shutdown_handle()
    }

    pub fn stats(&self) -> Stats {
        self.io.stats()
    }

    /// spec §5.3: starts the shard, loops until the exit status; returns the
    /// shard so the binary can close its transport.
    pub fn run<T: TransportOps, A: App>(self, shard: Shard<T, A>) -> (i32, Shard<T, A>) {
        let mut core = LoopCore::new(self.io, shard, self.cfg);
        if let Some((s, id)) = self.primary {
            core.attach_primary_udp(s, id);
        }
        for (l, id) in self.listeners {
            core.attach_listener(l, id);
        }
        if let Some(hook) = self.hook {
            core.on_shutdown(hook);
        }
        core.run()
    }
}
