//! The loopback harness (spec §8.1 "Loopback"): a server side and a client
//! side, each a production `Driver` with a shard over the real transport,
//! each on its own thread, talking over loopback UDP. The test thread plays
//! the local application and the origin with plain `std::net` sockets.

use crate::driver_harness::DriverThread;
use mq_proxy::client::{Client, HTTP_CONNECT, SOCKS5};
use mq_proxy::config::{ClientConfig, ServerConfig};
use mq_proxy::server::Server;
use mq_runtime::driver::{DriverConfig, StdResolver};
use mq_runtime::{App, ListenKind, ListenerTag, Shard};
use mq_transport::Transport;
use mq_transport_api::{CongestionControl, Role, Scheduler, TransportConfig, TransportOps};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Both sides, already running. `S`/`C` are what the factories handed back.
pub struct LoopbackPair<S, C> {
    pub server: DriverThread<S>,
    pub client: DriverThread<C>,
}

fn driver_config() -> DriverConfig {
    DriverConfig {
        resolver: Arc::new(StdResolver),
        install_signal_handlers: false,
        ..DriverConfig::default()
    }
}

impl<S: Send + 'static, C: Send + 'static> LoopbackPair<S, C> {
    /// spec §8.1: `server(local)` and `client(local, server_udp)` build each
    /// side's shard on its own driver thread (one transport per thread);
    /// `client_listeners` are bound on loopback for the test's local app.
    /// The server starts first, then the client.
    pub fn spawn<TS, AS, TC, AC>(
        client_listeners: Vec<(ListenKind, ListenerTag)>,
        server: impl FnOnce(SocketAddr) -> (Shard<TS, AS>, S) + Send + 'static,
        client: impl FnOnce(SocketAddr, SocketAddr) -> (Shard<TC, AC>, C) + Send + 'static,
    ) -> LoopbackPair<S, C>
    where
        TS: TransportOps + 'static,
        AS: App + 'static,
        TC: TransportOps + 'static,
        AC: App + 'static,
    {
        let mut server = DriverThread::spawn_with(driver_config(), Vec::new(), server);
        let server_udp = server.udp_addr;
        let mut client =
            DriverThread::spawn_with(driver_config(), client_listeners, move |local| {
                client(local, server_udp)
            });
        server.start();
        client.start();
        LoopbackPair { server, client }
    }

    /// Stops each side through its own `ShutdownHandle` (client first) and
    /// returns the exit statuses `(server, client)`.
    pub fn join_both(self) -> (i32, i32) {
        self.client.shutdown.trigger();
        self.server.shutdown.trigger();
        let c = self.client.join();
        (self.server.join(), c)
    }
}

/// The real proxy over loopback: `Server` and `Client` on real transports
/// (test cert, ALPN "mqproxy-tcp/1", BBR/MinRtt); the client opens a SOCKS5
/// (`client.listen_addrs[0]`) and an HTTP CONNECT (`[1]`) listener.
pub type LoopbackProxy = LoopbackPair<(), ()>;

fn transport(role: Role) -> Transport {
    Transport::new(TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns: 0,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
    })
    .expect("transport")
}

fn cert(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs")).join(name)
}

impl LoopbackProxy {
    /// `client.server` is overwritten with the server's bound UDP address.
    pub fn spawn_proxy(server: ServerConfig, mut client: ClientConfig) -> LoopbackProxy {
        LoopbackPair::spawn(
            vec![
                (ListenKind::Plain, SOCKS5),
                (ListenKind::Plain, HTTP_CONNECT),
            ],
            move |local| {
                let t = transport(Role::Server {
                    cert: cert("test.crt"),
                    key: cert("test.key"),
                });
                (Shard::new(t, Server::new(server), local, 1), ())
            },
            move |local, server_udp| {
                client.server = server_udp;
                let t = transport(Role::Client);
                (Shard::new(t, Client::new(client), local, 2), ())
            },
        )
    }

    pub fn socks5_addr(&self) -> SocketAddr {
        self.client.listen_addrs[0]
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.client.listen_addrs[1]
    }
}
