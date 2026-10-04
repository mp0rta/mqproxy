//! The loopback harness (spec §8.1 "Loopback"): a server side and a client
//! side, each a production `Driver` with a shard over the real transport,
//! each on its own thread, talking over loopback UDP. The test thread plays
//! the local application and the origin with plain `std::net` sockets.

use crate::driver_harness::DriverThread;
use mq_proxy::client::{Client, FETCH, HTTP_CONNECT, SOCKS5};
use mq_proxy::config::{ClientConfig, GatewayConfig, ServerConfig};
use mq_proxy::server::Server;
use mq_proxy::server::origin::build_client_config;
use mq_runtime::driver::{DriverConfig, StdResolver};
use mq_runtime::{App, ListenKind, ListenerTag, Shard};
use mq_transport::Transport;
use mq_transport_api::{CongestionControl, Role, Scheduler, TransportConfig, TransportOps};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
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
    /// The primary UDP sockets bind `udp_ips` = (server IP, client IP). The
    /// server starts first, then the client.
    pub fn spawn<TS, AS, TC, AC>(
        (server_ip, client_ip): (IpAddr, IpAddr),
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
        let mut server = DriverThread::spawn_on(server_ip, driver_config(), Vec::new(), server);
        let server_udp = server.udp_addr;
        let mut client =
            DriverThread::spawn_on(client_ip, driver_config(), client_listeners, move |local| {
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

/// A real transport as the proxy runs it (test cert, ALPN "mqproxy-tcp/1", BBR/MinRtt); `h3`
/// registers the H3 ctx.
pub fn transport(role: Role, h3: bool) -> Transport {
    Transport::new(TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns: 0,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
        h3,
    })
    .expect("transport")
}

/// `tests/certs/<name>`.
pub fn cert(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs")).join(name)
}

impl LoopbackProxy {
    /// `client.server` is overwritten with the server's bound UDP address.
    pub fn spawn_proxy(server: ServerConfig, client: ClientConfig) -> LoopbackProxy {
        let lo = Ipv4Addr::LOCALHOST.into();
        Self::spawn_proxy_on((lo, lo), server, client)
    }

    /// `spawn_proxy` with the QUIC endpoints on `udp_ips` = (server IP,
    /// client IP), e.g. `::1`; the TCP listeners stay on IPv4 loopback.
    pub fn spawn_proxy_on(
        udp_ips: (IpAddr, IpAddr),
        server: ServerConfig,
        mut client: ClientConfig,
    ) -> LoopbackProxy {
        LoopbackPair::spawn(
            udp_ips,
            vec![
                (ListenKind::Plain, SOCKS5),
                (ListenKind::Plain, HTTP_CONNECT),
            ],
            move |local| {
                let t = transport(
                    Role::Server {
                        cert: cert("test.crt"),
                        key: cert("test.key"),
                    },
                    false,
                );
                (Shard::new(t, Server::new(server), local, 1), ())
            },
            move |local, server_udp| {
                client.server = server_udp;
                let t = transport(Role::Client, false);
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

    /// The gateway pair (spec §5, §6): the fetch client against `Server::with_gateway`, H3
    /// on both transports. The FETCH listener is the client's only listener (no TCP ingress,
    /// so no raw tunnel); `origin_ca` is the bridge's only trust root. A `None` gateway in
    /// either config is filled with a placeholder / `GatewayConfig::default()`.
    pub fn spawn_gateway(
        client: ClientConfig,
        mut server: ServerConfig,
        origin_ca: &Path,
    ) -> LoopbackProxy {
        server.gateway.get_or_insert_with(GatewayConfig::default);
        let tls = build_client_config(Some(origin_ca), &Vec::new).expect("origin CA");
        // `Server` holds `Rc`s: it is built on its driver thread.
        Self::gateway_pair(client, move || Server::with_gateway(server, tls))
    }

    /// The fetch client of `spawn_gateway` against an arbitrary H3 server `App` (a
    /// malformed peer).
    pub fn spawn_gateway_against<A: App + Send + 'static>(
        client: ClientConfig,
        server_app: A,
    ) -> LoopbackProxy {
        Self::gateway_pair(client, move || server_app)
    }

    fn gateway_pair<A: App + 'static>(
        mut client: ClientConfig,
        server_app: impl FnOnce() -> A + Send + 'static,
    ) -> LoopbackProxy {
        // The bound address is what `fetch_addr` reports; `Client::new` only needs `Some`.
        client
            .gateway
            .get_or_insert(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        client.has_tcp_ingress = false;
        let lo = Ipv4Addr::LOCALHOST.into();
        LoopbackPair::spawn(
            (lo, lo),
            vec![(ListenKind::Plain, FETCH)],
            move |local| {
                let t = transport(
                    Role::Server {
                        cert: cert("test.crt"),
                        key: cert("test.key"),
                    },
                    true,
                );
                (Shard::new(t, server_app(), local, 1), ())
            },
            move |local, server_udp| {
                client.server = server_udp;
                let t = transport(Role::Client, true);
                (Shard::new(t, Client::new(client), local, 2), ())
            },
        )
    }

    pub fn fetch_addr(&self) -> SocketAddr {
        self.client.listen_addrs[0]
    }
}
