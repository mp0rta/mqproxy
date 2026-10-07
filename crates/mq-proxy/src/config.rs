// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.2, §6.3, §6.5: client and server settings; the CLI maps onto these (Task 9.1).

use crate::client::mitm::MitmTuning;
use crate::client::mitm::ca::Ca;
use crate::client::mitm::policy::IgnoreHosts;
use crate::udp::DEFAULT_IDLE;
use mq_transport_api::Scheduler;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// spec §6.2: client settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    /// `--server`.
    pub server: SocketAddr,
    /// `--path` entries, config file first then CLI, at most 8 (the CLI caps the
    /// list). The first is the primary bind; the rest are the path candidates.
    pub paths: Vec<IpAddr>,
    /// `--scheduler`; `Backup` adds the extra paths as standby.
    pub scheduler: Scheduler,
    /// `--keepalive-idle`: the QUIC idle timeout; `None` disables it.
    pub keepalive_idle: Option<Duration>,
    /// `--client-id` (default "mqproxy"); truncated to 63 bytes on the wire.
    pub client_id: String,
    /// `--token`; truncated to 255 bytes on the wire.
    pub token: String,
    /// `--reconnect` / `--no-reconnect`.
    pub reconnect: bool,
    /// `--reconnect-max-backoff` (floored to 1 s by `Backoff::new`).
    pub reconnect_max_backoff: Duration,
    /// `--metrics-interval`; `None` is off.
    pub metrics_interval: Option<Duration>,
    /// No `AUTH_RESPONSE` this long after `ConnEstablished` closes the connection.
    pub auth_deadline: Duration,
    /// A request pending longer than this gets an error reply.
    pub pending_deadline: Duration,
    /// An ingress request not complete within this is closed (the fetch
    /// head deadline too, SP3 spec §5.1).
    pub ingress_deadline: Duration,
    /// SP3 spec §8: `--gateway ip:port` / `[Ingress] Gateway`; the fetch API and
    /// its own H3 tunnel connection.
    pub gateway: Option<SocketAddr>,
    /// SP3 spec §5.7: a TCP ingress (`--socks5` / `--http-connect` / `--tproxy`)
    /// is configured, so the raw tunnel is created.
    pub has_tcp_ingress: bool,
    /// SP4 spec §9: `--mitm` with its CA and IgnoreHosts.
    pub mitm: Option<MitmConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            server: SocketAddr::from((Ipv4Addr::LOCALHOST, 4433)),
            paths: Vec::new(),
            scheduler: Scheduler::MinRtt,
            keepalive_idle: Some(Duration::from_secs(30)),
            client_id: "mqproxy".to_owned(),
            token: String::new(),
            reconnect: true,
            reconnect_max_backoff: Duration::from_secs(30),
            metrics_interval: None,
            auth_deadline: Duration::from_secs(10),
            pending_deadline: Duration::from_secs(30),
            ingress_deadline: Duration::from_secs(10),
            gateway: None,
            has_tcp_ingress: true,
            mitm: None,
        }
    }
}

/// spec §6.3: server settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// `--token`, compared in constant time.
    pub token: String,
    /// Resolve + connect deadline for a dial.
    pub dial_deadline: Duration,
    pub auth_deadline: Duration,
    pub request_deadline: Duration,
    /// `--metrics-interval`; `None` is off.
    pub metrics_interval: Option<Duration>,
    /// `--no-udp` clears it: advertise `MQ_FEAT_UDP_RELAY` (spec §7.3).
    pub udp_enabled: bool,
    /// `--udp-idle-timeout`: a UDP session idle this long is closed.
    pub udp_idle_timeout: Duration,
    /// SP3 spec §8: the HTTP gateway; `None` = `--no-gateway`.
    pub gateway: Option<GatewayConfig>,
}

/// SP3 spec §8: server gateway settings (the rustls config is built at
/// startup and handed to `Server::with_gateway`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayConfig {
    /// `--origin-ca`: the only roots for origin TLS (§7.8).
    pub origin_ca: Option<PathBuf>,
    /// `--masquerade`: a bare 404 to unauthenticated requests (§6.5).
    pub masquerade: bool,
    /// `--request-metrics`: one `mq.req` line per request (§6.6).
    pub request_metrics: bool,
    /// DNS + TCP + TLS deadline (`MQ_GW_ORIGIN_CONNECT_TIMEOUT_S`).
    pub origin_connect_timeout: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            origin_ca: None,
            masquerade: false,
            request_metrics: false,
            origin_connect_timeout: Duration::from_secs(10),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            token: String::new(),
            dial_deadline: Duration::from_secs(15),
            auth_deadline: Duration::from_secs(10),
            request_deadline: Duration::from_secs(10),
            metrics_interval: None,
            udp_enabled: true,
            udp_idle_timeout: DEFAULT_IDLE,
            gateway: None,
        }
    }
}

/// SP4 spec §9: the MITM front's settings, present iff `--mitm`.
#[derive(Clone)]
pub struct MitmConfig {
    pub ca: Arc<Ca>,
    pub ignore: IgnoreHosts,
    pub tuning: MitmTuning,
}

// Redacted: the CA key never reaches a log line.
impl fmt::Debug for MitmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmConfig")
            .field("ca", &self.ca.subject)
            .field("ignore", &format_args!("{} entries", self.ignore.len()))
            .field("tuning", &self.tuning)
            .finish()
    }
}

// The CA compares by identity: one load is one CA.
impl PartialEq for MitmConfig {
    fn eq(&self, o: &Self) -> bool {
        Arc::ptr_eq(&self.ca, &o.ca) && self.ignore == o.ignore && self.tuning == o.tuning
    }
}
impl Eq for MitmConfig {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mitm::ca::tests::stage;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ca() -> Arc<Ca> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = stage(&format!("cfg{n}"), &["ca-p256.crt", "ca-p256.key"]);
        let ca = Ca::load(&d.join("ca-p256.crt"), &d.join("ca-p256.key")).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        Arc::new(ca)
    }

    fn cfg(ca: Arc<Ca>) -> MitmConfig {
        MitmConfig {
            ca,
            ignore: IgnoreHosts::parse(["a.test", ".b.test"]).unwrap(),
            tuning: MitmTuning::default(),
        }
    }

    #[test]
    fn mitm_config_debug_redacts_key() {
        let c = cfg(ca());
        assert_eq!(
            format!("{c:?}"),
            format!(
                "MitmConfig {{ ca: \"CN=mqproxy test ca-p256\", ignore: 2 entries, tuning: {:?} }}",
                c.tuning
            )
        );
        let client = ClientConfig {
            mitm: Some(c),
            ..ClientConfig::default()
        };
        assert!(
            format!("{client:?}")
                .contains("mitm: Some(MitmConfig { ca: \"CN=mqproxy test ca-p256\", ignore")
        );
        assert_eq!(ClientConfig::default().mitm, None);
    }

    #[test]
    fn mitm_config_eq_by_arc() {
        let a = ca();
        let c = cfg(a.clone());
        assert_eq!(c, c.clone());
        assert_eq!(c, cfg(a.clone()));
        // The same files loaded twice are two CAs.
        assert_ne!(c, cfg(ca()));
        let mut d = cfg(a.clone());
        d.ignore = IgnoreHosts::default();
        assert_ne!(c, d);
        let mut d = cfg(a);
        d.tuning.max_conns = 1;
        assert_ne!(c, d);
    }
}
