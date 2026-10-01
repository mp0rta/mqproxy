//! spec §6.2, §6.3, §6.5: client and server settings; the CLI maps onto these (Task 9.1).

use std::time::Duration;

/// spec §6.2: client settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    /// `--client-id` (C default "mqproxy"); truncated to 63 bytes on the wire.
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
    /// An ingress request not complete within this is closed.
    pub ingress_deadline: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            client_id: "mqproxy".to_owned(),
            token: String::new(),
            reconnect: true,
            reconnect_max_backoff: Duration::from_secs(30),
            metrics_interval: None,
            auth_deadline: Duration::from_secs(10),
            pending_deadline: Duration::from_secs(30),
            ingress_deadline: Duration::from_secs(10),
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            token: String::new(),
            dial_deadline: Duration::from_secs(15),
            auth_deadline: Duration::from_secs(10),
            request_deadline: Duration::from_secs(10),
            metrics_interval: None,
        }
    }
}
