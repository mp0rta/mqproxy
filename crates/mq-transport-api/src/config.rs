//! Transport and connection configuration, stats (spec §4.2, §6.5).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Engine configuration (spec §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    pub role: Role,
    /// e.g. `"mqproxy-tcp/1"`.
    pub alpn: &'static str,
    /// Server; 0 = unlimited.
    pub max_conns: u32,
    pub scheduler: Scheduler,
    pub cc: CongestionControl,
    /// Wall clock minus monotonic, fixed at creation (spec §4.3).
    pub realtime_offset_us: i64,
}

/// Client or server; the server needs a cert and key (spec §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server { cert: PathBuf, key: PathBuf },
}

/// xquic multipath scheduler (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scheduler {
    MinRtt,
    Backup,
    Wlb,
}

/// Congestion controller (spec §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CongestionControl {
    Bbr,
    Bbr2,
    Cubic,
}

/// Per-connection configuration for `connect` (spec §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnConfig {
    pub peer: SocketAddr,
    /// e.g. `"mqproxy"`.
    pub sni: &'static str,
    /// `--keepalive-idle`; `None` disables keepalive.
    pub idle_timeout: Option<Duration>,
}

/// Snapshot for the `mq.conn` line (spec §6.5); `paths.len()` is `paths=`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// xquic `mp_state`.
    pub mp_state: i32,
    /// xquic `total_app_bytes`.
    pub app_bytes: u64,
    /// xquic `standby_path_app_bytes`.
    pub standby_bytes: u64,
    pub paths: Vec<PathStats>,
}

/// One `mq.path` line (spec §6.5). Times are raw microseconds; the formatter
/// divides by 1000 for `srtt_ms` / `min_rtt_ms`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PathStats {
    pub id: u64,
    /// Raw xquic path state (2 == ACTIVE).
    pub state: u32,
    pub srtt_us: u64,
    /// Estimated bandwidth, bytes/second.
    pub est_bw: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub lost_count: u64,
    pub min_rtt_us: u64,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
}
