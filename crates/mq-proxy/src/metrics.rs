//! spec §6.5: `mq.conn` / `mq.path` lines.

use mq_transport_api::{ConnStats, PathStats};

/// spec §6.5: `mq.conn mp_state=%d paths=%u app_bytes=%llu standby_bytes=%llu`.
pub fn format_conn_line(st: &ConnStats) -> String {
    format!(
        "mq.conn mp_state={} paths={} app_bytes={} standby_bytes={}",
        st.mp_state,
        st.paths.len(),
        st.app_bytes,
        st.standby_bytes
    )
}

/// spec §6.5: the `mq.path` line; µs times are divided by 1000 (truncating) into ms.
pub fn format_path_line(p: &PathStats) -> String {
    format!(
        "mq.path id={} state={} srtt_ms={} bw_Bps={} sent={} recv={} lost={} min_rtt_ms={} cwnd={} inflight={}",
        p.id,
        p.state,
        p.srtt_us / 1000,
        p.est_bw,
        p.sent_bytes,
        p.recv_bytes,
        p.lost_count,
        p.min_rtt_us / 1000,
        p.cwnd,
        p.bytes_in_flight
    )
}

/// spec §6.5: the lines one dump logs, in order: the conn line then one path line per
/// path, or a single diagnostic (`None` → no connection, no paths → no path metrics).
pub fn format_metrics(stats: Option<&ConnStats>) -> Vec<String> {
    match stats {
        None => vec!["mq_conn stats: no connection".to_owned()],
        Some(st) if st.paths.is_empty() => vec!["mq_conn stats: no path metrics".to_owned()],
        Some(st) => std::iter::once(format_conn_line(st))
            .chain(st.paths.iter().map(format_path_line))
            .collect(),
    }
}
