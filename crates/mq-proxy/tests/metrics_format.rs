//! spec §6.5: `mq.conn` / `mq.path` lines.

use mq_proxy::metrics::{format_conn_line, format_metrics, format_path_line};
use mq_transport_api::{ConnStats, PathStats};

#[test]
fn path_line() {
    let p = PathStats {
        id: 1,
        state: 2,
        srtt_us: 12345,
        est_bw: 6029312,
        sent_bytes: 1287654,
        recv_bytes: 83120,
        lost_count: 14,
        ..PathStats::default()
    };
    assert_eq!(
        format_path_line(&p),
        "mq.path id=1 state=2 srtt_ms=12 bw_Bps=6029312 sent=1287654 recv=83120 lost=14 min_rtt_ms=0 cwnd=0 inflight=0"
    );

    let p2 = PathStats {
        min_rtt_us: 12000,
        cwnd: 65535,
        bytes_in_flight: 4096,
        ..PathStats::default()
    };
    let l2 = format_path_line(&p2);
    assert!(l2.contains("min_rtt_ms=12 "), "{l2}");
    assert!(l2.contains("cwnd=65535 "), "{l2}");
    assert!(l2.ends_with("inflight=4096"), "{l2}");
}

#[test]
fn conn_line() {
    let st = ConnStats {
        mp_state: 1,
        app_bytes: 1320044,
        standby_bytes: 0,
        paths: vec![PathStats::default(); 2],
    };
    assert_eq!(
        format_conn_line(&st),
        "mq.conn mp_state=1 paths=2 app_bytes=1320044 standby_bytes=0"
    );
}

#[test]
fn negative_mp_state_is_signed() {
    let st = ConnStats {
        mp_state: -1,
        ..ConnStats::default()
    };
    assert_eq!(
        format_conn_line(&st),
        "mq.conn mp_state=-1 paths=0 app_bytes=0 standby_bytes=0"
    );
}

// The conn line, then one path line per path in order, or a diagnostic.
#[test]
fn dump_lines_and_diagnostics() {
    assert_eq!(format_metrics(None), ["mq_conn stats: no connection"]);
    assert_eq!(
        format_metrics(Some(&ConnStats::default())),
        ["mq_conn stats: no path metrics"]
    );

    let st = ConnStats {
        mp_state: 1,
        app_bytes: 7,
        standby_bytes: 3,
        paths: vec![
            PathStats {
                id: 0,
                state: 2,
                ..PathStats::default()
            },
            PathStats {
                id: 1,
                state: 2,
                srtt_us: 999,
                ..PathStats::default()
            },
        ],
    };
    assert_eq!(
        format_metrics(Some(&st)),
        [
            "mq.conn mp_state=1 paths=2 app_bytes=7 standby_bytes=3",
            "mq.path id=0 state=2 srtt_ms=0 bw_Bps=0 sent=0 recv=0 lost=0 min_rtt_ms=0 cwnd=0 inflight=0",
            "mq.path id=1 state=2 srtt_ms=0 bw_Bps=0 sent=0 recv=0 lost=0 min_rtt_ms=0 cwnd=0 inflight=0",
        ]
    );
}
