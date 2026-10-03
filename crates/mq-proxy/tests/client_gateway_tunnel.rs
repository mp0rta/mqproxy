//! spec §5.7 the gateway's H3 tunnel (eager connect, establish, loss, backoff,
//! `--no-reconnect`), §5.8 routing inside `Client`, §5.9 the joint shutdown exit.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::{Call, log_capture};
use mq_runtime::{IoRequest, SocketOpId};
use mq_transport_api::{
    CloseReason, ConnConfig, ConnId, ConnProto, ConnStats, ConnectError, ErrType, Event, PathStats,
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

fn gw_cfg() -> ClientConfig {
    ClientConfig {
        gateway: Some(addr(8080)),
        ..cfg()
    }
}

fn closed_ev(c: ConnId) -> Event {
    Event::ConnClosed(
        c,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

fn connect_cfgs(h: &H) -> Vec<ConnConfig> {
    h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::Connect(cc) => Some(cc),
            _ => None,
        })
        .collect()
}

fn tunnel_conn(h: &H) -> Option<ConnId> {
    h.sh.app()
        .gateway()
        .expect("gateway configured")
        .tunnel_conn()
}

fn has_line(lines: &[String], want: &str) -> bool {
    lines.iter().any(|l| l == want)
}

/// The pending reconnect delay (only the gateway arms a timer in these tests).
fn wait(h: &H) -> Duration {
    h.sh.next_timeout().expect("reconnect armed") - h.now
}

fn first_retry(d: Duration) -> bool {
    (Duration::from_millis(250)..=Duration::from_millis(500)).contains(&d)
}

#[test]
fn gateway_connects_eagerly_with_h3() {
    let h = H::new(gw_cfg());
    let cs = connect_cfgs(&h);
    assert_eq!(cs.len(), 2, "raw tunnel, then the gateway's");
    assert_eq!(cs[0].proto, ConnProto::Raw);
    let c = &cs[1];
    assert_eq!(c.proto, ConnProto::H3);
    assert_eq!(c.sni, "mqproxy");
    assert_eq!(c.peer, gw_cfg().server);
    assert_eq!(c.idle_timeout, gw_cfg().keepalive_idle);
    assert_eq!(tunnel_conn(&h), None, "not usable before establishment");
}

#[test]
fn established_resets_backoff_and_logs() {
    log_capture::install();
    let mut h = H::new(gw_cfg());
    let gw = h.gw_conn.unwrap();
    log_capture::take();
    h.event(Event::ConnEstablished(gw));
    let lines = log_capture::take();
    assert!(
        has_line(&lines, "INFO mq_gw_client: tunnel conn established"),
        "{lines:?}"
    );
    assert_eq!(tunnel_conn(&h), Some(gw));
    assert_eq!(
        h.opens(),
        0,
        "the raw tunnel's control stream is not opened"
    );
}

#[test]
fn closed_arms_backoff_and_logs() {
    log_capture::install();
    let mut h = H::new(gw_cfg());
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    log_capture::take();
    h.event(closed_ev(gw));
    let d = wait(&h);
    assert!(first_retry(d), "{d:?}");
    let lines = log_capture::take();
    assert!(
        has_line(&lines, "INFO mq_gw_client: tunnel conn closed"),
        "{lines:?}"
    );
    let want = format!("INFO mq_gw_client: reconnecting in {} ms", d.as_millis());
    assert!(has_line(&lines, &want), "{lines:?}");
    assert_eq!(tunnel_conn(&h), None);
    // The gateway's own timer reconnects it, with H3.
    h.advance(d);
    let cs = connect_cfgs(&h);
    assert_eq!(cs.len(), 3);
    assert_eq!(cs[2].proto, ConnProto::H3);
}

#[test]
fn backoff_resets_at_establish() {
    let mut h = H::new(gw_cfg());
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.event(closed_ev(gw));
    let d = wait(&h);
    assert!(first_retry(d), "{d:?}");
    let gw2 = h.t.new_conn_id();
    h.t.expect_connect(Ok(gw2));
    h.advance(d);
    h.event(Event::ConnEstablished(gw2));
    h.event(closed_ev(gw2));
    // Without the reset at establish this would be the second retry (500–1000 ms).
    let d = wait(&h);
    assert!(first_retry(d), "{d:?}");
}

#[test]
fn no_reconnect_is_terminal_and_502() {
    let mut h = H::new(ClientConfig {
        reconnect: false,
        ..gw_cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    assert!(!h.sh.app().gateway().unwrap().tunnel_gone());
    h.event(closed_ev(gw));
    assert_eq!(h.sh.next_timeout(), None, "no reconnect timer");
    assert!(h.sh.app().gateway().unwrap().tunnel_gone());
    assert_eq!(tunnel_conn(&h), None);
    h.advance(Duration::from_secs(60));
    assert_eq!(h.connects(), 2, "no reconnect");
    assert_eq!(h.sh.exit_status(), None, "the process keeps running");
}

#[test]
fn first_connect_failure_is_fatal() {
    log_capture::install();
    log_capture::take();
    let h = H::start(
        ClientConfig {
            has_tcp_ingress: false,
            ..gw_cfg()
        },
        Some(ConnectError::Other(-1)),
    );
    assert_eq!(h.sh.exit_status(), Some(1));
    let lines = log_capture::take();
    assert!(
        has_line(&lines, "ERROR mq_gw_client: tunnel connect failed"),
        "{lines:?}"
    );
}

#[test]
fn reconnect_failure_rearms() {
    log_capture::install();
    let mut h = H::new(gw_cfg());
    let gw = h.gw_conn.unwrap();
    h.event(closed_ev(gw)); // handshake failure: no establish
    let d = wait(&h);
    h.t.expect_connect(Err(ConnectError::Other(-1)));
    log_capture::take();
    h.advance(d);
    assert_eq!(h.connects(), 3);
    let lines = log_capture::take();
    assert!(
        has_line(&lines, "ERROR mq_gw_client: tunnel connect failed"),
        "{lines:?}"
    );
    assert_eq!(h.sh.exit_status(), None, "only the first connect is fatal");
    // Re-armed as the next attempt (attempt 2: 500–1000 ms).
    let d = wait(&h);
    assert!(
        (Duration::from_millis(500)..=Duration::from_millis(1000)).contains(&d),
        "{d:?}"
    );
    h.advance(d);
    assert_eq!(h.connects(), 4);
}

#[test]
fn gateway_only_client_has_no_raw_tunnel() {
    let h = H::new(ClientConfig {
        has_tcp_ingress: false,
        ..gw_cfg()
    });
    let cs = connect_cfgs(&h);
    assert_eq!(cs.len(), 1);
    assert_eq!(cs[0].proto, ConnProto::H3);
}

#[test]
fn shutdown_exits_after_both_tunnels() {
    for gw_first in [false, true] {
        let mut h = H::new(gw_cfg());
        let gw = h.gw_conn.unwrap();
        h.serving();
        h.event(Event::ConnEstablished(gw));
        h.t.hold_conn_closed(true);
        h.sh.on_shutdown_signal(h.now);
        assert!(h.log().contains(&Call::CloseConn(h.conn)));
        assert!(h.log().contains(&Call::CloseConn(gw)));
        let (a, b) = if gw_first { (gw, h.conn) } else { (h.conn, gw) };
        h.event(closed_ev(a));
        assert_eq!(h.sh.exit_status(), None, "gw_first={gw_first}");
        h.event(closed_ev(b));
        assert_eq!(h.sh.exit_status(), Some(0), "gw_first={gw_first}");
        assert_eq!(h.connects(), 2, "no reconnect while shutting down");
    }
}

#[test]
fn gateway_only_shutdown_exits_at_gateway_close() {
    let mut h = H::new(ClientConfig {
        has_tcp_ingress: false,
        ..gw_cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.t.hold_conn_closed(true);
    h.sh.on_shutdown_signal(h.now);
    assert_eq!(h.sh.exit_status(), None);
    h.event(closed_ev(gw));
    assert_eq!(h.sh.exit_status(), Some(0));
}

#[test]
fn mp_ready_and_udp_socket_route_to_gateway_paths() {
    let a: IpAddr = "10.0.0.2".parse().unwrap();
    let mut h = H::new(ClientConfig {
        paths: vec!["10.0.0.1".parse().unwrap(), a],
        ..gw_cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.reqs();
    h.event(Event::MpReady(gw));
    let ops: Vec<(SocketOpId, IpAddr)> = h
        .reqs()
        .iter()
        .filter_map(|r| match r {
            IoRequest::OpenUdpSocket { op, local_ip } => Some((*op, *local_ip)),
            _ => None,
        })
        .collect();
    assert_eq!(ops.iter().map(|o| o.1).collect::<Vec<_>>(), [a]);
    h.sh.on_udp_socket(h.now, ops[0].0, Ok(SocketAddr::new(a, 40000)))
        .unwrap();
    assert!(h.log().contains(&Call::AddPath {
        conn: gw,
        standby: false
    }));
    assert!(
        !h.reqs()
            .iter()
            .any(|r| matches!(r, IoRequest::CloseUdpSocket { .. })),
        "the gateway kept the socket"
    );
}

#[test]
fn unknown_timer_offered_to_gateway() {
    log_capture::install();
    let mut h = H::new(ClientConfig {
        metrics_interval: Some(Duration::from_secs(1)),
        ..gw_cfg()
    });
    let gw = h.gw_conn.unwrap();
    h.event(Event::ConnEstablished(gw));
    h.event(closed_ev(gw));
    // Both the client's metrics timer and the gateway's reconnect timer fire.
    h.advance(Duration::from_secs(1));
    assert_eq!(h.connects(), 3, "the gateway's timer reached it");
    h.t.set_conn_stats(
        h.conn,
        ConnStats {
            mp_state: 1,
            app_bytes: 0,
            standby_bytes: 0,
            paths: vec![PathStats {
                id: 0,
                state: 1,
                srtt_us: 1,
                est_bw: 1,
                sent_bytes: 1,
                recv_bytes: 1,
                lost_count: 0,
                min_rtt_us: 1,
                cwnd: 1,
                bytes_in_flight: 0,
            }],
        },
    );
    log_capture::take();
    h.advance(Duration::from_secs(1));
    let lines = log_capture::take();
    assert!(
        lines.iter().any(|l| l.contains("mq.path")),
        "the client's own timer still re-arms: {lines:?}"
    );
}
