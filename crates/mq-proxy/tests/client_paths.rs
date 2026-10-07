// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §6.2 "Paths": candidates, `MpReady`, socket opens, `add_path` outcomes,
//! and the reset on `ConnClosed`.

mod common;

use common::*;
use mq_proxy::config::ClientConfig;
use mq_runtime::testing::Call;
use mq_runtime::{IoRequest, SocketOpId};
use mq_transport_api::{CloseReason, ErrType, Event, PathError, PathId, Scheduler};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const A: &str = "10.0.0.2";
const B: &str = "10.0.0.3";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn paths_cfg() -> ClientConfig {
    ClientConfig {
        paths: vec![ip("10.0.0.1"), ip(A), ip(B)],
        ..cfg()
    }
}

/// The `OpenUdpSocket` requests issued, in order.
fn opens(reqs: &[IoRequest]) -> Vec<(SocketOpId, IpAddr)> {
    reqs.iter()
        .filter_map(|r| match r {
            IoRequest::OpenUdpSocket { op, local_ip } => Some((*op, *local_ip)),
            _ => None,
        })
        .collect()
}

fn local(s: &str) -> SocketAddr {
    SocketAddr::new(ip(s), 40000)
}

fn add_paths(h: &H) -> Vec<bool> {
    h.log()
        .iter()
        .filter_map(|c| match c {
            Call::AddPath { standby, .. } => Some(*standby),
            _ => None,
        })
        .collect()
}

fn closed_ev(h: &H) -> Event {
    Event::ConnClosed(
        h.conn,
        CloseReason {
            err_type: ErrType::Transport,
            code: 0,
        },
    )
}

#[test]
fn paths_open_socket_then_add_path() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    assert_eq!(ops.iter().map(|o| o.1).collect::<Vec<_>>(), [ip(A), ip(B)]);
    assert!(add_paths(&h).is_empty(), "no socket yet");
    let sock = h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    assert_eq!(add_paths(&h), [false], "add_path at once");
    assert!(h.log().contains(&Call::AddPath {
        conn: h.conn,
        standby: false
    }));
    assert!(h.reqs().is_empty(), "socket kept: no close");
    let _ = sock;
}

#[test]
fn repeated_mp_ready_retries_socket_ready_only() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Err(PathError::NoPathId));
    h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    assert_eq!(add_paths(&h).len(), 1);
    // A is socket-ready, B still opening.
    h.event(Event::MpReady(h.conn));
    assert!(opens(&h.reqs()).is_empty(), "B's open is in flight");
    assert_eq!(add_paths(&h).len(), 2, "A retried");
    // B opens and goes active; A active too now.
    h.sh.on_udp_socket(h.now, ops[1].0, Ok(local(B))).unwrap();
    assert_eq!(add_paths(&h).len(), 3);
    h.event(Event::MpReady(h.conn));
    assert_eq!(add_paths(&h).len(), 3, "active candidates are not retried");
    assert!(opens(&h.reqs()).is_empty());
}

#[test]
fn path_no_path_id_keeps_socket() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Err(PathError::NoPathId));
    let sock = h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    assert!(
        !h.reqs().contains(&IoRequest::CloseUdpSocket { sock }),
        "socket kept"
    );
    h.event(Event::MpReady(h.conn));
    assert_eq!(add_paths(&h).len(), 2, "same socket retried");
    assert!(opens(&h.reqs()).is_empty(), "no new socket");
}

/// The first retry delay is at most 500 ms (backoff base 250 ms, jitter into `[d/2, d]`).
const FIRST_RETRY: Duration = Duration::from_millis(500);

#[test]
fn path_other_error_closes_socket_and_retries_after_backoff() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Err(PathError::Other));
    let sock = h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    assert!(h.reqs().contains(&IoRequest::CloseUdpSocket { sock }));
    h.event(Event::MpReady(h.conn));
    assert_eq!(add_paths(&h).len(), 1, "not on MpReady: backing off");
    assert!(opens(&h.reqs()).is_empty());
    h.advance(FIRST_RETRY);
    let again = opens(&h.reqs());
    assert_eq!(again.iter().map(|o| o.1).collect::<Vec<_>>(), [ip(A)]);
}

#[test]
fn socket_open_error_retries_after_backoff() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    assert_eq!(
        h.sh.on_udp_socket(h.now, ops[0].0, Err(std::io::ErrorKind::AddrNotAvailable)),
        None
    );
    h.event(Event::MpReady(h.conn));
    assert!(opens(&h.reqs()).is_empty(), "backing off");
    h.advance(FIRST_RETRY);
    let again = opens(&h.reqs());
    assert_eq!(again.iter().map(|o| o.1).collect::<Vec<_>>(), [ip(A)]);
}

#[test]
fn removed_extra_path_reopens_its_socket_after_backoff() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Ok(PathId(1)));
    h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    h.event(Event::PathRemoved(h.conn, PathId(1)));
    assert!(opens(&h.reqs()).is_empty(), "not at once");
    h.advance(FIRST_RETRY);
    let again = opens(&h.reqs());
    assert_eq!(again.iter().map(|o| o.1).collect::<Vec<_>>(), [ip(A)]);
    h.sh.on_udp_socket(h.now, again[0].0, Ok(local(A))).unwrap();
    assert_eq!(add_paths(&h).len(), 2, "re-added");
}

#[test]
fn removed_primary_path_is_readded_on_the_primary_socket() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::PathRemoved(h.conn, PathId(0)));
    h.advance(FIRST_RETRY);
    assert!(opens(&h.reqs()).is_empty(), "no new socket");
    assert_eq!(add_paths(&h), [false]);
}

#[test]
fn unknown_or_stale_path_removal_is_ignored() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::PathRemoved(h.conn, PathId(9)));
    let other = h.t.new_conn_id();
    h.event(Event::PathRemoved(other, PathId(0)));
    h.advance(FIRST_RETRY);
    assert!(opens(&h.reqs()).is_empty());
    assert!(add_paths(&h).is_empty());
}

#[test]
fn retry_timers_cancelled_on_conn_close() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::PathRemoved(h.conn, PathId(0)));
    h.event(closed_ev(&h));
    h.reqs();
    // The reconnect fires; the primary retry does not add a path to anything.
    let c2 = h.t.new_conn_id();
    h.t.expect_connect(Ok(c2));
    h.advance(FIRST_RETRY.max(h.sh.next_timeout().unwrap() - h.now));
    assert!(add_paths(&h).is_empty());
}

#[test]
fn sockets_closed_candidates_reset_and_opens_cancelled_on_conn_close() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Err(PathError::NoPathId));
    let sock = h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    h.event(closed_ev(&h));
    let reqs = h.reqs();
    assert!(
        reqs.contains(&IoRequest::CloseUdpSocket { sock }),
        "{reqs:?}"
    );
    assert!(reqs.contains(&IoRequest::CancelUdpSocket { op: ops[1].0 }));
    // Reconnect: every candidate starts again.
    let c2 = h.t.new_conn_id();
    h.t.expect_connect(Ok(c2));
    let wait = h.sh.next_timeout().unwrap() - h.now;
    h.advance(wait);
    h.conn = c2;
    h.serving();
    h.event(Event::MpReady(c2));
    let again = opens(&h.reqs());
    assert_eq!(
        again.iter().map(|o| o.1).collect::<Vec<_>>(),
        [ip(A), ip(B)]
    );
}

#[test]
fn socket_open_after_conn_gone_is_cancelled() {
    let mut h = H::new(paths_cfg());
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.event(closed_ev(&h));
    assert!(
        h.reqs()
            .contains(&IoRequest::CancelUdpSocket { op: ops[0].0 })
    );
    // The late completion is dropped by the shard; no path is added.
    assert_eq!(h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))), None);
    assert!(add_paths(&h).is_empty());
    h.advance(Duration::from_millis(1));
    assert!(add_paths(&h).is_empty());
}

#[test]
fn backup_scheduler_adds_standby() {
    let mut h = H::new(ClientConfig {
        scheduler: Scheduler::Backup,
        ..paths_cfg()
    });
    h.serving();
    h.reqs();
    h.event(Event::MpReady(h.conn));
    let ops = opens(&h.reqs());
    h.t.expect_add_path(Ok(PathId(5)));
    h.sh.on_udp_socket(h.now, ops[0].0, Ok(local(A))).unwrap();
    assert_eq!(add_paths(&h), [true]);
}
