//! One path of two black-holed in both directions while the other keeps carrying traffic:
//! xquic closes the dead path after the idle timeout (its path idle timer is the
//! connection's), raises `PathRemoved`, the connection lives on, and a path added afresh
//! from the same address becomes active once the black hole lifts. `MpReady` is not raised
//! again, so re-adding is up to the app.
mod common;

use common::pair::{ACTIVE, MS, Opts, Pair, add_path, cli_addr, mp_ready_count, path_state, send};
use mq_transport_api::{Event, PathId};
use std::time::Duration;

const IDLE: Duration = Duration::from_secs(30);
const CLOSED: u32 = 4; // XQC_PATH_STATE_CLOSED

fn two_paths() -> (Pair, PathId) {
    let mut p = Pair::with(Opts {
        paths: 2,
        idle: Some(IDLE),
        ..Opts::default()
    });
    assert!(p.pump_until(MS, 2000, |p| mp_ready_count(p) > 0));
    let pid = add_path(&p).expect("add_path");
    assert!(p.pump_until(MS, 5000, |p| path_state(p, pid.0) == Some(ACTIVE)));
    (p, pid)
}

/// 50 ms steps for `dur`, a little stream data every 200 ms, dropping every datagram from
/// or to `dead`.
fn run_blackholed(p: &mut Pair, dead: std::net::SocketAddr, dur: Duration) {
    let s = p.open();
    let end = p.now + dur;
    let mut step = 0u32;
    while p.now < end {
        p.now = p.now + Duration::from_millis(50);
        if step.is_multiple_of(4) {
            let _ = send(&p.client, p.now, s, vec![0u8; 100], false);
        }
        step += 1;
        p.client.drive(p.now);
        p.server.drive(p.now);
        loop {
            let mut moved = 0;
            for (src, dst) in [(&p.client, &p.server), (&p.server, &p.client)] {
                for d in src.pump_out(p.now) {
                    moved += 1;
                    if d.from != dead && d.to != dead {
                        dst.deliver(p.now, d.to, d.from, d.data);
                    }
                }
                dst.drive(p.now);
            }
            if moved == 0 {
                break;
            }
        }
        p.collect();
    }
}

fn removed(p: &Pair) -> Vec<PathId> {
    p.cev
        .iter()
        .filter_map(|e| match e {
            Event::PathRemoved(c, id) if *c == p.conn => Some(*id),
            _ => None,
        })
        .collect()
}

fn blackhole_then_readd(dead_idx: usize) {
    let (mut p, pid) = two_paths();
    let dead_path = if dead_idx == 0 { PathId(0) } else { pid };
    let mp = mp_ready_count(&p);

    run_blackholed(&mut p, cli_addr(dead_idx), IDLE - Duration::from_secs(1));
    assert!(removed(&p).is_empty(), "removed before the idle timeout");
    run_blackholed(&mut p, cli_addr(dead_idx), Duration::from_secs(5));
    assert_eq!(removed(&p), vec![dead_path]);
    assert_eq!(path_state(&p, dead_path.0), Some(CLOSED));
    assert_eq!(p.client_closed(), None, "the connection survives");
    assert_eq!(mp_ready_count(&p), mp, "no MpReady after a removal");

    // The black hole lifts; a new path from the same address comes up.
    let id = add_path(&p).expect("add_path after removal");
    p.client.path_addr.insert(id.0, dead_idx);
    assert!(p.pump_until(MS, 5000, |p| path_state(p, id.0) == Some(ACTIVE)));
}

#[test]
fn blackholed_second_path_is_removed_and_can_be_readded() {
    blackhole_then_readd(1);
}

#[test]
fn blackholed_primary_path_is_removed_and_can_be_readded() {
    blackhole_then_readd(0);
}

/// An idle two-path tunnel keeps both paths: keepalive PINGs go out on every path.
#[test]
fn idle_two_path_tunnel_keeps_both_paths() {
    let (mut p, pid) = two_paths();
    let end = p.now + 6 * IDLE;
    while p.now < end {
        assert!(p.follow_timeout());
    }
    assert_eq!(p.client_closed(), None);
    assert!(removed(&p).is_empty());
    assert_eq!(path_state(&p, 0), Some(ACTIVE));
    assert_eq!(path_state(&p, pid.0), Some(ACTIVE));
}
