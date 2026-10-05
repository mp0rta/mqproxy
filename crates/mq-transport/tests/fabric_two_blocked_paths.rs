//! spec §4.4, §8.4 "Two paths blocked, one drains": `resume_pending` becomes true at once,
//! without any timer.
mod common;

use common::lockstep::cfg;
use common::pair::{MS, Opts, Pair};
use common::xfer::Xfer;
use mq_transport_api::{CongestionControl, Event, PathId, Role, TransportOps, TxKey};

/// spec §4.4 per-queue quota.
const QUEUE_QUOTA: usize = 1024 * 1024;

#[test]
fn two_blocked_paths_one_drains_resumes_at_once() {
    // Cubic: its window grows with every ACK in this zero-delay fabric, so both paths can
    // get windows larger than the queue quota (BBR's stays below it here).
    let mut client = cfg(Role::Client);
    client.cc = CongestionControl::Cubic;
    let mut p = Pair::with(Opts {
        paths: 2,
        client,
        ..Opts::default()
    });
    let c = p.conn;
    assert!(p.pump_until(MS, 2000, |p| p.cev.contains(&Event::MpReady(c))));
    let pid = p
        .client
        .call(p.now, move |t, now| t.add_path(now, c, false))
        .unwrap();
    let paths = |p: &Pair| {
        p.client
            .call(p.now, move |t, _| t.conn_stats(c))
            .unwrap()
            .paths
    };
    assert!(p.pump_until(MS, 5000, |p| {
        paths(p).iter().any(|x| x.id == pid.0 && x.state == 2)
    }));

    // Offer more per step than one path's window, so minRTT spills onto the other path and
    // both windows grow past the quota. (xquic counts what a refused socket left in a path's
    // schedule buffer against that path's window, so once both are blocked the preferred path
    // takes data only up to its window and the rest goes to the other one.)
    let mut x = Xfer::start(&p, 64 * 1024 * 1024);
    x.chunk = 1024 * 1024;
    assert!(p.pump_until(MS, 20_000, |p| {
        x.step(p);
        paths(p).iter().all(|x| x.cwnd >= 400_000)
    }));

    let (a, b): (TxKey, TxKey) = ((Some(c), PathId(0)), (Some(c), pid));
    let full = |p: &Pair, k: TxKey| {
        p.client.call(p.now, move |t, _| t.queued_bytes(k)) > QUEUE_QUOTA - 1500
    };
    let refused = |p: &Pair| p.client.call(p.now, |t, _| t.blocked_conns()) == vec![c];
    p.client.blocked.extend([a, b]);
    assert!(
        p.pump_until(MS, 20_000, |p| {
            x.step(p);
            full(p, a) && full(p, b)
        }),
        "both queues never reached their quota"
    );
    assert!(refused(&p));
    let resume_pending = |p: &Pair| p.client.call(p.now, |t, _| t.resume_pending());
    assert!(!resume_pending(&p));

    // Only path A's socket drains; B stays blocked and full. No time passes.
    p.client.blocked.remove(&a);
    let now = p.now;
    let out = p.client.pump_out(now);
    assert!(!out.is_empty());
    assert!(out.iter().all(|d| d.key == a));
    assert_eq!(p.now, now);
    assert!(resume_pending(&p), "resumable at once, without a timer");
    assert!(full(&p, b));

    for d in out {
        p.server.deliver(p.now, d.to, d.from, d.data);
    }
    p.client.blocked.clear();
    x.finish(&mut p, MS, 60_000);
}
