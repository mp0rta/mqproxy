//! spec §4.4, §8.4 "Transmit queue full, then drained".
mod common;

use common::pair::{MS, Opts, Pair};
use common::xfer::Xfer;
use mq_transport_api::{CongestionControl, PathId, TransportOps};

/// spec §4.4 per-queue quota.
const QUEUE_QUOTA: usize = 1024 * 1024;

#[test]
fn txq_full_then_drained_resumes() {
    // Cubic: in the fabric BBR's window settles below one queue quota; cubic's keeps growing.
    let mut o = Opts::default();
    o.client.cc = CongestionControl::Cubic;
    let mut p = Pair::with(o);
    let key = (Some(p.conn), PathId(0));
    let mut x = Xfer::start(&p, 64 * 1024 * 1024);
    // Grow the congestion window past the queue quota first, or the window, not the queue,
    // stops the sender.
    assert!(p.pump_until(MS, 20_000, |p| {
        x.step(p);
        x.got.len() >= 4 * 1024 * 1024
    }));

    // The path-0 socket stops accepting: send until the queue refuses.
    p.client.blocked.insert(key);
    let refused = |p: &Pair| p.client.call(p.now, |t, _| t.blocked_conns()) == vec![p.conn];
    assert!(p.pump_until(MS, 20_000, |p| {
        x.step(p);
        refused(p)
    }));
    let resume_pending = |p: &Pair| p.client.call(p.now, |t, _| t.resume_pending());
    assert!(!resume_pending(&p));
    let queued = p.client.call(p.now, move |t, _| t.queued_bytes(key));
    assert!(
        queued > QUEUE_QUOTA - 1500 && queued <= QUEUE_QUOTA,
        "{queued}"
    );

    // The socket becomes writable: one commit, at the same `now`.
    p.client.blocked.clear();
    let out = p.client.pump_out(p.now);
    assert!(!out.is_empty());
    assert!(
        resume_pending(&p),
        "a commit below the low mark makes it resumable"
    );
    assert!(p.client.call(p.now, |t, _| t.blocked_conns()).is_empty());
    for d in out {
        p.server.deliver(p.now, d.to, d.from, d.data);
    }
    p.client.drive(p.now);
    assert!(!resume_pending(&p), "drive resumed it");

    // The transfer completes; every byte exactly once, in order.
    x.finish(&mut p, MS, 60_000);
}
