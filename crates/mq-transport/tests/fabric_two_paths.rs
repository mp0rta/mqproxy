//! Ports `test_two_paths` and the address assertions of `test_path_bind` (spec §8.3), plus
//! spec §4.2 "MpReady may repeat".
mod common;

use common::pair::{
    ACTIVE, MS, Opts, Pair, add_path, cli_addr, mp_ready_count, new_streams, path_state, read_all,
    send, srv_addr,
};
use mq_transport_api::{PathError, PathId, TransportOps};

/// Echoes `n` bytes over a new stream; returns the echoed bytes.
fn echo(p: &mut Pair, n: usize) -> Vec<u8> {
    let data: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, data.clone(), true), Ok(n));
    let seen = p.sev.len();
    let mut ss = None;
    let (mut srx, mut sfin, mut back, mut cfin) = (Vec::new(), false, Vec::new(), false);
    assert!(p.pump_until(MS, 5000, |p| {
        if ss.is_none() {
            ss = new_streams(&p.sev[seen..]).first().map(|x| x.0);
        }
        if let (Some(s), false) = (ss, sfin) {
            let (b, f) = read_all(&p.server, p.now, s).unwrap();
            srx.extend(b);
            sfin = f;
            if f {
                assert_eq!(send(&p.server, p.now, s, srx.clone(), true), Ok(srx.len()));
            }
        }
        if !cfin {
            let (b, f) = read_all(&p.client, p.now, cs).unwrap();
            back.extend(b);
            cfin = f;
        }
        cfin
    }));
    assert!(back == data);
    back
}

#[test]
fn second_path_comes_up_and_carries_traffic() {
    let mut p = Pair::with(Opts {
        paths: 2,
        ..Opts::default()
    });
    assert!(p.pump_until(MS, 2000, |p| mp_ready_count(p) > 0));
    let pid = add_path(&p).expect("add_path");
    assert_ne!(pid, PathId(0), "distinct from the primary path");
    p.record = true;
    assert!(
        p.pump_until(MS, 5000, |p| path_state(p, pid.0) == Some(ACTIVE)),
        "path {} never became active",
        pid.0
    );
    echo(&mut p, 4096);

    // A larger transfer; both paths report counters and together moved the bytes.
    echo(&mut p, 512 * 1024);
    let c = p.conn;
    let st = p.client.call(p.now, move |t, _| t.conn_stats(c)).unwrap();
    let ids: Vec<u64> = st.paths.iter().map(|x| x.id).collect();
    assert!(ids.contains(&0) && ids.contains(&pid.0), "{ids:?}");
    let sent: u64 = st.paths.iter().map(|x| x.sent_bytes).sum();
    let recv: u64 = st.paths.iter().map(|x| x.recv_bytes).sum();
    assert!(
        sent >= 256 * 1024 && recv >= 256 * 1024,
        "sent {sent} recv {recv}"
    );

    // Addresses (test_path_bind): each path keeps its own 4-tuple on both sides.
    let srv_key_path1 = |d: &&common::lockstep::Datagram| d.key.1 == pid && d.from == srv_addr();
    assert!(
        p.wire.iter().any(|d| d.from == cli_addr(1)),
        "nothing sent from path 1's address"
    );
    assert!(
        p.wire.iter().any(|d| srv_key_path1(&d)),
        "server never used path 1"
    );
    for d in &p.wire {
        if d.from == srv_addr() {
            let want = if d.key.1 == pid {
                cli_addr(1)
            } else {
                cli_addr(0)
            };
            assert_eq!(d.to, want, "server datagram on path {:?}", d.key.1);
        } else {
            assert_eq!(d.to, srv_addr());
            assert_eq!(d.from, cli_addr(d.key.1.0 as usize));
        }
    }
}

/// spec §4.2: after `add_path` fails with `NoPathId`, xquic raises `MpReady` again once an id
/// is available, and `add_path` then succeeds.
#[test]
fn mp_ready_fires_again_after_no_path_id() {
    let mut p = Pair::with(Opts {
        paths: 16,
        ..Opts::default()
    });
    assert!(p.pump_until(MS, 2000, |p| mp_ready_count(p) > 0));
    let mut added = Vec::new();
    let err = loop {
        match add_path(&p) {
            Ok(id) => added.push(id),
            Err(e) => break e,
        }
        assert!(added.len() < 15, "never ran out of path ids");
    };
    assert_eq!(err, PathError::NoPathId, "after {added:?}");
    let before = mp_ready_count(&p);
    assert!(
        p.pump_until(MS, 5000, |p| mp_ready_count(p) > before),
        "no MpReady after NoPathId (added {added:?})"
    );
    let id = add_path(&p).expect("add_path after the repeated MpReady");
    assert!(!added.contains(&id));
}
