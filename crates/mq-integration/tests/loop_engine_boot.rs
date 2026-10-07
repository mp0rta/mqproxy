// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Engine boot on the loopback harness (spec §8.1 "Loopback"): both sides
//! boot (real xquic engine, production driver, each on its own thread) on
//! `127.0.0.1:0`, the client completes a handshake with the server, and each
//! driver is stopped through its `ShutdownHandle` with exit status 0.

use mq_integration::loopback::LoopbackPair;
use mq_runtime::Shard;
use mq_runtime::testing::{RecordHandle, Recorded, RecordingApp};
use mq_transport::Transport;
use mq_transport_api::{
    CongestionControl, ConnConfig, ConnProto, Event, Role, Scheduler, TransportConfig,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);

fn cfg(role: Role) -> TransportConfig {
    TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns: 0,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
        h3: false,
        qlog: None,
    }
}

fn cert(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs")).join(name)
}

/// A `RecordingApp` that exits 0 on the shutdown signal.
fn recording() -> (RecordingApp, RecordHandle) {
    let (app, rec) = RecordingApp::new();
    rec.on(|r, cx| {
        if *r == Recorded::Shutdown {
            cx.request_exit(0);
        }
    });
    (app, rec)
}

fn wait_for(rec: &RecordHandle, pred: impl Fn(&Recorded) -> bool) -> bool {
    let end = Instant::now() + T;
    while Instant::now() < end {
        if rec.records().iter().any(&pred) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    false
}

#[test]
fn loop_engine_boot() {
    let pair = LoopbackPair::spawn(
        (
            std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::Ipv4Addr::LOCALHOST.into(),
        ),
        Vec::new(),
        |local| {
            let t = Transport::new(cfg(Role::Server {
                cert: cert("test.crt"),
                key: cert("test.key"),
            }))
            .expect("server engine boots");
            let (app, rec) = recording();
            (Shard::new(t, app, local, 1), rec)
        },
        |local, server| {
            let t = Transport::new(cfg(Role::Client)).expect("client engine boots");
            let (app, rec) = recording();
            rec.on(move |r, cx| {
                if *r == Recorded::Start {
                    let peer = ConnConfig {
                        peer: server,
                        sni: "mqproxy",
                        idle_timeout: None,
                        proto: ConnProto::Raw,
                    };
                    cx.connect(&peer).expect("connect");
                }
            });
            (Shard::new(t, app, local, 2), rec)
        },
    );
    // Both primary UDP paths are bound on loopback with a kernel-chosen port.
    for a in [pair.server.udp_addr, pair.client.udp_addr] {
        assert!(a.ip().is_loopback() && a.port() != 0, "{a}");
    }

    let est = |r: &Recorded| matches!(r, Recorded::TransportEvent(Event::ConnEstablished(_)));
    let new = |r: &Recorded| matches!(r, Recorded::TransportEvent(Event::NewConn(..)));
    assert!(
        wait_for(&pair.client.handle, est),
        "client: {:?}",
        pair.client.handle.records()
    );
    assert!(
        wait_for(&pair.server.handle, new),
        "server: {:?}",
        pair.server.handle.records()
    );
    assert!(pair.server.stats.iterations() > 0 && pair.client.stats.iterations() > 0);

    // Each side stopped through its own handle.
    assert_eq!(pair.join_both(), (0, 0));
}
