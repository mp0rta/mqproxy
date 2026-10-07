// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §4.2 stream semantics over the lockstep fabric.
mod common;

use common::pair::{MS, Pair, new_streams, read_all, recv, send, stream_events};
use mq_transport_api::{Event, StreamKind, TransportOps};

const MIB: usize = 1024 * 1024;
const KIB: usize = 1024;

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

/// Client sends 1 MiB + FIN; the server echoes it back + FIN. On both readers the FIN comes
/// with (or after) the last byte, never earlier.
#[test]
fn echo_1mib_fin_last() {
    let mut p = Pair::new();
    let data = pattern(MIB);
    let cs = p.open();
    let (mut c_off, mut c_fin_sent) = (0usize, false);
    let mut ss = None;
    let (mut srv_rx, mut srv_fin) = (Vec::new(), false);
    let (mut e_off, mut e_fin_sent) = (0usize, false);
    let (mut cli_rx, mut cli_fin) = (Vec::new(), false);

    let done = p.pump_until(MS, 20_000, |p| {
        let now = p.now;
        if !c_fin_sent {
            let chunk = data[c_off..].to_vec();
            if let Ok(n) = send(&p.client, now, cs, chunk, true) {
                c_off += n;
                c_fin_sent = c_off == data.len();
            }
        }
        p.exchange();
        if ss.is_none() {
            ss = new_streams(&p.sev).first().map(|(s, _)| *s);
        }
        if let Some(s) = ss {
            if !srv_fin {
                let (b, fin) = read_all(&p.server, now, s).expect("server read");
                srv_rx.extend(b);
                if fin {
                    assert_eq!(srv_rx.len(), MIB, "server: FIN before the last byte");
                }
                srv_fin = fin;
            }
            if !e_fin_sent && e_off < srv_rx.len() + usize::from(srv_fin) {
                let chunk = srv_rx[e_off..].to_vec();
                if let Ok(n) = send(&p.server, now, s, chunk, srv_fin) {
                    e_off += n;
                    e_fin_sent = srv_fin && e_off == srv_rx.len();
                }
            }
        }
        p.exchange();
        if !cli_fin {
            let (b, fin) = read_all(&p.client, now, cs).expect("client read");
            cli_rx.extend(b);
            if fin {
                assert_eq!(cli_rx.len(), MIB, "client: FIN before the last byte");
            }
            cli_fin = fin;
        }
        cli_fin
    });
    assert!(
        done,
        "echo did not finish: client got {} bytes",
        cli_rx.len()
    );
    assert!(srv_rx == data, "server bytes differ");
    assert!(cli_rx == data, "echoed bytes differ");
    // Nothing after FIN.
    assert_eq!(recv(&p.client, p.now, cs, 64), Ok((vec![], true)));
}

/// spec §4.2: `Ok(n)` with `n < len` never commits the FIN.
#[test]
fn partial_send_with_fin_does_not_commit_fin() {
    let mut p = Pair::new();
    let cs = p.open();
    let chunk = pattern(64 * KIB);
    // The peer never reads: the 16 MiB stream window is all the client may send. xquic's
    // flow-control check is per packet, so the last write must leave a margin of many
    // packets (32 KiB) to be partial rather than refused outright.
    let full = 16 * MIB - 32 * KIB;
    let mut sent = 0usize;
    while sent < full {
        let len = (full - sent).min(64 * KIB);
        let n = send(&p.client, p.now, cs, chunk[..len].to_vec(), false);
        assert_eq!(n, Ok(len), "write at offset {sent} not fully accepted");
        sent += len;
        p.tick(MS);
    }
    let n = send(&p.client, p.now, cs, chunk.clone(), true).expect("partial write");
    assert!(n > 0 && n < 64 * KIB, "expected a partial write, got {n}");
    sent += n;
    p.tick(MS);

    // The server reads everything: no FIN yet.
    let ss = new_streams(&p.sev)[0].0;
    let mut got = 0usize;
    assert!(p.pump_until(MS, 10_000, |p| {
        let (b, fin) = read_all(&p.server, p.now, ss).expect("server read");
        assert!(!fin, "FIN seen although the FIN write was partial");
        got += b.len();
        got == sent
    }));
    // The remainder, with FIN, in a later write.
    let rest = chunk[n..].to_vec();
    let rest_len = rest.len();
    assert!(p.pump_until(MS, 1000, |p| {
        send(&p.client, p.now, cs, rest.clone(), true) == Ok(rest_len)
    }));
    let mut fin = false;
    assert!(p.pump_until(MS, 1000, |p| {
        let (b, f) = read_all(&p.server, p.now, ss).expect("server read");
        got += b.len();
        fin = f;
        f
    }));
    assert!(fin);
    assert_eq!(got, full + 64 * KIB);
}

#[test]
fn recv_after_fin_returns_zero_true() {
    let mut p = Pair::new();
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"abc".to_vec(), true), Ok(3));
    p.exchange();
    let ss = new_streams(&p.sev)[0].0;
    assert_eq!(recv(&p.server, p.now, ss, 64), Ok((b"abc".to_vec(), true)));
    for cap in [64, 1, 0] {
        assert_eq!(
            recv(&p.server, p.now, ss, cap),
            Ok((vec![], true)),
            "cap {cap}"
        );
    }
}

/// spec §4.2: a stream that closes before its reader saw FIN (here: the connection closes)
/// is reported with `StreamClosed` only — no FIN, no other event.
#[test]
fn close_before_fin_gives_only_stream_closed() {
    let mut p = Pair::new();
    let cs = p.open();
    assert_eq!(
        send(&p.client, p.now, cs, b"partial".to_vec(), false),
        Ok(7)
    );
    p.exchange();
    let ss = new_streams(&p.sev)[0].0;
    assert_eq!(
        recv(&p.server, p.now, ss, 64),
        Ok((b"partial".to_vec(), false))
    );
    let seen = p.sev.len();

    let c = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, c));
    assert!(p.pump_until(10 * MS, 1000, |p| p.server_closed().is_some()));
    assert_eq!(
        stream_events(&p.sev[seen..], ss),
        vec![Event::StreamClosed(ss)]
    );
    assert_eq!(
        p.server.call(p.now, move |t, _| t.stream_info(ss)),
        Err(mq_transport_api::Error::Stale)
    );
    // The local side of the closed connection reports its stream the same way.
    assert!(stream_events(&p.cev, cs).contains(&Event::StreamClosed(cs)));
}

#[test]
fn new_stream_and_stream_info_carry_quic_id_and_kind() {
    let mut p = Pair::new();
    let cs: Vec<_> = (0..3).map(|_| p.open()).collect();
    for s in &cs {
        assert_eq!(send(&p.client, p.now, *s, b"x".to_vec(), false), Ok(1));
    }
    p.exchange();
    let news = new_streams(&p.sev);
    assert_eq!(news.len(), 3, "{:?}", p.sev);
    for (k, (ss, info)) in news.iter().enumerate() {
        let want = 4 * k as u64; // client-initiated bidi ids 0, 4, 8
        assert_eq!(info.quic_id, want);
        assert_eq!(info.kind, StreamKind::Bidi);
        assert_eq!(info.conn, p.srv_conn);
        let s = *ss;
        assert_eq!(
            p.server.call(p.now, move |t, _| t.stream_info(s)),
            Ok(*info)
        );
        let c = cs[k];
        let ci = p.client.call(p.now, move |t, _| t.stream_info(c)).unwrap();
        assert_eq!(
            (ci.conn, ci.quic_id, ci.kind),
            (p.conn, want, StreamKind::Bidi)
        );
    }
    // The NewStream event carries the same connection id.
    assert!(p.sev.iter().all(|e| match e {
        Event::NewStream(c, _, i) => *c == p.srv_conn && i.conn == *c,
        _ => true,
    }));
}
