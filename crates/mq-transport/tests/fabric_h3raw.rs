//! adoption spec §3 "Raw-H3 backend": ALPN `h3` over raw xquic streams.
mod common;

use common::lockstep::{self, Peer, cfg, server_role};
use common::pair::{MS, Opts, Pair, new_streams, read_all, recv, send};
use mq_transport_api::{
    ConnProto, Error, Event, H3Backend, Role, StreamError, StreamId, StreamKind, Time,
    TransportConfig, TransportOps,
};

fn raw_h3_cfg(role: Role) -> TransportConfig {
    TransportConfig {
        h3: true,
        h3_backend: H3Backend::Raw,
        qlog: None,
        ..cfg(role)
    }
}

fn h3raw_opts() -> Opts {
    Opts {
        server: raw_h3_cfg(server_role()),
        client: raw_h3_cfg(Role::Client),
        proto: ConnProto::H3,
        ..Opts::default()
    }
}

#[test]
fn raw_h3_conn_establishes() {
    let p = Pair::with(h3raw_opts());
    assert!(
        p.sev.contains(&Event::NewConn(p.srv_conn, ConnProto::H3)),
        "{:?}",
        p.sev
    );
}

#[test]
fn raw_h3_bidi_echo() {
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    let data: Vec<u8> = (0..64 * 1024).map(|i| (i * 31 + 7) as u8).collect();
    let (mut off, mut fin_sent) = (0, false);
    let mut ss = None;
    let (mut rx, mut fin) = (Vec::new(), false);
    let done = p.pump_until(MS, 5_000, |p| {
        let now = p.now;
        if !fin_sent && let Ok(n) = send(&p.client, now, cs, data[off..].to_vec(), true) {
            off += n;
            fin_sent = off == data.len();
        }
        p.exchange();
        if ss.is_none() {
            ss = new_streams(&p.sev).first().copied();
        }
        if let Some((s, _)) = ss
            && !fin
        {
            let (b, f) = read_all(&p.server, now, s).expect("server read");
            rx.extend(b);
            fin = f;
        }
        fin
    });
    assert!(done, "no FIN after {} bytes", rx.len());
    assert_eq!(rx, data);
    let (_, info) = ss.unwrap();
    assert_eq!(info.kind, StreamKind::Bidi);
    assert_eq!(info.quic_id, 0);
    assert_eq!(info.conn, p.srv_conn);
}

#[test]
fn raw_h3_rejects_open_h3_request() {
    let p = Pair::with(h3raw_opts());
    let c = p.conn;
    let r = p
        .client
        .call(p.now, move |t, now| t.open_h3_request(now, c));
    assert_eq!(r.err(), Some(Error::Other));
}

#[test]
fn raw_alpn_alongside_raw_h3() {
    let p = Pair::with(Opts {
        client: cfg(Role::Client),
        proto: ConnProto::Raw,
        ..h3raw_opts()
    });
    assert!(
        p.sev.contains(&Event::NewConn(p.srv_conn, ConnProto::Raw)),
        "{:?}",
        p.sev
    );
}

/// H3_REQUEST_CANCELLED: the code of xquic's automatic reply to STOP_SENDING.
const CANCELLED: u64 = 0x10c;

fn reset_send(p: &Peer, now: Time, s: StreamId, code: u64) {
    p.call(now, move |t, now| t.stream_reset_send(now, s, code))
}

fn stop_sending(p: &Peer, now: Time, s: StreamId, code: u64) {
    p.call(now, move |t, now| t.stream_stop_sending(now, s, code))
}

/// The `StreamPeerReset` / `StreamStopSending` events in `ev`.
fn aborts(ev: &[Event]) -> Vec<Event> {
    ev.iter()
        .filter(|e| matches!(e, Event::StreamPeerReset(..) | Event::StreamStopSending(..)))
        .cloned()
        .collect()
}

/// Opens a client stream and sends `n` bytes without FIN: (client id, server id).
fn open_with_data(p: &mut Pair, n: usize) -> (StreamId, StreamId) {
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, vec![0x42; n], false), Ok(n));
    p.exchange();
    let (ss, _) = *new_streams(&p.sev).last().expect("server NewStream");
    (cs, ss)
}

/// Pumps (at most 2 s virtual) until both sides report `StreamClosed`.
fn pump_closed(p: &mut Pair, cs: StreamId, ss: StreamId) -> bool {
    p.pump_until(MS, 2_000, |p| {
        p.cev.contains(&Event::StreamClosed(cs)) && p.sev.contains(&Event::StreamClosed(ss))
    })
}

/// Pumps until `reader` has read `s` to FIN; the bytes read.
fn read_to_fin(p: &mut Pair, client: bool, s: StreamId) -> Vec<u8> {
    let mut rx = Vec::new();
    let done = p.pump_until(MS, 2_000, |p| {
        let peer = if client { &p.client } else { &p.server };
        let (b, fin) = read_all(peer, p.now, s).expect("read");
        rx.extend(b);
        fin
    });
    assert!(done, "no FIN after {} bytes", rx.len());
    rx
}

#[test]
fn reset_send_keeps_receiving() {
    let mut p = Pair::with(h3raw_opts());
    let (cs, ss) = open_with_data(&mut p, 4 * 1024);
    reset_send(&p.client, p.now, cs, CANCELLED);
    p.exchange();
    assert!(
        p.sev.contains(&Event::StreamPeerReset(ss, CANCELLED)),
        "{:?}",
        p.sev
    );
    assert_eq!(
        recv(&p.server, p.now, ss, 64 * 1024),
        Err(StreamError::Reset)
    );

    let data: Vec<u8> = (0..16 * 1024).map(|i| (i * 13 + 1) as u8).collect();
    assert_eq!(
        send(&p.server, p.now, ss, data.clone(), true),
        Ok(data.len())
    );
    assert_eq!(read_to_fin(&mut p, true, cs), data);
    assert!(pump_closed(&mut p, cs, ss), "{:?} / {:?}", p.cev, p.sev);
    // no_reset_echo: the server's send side was untouched, so nothing came back.
    assert_eq!(aborts(&p.cev), vec![]);
}

#[test]
fn stop_sending_keeps_receiving() {
    let mut p = Pair::with(h3raw_opts());
    let (cs, ss) = open_with_data(&mut p, 1024);
    stop_sending(&p.client, p.now, cs, 0x10b);
    p.exchange();
    assert!(
        p.sev.contains(&Event::StreamStopSending(ss, 0x10b)),
        "{:?}",
        p.sev
    );
    assert!(
        p.cev.contains(&Event::StreamPeerReset(cs, CANCELLED)),
        "{:?}",
        p.cev
    );
    assert_eq!(recv(&p.client, p.now, cs, 1024), Err(StreamError::Reset));

    let data: Vec<u8> = (0..16 * 1024).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(
        send(&p.client, p.now, cs, data.clone(), true),
        Ok(data.len())
    );
    let rx = read_to_fin(&mut p, false, ss);
    assert_eq!(rx.len(), 1024 + data.len());
    assert_eq!(&rx[1024..], &data[..]);
    assert!(pump_closed(&mut p, cs, ss), "{:?} / {:?}", p.cev, p.sev);
}

/// Review Focus 2: a RESET_STREAM as the first frame creates the stream passively.
#[test]
fn peer_reset_on_unseen_stream() {
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    reset_send(&p.client, p.now, cs, CANCELLED);
    p.exchange();
    let (ss, _) = new_streams(&p.sev)[0];
    let created = p
        .sev
        .iter()
        .position(|e| matches!(e, Event::NewStream(_, s, _) if *s == ss));
    let reset = p
        .sev
        .iter()
        .position(|e| *e == Event::StreamPeerReset(ss, CANCELLED));
    assert!(
        matches!((created, reset), (Some(c), Some(r)) if c < r),
        "{:?}",
        p.sev
    );
}

/// Review Focus 3: a 62-bit code arrives intact on both notifications.
#[test]
fn max_code_round_trip() {
    const MAX: u64 = (1 << 62) - 1;
    let mut p = Pair::with(h3raw_opts());
    let (a, sa) = open_with_data(&mut p, 1);
    let (b, sb) = open_with_data(&mut p, 1);
    reset_send(&p.client, p.now, a, MAX);
    stop_sending(&p.client, p.now, b, MAX);
    p.exchange();
    assert!(
        p.sev.contains(&Event::StreamPeerReset(sa, MAX)),
        "{:?}",
        p.sev
    );
    assert!(
        p.sev.contains(&Event::StreamStopSending(sb, MAX)),
        "{:?}",
        p.sev
    );
}

/// Review Focus 5: a RESET_STREAM after the FIN was read.
#[test]
fn late_reset_after_fin_read() {
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, vec![1; 1024], true), Ok(1024));
    p.exchange();
    let (ss, _) = new_streams(&p.sev)[0];
    assert_eq!(
        read_all(&p.server, p.now, ss).map(|(b, f)| (b.len(), f)),
        Ok((1024, true))
    );

    reset_send(&p.client, p.now, cs, CANCELLED);
    p.pump_until(MS, 200, |_| false);
    let n = p
        .sev
        .iter()
        .filter(|e| matches!(e, Event::StreamPeerReset(s, _) if *s == ss))
        .count();
    // Virtual time is deterministic: the FIN's ACK has not reached the client yet, so the
    // RESET_STREAM is really sent (Review Focus 5); exactly one event.
    assert_eq!(n, 1, "{:?}", p.sev);
    let r = recv(&p.server, p.now, ss, 1024);
    assert!(
        matches!(
            r,
            Ok((ref b, true)) if b.is_empty()
        ) || matches!(r, Err(StreamError::Reset | StreamError::Stale)),
        "{r:?}"
    );
    assert_eq!(aborts(&p.cev), vec![], "no echo");
}

/// adoption spec §3 table: a `StreamReadable` queued before the reset pops first, and the
/// read on it already fails while `StreamPeerReset` is still queued (§4.4 "reset, code
/// pending").
#[test]
fn peer_abort_preserves_earlier_readable_order() {
    let p = Pair::with(h3raw_opts());
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, vec![1; 1024], false), Ok(1024));
    lockstep::exchange(p.now, &p.client, &p.server); // the server's events stay queued
    reset_send(&p.client, p.now, cs, CANCELLED);
    lockstep::exchange(p.now, &p.client, &p.server);
    let (evs, read) = p.server.call(p.now, |t, now| {
        let (mut evs, mut read) = (Vec::new(), None);
        while let Some(e) = t.poll_event() {
            if let Event::StreamReadable(s) = e
                && read.is_none()
            {
                read = Some(t.stream_recv(now, s, &mut [0u8; 4096]));
            }
            evs.push(e);
        }
        (evs, read)
    });
    let (ss, _) = new_streams(&evs)[0];
    let readable = evs.iter().position(|e| *e == Event::StreamReadable(ss));
    let reset = evs
        .iter()
        .position(|e| *e == Event::StreamPeerReset(ss, CANCELLED));
    assert!(
        matches!((readable, reset), (Some(a), Some(b)) if a < b),
        "{evs:?}"
    );
    assert_eq!(read, Some(Err(StreamError::Reset)));
}

#[test]
fn peer_abort_precedes_new_readable() {
    let mut p = Pair::with(h3raw_opts());
    let (cs, ss) = open_with_data(&mut p, 1024);
    let mark = p.sev.len();
    reset_send(&p.client, p.now, cs, CANCELLED);
    p.exchange();
    let after = &p.sev[mark..];
    let reset = after
        .iter()
        .position(|e| *e == Event::StreamPeerReset(ss, CANCELLED));
    let readable = after.iter().position(|e| *e == Event::StreamReadable(ss));
    assert!(
        matches!((reset, readable), (Some(a), Some(b)) if a < b),
        "{after:?}"
    );
}

/// Review Focus 1: the op's connection logic closes another stream inside the call.
#[test]
fn op_survives_close_inside_the_call() {
    let mut p = Pair::with(h3raw_opts());
    let a = p.open();
    assert_eq!(send(&p.client, p.now, a, b"req".to_vec(), true), Ok(3));
    p.exchange();
    let (sa, _) = new_streams(&p.sev)[0];
    assert_eq!(read_all(&p.server, p.now, sa), Ok((b"req".to_vec(), true)));
    assert_eq!(send(&p.server, p.now, sa, b"resp".to_vec(), true), Ok(4));
    p.exchange();
    assert_eq!(read_all(&p.client, p.now, a), Ok((b"resp".to_vec(), true)));
    let b = p.open();
    assert_eq!(send(&p.client, p.now, b, vec![1], false), Ok(1));
    // Delayed ACKs (25 ms) land; the close timer (3 × PTO) has not fired yet.
    for _ in 0..30 {
        p.tick(MS);
    }
    assert!(!p.cev.contains(&Event::StreamClosed(a)), "{:?}", p.cev);
    assert!(p.client.call(p.now, move |t, _| t.stream_info(a)).is_ok());

    // Past 3 × PTO without driving: the op itself runs the expired timer.
    let late = p.now + std::time::Duration::from_millis(500);
    let (evs, info_a, info_b, recv_a) = p.client.call(late, move |t, now| {
        t.stream_reset_send(now, b, CANCELLED);
        let evs: Vec<_> = std::iter::from_fn(|| t.poll_event()).collect();
        let info_a = t.stream_info(a);
        t.stream_reset_send(now, a, CANCELLED);
        t.stream_stop_sending(now, a, CANCELLED);
        let recv_a = t.stream_recv(now, a, &mut [0u8; 16]);
        (evs, info_a, t.stream_info(b), recv_a)
    });
    assert!(evs.contains(&Event::StreamClosed(a)), "{evs:?}");
    assert_eq!(info_a, Err(Error::Stale));
    assert_eq!(recv_a, Err(StreamError::Stale));
    assert!(info_b.is_ok(), "B lives on");
}

/// adoption spec §7 item 3: receive credit is returned only as the receiver reads.
#[test]
fn credit_follows_reads() {
    const OFFER: usize = 24 << 20;
    const WINDOW: usize = 16 << 20; // XQC_MAX_RECV_WINDOW
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    let mut accepted = 0usize;
    let offer = |p: &Pair, accepted: &mut usize| {
        while *accepted < OFFER {
            let n = (OFFER - *accepted).min(256 * 1024);
            match send(&p.client, p.now, cs, vec![0x5a; n], false) {
                Ok(k) => {
                    *accepted += k;
                    if k < n {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    };
    for _ in 0..500 {
        offer(&p, &mut accepted);
        p.tick(MS);
    }
    let plateau = accepted;
    assert!(plateau > 0 && plateau <= WINDOW, "{plateau}");
    for _ in 0..500 {
        offer(&p, &mut accepted);
        p.tick(MS);
    }
    assert_eq!(accepted, plateau, "no credit without reads");

    let (ss, _) = new_streams(&p.sev)[0];
    let mut read = 0usize;
    let grew = p.pump_until(MS, 2_000, |p| {
        while read < 9 << 20 {
            match recv(&p.server, p.now, ss, (9 << 20) - read) {
                Ok((b, _)) if !b.is_empty() => read += b.len(),
                _ => break,
            }
        }
        offer(p, &mut accepted);
        read >= 9 << 20 && accepted > plateau
    });
    assert!(grew, "plateau {plateau}, read {read}, accepted {accepted}");
}

/// Raw conns keep xquic's reset echo and never report peer aborts (adoption spec §3).
#[test]
fn raw_conn_keeps_reset_echo() {
    let mut p = Pair::with(Opts {
        client: cfg(Role::Client),
        proto: ConnProto::Raw,
        ..h3raw_opts()
    });
    let (cs, ss) = open_with_data(&mut p, 1024);
    reset_send(&p.client, p.now, cs, CANCELLED);
    p.exchange();
    assert_eq!(recv(&p.server, p.now, ss, 4096), Err(StreamError::Reset));
    assert_eq!(recv(&p.client, p.now, cs, 4096), Err(StreamError::Reset));
    assert_eq!(aborts(&p.sev), vec![]);
    assert_eq!(aborts(&p.cev), vec![]);
}
