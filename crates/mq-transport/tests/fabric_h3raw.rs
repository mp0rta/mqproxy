//! adoption spec §3 "Raw-H3 backend": ALPN `h3` over raw xquic streams.
mod common;

use common::initial::{client_hello_fragment, initial};
use common::lockstep::{self, Peer, cfg, exchange_many, server_role};
use common::pair::{
    MS, Opts, Pair, T0, cli_addr, conn_cfg, new_streams, read_all, recv, send, srv_addr,
    stream_count,
};
use mq_transport_api::{
    ConnId, ConnProto, ErrType, Error, Event, Role, StreamCloseStats, StreamError, StreamId,
    StreamKind, Time, TransportConfig, TransportOps,
};

use std::net::SocketAddr;
use std::time::Duration;

fn raw_h3_cfg(role: Role) -> TransportConfig {
    TransportConfig {
        h3: true,
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
    assert_eq!(r.err(), Some(Error::Role));
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
    // Retirement contract: the reset-probe read above is terminal; a bidi stream closes once
    // the server also ends its own send side.
    assert_eq!(send(&p.server, p.now, ss, vec![], true), Ok(0));
    assert!(
        p.pump_until(MS, 2_000, |p| p.sev.contains(&Event::StreamClosed(ss))),
        "{:?}",
        p.sev
    );
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

fn open_uni(p: &Peer, now: Time, c: ConnId) -> Result<StreamId, Error> {
    p.call(now, move |t, now| t.open_uni(now, c))
}

fn info(p: &Peer, now: Time, s: StreamId) -> mq_transport_api::StreamInfo {
    p.call(now, move |t, _| t.stream_info(s))
        .expect("stream_info")
}

#[test]
fn open_uni_both_roles() {
    let mut p = Pair::with(h3raw_opts());
    let (cc, sc) = (p.conn, p.srv_conn);
    for (client, quic_id) in [(true, 2u64), (false, 3u64)] {
        let local = if client { &p.client } else { &p.server };
        let s = open_uni(local, p.now, if client { cc } else { sc }).expect("open_uni");
        assert_eq!(info(local, p.now, s).kind, StreamKind::Uni);
        assert_eq!(info(local, p.now, s).quic_id, quic_id);
        let data = vec![0x5a; 1024];
        assert_eq!(send(local, p.now, s, data.clone(), true), Ok(1024));
        p.exchange();
        let evs = if client { &p.sev } else { &p.cev };
        let (rs, ri) = *new_streams(evs)
            .iter()
            .find(|(_, i)| i.quic_id == quic_id)
            .expect("peer NewStream");
        assert_eq!((ri.kind, ri.quic_id), (StreamKind::Uni, quic_id));
        assert_eq!(read_to_fin(&mut p, !client, rs), data);
    }
    let all_closed = p.pump_until(MS, 2_000, |p| {
        stream_count(&p.client, p.conn) == 0 && stream_count(&p.server, p.srv_conn) == 0
    });
    assert!(all_closed, "slots not retired");
}

#[test]
fn open_uni_credit_exhausted() {
    let p = Pair::with(h3raw_opts());
    for i in 0..1024 {
        open_uni(&p.client, p.now, p.conn).unwrap_or_else(|e| panic!("open {i}: {e:?}"));
    }
    assert_eq!(stream_count(&p.client, p.conn), 1024);
    assert_eq!(open_uni(&p.client, p.now, p.conn), Err(Error::Other));
    assert_eq!(stream_count(&p.client, p.conn), 1024);
}

fn close_conn_with(p: &Peer, now: Time, c: ConnId, code: u64) {
    p.call(now, move |t, now| t.close_conn_with(now, c, code))
}

/// The stats for `s`, asserting they come directly before its `StreamClosed`.
fn close_stats(ev: &[Event], s: StreamId) -> StreamCloseStats {
    let i = ev
        .iter()
        .position(|e| *e == Event::StreamClosed(s))
        .expect("StreamClosed");
    match &ev[i.checked_sub(1).expect("event before StreamClosed")] {
        Event::StreamCloseStats(id, st) if *id == s => (**st).clone(),
        e => panic!("expected stats before StreamClosed, got {e:?}"),
    }
}

#[test]
fn close_conn_with_code() {
    let mut p = Pair::with(h3raw_opts());
    close_conn_with(&p.client, p.now, p.conn, 0x101);
    assert!(p.pump_until(MS, 2_000, |p| p.server_closed().is_some()));
    let r = p.server_closed().unwrap();
    assert_eq!((r.err_type, r.code), (ErrType::Application, 0x101));
    assert!(p.pump_until(MS, 2_000, |p| p.client_closed().is_some()));
    assert_eq!(p.client_closed().unwrap().err_type, ErrType::Unknown);
}

#[test]
fn close_conn_with_stale_is_noop() {
    let mut p = Pair::with(h3raw_opts());
    close_conn_with(&p.client, p.now, p.conn, 0x101);
    assert!(p.pump_until(MS, 2_000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    let n = p.cev.len();
    close_conn_with(&p.client, p.now, p.conn, 0x102);
    p.exchange();
    assert_eq!(p.cev.len(), n, "{:?}", &p.cev[n..]);
}

#[test]
fn close_stats_clean() {
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"req".to_vec(), true), Ok(3));
    p.exchange();
    let (ss, _) = new_streams(&p.sev)[0];
    assert_eq!(read_all(&p.server, p.now, ss), Ok((b"req".to_vec(), true)));
    assert_eq!(send(&p.server, p.now, ss, b"resp".to_vec(), true), Ok(4));
    assert_eq!(read_to_fin(&mut p, true, cs), b"resp");
    assert!(pump_closed(&mut p, cs, ss), "{:?} / {:?}", p.cev, p.sev);
    let st = close_stats(&p.cev, cs);
    assert!(st.fin_send_us > 0, "{st:?}");
    assert!(st.fin_ack_us >= st.fin_send_us, "{st:?}");
    assert_eq!((st.stream_err, st.mp_state), (0, 0));
    assert_eq!(st.close_msg, Some("finished".into()));
    close_stats(&p.sev, ss);
}

#[test]
fn close_stats_reset() {
    let mut p = Pair::with(h3raw_opts());
    let (cs, ss) = open_with_data(&mut p, 4 * 1024);
    reset_send(&p.client, p.now, cs, CANCELLED);
    p.exchange();
    assert_eq!(
        recv(&p.server, p.now, ss, 64 * 1024),
        Err(StreamError::Reset)
    );
    assert_eq!(send(&p.server, p.now, ss, vec![7; 1024], true), Ok(1024));
    read_to_fin(&mut p, true, cs);
    assert!(pump_closed(&mut p, cs, ss), "{:?} / {:?}", p.cev, p.sev);
    let st = close_stats(&p.cev, cs);
    assert_eq!(st.stream_err, CANCELLED as i32, "{st:?}");
    assert_eq!(st.close_msg, Some("local reset".into()));
}

#[test]
fn close_stats_conn_error() {
    let mut p = Pair::with(h3raw_opts());
    let (a, _) = open_with_data(&mut p, 1024);
    let (b, _) = open_with_data(&mut p, 1024);
    close_conn_with(&p.client, p.now, p.conn, 0x101);
    assert!(p.pump_until(MS, 2_000, |p| p.client_closed().is_some()));
    for s in [a, b] {
        let st = close_stats(&p.cev, s);
        assert_eq!(st.stream_err, 0x101, "{st:?}");
        assert_eq!(st.close_msg, Some("conn closed".into()));
        let at = |e: &Event| p.cev.iter().position(|x| x == e).unwrap();
        assert!(
            at(&Event::StreamClosed(s))
                < at(&Event::ConnClosed(p.conn, p.client_closed().unwrap()))
        );
    }
}

#[test]
fn no_close_stats_on_raw_conns() {
    let mut p = Pair::new();
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"x".to_vec(), true), Ok(1));
    p.exchange();
    let (ss, _) = new_streams(&p.sev)[0];
    assert_eq!(read_all(&p.server, p.now, ss), Ok((b"x".to_vec(), true)));
    assert_eq!(send(&p.server, p.now, ss, b"y".to_vec(), true), Ok(1));
    read_to_fin(&mut p, true, cs);
    assert!(pump_closed(&mut p, cs, ss));
    let n = |ev: &[Event]| {
        ev.iter()
            .filter(|e| matches!(e, Event::StreamCloseStats(..)))
            .count()
    };
    assert_eq!((n(&p.cev), n(&p.sev)), (0, 0));
}

fn new_conns(ev: &[Event]) -> Vec<(ConnId, ConnProto)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::NewConn(c, p) => Some((*c, *p)),
            _ => None,
        })
        .collect()
}

#[test]
fn raw_h3_conn_counts_toward_max_conns() {
    let mut scfg = raw_h3_cfg(server_role());
    scfg.max_conns = 1;
    let server = Peer::spawn(scfg, vec![srv_addr()]);
    let mut now = T0;
    let client = |k: usize, now: Time| {
        let c = Peer::spawn(raw_h3_cfg(Role::Client), vec![cli_addr(k)]);
        let mut cc = conn_cfg(None);
        cc.proto = ConnProto::H3;
        let id = c.call(now, move |t, now| t.connect(now, &cc)).unwrap();
        (c, id)
    };
    let run = |peers: &[&Peer], now: &mut Time, steps: usize| {
        for _ in 0..steps {
            *now = *now + MS;
            for p in peers {
                p.drive(*now);
            }
            exchange_many(*now, peers);
        }
    };
    let count = |s: &Peer| s.call(T0, |t, _| (t.conn_count(), t.n_provisional()));

    let (c0, id0) = client(3, now);
    run(&[&c0, &server], &mut now, 5);
    assert!(c0.drain_events().contains(&Event::ConnEstablished(id0)));
    let news = new_conns(&server.drain_events());
    assert!(matches!(news[..], [(_, ConnProto::H3)]), "{news:?}");
    assert_eq!(count(&server), (1, 0));

    // spec §4.7: an unauthenticated H3 conn (no request yet) is evicted by a newcomer.
    let (c1, id1) = client(0, now);
    let (mut sev, mut c0ev) = (Vec::new(), Vec::new());
    for _ in 0..1000 {
        run(&[&c0, &c1, &server], &mut now, 10);
        sev.extend(server.drain_events());
        c0ev.extend(c0.drain_events());
        if c0ev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(c1.drain_events().contains(&Event::ConnEstablished(id1)));
    assert!(
        c0ev.iter()
            .any(|e| matches!(e, Event::ConnClosed(c, r) if *c == id0 && r.code == 0x1002)),
        "{c0ev:?}"
    );
    let news = new_conns(&sev);
    assert!(matches!(news[..], [(_, ConnProto::H3)]), "{news:?}");
    assert_eq!(count(&server), (1, 0));
    let s1 = news[0].0;
    server.call(now, move |t, _| t.mark_conn_authed(s1));

    // The second H3 client is refused at the shared cap, before any slot: s1 is authed.
    let (c2, id2) = client(1, now);
    run(&[&c1, &c2, &server], &mut now, 50);
    assert!(!c2.drain_events().contains(&Event::ConnEstablished(id2)));
    assert!(new_conns(&server.drain_events()).is_empty());
    assert_eq!(count(&server), (1, 0));

    // Closing the first H3 connection releases its unit.
    c1.call(now, move |t, now| t.close_conn(now, id1));
    let mut sev = Vec::new();
    for _ in 0..1000 {
        run(&[&c1, &c2, &server], &mut now, 10);
        sev.extend(server.drain_events());
        if sev.iter().any(|e| matches!(e, Event::ConnClosed(..))) {
            break;
        }
    }
    assert!(
        sev.iter().any(|e| matches!(e, Event::ConnClosed(..))),
        "{sev:?}"
    );
    assert_eq!(count(&server), (0, 0));
}

/// Raw-H3 uses the same server_accept backlog cap and 10 s provisional deadline.
#[test]
fn raw_h3_provisional_cap_and_expiry() {
    let mut scfg = raw_h3_cfg(server_role());
    scfg.max_conns = 1;
    let server = Peer::spawn(scfg, vec![srv_addr()]);
    for i in 0..65u8 {
        let from = SocketAddr::from(([10, 2, 0, i], 40000));
        let pkt = initial(
            &[0xd0, i, 1, 1, 2, 3, 4, 5],
            &[0x5c, i, 1, 5, 4, 3, 2, 1],
            0,
            0,
            &client_hello_fragment(0, 300),
        );
        server.deliver(T0, srv_addr(), from, pkt);
        assert_eq!(
            server.call(Time::ZERO, |t, _| t.n_provisional()),
            u32::from(i + 1).min(64),
            "refused beyond the cap in server_accept"
        );
    }
    server.drive(T0);
    server.pump_out(T0);
    assert_eq!(server.call(T0, |t, _| t.conn_count()), 0);
    let mut now = T0;
    while server.call(Time::ZERO, |t, _| t.n_provisional()) > 0 {
        let d = server.next_timeout().expect("provisional deadline");
        now = now.max(d);
        server.drive(now);
        server.pump_out(now);
        assert!(now < T0 + Duration::from_secs(60), "never released");
    }
    assert!(
        now >= T0 + Duration::from_secs(10),
        "not before the 10 s deadline"
    );
    assert_eq!(server.call(now, |t, _| t.conn_count()), 0);
    assert_eq!(server.drain_events(), vec![], "never admitted: no events");
}

/// Bidi and uni streams on raw-H3 share the 8192-slot ceiling.
#[test]
fn raw_h3_streams_share_8192_ceiling() {
    const CEILING: u32 = 8192;
    let mut p = Pair::with(h3raw_opts());
    let uni = open_uni(&p.client, p.now, p.conn).expect("first uni");
    assert_eq!(send(&p.client, p.now, uni, vec![1], false), Ok(1));
    p.exchange();
    for _ in 1..CEILING {
        let c = p.conn;
        let s = (0..100)
            .find_map(
                |_| match p.client.call(p.now, move |t, now| t.open_stream(now, c)) {
                    Ok(s) => Some(s),
                    Err(_) => {
                        p.tick(MS);
                        None
                    }
                },
            )
            .expect("bidi credit");
        assert_eq!(send(&p.client, p.now, s, vec![1], false), Ok(1));
        p.exchange();
        p.cev.clear();
    }
    assert_eq!(stream_count(&p.client, p.conn), CEILING);
    p.tick(MS);
    assert_eq!(stream_count(&p.server, p.srv_conn), CEILING);
    assert_eq!(new_streams(&p.sev).len(), CEILING as usize);
    let c = p.conn;
    assert_eq!(
        p.client.call(p.now, move |t, now| t.open_stream(now, c)),
        Err(Error::Ceiling)
    );
    assert_eq!(open_uni(&p.client, p.now, c), Err(Error::Ceiling));
    assert_eq!(stream_count(&p.client, c), CEILING, "no refused slot");
    for _ in 0..100 {
        p.tick(10 * MS);
    }
    assert_eq!(p.client_closed(), None);
    assert_eq!(p.server_closed(), None);
}
