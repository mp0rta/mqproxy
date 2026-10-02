//! SP2 spec §10.3: the UDP relay on the shard pair — the real `Client` and
//! `Server` over the real xquic pair, with the SOCKS5 UDP app played on the
//! client's `FakeIo` and the UDP target (an echo) on the server's. Then the
//! same-iteration deferred flush of §10.2 on a bare `Shard` pair.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::client::{Client, SOCKS5};
use mq_proxy::config::ServerConfig;
use mq_proxy::server::Server;
use mq_runtime::UdpSocketId;
use mq_runtime::testing::{Recorded, RecordingApp};
use mq_transport_api::fabric::Packet;
use mq_transport_api::{ConnConfig, Event, Role, Time, TransportOps};
use std::net::SocketAddr;

/// An authenticated pair whose server's UDP target echoes.
fn udp_pair(cfg: ServerConfig) -> Pair<Server, Client> {
    let mut p = Pair::new(spawn_server(cfg, 0), spawn_client(client_cfg()));
    p.udp_echo();
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    p.run_for(10 * MS); // the client reads the AUTH_RESPONSE: UDP availability is known
    p
}

/// Sends `payload` to the UDP target through `app` and runs until replies arrive.
fn roundtrip(p: &mut Pair<Server, Client>, app: &SocksUdpApp, payload: &[u8]) -> Vec<Vec<u8>> {
    app.send(p, origin_addr(), payload);
    let mut got = Vec::new();
    let replied = p.run_until(5 * SEC, |p| {
        got.extend(app.recv(p));
        !got.is_empty()
    });
    assert!(replied, "no reply");
    got
}

#[test]
fn pair_udp_64_byte_roundtrip() {
    let mut p = udp_pair(server_cfg());
    let app = SocksUdpApp::associate(&mut p);
    let payload = bulk(64);
    assert_eq!(
        roundtrip(&mut p, &app, &payload),
        [socks_udp(origin_addr(), &payload)]
    );
}

/// spec §2.3/§5: 3000 bytes exceed the datagram mss, so both directions
/// fragment and reassemble.
#[test]
fn pair_udp_3000_byte_roundtrip_frags_reassembled_gt_0() {
    let mut p = udp_pair(server_cfg());
    let app = SocksUdpApp::associate(&mut p);
    let payload = bulk(3000);
    assert_eq!(
        roundtrip(&mut p, &app, &payload),
        [socks_udp(origin_addr(), &payload)]
    );
    let sc = p.server_conns()[0];
    let srv = p.with_server(move |n| n.app().udp_counters(sc)).unwrap();
    assert!(srv.frags_reassembled > 0, "{srv:?}");
    let cli = p.with_client(|n| n.app().udp_counters());
    assert!(cli.frags_reassembled > 0, "{cli:?}");
}

/// spec §6.3/§7.2 (C design §2): the client hands the OPEN and the first
/// datagram to the transport in one iteration and one server iteration takes
/// that flight; the real engine surfaces the datagram before the OPEN's
/// bytes, so the server holds it in the pre-OPEN buffer and delivers it once
/// the session is `Live`.
#[test]
fn pair_udp_same_flight_open_and_datagram() {
    let mut p = udp_pair(server_cfg());
    let app = SocksUdpApp::associate(&mut p);
    let (sc, cc) = (p.server_conns()[0], p.client_conns()[0]);
    let streams = p.stream_counts(sc, cc).1;
    let payload = bulk(64);
    app.send(&p, origin_addr(), &payload);
    p.step(); // the server idles, the client sends the flight
    assert_eq!(p.stream_counts(sc, cc).1, streams + 1, "the OPEN's stream");
    let seen = p.with_server(|n| n.tap().events.len());
    p.step(); // one server iteration takes it
    let ev = p.with_server(move |n| n.tap().events[seen..].to_vec());
    let at = |want: &Event| ev.iter().position(|(_, e)| e == want);
    let open = ev.iter().find_map(|(_, e)| match e {
        Event::NewStream(c, s, _) if *c == sc => Some(*s),
        _ => None,
    });
    let dgram = at(&Event::DatagramReadable(sc));
    match (dgram, open.and_then(|s| at(&Event::StreamReadable(s)))) {
        (Some(d), Some(o)) => assert!(d < o, "the OPEN was readable first: {ev:?}"),
        _ => panic!("not one flight: {ev:?}"),
    }
    let mut got = Vec::new();
    assert!(p.run_until(5 * SEC, |p| {
        got.extend(app.recv(p));
        !got.is_empty()
    }));
    assert_eq!(got, [socks_udp(origin_addr(), &payload)]);
    let c = p.with_server(move |n| n.app().udp_counters(sc)).unwrap();
    assert_eq!((c.preopen_evictions, c.drops_preauth), (0, 0), "{c:?}");
}

/// spec §7.2/§6.4: the server's idle timer ends a session on an association
/// that lives on; the client forgets the session without a negative-cache
/// entry, and the next packet through the same association opens a new sid.
#[test]
fn pair_udp_idle_expiry_on_surviving_association() {
    let cfg = ServerConfig {
        udp_idle_timeout: 200 * MS,
        ..server_cfg()
    };
    let mut p = udp_pair(cfg);
    let app = SocksUdpApp::associate(&mut p);
    let sc = p.server_conns()[0];
    let payload = bulk(64);
    let want = [socks_udp(origin_addr(), &payload)];
    assert_eq!(roundtrip(&mut p, &app, &payload), want);
    assert_eq!(p.with_server(move |n| n.app().udp_sessions(sc)), Some(1));
    p.run_for(300 * MS);
    assert_eq!(p.with_server(move |n| n.app().udp_sessions(sc)), Some(0));
    assert_eq!(p.with_client(|n| n.app().udp_negcache_len()), 0);
    assert_eq!(p.app_closed(app.control), None, "the association lives on");
    // A client still holding sid 1 would send on it, into the server's
    // pre-OPEN buffer, and get no reply.
    assert_eq!(roundtrip(&mut p, &app, &payload), want);
    let target = |sid| p.with_server(move |n| n.app().udp_target(sc, sid));
    assert_eq!((target(1), target(2)), (None, Some(origin_addr())));
}

/// SP2 spec §6.2/§7.3: a `--no-udp` server advertises no UDP relay, so the
/// client answers ASSOCIATE with REP 0x07.
#[test]
fn pair_udp_server_no_udp_rep_07() {
    let cfg = ServerConfig {
        udp_enabled: false,
        ..server_cfg()
    };
    let mut p = udp_pair(cfg);
    let s = p.with_client(|n| {
        let s = n.accept(SOCKS5, None);
        n.io_mut().tcp_feed(s, &SOCKS5_ASSOCIATE);
        s
    });
    assert!(p.run_until(5 * SEC, move |p| p.app_written(s).len() >= 12));
    assert_eq!(p.app_written(s), [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
}

// --- Deferred flush (spec §10.2, §3.3) ---

type Bare = Side<RecordingApp>;

/// Every transmit `side`'s shard holds, split into datagrams sent from `local`.
fn drain(side: &Bare, local: SocketAddr) -> Vec<Packet> {
    side.call(move |n| {
        let sh = n.shard_mut();
        let socks: Vec<UdpSocketId> = sh.pending_transmit().collect();
        let mut out = Vec::new();
        for s in socks {
            while let Some(t) = sh.peek_transmit(s) {
                let to = t.dst;
                let segs: Vec<Vec<u8>> = t
                    .payload
                    .chunks(t.segment_size)
                    .map(<[u8]>::to_vec)
                    .collect();
                sh.transmit_done(s, segs.len());
                out.extend(segs.into_iter().map(|data| Packet {
                    from: local,
                    to,
                    data,
                }));
            }
        }
        out
    })
}

/// `pkts` into `side`'s primary socket, then exactly one `Shard::drive` at `now`.
fn feed(side: &Bare, now: Time, pkts: Vec<Packet>) {
    side.call(move |n| {
        let sh = n.shard_mut();
        let s = sh.primary_udp();
        for p in pkts {
            sh.on_udp_rx(now, s, p.from, &p.data);
        }
        sh.drive(now);
    })
}

/// spec §3.3/§10.2: a `datagram_send` made from an app callback inside
/// `Shard::drive` leaves in that same `drive` (step 5's re-drive), with no
/// second drive of the sender and no clock movement.
#[test]
fn deferred_flush_same_iteration() {
    let (sapp, srec) = RecordingApp::new();
    let (capp, crec) = RecordingApp::new();
    let srv: Bare = Side::spawn(
        transport_cfg(server_role(), 0),
        server_addr(),
        vec![],
        move || sapp,
    );
    let cli: Bare = Side::spawn(
        transport_cfg(Role::Client, 0),
        client_addr(),
        vec![],
        move || capp,
    );
    let cfg = ConnConfig {
        peer: server_addr(),
        sni: "mqproxy",
        idle_timeout: None,
    };
    let c = cli.call(move |n| n.with_app(|_, cx| cx.connect(&cfg)).expect("connect"));
    feed(&cli, T0, Vec::new());
    loop {
        let (to_s, to_c) = (drain(&cli, client_addr()), drain(&srv, server_addr()));
        if to_s.is_empty() && to_c.is_empty() {
            break;
        }
        feed(&srv, T0, to_s);
        feed(&cli, T0, to_c);
    }
    let sc = (srec.records().iter())
        .find_map(|r| match r {
            Recorded::TransportEvent(Event::ConnEstablished(x)) => Some(*x),
            _ => None,
        })
        .expect("server established");
    assert!(
        crec.records()
            .contains(&Recorded::TransportEvent(Event::ConnEstablished(c)))
    );
    assert!(cli.call(move |n| n.transport().datagram_mss(c)) > 0);
    srec.on(move |r, cx| {
        if let Recorded::TransportEvent(Event::StreamReadable(_)) = r {
            assert_eq!(cx.datagram_send(sc, &[0u8; 64]), Ok(()));
        }
    });
    cli.call(move |n| {
        n.with_app(|_, cx| {
            let s = cx.open_stream(c).expect("open_stream");
            assert_eq!(cx.stream_send(s, b"x", false), Ok(1));
        })
    });
    feed(&cli, T0, Vec::new());
    let stream_pkt = drain(&cli, client_addr());
    assert_eq!(stream_pkt.len(), 1, "one stream packet");
    feed(&srv, T0, stream_pkt); // the one drive of the sender
    let readable = |r: &Recorded| matches!(r, Recorded::TransportEvent(Event::StreamReadable(_)));
    assert!(srec.records().iter().any(readable), "the reaction ran");
    feed(&cli, T0, drain(&srv, server_addr()));
    assert!(
        crec.records()
            .contains(&Recorded::TransportEvent(Event::DatagramReadable(c)))
    );
    let got = cli.call(move |n| {
        n.with_app(|_, cx| {
            let mut b = vec![0u8; 65535];
            cx.datagram_recv(c, &mut b).map(|k| b[..k].to_vec())
        })
    });
    assert_eq!(got, Some(vec![0u8; 64]));
}
