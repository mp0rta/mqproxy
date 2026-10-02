//! spec §5.2 Shard, §5.4 app interface: the shard driven by a `ScriptedTransport`
//! on the QUIC side and by hand (as the driver would) on the socket side.

use mq_runtime::testing::{
    Call, RecordHandle, Recorded, RecordingApp, ScriptedHandle, ScriptedTransport,
};
use mq_runtime::{
    AcceptMeta, Cx, DialError, Host, Interest, IoRequest, IoResult, ListenerId, ListenerTag,
    PrereadTooLarge, RELAY_BUF, Shard, StreamPreread, TCP_BUF, Target, TcpEnd, TcpId,
};
use mq_transport_api::{
    CloseReason, ConnId, ErrType, Event, PathError, PathId, StreamError, StreamId, StreamInfo,
    StreamKind, Time,
};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

type S = Shard<ScriptedTransport, RecordingApp>;

const T0: Time = Time(0);
const CAP: usize = 4096;
const NO_PREREAD: StreamPreread<'static> = StreamPreread {
    bytes: &[],
    fin: false,
};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
fn meta() -> AcceptMeta {
    AcceptMeta {
        peer: addr(5000),
        original_dst: None,
    }
}
fn target() -> Target {
    Target {
        host: Host::Domain("example.com".into()),
        port: 443,
    }
}

struct H {
    sh: S,
    t: ScriptedHandle,
    app: RecordHandle,
    l: ListenerId,
}

fn setup_seeded(seed: u64) -> H {
    let (transport, t) = ScriptedTransport::new();
    let (app, rec) = RecordingApp::new();
    let mut sh = Shard::new(transport, app, addr(4433), seed);
    let l = sh.add_listener(ListenerTag(1));
    sh.start(T0);
    rec.take();
    H { sh, t, app: rec, l }
}
fn setup() -> H {
    setup_seeded(1)
}

impl H {
    fn accept(&mut self) -> TcpId {
        self.sh
            .on_accepted(T0, self.l, meta())
            .expect("below the cap")
    }
    fn reqs(&mut self) -> Vec<IoRequest> {
        std::iter::from_fn(|| self.sh.poll_io_request()).collect()
    }
    /// The driver's read: copy into `tcp_rx_buf`, commit.
    fn rx(&mut self, tcp: TcpId, bytes: &[u8]) {
        let buf = self.sh.tcp_rx_buf(tcp);
        assert!(buf.len() >= bytes.len(), "rx buffer room");
        buf[..bytes.len()].copy_from_slice(bytes);
        self.sh.tcp_rx_commit(T0, tcp, IoResult::Bytes(bytes.len()));
    }
    /// The driver's write: everything in `tcp_tx_buf`, committed.
    fn tx_all(&mut self, tcp: TcpId) -> Vec<u8> {
        let out = self.sh.tcp_tx_buf(tcp).to_vec();
        self.sh.tcp_tx_commit(T0, tcp, IoResult::Bytes(out.len()));
        out
    }
    fn conn(&self) -> ConnId {
        self.t.new_conn_id()
    }
    fn stream(&self, conn: ConnId) -> StreamId {
        let s = self.t.new_stream_id();
        self.t.set_stream_info(
            s,
            StreamInfo {
                conn,
                quic_id: 0,
                kind: StreamKind::Bidi,
            },
        );
        s
    }
    /// An accepted socket handed to a relay on a fresh stream of `conn`.
    fn relay_on(&mut self, conn: ConnId) -> (TcpId, StreamId) {
        let tcp = self.accept();
        let s = self.stream(conn);
        self.sh
            .with_app(T0, |_, cx| cx.start_relay(tcp, s, NO_PREREAD))
            .unwrap();
        (tcp, s)
    }
    fn relay(&mut self) -> (TcpId, StreamId) {
        let c = self.conn();
        self.relay_on(c)
    }
    fn drives(&self) -> usize {
        self.t
            .log()
            .iter()
            .filter(|c| matches!(c, Call::Drive(_)))
            .count()
    }
    fn app_saw_stream(&self, s: StreamId) -> bool {
        self.app.records().iter().any(|r| {
            matches!(r, Recorded::TransportEvent(
                Event::StreamReadable(x) | Event::StreamWritable(x) | Event::StreamClosed(x)
            ) if *x == s)
        })
    }
}

fn closed(c: ConnId) -> Event {
    Event::ConnClosed(
        c,
        CloseReason {
            err_type: ErrType::Transport,
            code: 1,
        },
    )
}

// --- start, accept, app-owned phase ---

#[test]
fn start_calls_on_start() {
    let (transport, _t) = ScriptedTransport::new();
    let (app, rec) = RecordingApp::new();
    let mut sh: S = Shard::new(transport, app, addr(4433), 1);
    assert!(rec.records().is_empty(), "nothing before start");
    sh.start(T0);
    assert_eq!(rec.records(), [Recorded::Start]);
}

#[test]
fn accepted_socket_is_app_owned() {
    let mut h = setup();
    let l7 = h.sh.add_listener(ListenerTag(7));
    let m = AcceptMeta {
        peer: addr(6000),
        original_dst: Some(addr(80)),
    };
    let tcp = h.sh.on_accepted(T0, l7, m).unwrap();
    assert_eq!(
        h.app.records(),
        [Recorded::Accepted {
            l: ListenerTag(7),
            tcp,
            meta: m
        }]
    );
    // App-owned: the app writes into it, and nothing goes to a relay.
    assert!(h.sh.with_app(T0, |_, cx| cx.tcp_write(tcp, b"hi")).is_ok());
    assert_eq!(h.sh.tcp_tx_buf(tcp), b"hi");
    h.rx(tcp, b"req");
    assert_eq!(h.app.records().last(), Some(&Recorded::TcpData(tcp)));
    assert!(
        h.t.log()
            .iter()
            .all(|c| !matches!(c, Call::StreamSend { .. }))
    );
}

#[test]
fn tcp_data_delivered_and_consumable() {
    let mut h = setup();
    let tcp = h.accept();
    h.app.take();
    h.rx(tcp, b"hello");
    assert_eq!(h.app.take(), [Recorded::TcpData(tcp)]);
    let seen = h.sh.with_app(T0, |_, cx| {
        let a = cx.tcp_rx(tcp).to_vec();
        cx.tcp_consume(tcp, 2);
        (a, cx.tcp_rx(tcp).to_vec())
    });
    assert_eq!(seen, (b"hello".to_vec(), b"llo".to_vec()));
    h.rx(tcp, b" world");
    assert_eq!(
        h.sh.with_app(T0, |_, cx| cx.tcp_rx(tcp).to_vec()),
        b"llo world"
    );
}

#[test]
fn tcp_write_queues_and_close_waits_for_drain() {
    let mut h = setup();
    let tcp = h.accept();
    h.sh.with_app(T0, |_, cx| {
        cx.tcp_write(tcp, b"reply").unwrap();
        cx.tcp_close(tcp);
        assert!(
            cx.tcp_write(tcp, b"more").is_err(),
            "closing: no more writes"
        );
    });
    assert!(h.reqs().is_empty(), "close waits for the send buffer");
    assert_eq!(
        h.sh.tcp_interest(tcp),
        Interest {
            read: false,
            write: true
        }
    );
    h.sh.tcp_tx_commit(T0, tcp, IoResult::Bytes(2));
    assert_eq!(h.sh.tcp_tx_buf(tcp), b"ply");
    assert!(h.reqs().is_empty());
    h.sh.tcp_tx_commit(T0, tcp, IoResult::Bytes(3));
    assert_eq!(h.reqs(), [IoRequest::TcpClose { tcp, abort: false }]);
    assert_eq!(h.sh.tcp_interest(tcp), Interest::default());
}

#[test]
fn tcp_abort_closes_now() {
    let mut h = setup();
    let tcp = h.accept();
    h.sh.with_app(T0, |_, cx| {
        cx.tcp_write(tcp, b"unsent").unwrap();
        cx.tcp_abort(tcp);
    });
    assert_eq!(h.reqs(), [IoRequest::TcpClose { tcp, abort: true }]);
    assert_eq!(h.sh.tcp_interest(tcp), Interest::default());
    assert!(h.sh.tcp_tx_buf(tcp).is_empty());
}

#[test]
fn read_eof_only_from_zero_read() {
    let mut h = setup();
    let tcp = h.accept();
    h.app.take();
    h.rx(tcp, b"abc");
    h.sh.tcp_rx_commit(T0, tcp, IoResult::WouldBlock);
    assert_eq!(
        h.app.take(),
        [Recorded::TcpData(tcp)],
        "no EOF from would-block"
    );
    h.sh.tcp_rx_commit(T0, tcp, IoResult::Eof);
    assert_eq!(h.app.take(), [Recorded::TcpEnd(tcp, TcpEnd::ReadEof)]);
    // Still writable; the read side is finished.
    assert!(h.sh.with_app(T0, |_, cx| cx.tcp_write(tcp, b"x")).is_ok());
    assert_eq!(
        h.sh.tcp_interest(tcp),
        Interest {
            read: false,
            write: true
        }
    );
    assert!(h.reqs().is_empty(), "read EOF does not close");
    // An error is terminal: closed, id dead.
    let t2 = h.accept();
    h.app.take();
    h.sh.on_tcp_error(T0, t2, ErrorKind::ConnectionReset);
    assert_eq!(
        h.app.take(),
        [Recorded::TcpEnd(
            t2,
            TcpEnd::Error(ErrorKind::ConnectionReset)
        )]
    );
    assert_eq!(
        h.reqs(),
        [IoRequest::TcpClose {
            tcp: t2,
            abort: true
        }]
    );
}

#[test]
fn read_eof_survives_start_relay() {
    let mut h = setup();
    let tcp = h.accept();
    h.rx(tcp, b"GET");
    h.sh.tcp_rx_commit(T0, tcp, IoResult::Eof);
    let s = h.stream(h.conn());
    h.sh.with_app(T0, |_, cx| cx.start_relay(tcp, s, NO_PREREAD))
        .unwrap();
    h.sh.drive(T0);
    assert_eq!(h.t.sent_bytes(s), b"GET");
    assert!(
        h.t.log().contains(&Call::StreamSend {
            s,
            bytes: b"GET".to_vec(),
            fin: true
        }),
        "FIN coalesced with the prebuffer: the read EOF survived"
    );
    assert!(!h.sh.tcp_interest(tcp).read);
}

#[test]
fn start_relay_moves_prebuffer_reply_and_preread() {
    let mut h = setup();
    let tcp = h.accept();
    h.rx(tcp, b"early");
    let s = h.stream(h.conn());
    h.sh.with_app(T0, |_, cx| {
        cx.tcp_write(tcp, b"REPLY").unwrap();
        cx.start_relay(
            tcp,
            s,
            StreamPreread {
                bytes: b"pre",
                fin: false,
            },
        )
        .unwrap();
        // Relaying: the app no longer acts on the socket.
        assert!(cx.tcp_write(tcp, b"x").is_err());
        assert!(cx.tcp_rx(tcp).is_empty());
    });
    assert_eq!(
        h.sh.tcp_tx_buf(tcp),
        b"REPLYpre",
        "reply first, then preread"
    );
    h.app.take();
    h.sh.drive(T0);
    assert_eq!(
        h.t.sent_bytes(s),
        b"early",
        "unconsumed rx is the prebuffer"
    );
    h.rx(tcp, b"late");
    assert_eq!(h.t.sent_bytes(s), b"earlylate");
    assert!(h.app.take().is_empty(), "no callbacks once relaying");
}

#[test]
fn start_relay_rejects_oversized_preread() {
    let mut h = setup();
    let tcp = h.accept();
    let s = h.stream(h.conn());
    let big = vec![0u8; 8 * 1024];
    let small = vec![0u8; 4 * 1024];
    h.sh.with_app(T0, |_, cx| {
        cx.tcp_write(tcp, &[0; 60 * 1024]).unwrap();
        assert_eq!(
            cx.start_relay(
                tcp,
                s,
                StreamPreread {
                    bytes: &big,
                    fin: false
                }
            ),
            Err(PrereadTooLarge)
        );
        // Still app-owned after the rejection.
        assert!(cx.tcp_write(tcp, b"").is_ok());
        assert_eq!(
            cx.start_relay(
                tcp,
                s,
                StreamPreread {
                    bytes: &small,
                    fin: false
                }
            ),
            Ok(())
        );
    });
    assert_eq!(h.sh.tcp_tx_buf(tcp).len(), 64 * 1024);
}

#[test]
fn relaying_rx_commit_forwards_immediately() {
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.sh.drive(T0);
    h.app.take();
    h.rx(tcp, b"data");
    assert_eq!(h.t.sent_bytes(s), b"data", "no drive needed");
    assert!(h.app.take().is_empty());
}

// --- timers, dials, cap ---

#[test]
fn timers_fire_in_order_and_cancel() {
    let mut h = setup();
    let (a, b, d) = h.sh.with_app(T0, |_, cx| {
        let a = cx.set_timer(Duration::from_millis(5));
        let b = cx.set_timer(Duration::from_millis(1));
        let c = cx.set_timer(Duration::from_millis(3));
        let d = cx.set_timer(Duration::from_millis(1));
        cx.cancel_timer(c);
        (a, b, d)
    });
    assert_eq!(h.sh.next_timeout(), Some(Time(1_000)));
    h.sh.drive(Time(500));
    assert!(h.app.take().is_empty(), "nothing due");
    h.sh.drive(Time(4_000));
    assert_eq!(h.app.take(), [Recorded::Timer(b), Recorded::Timer(d)]);
    assert_eq!(h.sh.next_timeout(), Some(Time(5_000)));
    h.sh.drive(Time(10_000));
    assert_eq!(h.app.take(), [Recorded::Timer(a)]);
    assert_eq!(h.sh.next_timeout(), None);
}

#[test]
fn dial_at_cap_completes_with_limit_in_next_drive() {
    let mut h = setup();
    let socks: Vec<TcpId> = (0..CAP).map(|_| h.accept()).collect();
    h.app.take();
    let op =
        h.sh.with_app(T0, |_, cx| cx.dial(target(), Duration::from_secs(15)));
    assert!(h.reqs().is_empty(), "never reaches the driver");
    assert!(h.app.records().is_empty(), "completes in drive, not inline");
    assert!(h.sh.has_runnable_work());
    h.sh.drive(T0);
    assert_eq!(
        h.app.take(),
        [Recorded::DialResult(op, Err(DialError::Limit))]
    );
    // Below the cap a dial goes to the driver.
    h.sh.with_app(T0, |_, cx| cx.tcp_abort(socks[0]));
    h.reqs();
    let op2 =
        h.sh.with_app(T0, |_, cx| cx.dial(target(), Duration::from_secs(15)));
    assert_eq!(
        h.reqs(),
        [IoRequest::Dial {
            op: op2,
            target: target(),
            deadline: Duration::from_secs(15)
        }]
    );
}

#[test]
fn accepting_false_at_cap_true_after_close() {
    let mut h = setup();
    for _ in 0..CAP - 1 {
        h.accept();
    }
    assert!(h.sh.accepting());
    // A dial in progress counts toward the cap.
    let op =
        h.sh.with_app(T0, |_, cx| cx.dial(target(), Duration::from_secs(1)));
    assert!(!h.sh.accepting());
    assert_eq!(h.sh.on_accepted(T0, h.l, meta()), None);
    h.sh.on_dial_result(T0, op, Err(DialError::Refused));
    assert!(h.sh.accepting());
    let last = h.accept();
    assert!(!h.sh.accepting());
    h.sh.with_app(T0, |_, cx| cx.tcp_close(last));
    assert!(h.sh.accepting(), "a close frees a slot");
}

#[test]
fn set_accepting_false_overrides_cap_state() {
    let mut h = setup();
    h.accept();
    assert!(h.sh.accepting());
    h.sh.with_app(T0, |_, cx| cx.set_accepting(false));
    assert!(!h.sh.accepting(), "below the cap, the app's flag wins");
    h.sh.with_app(T0, |_, cx| cx.set_accepting(true));
    assert!(h.sh.accepting());
}

// --- routing ---

#[test]
fn conn_closed_sweeps_relays_by_conn_id_and_mapped_sockets() {
    let mut h = setup();
    let (a, b) = (h.conn(), h.conn());
    let (ta1, sa1) = h.relay_on(a);
    let (ta2, sa2) = h.relay_on(a);
    let (tb, _sb) = h.relay_on(b);
    let op = h.sh.with_app(T0, |_, cx| {
        cx.open_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST))
    });
    let sock = h.sh.on_udp_socket(T0, op, Ok(addr(7000))).unwrap();
    let primary = h.sh.primary_udp();
    h.sh.with_app(T0, |_, cx| {
        cx.add_path(a, sock, false).unwrap();
        cx.add_path(a, primary, false).unwrap();
    });
    h.sh.drive(T0);
    h.reqs();
    h.app.take();
    h.t.push_event(closed(a));
    h.sh.drive(T0);
    let reqs = h.reqs();
    for tcp in [ta1, ta2] {
        assert!(reqs.contains(&IoRequest::TcpClose { tcp, abort: true }));
        assert_eq!(h.sh.tcp_interest(tcp), Interest::default());
    }
    assert!(reqs.contains(&IoRequest::CloseUdpSocket { sock }));
    assert!(!reqs.contains(&IoRequest::CloseUdpSocket { sock: primary }));
    assert!(
        !reqs
            .iter()
            .any(|r| matches!(r, IoRequest::TcpClose { tcp, .. } if *tcp == tb))
    );
    let log = h.t.log();
    assert!(log.contains(&Call::StreamReset(sa1)) && log.contains(&Call::StreamReset(sa2)));
    assert_eq!(h.app.take(), [Recorded::TransportEvent(closed(a))]);
    // The socket mapping is gone: conn a's path now falls back to the primary.
    h.t.set_transmit((Some(a), PathId(1)), addr(9), vec![vec![1]]);
    assert_eq!(h.sh.pending_transmit().collect::<Vec<_>>(), [primary]);
}

#[test]
fn late_event_for_closed_relay_dropped() {
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.sh.drive(T0);
    h.sh.on_tcp_error(T0, tcp, ErrorKind::ConnectionReset);
    h.sh.drive(T0);
    assert!(h.t.log().contains(&Call::StreamReset(s)));
    assert_eq!(h.sh.dead_stream_count(), 1, "kept until its StreamClosed");
    let recvs = |h: &H| {
        h.t.log()
            .iter()
            .filter(|c| matches!(c, Call::StreamRecv { .. }))
            .count()
    };
    let before = recvs(&h);
    h.app.take();
    h.t.push_event(Event::StreamReadable(s));
    h.t.push_event(Event::StreamClosed(s));
    // Contrast: a stream no relay ever owned goes to the app.
    let other = h.t.new_stream_id();
    h.t.push_event(Event::StreamReadable(other));
    h.sh.drive(T0);
    assert!(!h.app_saw_stream(s), "dropped, not routed to the app");
    assert_eq!(recvs(&h), before, "and not to a relay");
    assert_eq!(
        h.app.take(),
        [Recorded::TransportEvent(Event::StreamReadable(other))]
    );
    assert_eq!(h.sh.dead_stream_count(), 0, "pruned by its StreamClosed");
}

#[test]
fn late_event_behind_stream_closed_in_same_drive_dropped() {
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.sh.drive(T0);
    h.reqs();
    h.app.take();
    // StreamClosed before both FINs ends the relay; a stray event behind it
    // in the same poll loop is still the relay's, not the app's.
    h.t.push_event(Event::StreamClosed(s));
    h.t.push_event(Event::StreamReadable(s));
    h.sh.drive(T0);
    assert_eq!(h.reqs(), [IoRequest::TcpClose { tcp, abort: true }]);
    assert!(h.app.take().is_empty());
    assert_eq!(h.sh.dead_stream_count(), 0);
}

#[test]
fn relay_ended_by_stream_closed_leaves_no_dead_entry() {
    let mut h = setup();
    // Abort: StreamClosed before both FINs.
    let (_t1, s1) = h.relay();
    h.t.push_event(Event::StreamClosed(s1));
    h.sh.drive(T0);
    assert_eq!(h.sh.dead_stream_count(), 0);
    // Clean: StreamClosed after both FINs while QUIC → TCP still drains
    // (the download case); the relay ends later, on the TCP side.
    let (tcp, s) = h.relay();
    h.sh.tcp_rx_commit(T0, tcp, IoResult::Eof); // FIN sent at once
    h.t.expect_stream_recv(s, Ok((b"bye".to_vec(), true)));
    h.sh.drive(T0);
    h.t.push_event(Event::StreamClosed(s));
    h.sh.drive(T0);
    h.reqs();
    assert_eq!(h.tx_all(tcp), b"bye");
    assert_eq!(
        h.reqs(),
        [
            IoRequest::TcpShutdownWrite { tcp },
            IoRequest::TcpClose { tcp, abort: false }
        ]
    );
    assert_eq!(
        h.sh.dead_stream_count(),
        0,
        "its StreamClosed was already consumed"
    );
}

#[test]
fn add_path_needs_a_live_socket_and_a_stream_relays_once() {
    let mut h = setup();
    let c = h.conn();
    let op = h.sh.with_app(T0, |_, cx| {
        cx.open_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST))
    });
    let sock = h.sh.on_udp_socket(T0, op, Ok(addr(7000))).unwrap();
    h.sh.with_app(T0, |_, cx| cx.close_udp_socket(sock));
    assert_eq!(
        h.sh.with_app(T0, |_, cx| cx.add_path(c, sock, false)),
        Err(PathError::Stale)
    );
    assert!(!h.t.log().iter().any(|c| matches!(c, Call::AddPath { .. })));
    let (_, s) = h.relay_on(c);
    let t2 = h.accept();
    assert_eq!(
        h.sh.with_app(T0, |_, cx| cx.start_relay(t2, s, NO_PREREAD)),
        Err(PrereadTooLarge)
    );
    assert!(h.sh.tcp_interest(t2).read, "still app-owned");
}

// --- interest ---

#[test]
fn app_owned_interest_follows_flag_and_buffer_room() {
    let mut h = setup();
    let tcp = h.accept();
    assert_eq!(
        h.sh.tcp_interest(tcp),
        Interest {
            read: true,
            write: false
        },
        "accepted sockets start readable"
    );
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), TCP_BUF);
    h.sh.with_app(T0, |_, cx| cx.tcp_set_read(tcp, false));
    assert!(!h.sh.tcp_interest(tcp).read);
    assert!(
        h.sh.tcp_rx_buf(tcp).is_empty(),
        "empty only with interest off"
    );
    h.sh.with_app(T0, |_, cx| cx.tcp_set_read(tcp, true));
    h.rx(tcp, &[7; TCP_BUF]);
    assert!(!h.sh.tcp_interest(tcp).read, "receive buffer full");
    assert!(h.sh.tcp_rx_buf(tcp).is_empty());
    h.sh.with_app(T0, |_, cx| cx.tcp_consume(tcp, 1));
    assert!(h.sh.tcp_interest(tcp).read);
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 1);
    assert!(!h.sh.tcp_interest(tcp).write);
    h.sh.with_app(T0, |_, cx| cx.tcp_write(tcp, b"x")).unwrap();
    assert!(h.sh.tcp_interest(tcp).write, "bytes waiting");
    h.tx_all(tcp);
    assert!(!h.sh.tcp_interest(tcp).write);
}

#[test]
fn rx_limit_caps_app_owned_reads_and_lifts_on_relay() {
    let mut h = setup();
    let tcp = h.accept();
    h.sh.with_app(T0, |_, cx| cx.tcp_set_rx_limit(tcp, 8192));
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 8192);
    h.rx(tcp, &[1; 100]);
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 8092, "room up to the limit");
    h.rx(tcp, &[2; 8092]);
    assert!(!h.sh.tcp_interest(tcp).read, "limit reached");
    assert!(h.sh.tcp_rx_buf(tcp).is_empty());
    h.sh.with_app(T0, |_, cx| cx.tcp_consume(tcp, 100));
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), 100);
    // Above the 64 KiB buffer: clamped.
    h.sh.with_app(T0, |_, cx| cx.tcp_set_rx_limit(tcp, 1 << 20));
    assert_eq!(h.sh.tcp_rx_buf(tcp).len(), TCP_BUF - 8092);
    h.sh.with_app(T0, |_, cx| cx.tcp_set_rx_limit(tcp, 8192));
    // The relay has its own 64 KiB buffer: the limit is gone.
    let s = h.stream(h.conn());
    h.sh.with_app(T0, |_, cx| cx.start_relay(tcp, s, NO_PREREAD))
        .unwrap();
    h.sh.drive(T0);
    assert!(h.sh.tcp_interest(tcp).read);
    assert!(h.sh.tcp_rx_buf(tcp).len() > 8192);
}

#[test]
fn app_owned_read_interest_off_after_eof() {
    let mut h = setup();
    let tcp = h.accept();
    h.sh.tcp_rx_commit(T0, tcp, IoResult::Eof);
    h.sh.with_app(T0, |_, cx| cx.tcp_set_read(tcp, true));
    assert!(!h.sh.tcp_interest(tcp).read);
    assert!(h.sh.tcp_rx_buf(tcp).is_empty());
}

// --- UDP ---

#[test]
fn path_mapping_selects_socket_and_falls_back_to_primary() {
    let mut h = setup();
    let primary = h.sh.primary_udp();
    let c = h.conn();
    let op = h.sh.with_app(T0, |_, cx| {
        cx.open_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST))
    });
    assert_eq!(
        h.reqs(),
        [IoRequest::OpenUdpSocket {
            op,
            local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST)
        }]
    );
    let sock = h.sh.on_udp_socket(T0, op, Ok(addr(7000))).unwrap();
    assert_eq!(
        h.app.take(),
        [Recorded::UdpSocket(op, Ok((sock, addr(7000))))]
    );
    let p =
        h.sh.with_app(T0, |_, cx| cx.add_path(c, sock, true))
            .unwrap();
    h.t.set_transmit((Some(c), p), addr(9), vec![vec![1, 1]]);
    h.t.set_transmit((Some(c), PathId(99)), addr(9), vec![vec![2]]);
    h.t.set_transmit((None, PathId(0)), addr(9), vec![vec![3]]);
    let mut socks: Vec<_> = h.sh.pending_transmit().collect();
    socks.sort();
    assert_eq!(socks, [primary, sock]);
    assert_eq!(h.sh.peek_transmit(sock).unwrap().payload, [1, 1]);
    h.sh.transmit_done(sock, 1);
    assert!(h.sh.peek_transmit(sock).is_none());
    // The primary serves the unmapped queues in turn.
    let mut served = Vec::new();
    while let Some(tx) = h.sh.peek_transmit(primary) {
        served.push(tx.payload.to_vec());
        h.sh.transmit_done(primary, 1);
    }
    served.sort();
    assert_eq!(served, [vec![2], vec![3]]);
    // Receive goes to the transport with the socket's own local address.
    h.sh.on_udp_rx(T0, sock, addr(9), b"pkt");
    assert!(h.t.log().contains(&Call::RecvDatagram {
        now: T0,
        local: addr(7000),
        peer: addr(9),
        data: b"pkt".to_vec()
    }));
    // The primary cannot be closed by the app.
    h.reqs();
    h.sh.with_app(T0, |_, cx| cx.close_udp_socket(primary));
    assert!(h.reqs().is_empty());
}

#[test]
fn cancelled_dial_and_socket_results_return_none() {
    let mut h = setup();
    let (d, o) = h.sh.with_app(T0, |_, cx| {
        let d = cx.dial(target(), Duration::from_secs(1));
        cx.cancel_dial(d);
        let o = cx.open_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST));
        cx.cancel_udp_socket(o);
        (d, o)
    });
    let reqs = h.reqs();
    assert!(reqs.contains(&IoRequest::CancelDial { op: d }));
    assert!(reqs.contains(&IoRequest::CancelUdpSocket { op: o }));
    assert_eq!(h.sh.on_dial_result(T0, d, Ok(addr(80))), None);
    assert_eq!(h.sh.on_udp_socket(T0, o, Ok(addr(7000))), None);
    assert!(
        h.app.take().is_empty(),
        "cancelled results are not delivered"
    );
    // A live dial is delivered and yields a socket.
    let d2 =
        h.sh.with_app(T0, |_, cx| cx.dial(target(), Duration::from_secs(1)));
    let tcp = h.sh.on_dial_result(T0, d2, Ok(addr(80))).unwrap();
    assert_eq!(h.app.take(), [Recorded::DialResult(d2, Ok(tcp))]);
    // A second result for the same op is stale.
    assert_eq!(h.sh.on_dial_result(T0, d2, Ok(addr(80))), None);
}

// --- loop contract ---

#[test]
fn has_runnable_work_reflects_relay_event_completion_and_resume_pending() {
    let mut h = setup();
    h.sh.drive(T0);
    assert!(!h.sh.has_runnable_work(), "idle");
    // A relay starts with stream_readable set: runnable until pumped.
    let (_tcp, _s) = h.relay();
    assert!(h.sh.has_runnable_work(), "runnable relay");
    h.sh.drive(T0);
    h.sh.drive(T0);
    assert!(!h.sh.has_runnable_work(), "relay pumped to Blocked");
    // An event the transport queued from a datagram, not yet dispatched.
    h.t.push_event(Event::MpReady(h.conn()));
    h.sh.on_udp_rx(T0, h.sh.primary_udp(), addr(9), b"x");
    assert!(h.sh.has_runnable_work(), "undispatched event");
    h.sh.drive(T0);
    assert!(!h.sh.has_runnable_work());
    // resume_pending.
    h.t.set_resume_pending(true);
    assert!(h.sh.has_runnable_work(), "resume_pending");
    h.t.set_resume_pending(false);
    // A shard-raised completion.
    for _ in 0..CAP - 1 {
        h.accept();
    }
    h.sh.with_app(T0, |_, cx| cx.dial(target(), Duration::from_secs(1)));
    assert!(h.sh.has_runnable_work(), "Limit completion pending");
    h.sh.drive(T0);
    assert!(!h.sh.has_runnable_work());
}

#[test]
fn next_timeout_min_of_transport_and_timers() {
    let mut h = setup();
    assert_eq!(h.sh.next_timeout(), None);
    h.t.set_next_timeout(Some(Time(10_000)));
    assert_eq!(h.sh.next_timeout(), Some(Time(10_000)));
    h.sh.with_app(T0, |_, cx| cx.set_timer(Duration::from_millis(5)));
    assert_eq!(h.sh.next_timeout(), Some(Time(5_000)));
    h.t.set_next_timeout(Some(Time(2_000)));
    assert_eq!(h.sh.next_timeout(), Some(Time(2_000)));
    h.t.set_next_timeout(None);
    assert_eq!(h.sh.next_timeout(), Some(Time(5_000)));
}

#[test]
fn budget_limits_bytes_per_drive() {
    // The 64 KiB relay buffers bind before the 256 KiB budget does (each relay
    // is pumped once per drive), so this checks the bound, not the exact budget.
    const BUDGET: usize = 256 * 1024;
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.t.expect_stream_recv(s, Ok((vec![9; 1024 * 1024], false)));
    let pulled = |h: &H| -> usize {
        h.t.log()
            .iter()
            .map(|c| match c {
                Call::StreamRecv { cap, .. } => *cap,
                _ => 0,
            })
            .sum()
    };
    h.sh.drive(T0);
    let first = pulled(&h);
    assert!(first <= BUDGET, "at most 256 KiB per relay per direction");
    assert_eq!(
        h.sh.tcp_tx_buf(tcp).len(),
        RELAY_BUF,
        "bounded by the buffer too"
    );
    // The rest arrives in later drives as the TCP side drains.
    let mut total = h.tx_all(tcp).len();
    for _ in 0..32 {
        h.sh.drive(T0);
        total += h.tx_all(tcp).len();
    }
    assert_eq!(total, 1024 * 1024);
}

#[test]
fn drive_again_when_steps_touched_transport() {
    let mut h = setup();
    h.sh.drive(T0);
    assert_eq!(h.drives(), 1, "nothing touched: one transport drive");
    // Step 3: the app answers an event with a transport call.
    let s = h.t.new_stream_id();
    h.app.on(move |r, cx| {
        if let Recorded::TransportEvent(Event::StreamWritable(x)) = r {
            let _ = cx.stream_send(*x, b"hi", false);
        }
    });
    h.t.push_event(Event::StreamWritable(s));
    h.sh.drive(T0);
    assert_eq!(h.drives(), 3, "step 3 touched the transport");
    // Step 4: pumping a relay.
    h.relay();
    h.sh.drive(T0);
    assert_eq!(h.drives(), 5, "step 4 touched the transport");
}

/// Transport drives after one drive pass whose step 3 runs `f` (spec §5.2 step 5).
fn drives_after_app_call(f: impl Fn(&mut Cx<'_>, ConnId) + Send + 'static) -> usize {
    let mut h = setup();
    let c = h.conn();
    let s = h.t.new_stream_id();
    h.app.on(move |r, cx| {
        if let Recorded::TransportEvent(Event::StreamWritable(_)) = r {
            f(cx, c);
        }
    });
    h.t.push_event(Event::StreamWritable(s));
    h.sh.drive(T0);
    h.drives()
}

#[test]
fn datagram_send_and_recv_redrive_but_mss_does_not() {
    // spec §3.1: send/recv go through `tm()`; `datagram_mss` is a query like `conn_stats`
    assert_eq!(drives_after_app_call(|cx, c| _ = cx.datagram_mss(c)), 1);
    assert_eq!(
        drives_after_app_call(|cx, c| _ = cx.datagram_send(c, b"x")),
        2
    );
    assert_eq!(
        drives_after_app_call(|cx, c| _ = cx.datagram_recv(c, &mut [0; 8])),
        2
    );
}

#[test]
fn rng_reproducible() {
    let draw = |seed| {
        let mut h = setup_seeded(seed);
        h.sh.with_app(T0, |_, cx| [cx.rng().next_u64(), cx.rng().next_u64()])
    };
    assert_eq!(draw(42), draw(42));
    assert_ne!(draw(42), draw(43));
}

// --- relay end ---

#[test]
fn abort_relay_resets_stream_and_aborts_tcp() {
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.t.expect_stream_recv(s, Err(StreamError::Reset));
    h.app.take();
    h.sh.drive(T0);
    assert!(h.t.log().contains(&Call::StreamReset(s)));
    assert_eq!(h.reqs(), [IoRequest::TcpClose { tcp, abort: true }]);
    assert_eq!(h.sh.tcp_interest(tcp), Interest::default());
    assert!(h.app.take().is_empty(), "no app callback for a relay's end");
}

#[test]
fn owed_shutdown_requested_once_and_done() {
    let mut h = setup();
    let (tcp, s) = h.relay();
    h.t.expect_stream_recv(s, Ok((b"bye".to_vec(), true)));
    h.sh.drive(T0);
    assert!(h.reqs().is_empty(), "SHUT_WR waits for the buffer to drain");
    assert_eq!(h.tx_all(tcp), b"bye");
    h.sh.drive(T0);
    assert_eq!(h.reqs(), [IoRequest::TcpShutdownWrite { tcp }]);
    h.sh.drive(T0);
    h.sh.drive(T0);
    assert!(h.reqs().is_empty(), "requested once");
    // The other direction finishes: clean close, no reset.
    h.sh.tcp_rx_commit(T0, tcp, IoResult::Eof);
    h.sh.drive(T0);
    assert_eq!(h.reqs(), [IoRequest::TcpClose { tcp, abort: false }]);
    assert!(!h.t.log().contains(&Call::StreamReset(s)));
}

// --- process ---

#[test]
fn shutdown_signal_calls_on_shutdown() {
    let mut h = setup();
    h.sh.on_shutdown_signal(T0);
    assert_eq!(h.app.take(), [Recorded::Shutdown]);
}

#[test]
fn request_exit_sets_exit_status() {
    let mut h = setup();
    assert_eq!(h.sh.exit_status(), None);
    h.app.on(|r, cx| {
        if *r == Recorded::Shutdown {
            cx.request_exit(0);
        }
    });
    h.sh.with_app(T0, |_, cx| cx.request_exit(3));
    assert_eq!(h.sh.exit_status(), Some(3));
    h.sh.on_shutdown_signal(T0);
    assert_eq!(h.sh.exit_status(), Some(0));
}
