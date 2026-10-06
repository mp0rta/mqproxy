//! Pass-through behaviour of `H3Wire` over `ScriptedTransport` (adoption spec §4.1).

use mq_h3::H3Wire;
use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_transport_api::{
    CloseReason, ConnConfig, ConnProto, ErrType, Error, Event, H3Close, H3ReqStats, StreamError,
    StreamInfo, StreamKind, Time, TransportOps,
};
use std::net::SocketAddr;

fn mk(active: bool) -> (H3Wire<ScriptedTransport>, ScriptedHandle) {
    let (t, h) = ScriptedTransport::new();
    (
        if active {
            H3Wire::new(t)
        } else {
            H3Wire::passthrough(t)
        },
        h,
    )
}

const NOW: Time = Time::ZERO;

fn addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

fn raw_ops(active: bool) {
    let (mut w, h) = mk(active);
    let cfg = ConnConfig {
        peer: addr(),
        sni: "mqproxy",
        idle_timeout: None,
        proto: ConnProto::Raw,
    };
    let c = w.connect(NOW, &cfg).unwrap();
    let s = w.open_stream(NOW, c).unwrap();
    assert_eq!(w.stream_send(NOW, s, b"abc", true), Ok(3));
    let mut buf = [0u8; 8];
    assert_eq!(w.stream_recv(NOW, s, &mut buf), Err(StreamError::Blocked));
    w.stream_reset(NOW, s);
    w.stream_reset_send(NOW, s, 0x10c);
    w.stream_stop_sending(NOW, s, 0x10b);
    let u = w.open_uni(NOW, c).unwrap();
    assert_eq!(w.add_path(NOW, c, true).map(|_| ()), Ok(()));
    assert_eq!(w.datagram_send(NOW, c, b"dg"), Ok(()));
    w.close_conn(NOW, c);
    w.close_conn_with(NOW, c, 0x101);
    let _ = w.conn_stats(c);
    let _ = w.stream_info(s);
    let log = h.log();
    let want = [
        Call::Connect(cfg),
        Call::OpenStream(c),
        Call::StreamSend {
            s,
            bytes: b"abc".to_vec(),
            fin: true,
        },
        Call::StreamRecv { s, cap: 8 },
        Call::StreamReset(s),
        Call::StreamResetSend { s, code: 0x10c },
        Call::StreamStopSending { s, code: 0x10b },
        Call::OpenUni(c),
        Call::AddPath {
            conn: c,
            standby: true,
        },
        Call::DatagramSend {
            conn: c,
            bytes: b"dg".to_vec(),
        },
        Call::CloseConn(c),
        Call::CloseConnWith {
            conn: c,
            code: 0x101,
        },
    ];
    assert_eq!(log, want);
    let _ = u;
}

#[test]
fn raw_ops_reach_inner() {
    raw_ops(false);
    raw_ops(true);
}

fn raw_events(active: bool) {
    let (mut w, h) = mk(active);
    let c = h.new_conn_id();
    let s = h.new_stream_id();
    let info = StreamInfo {
        conn: c,
        quic_id: 0,
        kind: StreamKind::Bidi,
    };
    h.set_stream_info(s, info);
    h.set_conn_stats(c, Default::default()); // the conn is live
    let reason = CloseReason {
        err_type: ErrType::Unknown,
        code: 0,
    };
    let evs = vec![
        Event::NewConn(c, ConnProto::Raw),
        Event::ConnEstablished(c),
        Event::NewStream(c, s, info),
        Event::StreamReadable(s),
        Event::StreamWritable(s),
        Event::StreamPeerReset(s, 0x10c),
        Event::StreamStopSending(s, 0x10b),
        Event::MpReady(c),
        Event::DatagramReadable(c),
        Event::StreamClosed(s),
        Event::ConnClosed(c, reason),
    ];
    for e in &evs {
        h.push_event(e.clone());
    }
    w.drive(NOW);
    let got: Vec<_> = std::iter::from_fn(|| w.poll_event()).collect();
    assert_eq!(got, evs);
}

#[test]
fn raw_events_pop_out() {
    raw_events(false);
    raw_events(true);
}

#[test]
fn passthrough_h3_ops_and_events() {
    let (mut w, h) = mk(false);
    let c = h.new_conn_id();
    let r = h.new_h3_request(c);
    h.expect_open_h3_request(c, Ok(r));
    assert_eq!(w.open_h3_request(NOW, c), Ok(r));
    assert_eq!(w.h3_send_body(NOW, r, b"x", false), Ok(1));
    assert_eq!(w.h3_finish(NOW, r), Ok(()));
    let mut buf = [0u8; 4];
    assert_eq!(w.h3_recv_body(NOW, r, &mut buf), Err(StreamError::Blocked));
    assert_eq!(
        w.h3_recv_headers(NOW, r, &mut |_, _| {}),
        Err(StreamError::Blocked)
    );
    w.h3_reset(NOW, r);
    let log = h.log();
    for call in [
        Call::OpenH3Request(c),
        Call::H3Finish(r),
        Call::H3Reset(r),
        Call::H3RecvHeaders(r),
    ] {
        assert!(log.contains(&call), "{call:?} missing in {log:?}");
    }
    assert!(log.contains(&Call::H3RecvBody { r, cap: 4 }));

    // Events for ids the wrapper never saw pass unchanged.
    let r2 = h.new_h3_request(c);
    let stats = H3ReqStats {
        send_body: 0,
        recv_body: 0,
        begin_us: 0,
        header_send_us: 0,
        fin_send_us: 0,
        fin_ack_us: 0,
        mp_state: 0,
        stream_err: 0,
        close_msg: None,
    };
    let closed = Event::H3Closed(
        r2,
        Box::new(H3Close {
            stats,
            unread: None,
        }),
    );
    h.push_event(Event::H3Readable(r2));
    h.push_event(Event::H3Writable(r2));
    h.push_event(closed.clone());
    w.drive(NOW);
    let got: Vec<_> = std::iter::from_fn(|| w.poll_event()).collect();
    assert_eq!(
        got,
        vec![
            Event::H3Request(c, r),
            Event::H3Request(c, r2),
            Event::H3Readable(r2),
            Event::H3Writable(r2),
            closed
        ]
    );
}

#[test]
fn active_unknown_id_is_stale_and_not_forwarded() {
    let (mut w, h) = mk(true);
    let c = h.new_conn_id();
    let r = h.new_h3_request(c);
    let mut buf = [0u8; 4];
    assert_eq!(w.h3_recv_body(NOW, r, &mut buf), Err(StreamError::Stale));
    assert_eq!(w.h3_send_body(NOW, r, b"x", false), Err(StreamError::Stale));
    assert_eq!(w.h3_finish(NOW, r), Err(StreamError::Stale));
    assert_eq!(w.h3_req_info(r), Err(Error::Stale));
    w.h3_reset(NOW, r);
    let log = h.log();
    assert!(
        !log.iter().any(|c| matches!(
            c,
            Call::H3RecvBody { .. }
                | Call::H3SendBody { .. }
                | Call::H3Finish(_)
                | Call::H3Reset(_)
        )),
        "forwarded: {log:?}"
    );
}

/// Pops are filtered as the bare transport filters them (adoption spec §4.1): in passthrough,
/// an H3 event whose request the inner transport no longer knows is dropped; in both modes a
/// readiness or creation event of a gone conn is dropped. Close events always pop.
#[test]
fn stale_on_pop_dropped_like_bare_transport() {
    for active in [false, true] {
        let (mut w, h) = mk(active);
        let (live, gone) = (h.new_conn_id(), h.new_conn_id());
        h.set_conn_stats(live, Default::default());
        let r = h.new_h3_request(live);
        h.inject_h3_headers(r, vec![(b":method".to_vec(), b"GET".to_vec())], true);
        h.push_event(Event::MpReady(gone));
        h.push_event(Event::DatagramReadable(gone));
        h.push_event(Event::MpReady(live));
        w.drive(NOW); // drained while everything was still live in the inner queue
        let close = H3Close {
            stats: H3ReqStats {
                send_body: 0,
                recv_body: 0,
                begin_us: 0,
                header_send_us: 0,
                fin_send_us: 0,
                fin_ack_us: 0,
                mp_state: 0,
                stream_err: 0,
                close_msg: None,
            },
            unread: None,
        };
        h.close_h3(r, close.clone()); // the request goes stale between drain and pop
        let got: Vec<_> = std::iter::from_fn(|| w.poll_event()).collect();
        assert_eq!(got, vec![Event::MpReady(live)], "active={active}");
        w.drive(NOW);
        let got: Vec<_> = std::iter::from_fn(|| w.poll_event()).collect();
        assert_eq!(
            got,
            vec![Event::H3Closed(r, Box::new(close))],
            "active={active}"
        );
    }
}
