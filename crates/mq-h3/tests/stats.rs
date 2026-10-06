//! Request metrics: the `H3ReqStats` of `H3Closed` (adoption spec §4.6).

mod common;

use common::Rig;
use h3wire::{FieldRef, H3Code, StreamId as Q};
use mq_transport_api::{
    CloseReason, ErrType, Event, H3Close, H3Header, H3ReqId, H3ReqStats, StreamCloseStats,
    StreamError, StreamId, Time, TransportOps,
};

fn request() -> Vec<FieldRef<'static>> {
    [
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/x"),
    ]
    .map(|(n, v)| FieldRef::new(n.as_bytes(), v.as_bytes()))
    .to_vec()
}

fn at(r: &mut Rig, us: u64) {
    r.now = Time::from_micros(us);
}

/// A started server request whose HEADERS the gateway took, at rig time `t0`.
fn server_request(t0: u64) -> (Rig, H3ReqId, StreamId) {
    let mut r = Rig::server();
    r.pump();
    r.events();
    at(&mut r, t0);
    r.peer.send_headers(Q(0), &request(), false).unwrap();
    r.pump();
    let id = r
        .events()
        .iter()
        .find_map(|e| match *e {
            Event::H3Request(_, id) => Some(id),
            _ => None,
        })
        .expect("H3Request");
    assert_eq!(r.w.h3_recv_headers(r.now, id, &mut |_, _| {}), Ok(false));
    let s = r.peer_stream(Q(0));
    (r, id, s)
}

/// The `H3Close`s in `ev`.
fn closes(ev: &[Event]) -> Vec<(H3ReqId, H3Close)> {
    ev.iter()
        .filter_map(|e| match e {
            Event::H3Closed(id, c) => Some((*id, (**c).clone())),
            _ => None,
        })
        .collect()
}

fn pull_all(r: &mut Rig, id: H3ReqId) -> Result<(usize, bool), StreamError> {
    let mut buf = [0u8; 1024];
    let mut total = 0;
    loop {
        let (n, fin) = r.w.h3_recv_body(r.now, id, &mut buf)?;
        total += n;
        if fin {
            return Ok((total, true));
        }
    }
}

#[test]
fn stats_clean() {
    let (mut r, id, s) = server_request(100);
    r.peer_send_body(Q(0), &vec![1u8; 5000], true);
    r.pump();
    assert_eq!(pull_all(&mut r, id), Ok((5000, true)));
    at(&mut r, 250);
    let hs = [H3Header {
        name: b":status",
        value: b"200",
    }];
    r.w.h3_send_headers(r.now, id, &hs, false).unwrap();
    let body = vec![2u8; 7000];
    let mut sent = 0;
    while sent < body.len() {
        let fin = true;
        sent += r.w.h3_send_body(r.now, id, &body[sent..], fin).unwrap();
        r.pump();
    }
    r.h.push_event(snapshot_for(s, 0, "finished"));
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let got = closes(&r.events());
    assert_eq!(
        got,
        [(
            id,
            H3Close {
                stats: H3ReqStats {
                    send_body: 7000,
                    recv_body: 5000,
                    begin_us: 100,
                    header_send_us: 250,
                    fin_send_us: 11,
                    fin_ack_us: 22,
                    mp_state: 3,
                    stream_err: 0,
                    close_msg: Some("finished".into()),
                },
                unread: None,
            }
        )]
    );
}

fn snapshot_for(s: StreamId, err: i32, msg: &str) -> Event {
    let st = StreamCloseStats {
        fin_send_us: 11,
        fin_ack_us: 22,
        mp_state: 3,
        stream_err: err,
        close_msg: Some(msg.into()),
    };
    Event::StreamCloseStats(s, Box::new(st))
}

#[test]
fn stats_reset_code() {
    let (mut r, id, s) = server_request(5);
    r.peer.abort(Q(0), H3Code::REQUEST_CANCELLED).unwrap();
    r.pump();
    assert_eq!(pull_all(&mut r, id), Err(StreamError::Reset));
    r.h.push_event(snapshot_for(s, 0x10c, "reset"));
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let got = closes(&r.events());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1.stats.stream_err, 0x10c);
    assert_eq!(got[0].1.stats.close_msg.as_deref(), Some("reset"));
    assert_eq!(got[0].1.stats.fin_ack_us, 22);
}

/// adoption spec §4.4: a snapshot of a non-request stream is ignored.
#[test]
fn close_stats_on_uni_ignored() {
    let (mut r, id, s) = server_request(5);
    let ctrl = r.peer_stream(Q(2)); // the peer's control stream
    r.events();
    r.h.push_event(snapshot_for(ctrl, 7, "uni"));
    r.h.push_event(Event::StreamClosed(ctrl));
    r.w.drive(r.now);
    assert_eq!(r.events(), []);
    r.peer.abort(Q(0), H3Code::REQUEST_CANCELLED).unwrap();
    r.pump();
    let _ = pull_all(&mut r, id);
    r.h.push_event(Event::StreamClosed(s));
    r.w.drive(r.now);
    let got = closes(&r.events());
    assert_eq!(got.len(), 1);
    let st = &got[0].1.stats;
    assert_eq!(
        (st.stream_err, st.fin_ack_us, st.close_msg.clone()),
        (0, 0, None)
    );
}

#[test]
fn stats_fan_out_without_snapshot() {
    let (mut r, id, _) = server_request(5);
    r.events();
    r.close_transport(CloseReason {
        err_type: ErrType::Application,
        code: 0x1234,
    });
    r.w.drive(r.now);
    let got = closes(&r.events());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, id);
    assert_eq!(got[0].1.stats.stream_err, 0x1234);
    assert_eq!(got[0].1.stats.close_msg.as_deref(), Some("conn closed"));
}
