//! spec §4.8 "Abandoned streams are drained by the transport": resets from either side,
//! before and after the peer's FIN, release every slot on both sides.
mod common;

use common::pair::{MS, Pair, new_streams, read_all, recv, send, stream_count, stream_events};
use mq_transport_api::{Event, StreamError, StreamId, TransportOps};
use std::collections::HashMap;

const N: usize = 100;

#[derive(Default)]
struct St {
    fin_rx: bool,
    got: usize,
    sent: bool,
    done: bool,
}

/// Reads what is there; a reset is answered with a reset (as the relay does, spec §5.6).
fn serve_read(p: &Pair, server: bool, s: StreamId, st: &mut St) {
    let peer = if server { &p.server } else { &p.client };
    match read_all(peer, p.now, s) {
        Ok((b, fin)) => {
            st.got += b.len();
            st.fin_rx |= fin;
        }
        Err(StreamError::Reset) => reset(p, server, s, st),
        Err(e) => panic!("stream {s:?}: {e:?}"),
    }
}

fn reset(p: &Pair, server: bool, s: StreamId, st: &mut St) {
    let peer = if server { &p.server } else { &p.client };
    peer.call(p.now, move |t, now| t.stream_reset(now, s));
    st.done = true;
}

/// Streams 0..N: the client resets them — the even ones after reading the server's FIN,
/// the odd ones at once, mid-transfer. Streams N..2N: the server resets them — the even
/// ones after reading the client's FIN, the odd ones mid-transfer.
#[test]
fn hundred_resets_each_side_release_all_slots() {
    let mut p = Pair::new();
    let payload = vec![7u8; 1024];
    let mut cli: Vec<(StreamId, St)> = Vec::new();
    for k in 0..2 * N {
        let s = p.open();
        let client_fin = k >= N && k % 2 == 0;
        assert_eq!(
            send(&p.client, p.now, s, payload.clone(), client_fin),
            Ok(1024)
        );
        let mut st = St::default();
        if k < N && k % 2 == 1 {
            reset(&p, false, s, &mut st);
        }
        cli.push((s, st));
    }
    let mut srv: HashMap<u64, (StreamId, St)> = HashMap::new();

    let ok = p.pump_until(MS, 5000, |p| {
        for (s, i) in new_streams(&p.sev) {
            srv.entry(i.quic_id).or_insert((s, St::default()));
        }
        for (&qid, (s, st)) in srv.iter_mut() {
            let k = (qid / 4) as usize;
            if st.done {
                continue;
            }
            serve_read(p, true, *s, st);
            if st.done {
                continue;
            }
            if k < N && !st.sent {
                let fin = k % 2 == 0;
                assert_eq!(send(&p.server, p.now, *s, payload.clone(), fin), Ok(1024));
                st.sent = true;
            }
            let reset_now = k >= N && if k % 2 == 0 { st.fin_rx } else { st.got > 0 };
            if reset_now {
                reset(p, true, *s, st);
            }
        }
        for (k, (s, st)) in cli.iter_mut().enumerate() {
            if st.done {
                continue;
            }
            serve_read(p, false, *s, st);
            if !st.done && k < N && st.fin_rx {
                reset(p, false, *s, st);
            }
        }
        let (c, sc) = (p.conn, p.srv_conn);
        stream_count(&p.client, c) == 0 && stream_count(&p.server, sc) == 0
    });
    assert!(
        ok,
        "slots left: client {}, server {}",
        stream_count(&p.client, p.conn),
        stream_count(&p.server, p.srv_conn)
    );
    assert_eq!(srv.len(), 2 * N, "every stream reached the server");
    let closed = |ev: &[Event]| {
        ev.iter()
            .filter(|e| matches!(e, Event::StreamClosed(_)))
            .count()
    };
    assert_eq!(closed(&p.cev), 2 * N);
    assert_eq!(closed(&p.sev), 2 * N);
    assert!(p.client_closed().is_none() && p.server_closed().is_none());
}

/// spec §4.2: the peer sends FIN, the local side reads it, then the peer resets: a
/// `StreamReadable` arrives, `stream_recv` returns `Err(Reset)`, and the slot is released.
#[test]
fn reset_after_fin_is_reported_as_readable_then_reset() {
    let mut p = Pair::new();
    let cs = p.open();
    assert_eq!(send(&p.client, p.now, cs, b"req".to_vec(), true), Ok(3));
    p.exchange();
    let ss = new_streams(&p.sev)[0].0;
    assert_eq!(recv(&p.server, p.now, ss, 64), Ok((b"req".to_vec(), true)));
    assert_eq!(send(&p.server, p.now, ss, b"resp".to_vec(), true), Ok(4));
    p.exchange();
    assert_eq!(recv(&p.client, p.now, cs, 64), Ok((b"resp".to_vec(), true)));
    let seen = p.cev.len();

    p.server.call(p.now, move |t, now| t.stream_reset(now, ss));
    p.exchange();
    assert_eq!(
        stream_events(&p.cev[seen..], cs),
        vec![Event::StreamReadable(cs)],
        "the reset after FIN is announced as readable"
    );
    assert_eq!(recv(&p.client, p.now, cs, 64), Err(StreamError::Reset));
    let c = p.conn;
    assert!(p.pump_until(MS, 1000, |p| stream_count(&p.client, c) == 0));
    assert!(stream_events(&p.cev[seen..], cs).contains(&Event::StreamClosed(cs)));
    assert_eq!(
        p.client.call(p.now, move |t, _| t.stream_info(cs)),
        Err(mq_transport_api::Error::Stale)
    );
    let sc = p.srv_conn;
    assert!(p.pump_until(MS, 1000, |p| stream_count(&p.server, sc) == 0));
}
