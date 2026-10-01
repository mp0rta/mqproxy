//! spec §7, §8.4: sparse stream ids. A peer stream id makes xquic hold an entry for every
//! lower id it skipped; the fork's implicit-stream cap (`max_implicit_streams`, 16384 live
//! entries) closes the connection with `TRA_STREAM_LIMIT_ERROR` before it would grow past it.
//! The facade's slot ceiling cannot see those entries, so this asserts the close itself.
mod common;

use common::pair::{MS, Pair, new_streams, send, stream_count};
use mq_transport_api::{CloseReason, ErrType, Event, StreamId, TransportOps};

const CAP: u64 = 16384;
/// QUIC id step: each stream skips 249 client-bidi ids (the first one 250: ids 0..=996).
const SPACING: u64 = 1000;
const TRA_STREAM_LIMIT_ERROR: u64 = 0x4;

/// Opens client stream `quic_id` and sends one byte on it; retries after a tick while the
/// client has no credit for that id yet (the server's MAX_STREAMS grows as it sees ids).
fn open_sparse(p: &mut Pair, quic_id: u64) -> StreamId {
    for _ in 0..100 {
        let c = p.conn;
        let r = p
            .client
            .call(p.now, move |t, now| t.open_stream_with_id(now, c, quic_id));
        if let Ok(s) = r {
            assert_eq!(send(&p.client, p.now, s, vec![1], false), Ok(1));
            return s;
        }
        p.tick(MS);
    }
    panic!("no stream credit for id {quic_id}");
}

fn implicit(p: &Pair) -> u64 {
    let c = p.srv_conn;
    p.server.call(p.now, move |t, _| t.implicit_stream_count(c))
}

#[test]
fn sparse_ids_hit_the_implicit_stream_cap() {
    let mut p = Pair::new();
    let mut live = 0u64; // the server's live gap entries, as the cap counts them
    let mut next_index = 0u64; // lowest client-bidi index the server has not seen
    let mut quic_id = 0u64;
    let mut opened = 0u32;
    let gaps = loop {
        quic_id += SPACING;
        let gaps = quic_id / 4 - next_index;
        if live + gaps > CAP {
            break gaps;
        }
        // open, one byte, reset: the client's own slot drains, the server keeps its entries
        let s = open_sparse(&mut p, quic_id);
        p.client.call(p.now, move |t, now| t.stream_reset(now, s));
        p.tick(MS);
        live += gaps;
        next_index = quic_id / 4 + 1;
        opened += 1;
        assert_eq!(implicit(&p), live, "after id {quic_id}");
        assert_eq!(p.server_closed(), None);
        p.cev.retain(|e| matches!(e, Event::ConnClosed(..)));
    };
    assert_eq!(new_streams(&p.sev).len(), opened as usize);
    let srv_streams = stream_count(&p.server, p.srv_conn);

    // The client holds credit for this id (the hook checks it), so the server's MAX_STREAMS
    // admits it: only the implicit-entry cap can refuse it.
    open_sparse(&mut p, quic_id);
    assert!(live <= CAP && live + gaps > CAP);
    for d in p.client.pump_out(p.now) {
        p.server.deliver(p.now, d.to, d.from, d.data);
    }
    // Refused before insertion: no entry, no stream, no slot.
    assert_eq!(implicit(&p), live);
    assert_eq!(stream_count(&p.server, p.srv_conn), srv_streams);
    assert!(new_streams(&p.server.drain_events()).is_empty());

    // Both sides report the transport error: the server's close is xquic's own, not a
    // `close_conn`, so it is not marked as locally initiated.
    assert!(p.pump_until(10 * MS, 2000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    let want = Some(CloseReason {
        err_type: ErrType::Transport,
        code: TRA_STREAM_LIMIT_ERROR,
    });
    assert_eq!(p.client_closed(), want);
    assert_eq!(p.server_closed(), want);
}
