//! spec §4.2, §4.8: at most 8192 stream slots per connection. A peer stream over the
//! ceiling gets no slot and no event, and closes the connection with application error
//! `0x1001`; the client's own `open_stream` refuses at the ceiling.
//!
//! The "several peer streams inside one datagram" case cannot be built through the facade
//! (xquic never puts STREAM frames of two streams in one packet); it is covered by the unit
//! test `ceiling_checked_per_callback_not_per_drive` in `ffi::trampolines`.
mod common;

use common::lockstep::Datagram;
use common::pair::{MS, Pair, closed, new_streams, send, stream_count};
use mq_transport_api::{CloseReason, ErrType, Event, StreamId, TransportOps};

const CEILING: u32 = 8192;
const CLOSE_CODE: u64 = 0x1001;

fn pending_close(p: &Pair) -> Option<u64> {
    let c = p.srv_conn;
    p.server.call(p.now, move |t, _| t.pending_close(c))
}

/// Opens a client stream and sends one byte on it; retries after a tick while xquic has no
/// stream credit yet (MAX_STREAMS grows as the server sees higher ids).
fn open_with_byte(p: &mut Pair) -> StreamId {
    for _ in 0..100 {
        let c = p.conn;
        if let Ok(s) = p.client.call(p.now, move |t, now| t.open_stream(now, c)) {
            assert_eq!(send(&p.client, p.now, s, vec![1], false), Ok(1));
            return s;
        }
        p.tick(MS);
    }
    panic!(
        "open_stream kept failing at {} client streams",
        stream_count(&p.client, p.conn)
    );
}

fn reset(p: &Pair, s: StreamId) {
    p.client.call(p.now, move |t, now| t.stream_reset(now, s));
}

/// 8192 iterations of open, one byte, reset — advancing `now` by 1 ms and driving each
/// time: xquic releases a finished stream only when its close timer (3 × PTO) fires, so
/// with a fixed clock the client's own slots would never drain. The server never reads,
/// so its slots pile up to the ceiling.
fn server_at_ceiling() -> Pair {
    let mut p = Pair::new();
    for _ in 0..CEILING {
        let s = open_with_byte(&mut p);
        reset(&p, s);
        p.tick(MS);
        p.sev
            .retain(|e| matches!(e, Event::NewStream(..) | Event::ConnClosed(..)));
        p.cev.retain(|e| matches!(e, Event::ConnClosed(..)));
    }
    assert_eq!(stream_count(&p.server, p.srv_conn), CEILING);
    assert_eq!(new_streams(&p.sev).len(), CEILING as usize);
    assert!(
        stream_count(&p.client, p.conn) < CEILING,
        "client slots drained"
    );
    assert_eq!(pending_close(&p), None);
    p
}

/// Delivers what the client has queued to the server without driving it.
fn deliver_only(p: &Pair) -> Vec<Datagram> {
    let out = p.client.pump_out(p.now);
    assert!(!out.is_empty());
    for d in &out {
        p.server.deliver(p.now, d.to, d.from, d.data.clone());
    }
    out
}

/// After the deferred close: the client sees the application error, the server its own
/// (locally initiated) close.
fn assert_closed_with_ceiling_code(p: &mut Pair) {
    assert!(p.pump_until(10 * MS, 2000, |p| {
        p.client_closed().is_some() && p.server_closed().is_some()
    }));
    assert_eq!(
        p.client_closed(),
        Some(CloseReason {
            err_type: ErrType::Application,
            code: CLOSE_CODE
        })
    );
    let r = p.server_closed().unwrap();
    assert_eq!((r.err_type, r.code), (ErrType::Unknown, CLOSE_CODE));
}

#[test]
fn peer_stream_over_ceiling_closes_connection() {
    let mut p = server_at_ceiling();
    let s = open_with_byte(&mut p);
    reset(&p, s);
    deliver_only(&p);
    // Between delivery and the next drive: checked before allocating (spec §4.8).
    assert_eq!(stream_count(&p.server, p.srv_conn), CEILING);
    let ev = p.server.drain_events();
    assert!(new_streams(&ev).is_empty(), "{ev:?}");
    assert_eq!(pending_close(&p), Some(CLOSE_CODE));
    p.server.drive(p.now);
    assert_closed_with_ceiling_code(&mut p);
}

/// A RESET_STREAM for the rejected (DISCARDED) stream reaches the read trampoline with null
/// user data: no event, no slot change, no panic.
#[test]
fn discarded_stream_reset_notifies_with_null_ud_and_is_ignored() {
    let mut p = server_at_ceiling();
    let s = open_with_byte(&mut p);
    deliver_only(&p);
    assert_eq!(pending_close(&p), Some(CLOSE_CODE));
    assert!(new_streams(&p.server.drain_events()).is_empty());

    reset(&p, s);
    deliver_only(&p);
    assert_eq!(stream_count(&p.server, p.srv_conn), CEILING);
    // xquic re-notifies the admitted streams whose resets nobody read; nothing else arrives
    // (the discarded stream has no slot, so any event for it would carry an unknown id).
    let known: std::collections::HashSet<StreamId> =
        new_streams(&p.sev).into_iter().map(|x| x.0).collect();
    for e in p.server.drain_events() {
        assert!(
            matches!(e, Event::StreamReadable(x) if known.contains(&x)),
            "unexpected {e:?}"
        );
    }
    assert_eq!(pending_close(&p), Some(CLOSE_CODE), "set once, stays set");
    p.server.drive(p.now);
    assert_closed_with_ceiling_code(&mut p);
}

/// The client opens streams without resetting them, one byte each, pumping both ways so the
/// server sees the ids and its MAX_STREAMS updates arrive (xquic's initial credit is 1024
/// streams). At 8192 live streams nothing closes; the 8193rd `open_stream` is refused.
#[test]
fn client_open_stream_refused_at_ceiling() {
    let mut p = Pair::new();
    for _ in 0..CEILING {
        open_with_byte(&mut p);
        p.exchange();
        p.sev
            .retain(|e| matches!(e, Event::NewStream(..) | Event::ConnClosed(..)));
        p.cev.clear();
    }
    assert_eq!(stream_count(&p.client, p.conn), CEILING);
    p.tick(MS);
    assert_eq!(stream_count(&p.server, p.srv_conn), CEILING);
    assert_eq!(new_streams(&p.sev).len(), CEILING as usize);
    let c = p.conn;
    assert_eq!(
        p.client.call(p.now, move |t, now| t.open_stream(now, c)),
        Err(mq_transport_api::Error::Ceiling)
    );
    assert_eq!(
        stream_count(&p.client, p.conn),
        CEILING,
        "no slot for the refused open"
    );
    for _ in 0..100 {
        p.tick(10 * MS);
    }
    assert_eq!(pending_close(&p), None);
    assert_eq!(closed(&p.cev, p.conn), None);
    assert_eq!(closed(&p.sev, p.srv_conn), None);
}
