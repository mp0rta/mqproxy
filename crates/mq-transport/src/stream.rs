//! Streams: open, send, recv, reset, info, and the abandoned drain (spec §4.2, §4.8).

use crate::ffi::trampolines::{STREAM_CEILING, ud_of};
use crate::slots::StreamSlot;
use crate::{Inner, Transport};
use core::ptr;
use mq_transport_api::{
    ConnId, Error, Role, SlotId, StreamError, StreamId, StreamInfo, StreamKind, Time,
};
use xquic_sys::*;

fn stream_err(r: isize) -> StreamError {
    match u32::try_from(-r).unwrap_or(0) {
        XQC_EAGAIN => StreamError::Blocked,
        XQC_ESTREAM_RESET | XQC_ESTREAM_ST => StreamError::Reset,
        _ => StreamError::Conn,
    }
}

/// spec §4.2: client only, at most 8192 stream slots per connection; the slot is allocated
/// before `xqc_stream_create` and released if it fails (spec §4.8).
pub(crate) fn open_stream(t: &mut Transport, now: Time, c: ConnId) -> Result<StreamId, Error> {
    t.inner.last_now = now;
    if matches!(t.inner.cfg.role, Role::Server { .. }) {
        return Err(Error::Role); // xqc_stream_create always makes a client-initiated id
    }
    let conn = t.inner.conns.get_mut(c.slot()).ok_or(Error::Stale)?;
    if conn.streams >= STREAM_CEILING {
        return Err(Error::Ceiling);
    }
    conn.streams += 1;
    let cid = conn.cid;
    let s = t.inner.streams.insert(StreamSlot::new(
        c.slot(),
        ptr::null_mut(),
        0,
        StreamKind::Bidi,
    ));
    let created = t.with_engine(now, |_, engine| {
        // SAFETY: the engine is live; the cid outlives the call. The create notification
        // binds the slot; the id is read before any other xquic call.
        unsafe {
            let xs = xqc_stream_create(engine, &cid, ptr::null_mut(), ud_of(s));
            (!xs.is_null()).then(|| (xs, xqc_stream_id(xs)))
        }
    });
    let inner = &mut *t.inner;
    match (created, inner.streams.get_mut(s)) {
        (Some((xs, quic_id)), Some(slot)) => {
            slot.xqc = xs;
            slot.quic_id = quic_id;
            Ok(StreamId::from_slot(s).expect("live slot ids have a non-zero generation"))
        }
        (None, Some(_)) => {
            inner.streams.remove(s);
            if let Some(conn) = inner.conns.get_mut(c.slot()) {
                conn.streams -= 1;
            }
            Err(Error::Other)
        }
        // Released by a close notification inside the call (spec §4.8).
        (_, None) => Err(Error::Other),
    }
}

/// The stream's xquic pointer and its connection's slot.
fn xqc_of(t: &Transport, s: StreamId) -> Result<(*mut xqc_stream_t, SlotId), StreamError> {
    t.inner
        .streams
        .get(s.slot())
        .filter(|x| !x.xqc.is_null())
        .map(|x| (x.xqc, x.conn))
        .ok_or(StreamError::Stale)
}

/// A `xqc_stream_recv` that makes a stream terminal (FIN read, reset consumed) arms the
/// connection's stream-close timer, but outside the engine's own processing nothing reschedules
/// the connection, so the timer would wait for unrelated traffic. Running the connection logic
/// reschedules it and re-reports the deadline through `set_event_timer`. Inside a callback
/// xquic ignores this call and reschedules on its own when the callback returns.
fn wake_conn(inner: *mut Inner, conn: SlotId) {
    // SAFETY: statement-sized borrow of the live Inner; a live conn slot holds a valid pointer.
    if let Some(xqc) = unsafe { (*inner).conns.get(conn).map(|c| c.xqc) } {
        // SAFETY: as above; no reference into Inner is held across the call.
        unsafe { xqc_conn_continue_send_by_conn(xqc) };
    }
}

/// spec §4.2: `Ok(n)`; xquic commits the FIN only when all of `data` was accepted.
pub(crate) fn stream_send(
    t: &mut Transport,
    now: Time,
    s: StreamId,
    data: &[u8],
    fin: bool,
) -> Result<usize, StreamError> {
    t.inner.last_now = now;
    let (xs, _) = xqc_of(t, s)?;
    // SAFETY: a live slot holds a valid stream (released in its close notification, before
    // xquic frees it); xquic does not write through the data pointer.
    let r = t.with_engine(now, |_, _| unsafe {
        xqc_stream_send(xs, data.as_ptr().cast_mut(), data.len(), u8::from(fin))
    });
    if r < 0 {
        Err(stream_err(r))
    } else {
        Ok(r as usize)
    }
}

/// spec §4.2: always calls xquic (also after FIN: that call is what makes a reset after FIN
/// terminal); an empty `buf` is a reset probe.
pub(crate) fn stream_recv(
    t: &mut Transport,
    now: Time,
    s: StreamId,
    buf: &mut [u8],
) -> Result<(usize, bool), StreamError> {
    t.inner.last_now = now;
    let (xs, conn) = xqc_of(t, s)?;
    let mut fin = 0u8;
    let r = t.with_engine(now, |inner, _| {
        // SAFETY: as in `stream_send`; `buf` is writable for its length.
        let r = unsafe { xqc_stream_recv(xs, buf.as_mut_ptr(), buf.len(), &mut fin) };
        if fin != 0 || r == -(XQC_ESTREAM_RESET as isize) {
            wake_conn(inner, conn);
        }
        r
    });
    if r < 0 {
        return Err(stream_err(r));
    }
    if fin != 0 {
        if let Some(slot) = t.inner.streams.get_mut(s.slot()) {
            slot.fin_seen = true;
        }
    }
    Ok((r as usize, fin != 0))
}

/// spec §4.8: reset, then drain the abandoned stream so xquic can close it.
pub(crate) fn stream_reset(t: &mut Transport, now: Time, s: StreamId) {
    t.inner.last_now = now;
    let Ok((xs, conn)) = xqc_of(t, s) else {
        return;
    };
    t.with_engine(now, |inner, _| {
        // SAFETY: `xs` is valid (live slot). `xqc_stream_close` runs connection logic and
        // notifications can fire inside it, so the slot is looked up again afterwards, in a
        // statement-sized scope.
        let live = unsafe {
            xqc_stream_close(xs);
            match (*inner).streams.get_mut(s.slot()) {
                Some(slot) => {
                    slot.abandoned = true;
                    true
                }
                None => false,
            }
        };
        if live {
            drain(inner, s.slot());
            wake_conn(inner, conn);
        }
    })
}

/// spec §4.8 "Abandoned streams": read into scratch until xquic reports nothing more (≤ 0) or
/// FIN. Runs even after FIN: a RESET_STREAM after FIN is made terminal only by this call.
/// Must run inside `clock::enter`; holds no reference into `Inner` across `xqc_stream_recv`.
pub(crate) fn drain(inner: *mut Inner, s: SlotId) {
    let mut scratch = [0u8; 4096];
    loop {
        // SAFETY: `inner` is the live Box<Inner> of the transport inside xquic; this
        // statement-sized borrow ends before the xquic call.
        let Some(xs) = (unsafe { (*inner).streams.get(s).map(|x| x.xqc) }) else {
            return;
        };
        if xs.is_null() {
            return;
        }
        let mut fin = 0u8;
        // SAFETY: a live slot holds a valid stream.
        let r = unsafe { xqc_stream_recv(xs, scratch.as_mut_ptr(), scratch.len(), &mut fin) };
        if fin != 0 {
            // SAFETY: as above.
            if let Some(slot) = unsafe { (*inner).streams.get_mut(s) } {
                slot.fin_seen = true;
            }
        }
        if r <= 0 || fin != 0 {
            return;
        }
    }
}

pub(crate) fn stream_info(t: &Transport, s: StreamId) -> Result<StreamInfo, Error> {
    let slot = t.inner.streams.get(s.slot()).ok_or(Error::Stale)?;
    Ok(StreamInfo {
        conn: ConnId::from_slot(slot.conn).ok_or(Error::Stale)?,
        quic_id: slot.quic_id,
        kind: slot.kind,
    })
}
