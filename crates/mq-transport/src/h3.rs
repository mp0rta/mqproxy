//! H3 requests: open, send, recv, reset, info (spec §3.1 contracts, §3.3, §3.4).
//!
//! Every op that calls xquic can run connection logic, whose notifications may release this or
//! any other request (spec §3.1 "Synchronous notifications"): no reference into `Inner` is held
//! across the call, and the slot is looked up again afterwards.

use crate::Transport;
use crate::ffi::trampolines::{READ_HEADER, READ_TRAILER, req_id, ud_of};
use crate::slots::H3ReqSlot;
use crate::stream::{reserve_local, stream_err};
use core::ptr;
use libc::iovec;
use mq_transport_api::{ConnId, Error, H3Header, H3ReqId, H3ReqInfo, StreamError, Time};
use xquic_sys::*;

/// spec §3.3: client only; shares the connection's stream ceiling. The slot is allocated before
/// `xqc_h3_request_create`, whose create notification binds it, and released if xquic fails.
pub(crate) fn open_h3_request(t: &mut Transport, now: Time, c: ConnId) -> Result<H3ReqId, Error> {
    t.inner.last_now = now;
    let cid = reserve_local(&mut t.inner, c, true)?;
    let s = t
        .inner
        .h3reqs
        .insert(H3ReqSlot::new(c.slot(), ptr::null_mut(), 0));
    // SAFETY: the engine is live; the cid outlives the call.
    let created = t.with_engine(now, |_, engine| unsafe {
        !xqc_h3_request_create(engine, &cid, ptr::null_mut(), ud_of(s)).is_null()
    });
    let inner = &mut *t.inner;
    match (created, inner.h3reqs.is_live(s)) {
        (true, true) => Ok(req_id(s)),
        (false, true) => {
            inner.h3reqs.remove(s);
            if let Some(conn) = inner.conns.get_mut(c.slot()) {
                conn.streams -= 1;
            }
            Err(Error::Other)
        }
        // Released by a close notification inside the call (spec §3.1).
        (_, false) => Err(Error::Other),
    }
}

/// The request's xquic pointer; `Stale` for a released (or not yet bound) slot.
fn xqc_of(t: &Transport, r: H3ReqId) -> Result<*mut xqc_h3_request_t, StreamError> {
    t.inner
        .h3reqs
        .get(r.slot())
        .map(|x| x.xqc)
        .filter(|x| !x.is_null())
        .ok_or(StreamError::Stale)
}

fn iov(b: &[u8]) -> iovec {
    iovec {
        iov_base: b.as_ptr().cast_mut().cast(),
        iov_len: b.len(),
    }
}

/// spec §3.1: all-or-error (xquic buffers the whole HEADERS frame); `Blocked` never occurs.
pub(crate) fn h3_send_headers(
    t: &mut Transport,
    now: Time,
    r: H3ReqId,
    hs: &[H3Header<'_>],
    fin: bool,
) -> Result<(), StreamError> {
    t.inner.last_now = now;
    let h3r = xqc_of(t, r)?;
    let mut v: Vec<xqc_http_header_t> = hs
        .iter()
        .map(|h| xqc_http_header_t {
            name: iov(h.name),
            value: iov(h.value),
            flags: 0, // XQC_HTTP_HEADER_FLAG_NONE, as C
            save_nv_hit_flags: 0,
            nv_hit_flags: 0,
            src_header: ptr::null_mut(),
        })
        .collect();
    let mut headers = xqc_http_headers_t {
        headers: v.as_mut_ptr(),
        count: v.len(),
        capacity: v.len(),
        total_len: hs.iter().map(|h| h.name.len() + h.value.len()).sum(),
    };
    // SAFETY: a live slot holds a valid request; xquic copies the headers and does not write
    // through the name/value pointers.
    let n = t.with_engine(now, |_, _| unsafe {
        xqc_h3_request_send_headers(h3r, &mut headers, u8::from(fin))
    });
    match n {
        0.. => Ok(()),
        n if n == -(XQC_ESTREAM_RESET as isize) => Err(StreamError::Reset),
        _ => Err(StreamError::Conn),
    }
}

/// spec §3.1: the `stream_send` contract.
pub(crate) fn h3_send_body(
    t: &mut Transport,
    now: Time,
    r: H3ReqId,
    data: &[u8],
    fin: bool,
) -> Result<usize, StreamError> {
    t.inner.last_now = now;
    let h3r = xqc_of(t, r)?;
    // SAFETY: as in `h3_send_headers`; xquic does not write through the data pointer.
    let n = t.with_engine(now, |_, _| unsafe {
        xqc_h3_request_send_body(h3r, data.as_ptr().cast_mut(), data.len(), u8::from(fin))
    });
    if n < 0 {
        Err(stream_err(n))
    } else {
        Ok(n as usize)
    }
}

/// spec §3.1: a bare FIN; EAGAIN means queued (the write notify flushes it).
pub(crate) fn h3_finish(t: &mut Transport, now: Time, r: H3ReqId) -> Result<(), StreamError> {
    t.inner.last_now = now;
    let h3r = xqc_of(t, r)?;
    // SAFETY: as in `h3_send_headers`.
    let n = t.with_engine(now, |_, _| unsafe { xqc_h3_request_finish(h3r) });
    if n >= 0 || n == -(XQC_EAGAIN as isize) {
        Ok(())
    } else {
        Err(StreamError::Conn)
    }
}

/// Calls `each` for every field of a section xquic returned.
///
/// # Safety
/// `hs` is a header section of a live request, unchanged for this call.
pub(crate) unsafe fn for_each_header(
    hs: *const xqc_http_headers_t,
    each: &mut dyn FnMut(&[u8], &[u8]),
) {
    let bytes = |v: &iovec| {
        if v.iov_len == 0 {
            &[][..]
        } else {
            // SAFETY: xquic's decoded field: `iov_len` readable bytes.
            unsafe { core::slice::from_raw_parts(v.iov_base.cast::<u8>(), v.iov_len) }
        }
    };
    // SAFETY: guaranteed by the caller.
    let hs = unsafe { &*hs };
    for k in 0..hs.count {
        // SAFETY: `count` entries are initialised.
        let h = unsafe { &*hs.headers.add(k) };
        each(bytes(&h.name), bytes(&h.value));
    }
}

/// spec §3.4: gated on the HEADER flag; a pending trailer section is drained (discarded) right
/// after the header section. Returns the header call's own fin.
pub(crate) fn h3_recv_headers(
    t: &mut Transport,
    now: Time,
    r: H3ReqId,
    each: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<bool, StreamError> {
    t.inner.last_now = now;
    let h3r = xqc_of(t, r)?;
    let flags = t.inner.h3reqs.get(r.slot()).map_or(0, |x| x.read_flags);
    if flags & READ_HEADER == 0 {
        return Err(StreamError::Blocked);
    }
    let fin = t.with_engine(now, |_, _| {
        let mut fin = 0u8; // xquic logs it before writing it
        // SAFETY: a live slot holds a valid request; getters that fire no notification.
        unsafe {
            let hs = xqc_h3_request_recv_headers(h3r, &mut fin);
            if hs.is_null() {
                return None;
            }
            for_each_header(hs, each);
            if flags & READ_TRAILER != 0 {
                let mut trailer_fin = 0u8;
                xqc_h3_request_recv_headers(h3r, &mut trailer_fin);
            }
        }
        Some(fin != 0)
    });
    let fin = fin.ok_or(StreamError::Conn)?;
    if let Some(x) = t.inner.h3reqs.get_mut(r.slot()) {
        x.read_flags &= !(READ_HEADER | READ_TRAILER);
        x.header_consumed = true;
        x.fin_consumed |= fin;
    }
    Ok(fin)
}

/// spec §3.4: `(n, fin)`; nothing and no fin is `Blocked`; an empty FIN is `(0, true)`.
pub(crate) fn h3_recv_body(
    t: &mut Transport,
    now: Time,
    r: H3ReqId,
    buf: &mut [u8],
) -> Result<(usize, bool), StreamError> {
    t.inner.last_now = now;
    let h3r = xqc_of(t, r)?;
    let mut fin = 0u8;
    // SAFETY: as in `h3_recv_headers`; `buf` is writable for its length.
    let n = t.with_engine(now, |_, _| unsafe {
        xqc_h3_request_recv_body(h3r, buf.as_mut_ptr(), buf.len(), &mut fin)
    });
    if n < 0 {
        return Err(stream_err(n));
    }
    if fin == 0 {
        return if n == 0 {
            Err(StreamError::Blocked)
        } else {
            Ok((n as usize, false))
        };
    }
    if let Some(x) = t.inner.h3reqs.get_mut(r.slot()) {
        x.fin_consumed = true;
    }
    Ok((n as usize, true))
}

/// spec §3.1: RESET_STREAM (+ STOP_SENDING); the slot is released in the close notification.
pub(crate) fn h3_reset(t: &mut Transport, now: Time, r: H3ReqId) {
    t.inner.last_now = now;
    if let Ok(h3r) = xqc_of(t, r) {
        // SAFETY: as in `h3_send_headers`.
        t.with_engine(now, |_, _| unsafe { xqc_h3_request_close(h3r) });
    }
}

pub(crate) fn h3_req_info(t: &Transport, r: H3ReqId) -> Result<H3ReqInfo, Error> {
    let x = t.inner.h3reqs.get(r.slot()).ok_or(Error::Stale)?;
    Ok(H3ReqInfo {
        conn: ConnId::from_slot(x.conn).ok_or(Error::Stale)?,
        quic_id: x.quic_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::trampolines::STREAM_CEILING;
    use mq_transport_api::{
        CongestionControl, ConnConfig, ConnProto, Role, Scheduler, TransportConfig, TransportOps,
    };

    /// A client transport with one (unestablished) connection of `proto`.
    fn client(proto: ConnProto) -> (Transport, ConnId) {
        let mut t = Transport::new(TransportConfig {
            role: Role::Client,
            alpn: "mqproxy-tcp/1",
            max_conns: 0,
            scheduler: Scheduler::MinRtt,
            cc: CongestionControl::Bbr,
            realtime_offset_us: 0,
            h3: true,
            qlog: None,
        })
        .expect("transport");
        let cc = ConnConfig {
            peer: "10.0.0.1:4433".parse().unwrap(),
            sni: "mqproxy",
            idle_timeout: None,
            proto,
        };
        let c = t.connect(Time(1), &cc).expect("connect");
        (t, c)
    }

    /// spec §3.3: requests share the per-connection 8192 ceiling with streams.
    #[test]
    fn h3_open_request_shares_stream_ceiling() {
        let (mut t, c) = client(ConnProto::H3);
        t.inner.conns.get_mut(c.slot()).unwrap().streams = STREAM_CEILING - 1;
        t.open_h3_request(Time(1), c)
            .expect("the 8192nd is admitted");
        assert_eq!(t.inner.conns.get(c.slot()).unwrap().streams, STREAM_CEILING);
        assert_eq!(t.open_h3_request(Time(1), c), Err(Error::Ceiling));
        assert_eq!(t.inner.h3reqs.len_live(), 1, "no slot for the refused one");
        assert_eq!(t.inner.conns.get(c.slot()).unwrap().streams, STREAM_CEILING);
    }

    /// A request needs an H3 connection and a raw stream a raw one: the other protocol's
    /// callbacks would take our slot id for their own state.
    #[test]
    fn open_checks_the_connection_protocol() {
        let (mut t, c) = client(ConnProto::Raw);
        assert_eq!(t.open_h3_request(Time(1), c), Err(Error::Other));
        assert!(t.open_stream(Time(1), c).is_ok());
        drop(t);
        let (mut t, c) = client(ConnProto::H3);
        assert_eq!(t.open_stream(Time(1), c), Err(Error::Other));
        assert_eq!(t.inner.conns.get(c.slot()).unwrap().streams, 0);
    }

    /// spec §3.4: no HEADER bit → `Blocked` without calling xquic; with the bit but nothing
    /// in xquic → `Conn`.
    #[test]
    fn h3_read_flags_gate_recv_headers() {
        let (mut t, c) = client(ConnProto::H3);
        let r = t.open_h3_request(Time(1), c).unwrap();
        let mut each = |_: &[u8], _: &[u8]| panic!("no header section");
        assert_eq!(
            t.h3_recv_headers(Time(1), r, &mut each),
            Err(StreamError::Blocked)
        );
        t.inner.h3reqs.get_mut(r.slot()).unwrap().read_flags = READ_TRAILER;
        assert_eq!(
            t.h3_recv_headers(Time(1), r, &mut each),
            Err(StreamError::Blocked)
        );
        t.inner.h3reqs.get_mut(r.slot()).unwrap().read_flags = READ_HEADER;
        assert_eq!(
            t.h3_recv_headers(Time(1), r, &mut each),
            Err(StreamError::Conn)
        );
        assert!(!t.inner.h3reqs.get(r.slot()).unwrap().header_consumed);
    }
}
