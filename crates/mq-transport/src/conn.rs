// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Connections: connect, close, stats, paths, packet input, `drive` (spec §4.2–§4.4, §4.7).

use crate::engine::conn_settings;
use crate::ffi::to_sockaddr;
use crate::ffi::trampolines::ud_of;
use crate::slots::ConnSlot;
use crate::{Inner, Transport, clock};
use core::ptr;
use mq_transport_api::{
    ConnConfig, ConnId, ConnProto, ConnStats, ConnectError, Error, PathError, PathId, PathStats,
    SlotId, Time,
};
use std::ffi::CString;
use std::net::SocketAddr;
use xquic_sys::*;

/// spec §4.2: xquic finds conn and path from the packet's CID.
pub(crate) fn recv_datagram(
    t: &mut Transport,
    now: Time,
    local: SocketAddr,
    peer: SocketAddr,
    data: &[u8],
) {
    let (l, llen) = to_sockaddr(local);
    let (p, plen) = to_sockaddr(peer);
    t.with_engine(now, |_, engine| {
        // SAFETY: the engine is live; every pointer outlives the call and xquic copies what it keeps.
        unsafe {
            xqc_engine_packet_process(
                engine,
                data.as_ptr(),
                data.len(),
                (&l as *const libc::sockaddr_storage).cast(),
                llen,
                (&p as *const libc::sockaddr_storage).cast(),
                plen,
                now.as_micros(),
                ptr::null_mut(),
            )
        };
    })
}

/// spec §4.2 `drive`, §4.3, §4.7.
pub(crate) fn drive(t: &mut Transport, now: Time) {
    let inner = &mut *t.inner;
    inner.deadline = None; // spec §4.3: cleared before the engine runs
    let mut expired = Vec::new();
    let mut closes = Vec::new();
    for (s, c) in inner.conns.iter_live() {
        if c.provisional_deadline.is_some_and(|d| d <= now) {
            expired.push((s, c.cid));
        }
        if c.pending_close.is_some() {
            closes.push(s);
        }
    }
    for (s, _) in &expired {
        // Dropped from scheduling; `provisional` stays true until `server_refuse` (spec §4.7).
        if let Some(c) = inner.conns.get_mut(*s) {
            c.provisional_deadline = None;
        }
    }
    t.with_engine(now, |inner, engine| {
        // SAFETY: the engine is live. `inner` is only dereferenced in statement-sized scopes
        // between xquic calls; a slot that is live holds a valid connection pointer (slots
        // are released in the destroy notifications, before xquic frees the connection).
        unsafe {
            for (_, cid) in &expired {
                xqc_conn_close(engine, cid);
            }
            for s in closes {
                let Some((xqc, code)) = (*inner)
                    .conns
                    .get_mut(s)
                    .and_then(|c| Some((c.xqc, c.pending_close.take()?)))
                else {
                    continue;
                };
                mark_closed_locally(inner, s, xqc);
                xqc_conn_close_with_error(xqc, code);
                // Build the CONNECTION_CLOSE now, not at the connection's next wakeup.
                xqc_conn_continue_send_by_conn(xqc);
            }
            xqc_engine_main_logic(engine);
            // By pointer: the cid can have been retired (spec §4.4).
            for c in (*inner).txq.take_resumable() {
                if let Some(xqc) = (*inner).conns.get(c.slot()).map(|c| c.xqc) {
                    xqc_conn_continue_send_by_conn(xqc);
                }
            }
        }
    })
}

/// The earlier of xquic's deadline and the earliest provisional deadline (spec §4.7).
// ponytail: O(conns) scan per call; keep a min-heap of deadlines if conns grow large.
pub(crate) fn next_timeout(inner: &Inner) -> Option<Time> {
    let provisional = inner
        .conns
        .iter_live()
        .filter_map(|(_, c)| c.provisional_deadline)
        .min();
    inner.deadline.into_iter().chain(provisional).min()
}

/// spec §4.8: the slot is allocated before `xqc_connect` and freed if it fails.
pub(crate) fn connect(
    t: &mut Transport,
    now: Time,
    cfg: &ConnConfig,
) -> Result<ConnId, ConnectError> {
    t.inner.last_now = now;
    let sni = CString::new(cfg.sni).map_err(|_| ConnectError::Other(-1))?;
    let settings = conn_settings(&t.inner.cfg, cfg.idle_timeout);
    let (peer, peerlen) = to_sockaddr(cfg.peer);
    let alpn = match cfg.proto {
        ConnProto::Raw => t.inner.alpn.as_ptr(),
        ConnProto::H3 => c"h3".as_ptr(),
    };
    // SAFETY: a plain C struct; all-zero is valid.
    let zero_cid: xqc_cid_t = unsafe { core::mem::zeroed() };
    let s = t
        .inner
        .conns
        .insert(ConnSlot::new(false, ptr::null_mut(), zero_cid));
    let cid = t.with_engine(now, |_, engine| {
        // SAFETY: the engine is live; settings, SNI, ssl config, peer and ALPN (owned by the
        // boxed Inner) outlive the call and are copied by xquic.
        unsafe {
            let ssl: xqc_conn_ssl_config_t = core::mem::zeroed();
            let peer = (&peer as *const libc::sockaddr_storage).cast();
            // spec §3.2: same settings and user data (the conn slot) for both protocols; the
            // create notification fires synchronously inside the call and binds the slot.
            let cid = xqc_connect(
                engine,
                &settings,
                ptr::null(),
                0,
                sni.as_ptr(),
                0,
                &ssl,
                peer,
                peerlen,
                alpn,
                ud_of(s),
            );
            // Copied before any other xquic call (spec §4.8 "Borrowed data").
            (!cid.is_null()).then(|| cid.read_unaligned())
        }
    });
    let Some(cid) = cid else {
        // xquic may have created and destroyed the connection already: remove only if live.
        t.inner.conns.remove(s);
        return Err(ConnectError::Other(-1));
    };
    match t.inner.conns.get_mut(s) {
        Some(c) => c.cid = cid,
        None => return Err(ConnectError::Other(-1)),
    }
    Ok(ConnId::from_slot(s).expect("live slot ids have a non-zero generation"))
}

fn cid_of(t: &Transport, c: ConnId) -> Option<xqc_cid_t> {
    t.inner.conns.get(c.slot()).map(|s| s.cid)
}

/// spec §4.2: a locally initiated close reports `ErrType::Unknown`. xquic records the error
/// type of every CONNECTION_CLOSE it receives, including the one an xquic peer sends back in
/// answer to ours, so the transport remembers who closed first.
///
/// # Safety
/// Inside `clock::enter`; `xqc` is null or the live connection of slot `s`.
unsafe fn mark_closed_locally(inner: *mut Inner, s: SlotId, xqc: *mut xqc_connection_t) {
    // SAFETY: a plain getter on a live connection.
    if xqc.is_null() || unsafe { xqc_conn_get_err_type(xqc) } == XQC_CONN_ERR_TYPE_UNKNOWN {
        // SAFETY: statement-sized borrow of the live Inner, no xquic call inside.
        if let Some(c) = unsafe { (*inner).conns.get_mut(s) } {
            c.closed_locally = true;
        }
    }
}

/// spec §4.2: a stale id is a no-op.
pub(crate) fn close_conn(t: &mut Transport, now: Time, c: ConnId) {
    t.inner.last_now = now;
    let Some((cid, xqc)) = t.inner.conns.get(c.slot()).map(|s| (s.cid, s.xqc)) else {
        return;
    };
    t.with_engine(now, |inner, engine| {
        // SAFETY: the engine is live; xquic looks the cid up and ignores an unknown one; a
        // live slot holds a valid (or not yet bound, null) connection pointer.
        unsafe {
            mark_closed_locally(inner, c.slot(), xqc);
            xqc_conn_close(engine, &cid)
        }
    });
}

/// adoption spec §3: CONNECTION_CLOSE with an application code; a stale id is a no-op.
pub(crate) fn close_conn_with(t: &mut Transport, now: Time, c: ConnId, code: u64) {
    t.inner.last_now = now;
    let Some(xqc) = t.inner.conns.get(c.slot()).map(|s| s.xqc) else {
        return;
    };
    t.with_engine(now, |inner, _| {
        // SAFETY: as `drive`'s pending_close path: a live slot holds a valid (or not yet
        // bound, null) connection pointer.
        unsafe {
            mark_closed_locally(inner, c.slot(), xqc);
            xqc_conn_close_with_error(xqc, code);
            xqc_conn_continue_send_by_conn(xqc);
        }
    });
}

/// spec §4.2, §6.5. `paths_info` is heap memory the caller frees with libc `free`.
pub(crate) fn conn_stats(t: &Transport, c: ConnId) -> Result<ConnStats, Error> {
    let cid = cid_of(t, c).ok_or(Error::Stale)?;
    let engine = t.inner.engine;
    // `&self`: no `*mut Inner` can be formed, so callbacks (only logging here) see none.
    let st = clock::enter(ptr::null_mut(), t.inner.last_now, || {
        // SAFETY: the engine is live; the cid outlives the call.
        unsafe { xqc_conn_get_stats(engine, &cid) }
    });
    let paths = if st.paths_info.is_null() {
        Vec::new()
    } else {
        // SAFETY: xquic allocated `paths_info_count` entries.
        let infos =
            unsafe { core::slice::from_raw_parts(st.paths_info, st.paths_info_count as usize) };
        infos
            .iter()
            .map(|p| PathStats {
                id: p.path_id,
                state: u32::from(p.path_state),
                srtt_us: p.path_srtt,
                est_bw: p.path_est_bw,
                sent_bytes: p.path_send_bytes,
                recv_bytes: p.path_recv_bytes,
                lost_count: u64::from(p.path_lost_count),
                min_rtt_us: p.path_min_rtt,
                cwnd: p.path_cwnd,
                bytes_in_flight: p.path_bytes_in_flight,
            })
            .collect()
    };
    // SAFETY: allocated by xquic with malloc; free(NULL) is a no-op.
    unsafe { libc::free(st.paths_info.cast()) };
    Ok(ConnStats {
        mp_state: st.mp_state,
        app_bytes: st.total_app_bytes,
        standby_bytes: st.standby_path_app_bytes,
        paths,
    })
}

/// spec §4.2: `NoPathId` until xquic has a path id; `MpReady` is raised again then.
pub(crate) fn add_path(
    t: &mut Transport,
    now: Time,
    c: ConnId,
    standby: bool,
) -> Result<PathId, PathError> {
    t.inner.last_now = now;
    let cid = cid_of(t, c).ok_or(PathError::Stale)?;
    t.with_engine(now, |_, engine| {
        let mut pid = 0u64;
        // SAFETY: the engine is live; the cid and `pid` outlive the calls.
        unsafe {
            // 0 = AVAILABLE; the status is then set explicitly.
            let r = xqc_conn_create_path(engine, &cid, &mut pid, 0);
            if r == -(XQC_EMP_NO_AVAIL_PATH_ID as xqc_int_t) {
                return Err(PathError::NoPathId);
            }
            if r < 0 {
                return Err(PathError::Other);
            }
            let m = if standby {
                xqc_conn_mark_path_standby(engine, &cid, pid)
            } else {
                xqc_conn_mark_path_available(engine, &cid, pid)
            };
            if m < 0 {
                log::warn!("add_path: marking path {pid} (standby={standby}) failed: {m}");
            }
        }
        Ok(PathId(pid))
    })
}
