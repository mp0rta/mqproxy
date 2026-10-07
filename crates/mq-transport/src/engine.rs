//! Engine creation, connection settings, logs and qlog (spec §4.9).

use crate::ffi::{app_proto_callbacks, guard, transport_callbacks};
use crate::{Error, Inner, Transport, clock};
use core::ffi::{c_char, c_void};
use core::ptr;
use mq_transport_api::{CongestionControl, ConnProto, Role, Scheduler, Time, TransportConfig};
use std::ffi::CString;
use std::io::Write;
use std::time::Duration;
use xquic_sys::*;

/// Connection settings (spec §4.9), built from a zeroed struct.
/// `idle` is the client's `--keepalive-idle`; the server passes `None`.
/// spec §7: live skipped-id entries a peer may make xquic hold per connection.
pub(crate) const MAX_IMPLICIT_STREAMS: u64 = 16384;
/// SP4 spec §5: the H3 field-section limit on both engines (xquic's default is 32 KiB), with
/// headroom above `mq_http::limits::SECTION_MAX`.
pub const H3_FIELD_SECTION_MAX: usize = 64 * 1024;

pub(crate) fn conn_settings(cfg: &TransportConfig, idle: Option<Duration>) -> xqc_conn_settings_t {
    let server = matches!(cfg.role, Role::Server { .. });
    // SAFETY: a plain C struct of integers, floats, arrays and Option<fn> fields; all-zero is
    // valid.
    let mut s: xqc_conn_settings_t = unsafe { core::mem::zeroed() };
    s.proto_version = XQC_VERSION_V1;
    s.pacing_on = 1;
    s.max_datagram_frame_size = 65535;
    // SP2 spec §3.3: a datagram send queues and arms a 1 µs wakeup; the next drive flushes the run.
    s.defer_send_flush = 1;
    s.enable_multipath = 1;
    s.mp_ping_on = 1;
    // spec §7: cap on implicitly opened (skipped) peer stream ids; explicit, not xquic's 0=default.
    s.max_implicit_streams = MAX_IMPLICIT_STREAMS;
    // SAFETY: by-value copies of immutable statics exported by xquic.
    s.cong_ctrl_callback = unsafe {
        match cfg.cc {
            CongestionControl::Bbr => xqc_bbr_cb,
            CongestionControl::Bbr2 => xqc_bbr2_cb,
            CongestionControl::Cubic => xqc_cubic_cb,
        }
    };
    // SAFETY: as above.
    s.scheduler_callback = unsafe {
        match cfg.scheduler {
            Scheduler::MinRtt => xqc_minrtt_scheduler_cb,
            Scheduler::Backup => xqc_backup_scheduler_cb,
            Scheduler::Wlb => xqc_wlb_scheduler_cb,
        }
    };
    if server {
        s.max_path_id_grant_max_value = 128;
    } else {
        s.max_pkt_out_size = 1200;
        if let Some(d) = idle {
            s.ping_on = 1;
            s.idle_time_out = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        }
    }
    s
}

/// What the server hands `xqc_server_set_conn_settings` (spec §4.9).
fn server_settings(cfg: &TransportConfig) -> xqc_conn_settings_t {
    conn_settings(cfg, None)
}

/// xquic's default engine config with the fields this tree pins.
fn engine_config(ty: xqc_engine_type_t, qlog: bool) -> Option<xqc_config_t> {
    // SAFETY: a plain C struct; xquic fills it.
    let mut config: xqc_config_t = unsafe { core::mem::zeroed() };
    // SAFETY: `config` outlives the call.
    if unsafe { xqc_engine_get_default_config(&mut config, ty) } < 0 {
        return None;
    }
    config.cfg_log_level = XQC_LOG_WARN;
    // Event qlog at EXTRA importance, but only with a qlog file: xquic formats every event
    // before the sink can drop it, and conns copy this flag at creation, so it is fixed here.
    // Pinned rather than left to xquic's defaults so a fork default change cannot drop events.
    config.cfg_log_event = qlog.into();
    config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA;
    Some(config)
}

fn cstring(what: &str, s: impl Into<Vec<u8>>) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::Config(format!("{what} contains a NUL byte")))
}

impl Transport {
    /// spec §4.9. One transport per thread (spec §4.6).
    pub fn new(cfg: TransportConfig) -> Result<Transport, Error> {
        clock::claim_thread(cfg.realtime_offset_us)?;
        // From here on, Drop releases the thread claim on every error path.
        let alpn = match cstring("alpn", cfg.alpn) {
            Ok(a) => a,
            Err(e) => {
                clock::release_thread();
                return Err(e);
            }
        };
        let mut t = Transport {
            inner: Box::new(Inner::new(cfg, alpn)),
        };
        if let Some(dir) = &t.inner.cfg.qlog {
            let name = match t.inner.cfg.role {
                Role::Client => "client.qlog",
                Role::Server { .. } => "server.qlog",
            };
            t.inner.qlog = Some(std::fs::File::create(dir.join(name)).map_err(Error::Qlog)?);
        }
        let qlog_on = t.inner.qlog.is_some();
        let (server, cert, key) = match &t.inner.cfg.role {
            Role::Client => (false, None, None),
            Role::Server { cert, key } => (
                true,
                Some(cstring("cert path", cert.as_os_str().as_encoded_bytes())?),
                Some(cstring("key path", key.as_os_str().as_encoded_bytes())?),
            ),
        };
        let ty = if server {
            XQC_ENGINE_SERVER
        } else {
            XQC_ENGINE_CLIENT
        };
        let settings = server.then(|| server_settings(&t.inner.cfg));
        let alpn_ptr = t.inner.alpn.as_ptr();
        let alpn_len = t.inner.alpn.as_bytes().len();
        let h3_on = t.inner.cfg.h3;
        let inner: *mut Inner = &mut *t.inner;

        let engine = clock::enter(inner, Time(0), || {
            // SAFETY: every pointer passed below outlives the call; xquic copies the ssl config
            // strings, the callback tables and the ALPN registration (xqc_engine.c). Engine user
            // data is SlotId::NONE (= null, spec §4.8): callbacks find Inner via clock::current().
            unsafe {
                let Some(config) = engine_config(ty, qlog_on) else {
                    return ptr::null_mut();
                };
                let mut ssl: xqc_engine_ssl_config_t = core::mem::zeroed();
                ssl.ciphers = XQC_TLS_CIPHERS.as_ptr() as *mut c_char;
                ssl.groups = XQC_TLS_GROUPS.as_ptr() as *mut c_char;
                if let (Some(c), Some(k)) = (&cert, &key) {
                    ssl.cert_file = c.as_ptr() as *mut c_char;
                    ssl.private_key_file = k.as_ptr() as *mut c_char;
                }
                let ecbs = xqc_engine_callback_t {
                    set_event_timer: Some(set_event_timer),
                    log_callbacks: xqc_log_callbacks_t {
                        xqc_log_write_err: Some(log_write),
                        xqc_log_write_stat: Some(log_write),
                        xqc_qlog_event_write: Some(qlog_write),
                    },
                    cid_generate_cb: None,
                    keylog_cb: None,
                    realtime_ts: Some(clock::realtime_ts),
                    monotonic_ts: Some(clock::monotonic_ts),
                };
                let tcbs = transport_callbacks();
                let engine = xqc_engine_create(ty, &config, &ssl, &ecbs, &tcbs, ptr::null_mut());
                if engine.is_null() {
                    return engine;
                }
                let mut ap = app_proto_callbacks(ConnProto::Raw);
                if xqc_engine_register_alpn(engine, alpn_ptr, alpn_len, &mut ap, ptr::null_mut())
                    != 0
                {
                    xqc_engine_destroy(engine);
                    return ptr::null_mut();
                }
                if h3_on {
                    // adoption spec §3, §7 item 1: ALPN `h3` on raw stream callbacks.
                    let mut ap = app_proto_callbacks(ConnProto::H3);
                    if xqc_engine_register_alpn(engine, c"h3".as_ptr(), 2, &mut ap, ptr::null_mut())
                        != 0
                    {
                        xqc_engine_destroy(engine);
                        return ptr::null_mut();
                    }
                }
                if let Some(s) = &settings {
                    xqc_server_set_conn_settings(engine, s);
                }
                engine
            }
        });
        if engine.is_null() {
            return Err(Error::EngineCreate); // Drop releases the thread claim
        }
        t.inner.engine = engine;
        Ok(t)
    }

    /// Destroys the engine under the clock guard (spec §4.2).
    pub fn close(mut self, now: Time) {
        self.destroy(now);
    }

    fn destroy(&mut self, now: Time) {
        let engine = self.inner.engine;
        if engine.is_null() {
            return;
        }
        let inner: *mut Inner = &mut *self.inner;
        // SAFETY: `engine` is live (non-null) and destroyed exactly once: it is nulled below.
        clock::enter(inner, now, || unsafe { xqc_engine_destroy(engine) });
        self.inner.engine = ptr::null_mut();
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let now = self.inner.last_now;
        self.destroy(now);
        clock::release_thread();
    }
}

// ── engine callbacks ────────────────────────────────────────────────────

/// spec §4.3: record the deadline at µs precision; the runtime arms the real timer.
unsafe extern "C" fn set_event_timer(wake_after: xqc_usec_t, _ud: *mut c_void) {
    guard(|| {
        let inner = clock::current();
        if inner.is_null() {
            return;
        }
        let at = Time(clock::monotonic_ts().saturating_add(wake_after));
        // SAFETY: `inner` is the live Box<Inner> set by `clock::enter`; the calling method holds
        // no reference into it across the xquic call (spec §4.8).
        unsafe { (*inner).deadline = Some(at) };
    })
}

/// xquic logs → `log`, with xquic's levels mapped onto `log::Level`.
unsafe extern "C" fn log_write(
    lvl: xqc_log_level_t,
    buf: *const c_void,
    size: usize,
    _ud: *mut c_void,
) {
    guard(|| {
        let level = match lvl {
            XQC_LOG_REPORT | XQC_LOG_FATAL | XQC_LOG_ERROR => log::Level::Error,
            XQC_LOG_WARN => log::Level::Warn,
            XQC_LOG_STATS | XQC_LOG_INFO => log::Level::Info,
            _ => log::Level::Debug,
        };
        if buf.is_null() || !log::log_enabled!(target: "xquic", level) {
            return;
        }
        // SAFETY: xquic passes `size` readable bytes at `buf` for the duration of the call.
        let msg = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), size) };
        log::log!(target: "xquic", level, "[xquic] {}", String::from_utf8_lossy(msg));
    })
}

/// qlog sink: the line plus a newline, only while a file is open.
unsafe extern "C" fn qlog_write(
    _imp: qlog_event_importance_t,
    buf: *const c_void,
    size: usize,
    _ud: *mut c_void,
) {
    guard(|| {
        let inner = clock::current();
        if inner.is_null() || buf.is_null() {
            return;
        }
        // SAFETY: `inner` as in `set_event_timer`; `buf` holds `size` bytes for this call.
        unsafe {
            if let Some(f) = (*inner).qlog.as_mut() {
                let line = core::slice::from_raw_parts(buf.cast::<u8>(), size);
                // Best effort.
                let _ = f.write_all(line).and_then(|()| f.write_all(b"\n"));
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(role: Role, cc: CongestionControl, scheduler: Scheduler) -> TransportConfig {
        TransportConfig {
            role,
            alpn: "mqproxy-tcp/1",
            max_conns: 0,
            scheduler,
            cc,
            realtime_offset_us: 0,
            h3: false,
            qlog: None,
        }
    }

    fn bytes<T>(v: &T) -> &[u8] {
        // SAFETY: reading the bytes of a fully initialised, padding-free C struct of pointers.
        unsafe { core::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
    }

    fn assert_common(s: &xqc_conn_settings_t, cc: CongestionControl, sched: Scheduler) {
        assert_eq!(s.proto_version, XQC_VERSION_V1);
        assert_eq!(s.pacing_on, 1);
        assert_eq!(s.enable_multipath, 1);
        assert_eq!(s.mp_ping_on, 1);
        assert_eq!(s.max_datagram_frame_size, 65535);
        assert_eq!(s.defer_send_flush, 1); // SP2 spec §3.3
        assert_eq!(s.max_implicit_streams, 16384); // spec §7
        // SAFETY: by-value reads of xquic's immutable statics.
        let (want_cc, want_sched) = unsafe {
            (
                match cc {
                    CongestionControl::Bbr => xqc_bbr_cb,
                    CongestionControl::Bbr2 => xqc_bbr2_cb,
                    CongestionControl::Cubic => xqc_cubic_cb,
                },
                match sched {
                    Scheduler::MinRtt => xqc_minrtt_scheduler_cb,
                    Scheduler::Backup => xqc_backup_scheduler_cb,
                    Scheduler::Wlb => xqc_wlb_scheduler_cb,
                },
            )
        };
        assert_eq!(bytes(&s.cong_ctrl_callback), bytes(&want_cc));
        assert_eq!(bytes(&s.scheduler_callback), bytes(&want_sched));
        // Left at the xquic default (zero = "use default").
        assert_eq!(s.max_streams_bidi, 0);
        assert_eq!(s.init_idle_time_out, 0);
        assert_eq!(s.enable_stream_rate_limit, 0);
        assert_eq!(s.init_recv_window, 0);
        assert_eq!(s.cc_params.customize_on, 0, "cc_params zeroed");
    }

    /// spec §8.3: each scheduler selects its own xquic callback table,
    /// on both roles. (Parsing the `--scheduler` names belongs to the config crate.)
    #[test]
    fn sched_selects_callback() {
        use Scheduler::*;
        let server = Role::Server {
            cert: "c".into(),
            key: "k".into(),
        };
        // SAFETY: by-value reads of xquic's immutable statics.
        let want = unsafe {
            [
                (MinRtt, xqc_minrtt_scheduler_cb),
                (Backup, xqc_backup_scheduler_cb),
                (Wlb, xqc_wlb_scheduler_cb),
            ]
        };
        for role in [Role::Client, server] {
            for (sched, cb) in &want {
                let s = conn_settings(&cfg(role.clone(), CongestionControl::Bbr, *sched), None);
                assert_eq!(bytes(&s.scheduler_callback), bytes(cb), "{sched:?}");
            }
        }
        // The three tables are distinct, so no scheduler silently falls back to another.
        for (i, (_, a)) in want.iter().enumerate() {
            for (_, b) in &want[i + 1..] {
                assert_ne!(bytes(a), bytes(b));
            }
        }
    }

    /// SP2 spec §3.3: of the datagram callbacks only read and write are registered.
    #[test]
    fn datagram_callbacks_match_spec() {
        let d = app_proto_callbacks(ConnProto::Raw).dgram_cbs;
        assert!(d.datagram_read_notify.is_some());
        assert!(d.datagram_write_notify.is_some());
        assert!(d.datagram_acked_notify.is_none());
        assert!(d.datagram_lost_notify.is_none());
        assert!(d.datagram_mss_updated_notify.is_none());
    }

    /// The transport pins the engine log level to WARN.
    #[test]
    fn engine_config_pins_log_level_warn() {
        for ty in [XQC_ENGINE_CLIENT, XQC_ENGINE_SERVER] {
            let c = engine_config(ty, true).expect("default config");
            assert_eq!(c.cfg_log_level, XQC_LOG_WARN);
            assert_eq!(c.cfg_log_event, 1);
            assert_eq!(c.cfg_qlog_importance, EVENT_IMPORTANCE_EXTRA);
        }
    }

    /// Without a qlog file xquic must not format qlog events at all: formatting them only to
    /// drop them cost ~40% of a saturated server core on the WAN bench (2026-10-05).
    #[test]
    fn engine_config_formats_qlog_events_only_with_a_qlog_file() {
        for ty in [XQC_ENGINE_CLIENT, XQC_ENGINE_SERVER] {
            assert_eq!(engine_config(ty, false).unwrap().cfg_log_event, 0);
            assert_eq!(engine_config(ty, true).unwrap().cfg_log_event, 1);
        }
    }

    #[test]
    fn settings_match_spec() {
        use CongestionControl::*;
        use Scheduler::*;
        let server = Role::Server {
            cert: "c".into(),
            key: "k".into(),
        };
        for cc in [Bbr, Bbr2, Cubic] {
            for sched in [MinRtt, Backup, Wlb] {
                // client, keepalive off
                let c = conn_settings(&cfg(Role::Client, cc, sched), None);
                assert_common(&c, cc, sched);
                assert_eq!(c.max_pkt_out_size, 1200);
                assert_eq!(c.ping_on, 0);
                assert_eq!(c.idle_time_out, 0);
                assert_eq!(c.max_path_id_grant_max_value, 0);
                // client, keepalive on
                let c = conn_settings(&cfg(Role::Client, cc, sched), Some(Duration::from_secs(30)));
                assert_eq!(c.ping_on, 1);
                assert_eq!(c.idle_time_out, 30_000);
                // server: what `new` passes to xqc_server_set_conn_settings
                let scfg = cfg(server.clone(), cc, sched);
                let s = server_settings(&scfg);
                assert_common(&s, cc, sched);
                assert_eq!(s.max_path_id_grant_max_value, 128);
                assert_eq!(s.max_pkt_out_size, 0);
                assert_eq!(s.ping_on, 0);
                assert_eq!(s.idle_time_out, 0);
            }
        }
    }
}
