// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Cross-safe layout check: bindgen struct sizes against the C compiler's `sizeof`.
use core::mem::size_of;
use xquic_sys::*;

unsafe extern "C" {
    static xqc_sys_sizeof_conn_settings: usize;
    static xqc_sys_sizeof_engine_callback: usize;
    static xqc_sys_sizeof_transport_callbacks: usize;
    static xqc_sys_sizeof_app_proto_callbacks: usize;
    static xqc_sys_sizeof_conn_ssl_config: usize;
    static xqc_sys_sizeof_engine_ssl_config: usize;
    static xqc_sys_sizeof_cid: usize;
    static xqc_sys_sizeof_conn_stats: usize;
    static xqc_sys_sizeof_path_metrics: usize;
    static xqc_sys_sizeof_stream_close_stats: usize;
}

#[test]
fn sizes_match_c() {
    unsafe {
        assert_eq!(
            size_of::<xqc_conn_settings_t>(),
            xqc_sys_sizeof_conn_settings
        );
        assert_eq!(
            size_of::<xqc_engine_callback_t>(),
            xqc_sys_sizeof_engine_callback
        );
        assert_eq!(
            size_of::<xqc_transport_callbacks_t>(),
            xqc_sys_sizeof_transport_callbacks
        );
        assert_eq!(
            size_of::<xqc_app_proto_callbacks_t>(),
            xqc_sys_sizeof_app_proto_callbacks
        );
        assert_eq!(
            size_of::<xqc_conn_ssl_config_t>(),
            xqc_sys_sizeof_conn_ssl_config
        );
        assert_eq!(
            size_of::<xqc_engine_ssl_config_t>(),
            xqc_sys_sizeof_engine_ssl_config
        );
        assert_eq!(size_of::<xqc_cid_t>(), xqc_sys_sizeof_cid);
        assert_eq!(size_of::<xqc_conn_stats_t>(), xqc_sys_sizeof_conn_stats);
        assert_eq!(size_of::<xqc_path_metrics_t>(), xqc_sys_sizeof_path_metrics);
        assert_eq!(
            size_of::<xqc_stream_close_stats_t>(),
            xqc_sys_sizeof_stream_close_stats
        );
    }
}
