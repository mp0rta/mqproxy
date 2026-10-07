// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §2.1
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    improper_ctypes,
    clippy::all
)]
include!("bindings.rs");

// Test-only xquic entry points, compiled in with `-DXQC_ENABLE_TEST_HOOKS=ON`. bindgen runs
// without that define, so they are declared here (spec §7, implicit streams).
#[cfg(feature = "test-hooks")]
unsafe extern "C" {
    /// A client-bidi stream with a caller-chosen id (not below the next local id, within credit).
    pub fn xqc_stream_create_with_id(
        engine: *mut xqc_engine_t,
        cid: *const xqc_cid_t,
        stream_id: xqc_stream_id_t,
        user_data: *mut core::ffi::c_void,
    ) -> *mut xqc_stream_t;
    /// The connection's live count of implicitly opened stream ids; 0 when unknown.
    pub fn xqc_conn_implicit_stream_count(engine: *mut xqc_engine_t, cid: *const xqc_cid_t) -> u64;
}
