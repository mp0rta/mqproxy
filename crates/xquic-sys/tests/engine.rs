//! Link smoke test: the statically built xquic + BoringSSL create and destroy a client engine.
use core::ffi::{c_char, c_uchar, c_void};
use core::ptr;
use xquic_sys::*;

unsafe extern "C" fn set_event_timer(_wake_after: xqc_usec_t, _user_data: *mut c_void) {}
unsafe extern "C" fn save_token(_token: *const c_uchar, _len: u32, _user_data: *mut c_void) {}
unsafe extern "C" fn save_string(_data: *const c_char, _len: usize, _user_data: *mut c_void) {}
unsafe extern "C" fn update_cid(
    _conn: *mut xqc_connection_t,
    _retire: *const xqc_cid_t,
    _new: *const xqc_cid_t,
    _user_data: *mut c_void,
) {
}

#[test]
fn create_and_destroy_client_engine() {
    unsafe {
        let mut config: xqc_config_t = core::mem::zeroed();
        assert_eq!(
            xqc_engine_get_default_config(&mut config, XQC_ENGINE_CLIENT),
            0
        );

        let ssl_config: xqc_engine_ssl_config_t = core::mem::zeroed();
        let mut engine_cbs: xqc_engine_callback_t = core::mem::zeroed();
        engine_cbs.set_event_timer = Some(set_event_timer);
        let mut transport_cbs: xqc_transport_callbacks_t = core::mem::zeroed();
        transport_cbs.save_token = Some(save_token);
        transport_cbs.save_session_cb = Some(save_string);
        transport_cbs.save_tp_cb = Some(save_string);
        transport_cbs.conn_update_cid_notify = Some(update_cid);

        let engine = xqc_engine_create(
            XQC_ENGINE_CLIENT,
            &config,
            &ssl_config,
            &engine_cbs,
            &transport_cbs,
            ptr::null_mut(),
        );
        assert!(!engine.is_null());
        xqc_engine_destroy(engine);
    }
}
