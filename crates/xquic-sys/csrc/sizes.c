/* sizeof exports for tests/layout.rs: compares C layouts with the bindgen types. */
#include <stddef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

const size_t xqc_sys_sizeof_conn_settings = sizeof(xqc_conn_settings_t);
const size_t xqc_sys_sizeof_engine_callback = sizeof(xqc_engine_callback_t);
const size_t xqc_sys_sizeof_transport_callbacks = sizeof(xqc_transport_callbacks_t);
const size_t xqc_sys_sizeof_app_proto_callbacks = sizeof(xqc_app_proto_callbacks_t);
const size_t xqc_sys_sizeof_conn_ssl_config = sizeof(xqc_conn_ssl_config_t);
const size_t xqc_sys_sizeof_engine_ssl_config = sizeof(xqc_engine_ssl_config_t);
const size_t xqc_sys_sizeof_cid = sizeof(xqc_cid_t);
const size_t xqc_sys_sizeof_conn_stats = sizeof(xqc_conn_stats_t);
const size_t xqc_sys_sizeof_path_metrics = sizeof(xqc_path_metrics_t);
const size_t xqc_sys_sizeof_stream_close_stats = sizeof(xqc_stream_close_stats_t);
