// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_transport.c — sans-io transport core (design §4.1/§4.2).
 *
 * mq_transport owns its own xqc_engine directly: no mq_engine, no libevent, no
 * event_base, no sockets. xquic's UDP send is routed through the send_udp
 * callback (the runtime owns the path-id->fd map). set_event_timer records a
 * deadline instead of arming a libevent timer; the runtime polls it via
 * mq_transport_next_timeout_ms (Chunk 4) and drives the engine via tick.
 *
 * Engine/ssl/config setup is a faithful port of mq_engine's mq_engine_new_impl;
 * the engine/transport/ssl callback tables mirror mq_engine.c. on_udp_recv is a
 * Chunk-1 stub (real impl is Chunk 5); next_timeout_ms returns -1 (Chunk 4).
 *
 * NB: src/transport/mq_transport.c must stay libevent-free.
 */
#include "transport/mq_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "util/mq_log.h"

struct mq_transport_s {
    xqc_engine_t *engine;
    mq_transport_callbacks_t cbs;
    void *user;
    int is_server;

    /* Multipath readiness hook (set via mq_transport_set_mp_ready_cb). */
    mq_transport_mp_ready_fn mp_ready_fn;
    void *mp_ready_user;

    /* qlog sink. qlog_fd < 0 == disabled (default). The xquic qlog callback
     * writes rendered lines here when armed via mq_transport_enable_qlog. */
    int qlog_fd;
    char qlog_path[512];

    /* Deadline recorded by set_event_timer; the runtime polls it (Chunk 4). */
    uint64_t next_deadline_us;
    int have_deadline;
};

/* Wall-clock microseconds since the epoch — the SAME epoch as xquic's xqc_now /
 * mq_path_now_us (gettimeofday-based). Do NOT use CLOCK_MONOTONIC: set_event_timer
 * deadlines are compared against xquic's internal clock. */
static xqc_usec_t
mq_tr_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + (xqc_usec_t)tv.tv_usec;
}

/* ── engine callbacks ─────────────────────────────────────────────────── */

/* xquic set_event_timer: record the next wake deadline instead of arming a
 * libevent timer (the runtime owns the timer). engine_user_data is the
 * mq_transport_t* passed to xqc_engine_create. */
static void
mq_transport_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    mq_transport_t *t = (mq_transport_t *)engine_user_data;
    if (!t) {
        return;
    }
    t->next_deadline_us = mq_tr_now_us() + wake_after;
    t->have_deadline = 1;
}

/* xquic log callback (REQUIRED by the engine). Route to mq_log. */
static void
mq_transport_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
                       void *engine_user_data)
{
    (void)engine_user_data;
    int ml;
    switch (lvl) {
    case XQC_LOG_REPORT:
    case XQC_LOG_FATAL:
    case XQC_LOG_ERROR: ml = MQ_LOG_ERROR; break;
    case XQC_LOG_WARN: ml = MQ_LOG_WARN; break;
    case XQC_LOG_STATS:
    case XQC_LOG_INFO: ml = MQ_LOG_INFO; break;
    case XQC_LOG_DEBUG:
    default: ml = MQ_LOG_DEBUG; break;
    }
    mq_log(ml, "[xquic] %.*s", (int)size, (const char *)buf);
}

/* xquic qlog event sink. engine_user_data is the mq_transport_t* passed to
 * xqc_engine_create. Writes the rendered qlog line + newline to the armed qlog
 * fd; a no-op until mq_transport_enable_qlog opens the file (fd < 0). */
static void
mq_transport_qlog_write(qlog_event_importance_t imp, const void *buf, size_t size,
                        void *engine_user_data)
{
    (void)imp;
    mq_transport_t *t = (mq_transport_t *)engine_user_data;
    if (!t || t->qlog_fd < 0) {
        return;
    }
    ssize_t w = write(t->qlog_fd, buf, size);
    if (w < 0) {
        return;
    }
    static const char nl = '\n';
    (void)write(t->qlog_fd, &nl, 1);
}

/* Multipath send callback. Route the outbound packet through the runtime's
 * send_udp hook. conn_user_data is the mq_transport_t* (bound as the
 * connection's transport user_data in server_accept / by mq_conn for clients).
 * Map send_udp's return: MQ_TX_AGAIN -> XQC_SOCKET_EAGAIN, <0 -> XQC_SOCKET_ERROR,
 * else the byte count. */
static ssize_t
mq_transport_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                             const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                             void *conn_user_data)
{
    mq_transport_t *t = (mq_transport_t *)conn_user_data;
    if (!t || !t->cbs.send_udp) {
        return XQC_SOCKET_ERROR;
    }
    int r = t->cbs.send_udp(path_id, buf, size, peer_addr, peer_addrlen, t->user);
    if (r == MQ_TX_AGAIN) {
        return XQC_SOCKET_EAGAIN;
    }
    if (r < 0) {
        return XQC_SOCKET_ERROR;
    }
    return r;
}

/* Single-path send callback: delegate to the multipath form on the initial
 * path. xquic requires write_socket; write_socket_ex covers multipath. */
static ssize_t
mq_transport_write_socket(const unsigned char *buf, size_t size,
                          const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                          void *conn_user_data)
{
    return mq_transport_write_socket_ex(XQC_INITIAL_PATH_ID, buf, size, peer_addr,
                                        peer_addrlen, conn_user_data);
}

/* Server accept callback (REQUIRED for server). user_data is the engine_user_data
 * == the mq_transport. Bind the transport as the connection's transport user_data
 * so the send callback can recover it, then accept. The application-protocol
 * mq_conn is created by the ALP conn_create_notify (see mq_conn.c). */
static int
mq_transport_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                           const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)cid;
    mq_transport_t *t = (mq_transport_t *)user_data;
    xqc_conn_set_transport_user_data(conn, t);
    return 0;
}

/* Server refuse callback. No transport-level context is allocated in accept, so
 * nothing to free here. */
static void
mq_transport_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                           const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)conn;
    (void)cid;
    (void)user_data;
}

/* Multipath ready-to-create-path notify. xquic fires this once cids are
 * exchanged (precondition for xqc_conn_create_path). conn_user_data is the
 * connection's transport user_data == the mq_transport. Route to the registered
 * mp_ready hook so mq_conn can flip its flag. */
static void
mq_transport_ready_to_create_path(const xqc_cid_t *scid, void *conn_user_data)
{
    mq_transport_t *t = (mq_transport_t *)conn_user_data;
    if (t && t->mp_ready_fn) {
        t->mp_ready_fn(scid, t->mp_ready_user);
    }
}

/* CID update notify (REQUIRED for both client and server). The mq_conn keys off
 * the original scid, which xquic keeps valid for the connection's life, so there
 * is nothing to re-key here. */
static void
mq_transport_conn_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                             const xqc_cid_t *new_cid, void *conn_user_data)
{
    (void)conn;
    (void)retire_cid;
    (void)new_cid;
    (void)conn_user_data;
}

/* Client TLS certificate verify (REQUIRED for client). The proxy trusts its own
 * peer (the cert is pinned out-of-band by deployment), so accept. */
static int
mq_transport_cert_verify(const unsigned char *certs[], const size_t cert_len[],
                         size_t certs_len, void *conn_user_data)
{
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    (void)conn_user_data;
    return 0;
}

/* Client token / session / transport-param save callbacks (REQUIRED for
 * client). No 0-RTT / resumption store in the proxy yet, so these are no-ops. */
static void
mq_transport_save_token(const unsigned char *token, unsigned token_len,
                        void *conn_user_data)
{
    (void)token;
    (void)token_len;
    (void)conn_user_data;
}

static void
mq_transport_save_session(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

static void
mq_transport_save_tp(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static mq_transport_t *
mq_transport_new_impl(int is_server, const mq_transport_callbacks_t *cbs, void *user,
                      const char *cert_file, const char *key_file)
{
    mq_transport_t *t = calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    if (cbs) {
        t->cbs = *cbs;
    } else {
        memset(&t->cbs, 0, sizeof(t->cbs));
    }
    t->user = user;
    t->is_server = is_server ? 1 : 0;
    t->qlog_fd = -1; /* qlog disabled until mq_transport_enable_qlog */

    xqc_engine_type_t type = is_server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;

    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;
    /* Server mode needs cert_file/private_key_file to complete handshakes.
     * xquic stores its own copies during xqc_engine_create, so the const cast
     * here is safe (the strings are only read). */
    if (cert_file) {
        ssl_config.cert_file = (char *)cert_file;
    }
    if (key_file) {
        ssl_config.private_key_file = (char *)key_file;
    }

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = mq_transport_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = mq_transport_log_write,
                .xqc_log_write_stat = mq_transport_log_write,
                /* qlog event sink: a no-op until mq_transport_enable_qlog arms
                 * the fd. Registered unconditionally so qlog can be enabled after
                 * engine create without recreating the engine. */
                .xqc_qlog_event_write = mq_transport_qlog_write,
            },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = mq_transport_write_socket,
        .write_socket_ex = mq_transport_write_socket_ex,
        .conn_update_cid_notify = mq_transport_conn_update_cid,
        /* Multipath: precondition signal for xqc_conn_create_path. Harmless on a
         * server engine (the proxy creates paths from the client side). */
        .ready_to_create_path_notify = mq_transport_ready_to_create_path,
        /* Server-only: accept/refuse and the pre-accept send path. Harmless to
         * register on a client engine (never invoked). */
        .server_accept = mq_transport_server_accept,
        .server_refuse = mq_transport_server_refuse,
        .conn_send_packet_before_accept = mq_transport_write_socket,
        /* Client-only: TLS verify + resumption-store hooks. Harmless on a server
         * engine (never invoked). */
        .cert_verify_cb = mq_transport_cert_verify,
        .save_token = mq_transport_save_token,
        .save_session_cb = mq_transport_save_session,
        .save_tp_cb = mq_transport_save_tp,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, type) < 0) {
        MQ_LOGE("mq_transport: xqc_engine_get_default_config failed");
        free(t);
        return NULL;
    }
    /* qlog: emit event-based qlog at EXTRA importance so the `frames_processed`
     * events (incl. DATA_BLOCKED / STREAM_DATA_BLOCKED) reach the qlog sink.
     * These are xquic's defaults; set them explicitly so the 1-B blocked-frame
     * instrument does not silently break if the fork's defaults drift. The sink
     * itself is a no-op until mq_transport_enable_qlog. */
    config.cfg_log_event = 1;
    config.cfg_qlog_importance = EVENT_IMPORTANCE_EXTRA;

    t->engine = xqc_engine_create(type, &config, &ssl_config, &engine_cbs, &tcbs, t);
    if (!t->engine) {
        MQ_LOGE("mq_transport: xqc_engine_create failed");
        free(t);
        return NULL;
    }

    return t;
}

mq_transport_t *
mq_transport_new(int is_server, const mq_transport_callbacks_t *cbs, void *user)
{
    return mq_transport_new_impl(is_server, cbs, user, NULL, NULL);
}

mq_transport_t *
mq_transport_new_server(const mq_transport_callbacks_t *cbs, void *user,
                        const char *cert_file, const char *key_file)
{
    if (!cert_file || !key_file) {
        MQ_LOGE("mq_transport: server transport requires cert_file and key_file");
        return NULL;
    }
    return mq_transport_new_impl(/*is_server=*/1, cbs, user, cert_file, key_file);
}

void
mq_transport_free(mq_transport_t *t)
{
    if (!t) {
        return;
    }
    /* NB: the ALP registration context is owned and freed by xquic itself in
     * xqc_engine_destroy (xqc_engine_free_alpn_list). Destroy the engine FIRST
     * (mirrors mq_engine_free's order); there is no event_base/timer to free. */
    if (t->engine) {
        xqc_engine_destroy(t->engine);
    }
    /* Close the qlog fd AFTER engine destroy so any qlog lines emitted while the
     * engine tears down its connections still land in the file. */
    if (t->qlog_fd >= 0) {
        close(t->qlog_fd);
        t->qlog_fd = -1;
    }
    free(t);
}

int
mq_transport_on_udp_recv(mq_transport_t *t, uint64_t path, const uint8_t *pkt, size_t len,
                         const struct sockaddr *peer, socklen_t peerlen)
{
    /* Chunk 5 wires this to xqc_engine_packet_process; minimal stub for now. */
    (void)t;
    (void)path;
    (void)pkt;
    (void)len;
    (void)peer;
    (void)peerlen;
    return 0;
}

void
mq_transport_tick(mq_transport_t *t)
{
    xqc_engine_main_logic(t->engine);
}

int
mq_transport_next_timeout_ms(mq_transport_t *t)
{
    /* Real deadline tracking lands in Chunk 4. */
    (void)t;
    return -1;
}

xqc_engine_t *
mq_transport_xqc(mq_transport_t *t)
{
    return t ? t->engine : NULL;
}

void
mq_transport_set_mp_ready_cb(mq_transport_t *t, mq_transport_mp_ready_fn fn, void *user)
{
    if (!t) {
        return;
    }
    t->mp_ready_fn = fn;
    t->mp_ready_user = user;
}

int
mq_transport_enable_qlog(mq_transport_t *t, const char *dir, const char **out_path)
{
    if (!t || !dir || dir[0] == '\0') {
        return -1;
    }
    if (t->qlog_fd >= 0) {
        /* Already armed; idempotent re-arm just returns the existing path. */
        if (out_path) *out_path = t->qlog_path;
        return 0;
    }
    int n = snprintf(t->qlog_path, sizeof(t->qlog_path), "%s/%s.qlog", dir,
                     t->is_server ? "server" : "client");
    if (n < 0 || (size_t)n >= sizeof(t->qlog_path)) {
        MQ_LOGE("mq_transport: qlog path too long");
        t->qlog_path[0] = '\0';
        return -1;
    }
    int fd = open(t->qlog_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        MQ_LOGE("mq_transport: failed to open qlog file '%s': %s", t->qlog_path,
                strerror(errno));
        t->qlog_path[0] = '\0';
        return -1;
    }
    t->qlog_fd = fd;
    MQ_LOGI("mq_transport: qlog enabled -> %s", t->qlog_path);
    if (out_path) *out_path = t->qlog_path;
    return 0;
}
