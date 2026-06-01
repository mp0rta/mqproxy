/* mq_engine.c — xquic engine + libevent event loop.
 *
 * Integration pattern mirrors third_party/xquic/demo/demo_client.c and
 * mqvpn's single-threaded libevent integration of the same xquic fork:
 *   - set_event_timer arms a libevent timer (ev_engine) whose callback calls
 *     xqc_engine_main_logic(engine);
 *   - write_socket_ex (multipath send) looks up a UDP fd by path_id in an
 *     engine-owned path-id->fd map and sendto()s it.
 */
#include "transport/mq_engine.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>

#include "util/mq_log.h"

/* Small fixed path-id -> fd map. XQC_INITIAL_PATH_ID == 0; multipath grows
 * from there. 8 slots is ample for the proxy's path count. */
#define MQ_ENGINE_MAX_PATHS 8

struct mq_engine_s {
    xqc_engine_t *engine;
    struct event_base *base;
    int base_owned;          /* 1 if we created (and must free) base */
    struct event *ev_engine; /* libevent timer driving main_logic */

    /* path-id -> fd map; -1 == unmapped */
    int path_fd[MQ_ENGINE_MAX_PATHS];

    /* Multipath readiness hook (set by mq_conn for the client conn). */
    mq_engine_mp_ready_fn mp_ready_fn;
    void *mp_ready_user;
};

/* ── engine callbacks ─────────────────────────────────────────────────── */

/* libevent timer callback: drive xquic's main logic. */
static void
mq_engine_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_engine_t *e = (mq_engine_t *)arg;
    xqc_engine_main_logic(e->engine);
}

/* xquic set_event_timer: (re)arm the libevent timer wake_after microseconds
 * out. engine_user_data is the mq_engine_t* passed to xqc_engine_create. */
static void
mq_engine_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    mq_engine_t *e = (mq_engine_t *)engine_user_data;
    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(e->ev_engine, &tv);
}

/* xquic log callback (REQUIRED by the engine). Route to mq_log. */
static void
mq_engine_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
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

/* Multipath send callback. Look up the UDP fd for path_id and sendto().
 * conn_user_data is unused at the engine level (the proxy sets per-conn fds
 * via the path-fd map keyed by path_id). */
static ssize_t
mq_engine_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                          const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                          void *conn_user_data)
{
    mq_engine_t *e = (mq_engine_t *)conn_user_data;

    if (!e || path_id >= MQ_ENGINE_MAX_PATHS) {
        MQ_LOGW("mq_engine: send on out-of-range path_id %llu",
                (unsigned long long)path_id);
        return XQC_SOCKET_ERROR;
    }

    int fd = e->path_fd[path_id];
    if (fd < 0) {
        /* A path's dedicated socket is registered (mq_path_open) only AFTER
         * xqc_conn_create_path returns its path_id, but xquic may queue the
         * first PATH_CHALLENGE on the new path before that. Fall back to the
         * primary path's socket (path_id 0) so the challenge still reaches the
         * peer via the primary 4-tuple — mirrors mqvpn's get_fd_for_path
         * fallback. Once the dedicated fd is mapped, sends route to it. */
        fd = e->path_fd[XQC_INITIAL_PATH_ID];
        if (fd < 0) {
            MQ_LOGW("mq_engine: send on unmapped path_id %llu (no primary fallback)",
                    (unsigned long long)path_id);
            return XQC_SOCKET_ERROR;
        }
    }

    ssize_t res;
    do {
        res = sendto(fd, buf, size, MSG_DONTWAIT, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        return XQC_SOCKET_ERROR;
    }
    return res;
}

/* Single-path send callback: delegate to the multipath form on the initial
 * path. xquic requires write_socket; write_socket_ex covers multipath. */
static ssize_t
mq_engine_write_socket(const unsigned char *buf, size_t size,
                       const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                       void *conn_user_data)
{
    return mq_engine_write_socket_ex(XQC_INITIAL_PATH_ID, buf, size, peer_addr,
                                     peer_addrlen, conn_user_data);
}

/* Server accept callback (REQUIRED for server). user_data is what mq_path
 * passed to xqc_engine_packet_process — i.e. the engine. Bind the engine as
 * the connection's transport user_data so the send callback can recover it,
 * then accept. The application-protocol mq_conn is created by the ALP
 * conn_create_notify (see mq_conn.c). */
static int
mq_engine_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                        const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)cid;
    mq_engine_t *e = (mq_engine_t *)user_data;
    xqc_conn_set_transport_user_data(conn, e);
    return 0;
}

/* Server refuse callback. No transport-level context is allocated in accept
 * (the engine is borrowed, not owned), so nothing to free here. */
static void
mq_engine_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                        const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)conn;
    (void)cid;
    (void)user_data;
}

/* Multipath ready-to-create-path notify. xquic fires this once cids are
 * exchanged (precondition for xqc_conn_create_path). conn_user_data is the
 * connection's transport user_data == the mq_engine (see mq_conn's user_data
 * scheme). Route to the registered mp_ready hook so mq_conn can flip its flag. */
static void
mq_engine_ready_to_create_path(const xqc_cid_t *scid, void *conn_user_data)
{
    mq_engine_t *e = (mq_engine_t *)conn_user_data;
    if (e && e->mp_ready_fn) {
        e->mp_ready_fn(scid, e->mp_ready_user);
    }
}

/* CID update notify (REQUIRED for both client and server). The mq_conn keys
 * off the original scid, which xquic keeps valid for the connection's life,
 * so there is nothing to re-key here. */
static void
mq_engine_conn_update_cid(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
                          const xqc_cid_t *new_cid, void *conn_user_data)
{
    (void)conn;
    (void)retire_cid;
    (void)new_cid;
    (void)conn_user_data;
}

/* Client TLS certificate verify (REQUIRED for client). The proxy trusts its
 * own peer (the cert is pinned out-of-band by deployment), so accept. */
static int
mq_engine_cert_verify(const unsigned char *certs[], const size_t cert_len[],
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
mq_engine_save_token(const unsigned char *token, unsigned token_len, void *conn_user_data)
{
    (void)token;
    (void)token_len;
    (void)conn_user_data;
}

static void
mq_engine_save_session(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

static void
mq_engine_save_tp(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

/* ── lifecycle ────────────────────────────────────────────────────────── */

static mq_engine_t *
mq_engine_new_impl(int is_server, struct event_base *base, const char *cert_file,
                   const char *key_file)
{
    mq_engine_t *e = calloc(1, sizeof(*e));
    if (!e) {
        return NULL;
    }
    for (int i = 0; i < MQ_ENGINE_MAX_PATHS; i++) {
        e->path_fd[i] = -1;
    }

    if (base) {
        e->base = base;
        e->base_owned = 0;
    } else {
        e->base = event_base_new();
        if (!e->base) {
            MQ_LOGE("mq_engine: event_base_new failed");
            free(e);
            return NULL;
        }
        e->base_owned = 1;
    }

    /* Timer event that drives xqc_engine_main_logic; armed by
     * set_event_timer. -1 fd, no flags (one-shot, re-added each arm). */
    e->ev_engine = event_new(e->base, -1, 0, mq_engine_timer_cb, e);
    if (!e->ev_engine) {
        MQ_LOGE("mq_engine: event_new failed");
        goto fail;
    }

    xqc_engine_type_t type = is_server ? XQC_ENGINE_SERVER : XQC_ENGINE_CLIENT;

    xqc_engine_ssl_config_t ssl_config;
    memset(&ssl_config, 0, sizeof(ssl_config));
    ssl_config.ciphers = XQC_TLS_CIPHERS;
    ssl_config.groups = XQC_TLS_GROUPS;
    /* Server mode needs cert_file/private_key_file to complete handshakes.
     * xquic stores its own copies during xqc_engine_create, so the const
     * cast here is safe (the strings are only read). */
    if (cert_file) {
        ssl_config.cert_file = (char *)cert_file;
    }
    if (key_file) {
        ssl_config.private_key_file = (char *)key_file;
    }

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = mq_engine_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = mq_engine_log_write,
                .xqc_log_write_stat = mq_engine_log_write,
            },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = mq_engine_write_socket,
        .write_socket_ex = mq_engine_write_socket_ex,
        .conn_update_cid_notify = mq_engine_conn_update_cid,
        /* Multipath: precondition signal for xqc_conn_create_path. Harmless on
         * a server engine (the proxy creates paths from the client side). */
        .ready_to_create_path_notify = mq_engine_ready_to_create_path,
        /* Server-only: accept/refuse and the pre-accept send path. Harmless
         * to register on a client engine (never invoked). */
        .server_accept = mq_engine_server_accept,
        .server_refuse = mq_engine_server_refuse,
        .conn_send_packet_before_accept = mq_engine_write_socket,
        /* Client-only: TLS verify + resumption-store hooks. Harmless on a
         * server engine (never invoked). */
        .cert_verify_cb = mq_engine_cert_verify,
        .save_token = mq_engine_save_token,
        .save_session_cb = mq_engine_save_session,
        .save_tp_cb = mq_engine_save_tp,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, type) < 0) {
        MQ_LOGE("mq_engine: xqc_engine_get_default_config failed");
        goto fail;
    }

    e->engine = xqc_engine_create(type, &config, &ssl_config, &engine_cbs, &tcbs, e);
    if (!e->engine) {
        MQ_LOGE("mq_engine: xqc_engine_create failed");
        goto fail;
    }

    return e;

fail:
    if (e->ev_engine) {
        event_free(e->ev_engine);
    }
    if (e->base_owned && e->base) {
        event_base_free(e->base);
    }
    free(e);
    return NULL;
}

mq_engine_t *
mq_engine_new(int is_server, struct event_base *base)
{
    return mq_engine_new_impl(is_server, base, NULL, NULL);
}

mq_engine_t *
mq_engine_new_server(struct event_base *base, const char *cert_file, const char *key_file)
{
    if (!cert_file || !key_file) {
        MQ_LOGE("mq_engine: server engine requires cert_file and key_file");
        return NULL;
    }
    return mq_engine_new_impl(/*is_server=*/1, base, cert_file, key_file);
}

void
mq_engine_run(mq_engine_t *e)
{
    if (!e) {
        return;
    }
    event_base_dispatch(e->base);
}

void
mq_engine_stop(mq_engine_t *e)
{
    if (!e) {
        return;
    }
    event_base_loopbreak(e->base);
}

xqc_engine_t *
mq_engine_xqc(mq_engine_t *e)
{
    return e ? e->engine : NULL;
}

struct event_base *
mq_engine_base(mq_engine_t *e)
{
    return e ? e->base : NULL;
}

int
mq_engine_register_path_fd(mq_engine_t *e, uint64_t path_id, int fd)
{
    if (!e || path_id >= MQ_ENGINE_MAX_PATHS) {
        return -1;
    }
    e->path_fd[path_id] = fd;
    return 0;
}

void
mq_engine_unregister_path_fd(mq_engine_t *e, uint64_t path_id)
{
    if (!e || path_id >= MQ_ENGINE_MAX_PATHS) {
        return;
    }
    e->path_fd[path_id] = -1;
}

void
mq_engine_set_mp_ready_cb(mq_engine_t *e, mq_engine_mp_ready_fn fn, void *user)
{
    if (!e) {
        return;
    }
    e->mp_ready_fn = fn;
    e->mp_ready_user = user;
}

void
mq_engine_free(mq_engine_t *e)
{
    if (!e) {
        return;
    }
    if (e->ev_engine) {
        event_free(e->ev_engine);
    }
    /* NB: the ALP registration context (mq_conn's alpn ctx, also stashed in
     * priv_ctx) is owned and freed by xquic itself in xqc_engine_destroy
     * (xqc_engine_free_alpn_list). We must NOT free priv_ctx here — doing so
     * would double-free. */
    if (e->engine) {
        xqc_engine_destroy(e->engine);
    }
    if (e->base_owned && e->base) {
        event_base_free(e->base);
    }
    free(e);
}
