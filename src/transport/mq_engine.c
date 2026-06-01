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
        MQ_LOGW("mq_engine: send on unmapped path_id %llu", (unsigned long long)path_id);
        return XQC_SOCKET_ERROR;
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

/* ── lifecycle ────────────────────────────────────────────────────────── */

mq_engine_t *
mq_engine_new(int is_server, struct event_base *base)
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
    /* NB: server mode additionally needs cert_file/private_key_file set by a
     * later task before accepting connections. Boot-only here. */

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
mq_engine_free(mq_engine_t *e)
{
    if (!e) {
        return;
    }
    if (e->ev_engine) {
        event_free(e->ev_engine);
    }
    if (e->engine) {
        xqc_engine_destroy(e->engine);
    }
    if (e->base_owned && e->base) {
        event_base_free(e->base);
    }
    free(e);
}
