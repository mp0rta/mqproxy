// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_runtime_libevent.c — Linux reference App-I/O runtime for mq_transport
 * (design §5).
 *
 * Owns libevent + the per-path UDP sockets and implements the transport's
 * callbacks:
 *   - rt_send_udp:         sendto() on the path's fd (primary-path fallback),
 *                          mapping EAGAIN -> MQ_TX_AGAIN (no txqueue / EV_WRITE;
 *                          xquic owns retry).
 *   - rt_open_path_socket: socket/bind/getsockname (ported from mq_path.c), arms
 *                          an EV_READ|EV_PERSIST recv-drain that feeds datagrams
 *                          into mq_transport_on_udp_recv with the path's cached
 *                          local addr + the recvfrom peer addr.
 *   - rt_close_path_socket: tear a path's socket/event down.
 * A libevent timer drives mq_transport_tick, (re)armed from
 * mq_transport_next_timeout_ms after every recv-drain and every tick.
 *
 * The transport core stays libevent-free; all OS I/O lives in this file. The
 * socket open / recvfrom-loop / getsockname logic is a faithful port of
 * mq_path.c; the send fallback + timer idiom mirror mq_engine.c.
 */
#include "runtime/mq_runtime_libevent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "util/mq_log.h"

/* Max paths the runtime can hold sockets for. Mirrors MQ_ENGINE_MAX_PATHS;
 * indexed by xquic path-id (primary == XQC_INITIAL_PATH_ID == 0). */
#define MQ_RT_MAX_PATHS 8

/* Max UDP datagram we read into a stack buffer per recvfrom. */
#define MQ_RT_RECV_BUF 65536

struct mq_runtime_s {
    mq_transport_t *t; /* borrowed; not freed by the runtime */
    struct event_base *base;
    int base_owned; /* 1 if we created (and must free) base */
    struct event *timer_ev;

    struct {
        int fd;
        struct event *read_ev;
        struct sockaddr_storage local; /* cached getsockname() value */
        socklen_t local_len;
        int in_use;
    } paths[MQ_RT_MAX_PATHS];
};

/* Per-path recv-drain context. Stored as the read event's arg so the callback
 * recovers both the runtime and which path fired. */
typedef struct {
    mq_runtime_t *rt;
    uint64_t path;
} rt_path_ctx_t;

/* (Re)arm the engine timer from the transport's next-timeout. ms < 0 -> the
 * core wants no wake right now (don't arm). Mirrors mq_engine's timer idiom but
 * driven by polling next_timeout_ms instead of set_event_timer. */
static void
rt_rearm_timer(mq_runtime_t *rt)
{
    int ms = mq_transport_next_timeout_ms(rt->t);
    if (ms < 0) {
        return;
    }
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    event_add(rt->timer_ev, &tv);
}

/* libevent timer callback: drive the transport's main logic, then re-arm. */
static void
rt_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_runtime_t *rt = (mq_runtime_t *)arg;
    mq_transport_tick(rt->t);
    rt_rearm_timer(rt);
}

/* on_timer callback: the transport's deadline changed (xquic called
 * set_event_timer). Re-arm immediately so deadlines set from app-initiated
 * paths (connect / stream send) — not just tick/recv — are honoured. */
static void
rt_on_timer(void *user)
{
    rt_rearm_timer((mq_runtime_t *)user);
}

/* ── transport callbacks ──────────────────────────────────────────────── */

/* send_udp: route an outbound packet to the path's UDP socket. Falls back to
 * the primary path's fd if the path's dedicated socket is not yet mapped
 * (mirrors mq_engine_write_socket_ex). EINTR retry loop; EAGAIN -> MQ_TX_AGAIN;
 * other error -> -1. No txqueue / EV_WRITE: xquic owns retry. */
static int
rt_send_udp(uint64_t path, const uint8_t *pkt, size_t len, const struct sockaddr *peer,
            socklen_t peerlen, void *user)
{
    mq_runtime_t *rt = (mq_runtime_t *)user;
    if (!rt || path >= MQ_RT_MAX_PATHS) {
        MQ_LOGW("mq_runtime: send on out-of-range path_id %llu",
                (unsigned long long)path);
        return -1;
    }

    int fd = rt->paths[path].fd;
    if (fd < 0) {
        /* A path's dedicated socket is registered only AFTER xqc_conn_create_path
         * returns its path_id, but xquic may queue the first PATH_CHALLENGE on
         * the new path before that. Fall back to the primary path's socket so the
         * challenge reaches the peer via the primary 4-tuple. */
        fd = rt->paths[0].fd;
        if (fd < 0) {
            MQ_LOGW("mq_runtime: send on unmapped path_id %llu (no primary fallback)",
                    (unsigned long long)path);
            return -1;
        }
    }

    ssize_t res;
    do {
        res = sendto(fd, pkt, len, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MQ_TX_AGAIN;
        }
        return -1;
    }
    return (int)res;
}

/* libevent EV_READ handler: drain all pending datagrams on this path, feed each
 * to the transport core (with the path's cached local addr + the recvfrom peer
 * addr), then re-arm the engine timer. Ported from mq_path_read_cb. */
static void
rt_path_read_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    rt_path_ctx_t *ctx = (rt_path_ctx_t *)arg;
    mq_runtime_t *rt = ctx->rt;
    uint64_t path = ctx->path;

    unsigned char buf[MQ_RT_RECV_BUF];

    for (;;) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        memset(&peer, 0, sizeof(peer));

        ssize_t n =
            recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            MQ_LOGW("mq_runtime: recvfrom(path %llu) failed: %s",
                    (unsigned long long)path, strerror(errno));
            break;
        }
        if (n == 0) {
            /* Empty datagram; nothing to process. */
            continue;
        }

        mq_transport_on_udp_recv(
            rt->t, path, buf, (size_t)n, (struct sockaddr *)&rt->paths[path].local,
            rt->paths[path].local_len, (struct sockaddr *)&peer, peer_len);
    }

    rt_rearm_timer(rt);
}

/* Parse local_ip into a sockaddr; sets *af. Returns 0 on success. Ported from
 * mq_path_build_addr. */
static int
rt_build_addr(const char *local_ip, uint16_t local_port, struct sockaddr_storage *out,
              socklen_t *out_len, int *af)
{
    memset(out, 0, sizeof(*out));

    struct in6_addr a6;
    struct in_addr a4;

    if (inet_pton(AF_INET, local_ip, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_addr = a4;
        sin->sin_port = htons(local_port);
        *out_len = sizeof(*sin);
        *af = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, local_ip, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a6;
        sin6->sin6_port = htons(local_port);
        *out_len = sizeof(*sin6);
        *af = AF_INET6;
        return 0;
    }
    return -1;
}

/* open_path_socket: create a non-blocking UDP socket bound to ip:port, cache the
 * actual bound addr via getsockname, register it under `path`, and arm an
 * EV_READ|EV_PERSIST recv-drain. Returns 0/-1. Faithful port of mq_path_open
 * (minus the engine path-fd map; here the fd lives in the runtime's paths[]). */
static int
rt_open_path_socket(uint64_t path, const char *ip, uint16_t port, void *user)
{
    mq_runtime_t *rt = (mq_runtime_t *)user;
    if (!rt || !ip || path >= MQ_RT_MAX_PATHS) {
        return -1;
    }
    if (rt->paths[path].in_use) {
        MQ_LOGE("mq_runtime: path %llu already open", (unsigned long long)path);
        return -1;
    }

    struct sockaddr_storage bind_addr;
    socklen_t bind_len = 0;
    int af = 0;
    if (rt_build_addr(ip, port, &bind_addr, &bind_len, &af) != 0) {
        MQ_LOGE("mq_runtime: invalid local_ip '%s'", ip);
        return -1;
    }

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        MQ_LOGE("mq_runtime: socket(af=%d) failed: %s", af, strerror(errno));
        return -1;
    }

    /* Non-blocking. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        MQ_LOGE("mq_runtime: set O_NONBLOCK failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        MQ_LOGW("mq_runtime: SO_REUSEADDR failed: %s", strerror(errno));
        /* non-fatal */
    }

    if (bind(fd, (struct sockaddr *)&bind_addr, bind_len) < 0) {
        MQ_LOGE("mq_runtime: bind(%s:%u) failed: %s", ip, port, strerror(errno));
        close(fd);
        return -1;
    }

    /* Read back the actual bound address (resolves ephemeral port). */
    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) < 0) {
        MQ_LOGE("mq_runtime: getsockname failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    rt_path_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        close(fd);
        return -1;
    }
    ctx->rt = rt;
    ctx->path = path;

    struct event *read_ev =
        event_new(rt->base, fd, EV_READ | EV_PERSIST, rt_path_read_cb, ctx);
    if (!read_ev || event_add(read_ev, NULL) < 0) {
        MQ_LOGE("mq_runtime: event_new/event_add failed");
        if (read_ev) {
            event_free(read_ev);
        }
        free(ctx);
        close(fd);
        return -1;
    }

    rt->paths[path].fd = fd;
    rt->paths[path].read_ev = read_ev;
    rt->paths[path].local = local;
    rt->paths[path].local_len = local_len;
    rt->paths[path].in_use = 1;
    return 0;
}

/* Tear down a single path's socket + read event. Frees the read event's ctx. */
static void
rt_teardown_path(mq_runtime_t *rt, uint64_t path)
{
    if (!rt->paths[path].in_use) {
        return;
    }
    if (rt->paths[path].read_ev) {
        rt_path_ctx_t *ctx =
            (rt_path_ctx_t *)event_get_callback_arg(rt->paths[path].read_ev);
        event_del(rt->paths[path].read_ev);
        event_free(rt->paths[path].read_ev);
        free(ctx);
        rt->paths[path].read_ev = NULL;
    }
    if (rt->paths[path].fd >= 0) {
        close(rt->paths[path].fd);
        rt->paths[path].fd = -1;
    }
    rt->paths[path].in_use = 0;
    rt->paths[path].local_len = 0;
}

/* close_path_socket: tear the path's socket down. */
static void
rt_close_path_socket(uint64_t path, void *user)
{
    mq_runtime_t *rt = (mq_runtime_t *)user;
    if (!rt || path >= MQ_RT_MAX_PATHS) {
        return;
    }
    rt_teardown_path(rt, path);
}

static const mq_transport_callbacks_t g_runtime_cbs = {
    .send_udp = rt_send_udp,
    .open_path_socket = rt_open_path_socket,
    .close_path_socket = rt_close_path_socket,
    .on_timer = rt_on_timer,
};

/* ── lifecycle ────────────────────────────────────────────────────────── */

mq_runtime_t *
mq_runtime_new(mq_transport_t *t, struct event_base *base)
{
    if (!t) {
        return NULL;
    }
    mq_runtime_t *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        return NULL;
    }
    rt->t = t;
    for (int i = 0; i < MQ_RT_MAX_PATHS; i++) {
        rt->paths[i].fd = -1;
    }

    if (base) {
        rt->base = base;
        rt->base_owned = 0;
    } else {
        rt->base = event_base_new();
        if (!rt->base) {
            MQ_LOGE("mq_runtime: event_base_new failed");
            free(rt);
            return NULL;
        }
        rt->base_owned = 1;
    }

    /* Timer event driving mq_transport_tick; (re)armed from next_timeout_ms.
     * -1 fd, no flags (one-shot, re-added each arm). */
    rt->timer_ev = event_new(rt->base, -1, 0, rt_timer_cb, rt);
    if (!rt->timer_ev) {
        MQ_LOGE("mq_runtime: event_new(timer) failed");
        if (rt->base_owned) {
            event_base_free(rt->base);
        }
        free(rt);
        return NULL;
    }

    /* Install the runtime as the transport's callback user. */
    mq_transport_set_callbacks(t, &g_runtime_cbs, rt);

    return rt;
}

struct event_base *
mq_runtime_base(mq_runtime_t *r)
{
    return r ? r->base : NULL;
}

int
mq_runtime_open_udp_path(mq_runtime_t *r, const char *local_ip, uint16_t port)
{
    /* Primary path == XQC_INITIAL_PATH_ID == 0. */
    return rt_open_path_socket(0, local_ip, port, r);
}

void
mq_runtime_run(mq_runtime_t *r)
{
    if (!r) {
        return;
    }
    event_base_dispatch(r->base);
}

void
mq_runtime_stop(mq_runtime_t *r)
{
    if (!r) {
        return;
    }
    event_base_loopbreak(r->base);
}

void
mq_runtime_free(mq_runtime_t *r)
{
    if (!r) {
        return;
    }
    for (uint64_t i = 0; i < MQ_RT_MAX_PATHS; i++) {
        rt_teardown_path(r, i);
    }
    if (r->timer_ev) {
        event_free(r->timer_ev);
    }
    if (r->base_owned && r->base) {
        event_base_free(r->base);
    }
    /* NB: the transport is borrowed — the caller owns and frees it. */
    free(r);
}
