// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_tproxy.c — transparent-capture TCP listener.
 *
 * Mirrors mq_listener.c's accept-loop pattern but with no protocol parser:
 * the original destination is obtained directly from the kernel on accept,
 * then the fd is handed immediately to the proxy core via mq_tcp_open_fn.
 *
 * fd-ownership contract (mirrors mq_listener.h):
 *   - The listener OWNS the accepted fd from accept() up to the moment
 *     open_fn is called.  If orig-dst recovery fails (pre-handoff), the
 *     listener closes cfd itself and returns.
 *   - Once open_fn is called the core (mq_client) OWNS the fd and closes
 *     it on every terminal outcome.  The listener MUST NOT close it after
 *     calling open_fn — not in on_accept, not in tproxy_open_result.
 *   - tproxy_open_result is a no-op on fd ownership: transparent capture has
 *     no in-band reply to write (unlike SOCKS5/HTTP CONNECT), so the body
 *     only needs to handle per-conn state cleanup.  Since no per-conn state
 *     is allocated (user=NULL passed to open_fn), the callback is empty
 *     except for the suppressed close.
 */

#include "ingress/mq_tproxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "ingress/mq_origdst.h"
#include "util/mq_log.h"

struct mq_tproxy_listener {
    struct event_base *base;
    int listen_fd;
    struct event *accept_ev;
    uint16_t local_port;
    mq_capture_mode_t mode;
    mq_tcp_open_fn open_fn;
    void *core;
};

/* ── open-result callback ──────────────────────────────────────────────────
 *
 * The core owns local_fd at this point.  On ok=1 the relay is live; on ok=0
 * the core closes it AFTER this callback returns.  We do NOT close local_fd
 * in either case — the ownership contract is identical to http_open_result
 * in mq_listener.c.
 *
 * Transparent capture has no in-band reply (no SOCKS5 REP, no HTTP 200), so
 * there is nothing to write.  No per-conn state was allocated (user==NULL),
 * so there is nothing to free either. */
static void
tproxy_open_result(int ok, mq_tcp_err_t err, void *user)
{
    /* The fd is owned by the core; do NOT close it here. */
    (void)ok;
    (void)err;
    (void)user; /* NULL — no per-conn state allocated */
}

/* ── helpers ───────────────────────────────────────────────────────────── */

static int
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ── accept event ───────────────────────────────────────────────────────── */

static void
on_accept(evutil_socket_t lfd, short what, void *user)
{
    (void)what;
    struct mq_tproxy_listener *l = (struct mq_tproxy_listener *)user;

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            MQ_LOGW("mq_tproxy: accept failed: %s", strerror(errno));
            return;
        }

        /* Set the accepted fd non-blocking before any further work. */
        if (set_nonblock(cfd) != 0) {
            MQ_LOGW("mq_tproxy: set_nonblock failed: %s", strerror(errno));
            close(cfd);
            continue;
        }

        /* Recover original destination — listener still owns cfd here. */
        struct sockaddr_storage od;
        int rc = (l->mode == MQ_CAPTURE_TPROXY) ? mq_origdst_from_fd_tproxy(cfd, &od)
                                                : mq_origdst_from_fd_redirect(cfd, &od);
        if (rc < 0) {
            MQ_LOGW("mq_tproxy: orig-dst recovery failed: %s", strerror(errno));
            close(cfd); /* pre-handoff: listener owns cfd */
            continue;
        }

        uint8_t host[16];
        size_t host_len;
        int atype;
        uint16_t port;
        if (mq_origdst_to_target(&od, host, sizeof(host), &host_len, &atype, &port) < 0) {
            MQ_LOGW("mq_tproxy: unsupported address family from orig-dst");
            close(cfd); /* pre-handoff: listener owns cfd */
            continue;
        }

        /* Hand off to the core — from this point the CORE owns cfd.
         * Do NOT close cfd after this call (on success OR failure path). */
        l->open_fn(l->core, host, host_len, (mq_addr_type_t)atype, port, cfd, NULL, 0,
                   NULL, tproxy_open_result);
        /* After open_fn returns, cfd is owned by the core; do not touch it. */
    }
}

/* ── construction ───────────────────────────────────────────────────────── */

mq_tproxy_listener_t *
mq_tproxy_listener_new(struct event_base *base, const char *bind_ip, uint16_t port,
                       mq_capture_mode_t mode, mq_tcp_open_fn open_fn, void *core)
{
    if (!base || !bind_ip || !open_fn) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        MQ_LOGE("mq_tproxy: socket: %s", strerror(errno));
        return NULL;
    }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /* IP_TRANSPARENT must be set BEFORE bind for TPROXY mode.
     * This requires CAP_NET_ADMIN; fail clearly if the privilege is absent. */
    if (mode == MQ_CAPTURE_TPROXY) {
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0) {
            MQ_LOGE("mq_tproxy: IP_TRANSPARENT setsockopt failed (CAP_NET_ADMIN "
                    "required): %s",
                    strerror(errno));
            close(fd);
            return NULL;
        }
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        MQ_LOGE("mq_tproxy: invalid bind_ip '%s'", bind_ip);
        close(fd);
        return NULL;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        MQ_LOGE("mq_tproxy: bind %s:%u failed: %s", bind_ip, (unsigned)port,
                strerror(errno));
        close(fd);
        return NULL;
    }
    if (listen(fd, 64) != 0) {
        MQ_LOGE("mq_tproxy: listen failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    if (set_nonblock(fd) != 0) {
        MQ_LOGE("mq_tproxy: set_nonblock(listen_fd) failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    /* Query actual bound port (support ephemeral port 0). */
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    uint16_t lport = 0;
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) == 0) {
        lport = ntohs(bound.sin_port);
    }

    struct mq_tproxy_listener *l = calloc(1, sizeof(*l));
    if (!l) {
        close(fd);
        return NULL;
    }
    l->base = base;
    l->listen_fd = fd;
    l->local_port = lport;
    l->mode = mode;
    l->open_fn = open_fn;
    l->core = core;

    l->accept_ev = event_new(base, fd, EV_READ | EV_PERSIST, on_accept, l);
    if (!l->accept_ev) {
        close(fd);
        free(l);
        return NULL;
    }
    event_add(l->accept_ev, NULL);
    return l;
}

/* ── accessors ──────────────────────────────────────────────────────────── */

uint16_t
mq_tproxy_listener_port(const mq_tproxy_listener_t *l)
{
    return l ? l->local_port : 0;
}

/* ── teardown ───────────────────────────────────────────────────────────── */

void
mq_tproxy_listener_free(mq_tproxy_listener_t *l)
{
    if (!l) return;
    if (l->accept_ev) {
        event_free(l->accept_ev);
        l->accept_ev = NULL;
    }
    if (l->listen_fd >= 0) {
        close(l->listen_fd);
        l->listen_fd = -1;
    }
    free(l);
}
