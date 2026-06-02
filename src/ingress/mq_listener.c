// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_listener.c — shared ingress TCP accept loop for SOCKS5 + HTTP CONNECT.
 *
 * One generic listener type backs both protocols. The protocol-specific logic
 * is captured by a `drive` function pointer (set at construction) that, given a
 * per-connection state and its accumulated read buffer, advances the parser and
 * decides what to do: keep reading, send an intermediate reply, hand off to
 * open_fn, or reject + close. This keeps the socket/accept/lifetime machinery
 * in one place and the SOCKS5 vs HTTP differences small and isolated.
 *
 * See mq_listener.h for the fd-ownership contract.
 */
#include "ingress/mq_listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "ingress/mq_http_connect.h"
#include "ingress/mq_socks5.h"
#include "util/mq_log.h"

/* Max bytes we buffer for a single request head before giving up (protects
 * against a slowloris / oversized greeting). 8 KiB comfortably covers a SOCKS5
 * request (~262 B) and a reasonable HTTP CONNECT head. */
#define MQ_LISTENER_RXCAP 8192

struct mq_conn_state; /* fwd */

/* Outcome of one drive() pass. */
typedef enum {
    MQ_DRIVE_NEED_MORE, /* keep reading */
    MQ_DRIVE_HANDOFF,   /* open_fn was called; fd ownership transferred */
    MQ_DRIVE_CLOSE      /* reject/error: close the accepted fd */
} mq_drive_result_t;

/* Protocol drive callback: process whatever is in c->rxbuf[0..rxlen). It may
 * write intermediate replies to c->fd (e.g. SOCKS5 method reply) and update
 * parser state. Returns one of mq_drive_result_t. On MQ_DRIVE_HANDOFF the
 * callback MUST have invoked l->open_fn (which takes fd ownership). */
typedef mq_drive_result_t (*mq_drive_fn)(struct mq_conn_state *c);

/* open-result callbacks (defined below; referenced by the drive functions). */
static void socks5_open_result(int ok, mq_tcp_err_t err, void *user);
static void http_open_result(int ok, mq_tcp_err_t err, void *user);

struct mq_listener_s {
    struct event_base *base;
    int listen_fd;
    struct event *accept_ev;
    uint16_t local_port;
    mq_tcp_open_fn open_fn;
    void *core;
    mq_drive_fn drive;
    /* Live per-conn states, singly linked, so free() can reap them. */
    struct mq_conn_state *conns;
};

struct mq_conn_state {
    mq_listener_t *l;
    int fd; /* accepted app socket; -1 once handed to open_fn */
    struct event *read_ev;
    uint8_t rxbuf[MQ_LISTENER_RXCAP];
    size_t rxlen;
    mq_socks5_parser_t s5; /* only used for the SOCKS5 drive */
    int handed_off;        /* 1 once open_fn was called (fd owned by core) */
    struct mq_conn_state *next;
};

/* ── per-conn list bookkeeping ──────────────────────────────────────────── */

static void
conn_unlink(mq_listener_t *l, struct mq_conn_state *c)
{
    struct mq_conn_state **pp = &l->conns;
    while (*pp) {
        if (*pp == c) {
            *pp = c->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Drop the listener's read interest on the accepted fd without closing it or
 * freeing the state. Used at hand-off: the core now owns the fd, so the
 * listener must stop its EV_READ event (which would otherwise keep firing on a
 * fd the relay drives). The state itself survives until the open-result cb. */
static void
conn_detach_read(struct mq_conn_state *c)
{
    if (c->read_ev) {
        event_free(c->read_ev);
        c->read_ev = NULL;
    }
}

/* Tear down a per-conn state. If close_fd is set AND the fd has not been handed
 * to open_fn, close it (listener still owns it). Always frees the read event
 * and the state and unlinks it. */
static void
conn_destroy(struct mq_conn_state *c, int close_fd)
{
    if (!c) return;
    conn_unlink(c->l, c);
    if (c->read_ev) {
        event_free(c->read_ev);
        c->read_ev = NULL;
    }
    if (close_fd && !c->handed_off && c->fd >= 0) {
        close(c->fd);
    }
    c->fd = -1;
    free(c);
}

/* ── SOCKS5 drive ───────────────────────────────────────────────────────── */

static mq_drive_result_t
drive_socks5(struct mq_conn_state *c)
{
    mq_listener_t *l = c->l;

    /* Feed whatever we have; the parser consumes greeting then request across
     * one or more passes. We loop so a single read containing both greeting and
     * request advances both. */
    for (;;) {
        size_t consumed = 0;
        mq_socks5_req_t req;
        memset(&req, 0, sizeof(req));
        mq_socks5_status_t st =
            mq_socks5_feed(&c->s5, c->rxbuf, c->rxlen, &consumed, &req);

        switch (st) {
        case MQ_SOCKS5_NEED_MORE: return MQ_DRIVE_NEED_MORE;

        case MQ_SOCKS5_GREETING_DONE: {
            /* Drop consumed greeting bytes, send the method reply, loop to try
             * the request (it may already be buffered). */
            memmove(c->rxbuf, c->rxbuf + consumed, c->rxlen - consumed);
            c->rxlen -= consumed;
            uint8_t mr[2];
            size_t n = mq_socks5_build_method_reply(mr, /*accepted=*/1);
            if (send(c->fd, mr, n, MSG_NOSIGNAL) != (ssize_t)n) {
                return MQ_DRIVE_CLOSE;
            }
            continue;
        }

        case MQ_SOCKS5_REQUEST_DONE: {
            /* Hand off: the core owns the fd from here. The success/error reply
             * is written by socks5_open_result on the (still-open) fd. Drop our
             * read interest first — the core (relay) now drives the fd, and
             * open_fn's result cb may fire asynchronously (later turn). */
            c->handed_off = 1;
            int fd = c->fd;
            conn_detach_read(c);
            l->open_fn(l->core, req.host, req.host_len, req.atype, req.port, fd, c,
                       socks5_open_result);
            return MQ_DRIVE_HANDOFF;
        }

        case MQ_SOCKS5_UNSUPPORTED: {
            /* Reject with command-not-supported (general failure REP) and close.
             * If we are still in the greeting phase, an UNSUPPORTED means no
             * acceptable auth method => send method reply 0xFF. */
            if (c->s5.phase == 0) {
                uint8_t mr[2];
                size_t n = mq_socks5_build_method_reply(mr, /*accepted=*/0);
                (void)send(c->fd, mr, n, MSG_NOSIGNAL);
            } else {
                uint8_t cr[10];
                size_t n = mq_socks5_build_connect_reply(
                    cr, mq_socks5_reply_code(MQ_TCP_CONN_REFUSED));
                (void)send(c->fd, cr, n, MSG_NOSIGNAL);
            }
            return MQ_DRIVE_CLOSE;
        }

        case MQ_SOCKS5_ERROR:
        default: return MQ_DRIVE_CLOSE;
        }
    }
}

/* ── HTTP CONNECT drive ─────────────────────────────────────────────────── */

static mq_drive_result_t
drive_http(struct mq_conn_state *c)
{
    mq_listener_t *l = c->l;

    mq_http_target_t tgt;
    memset(&tgt, 0, sizeof(tgt));
    size_t header_len = 0;
    mq_http_status_t st = mq_http_connect_parse(c->rxbuf, c->rxlen, &tgt, &header_len);

    switch (st) {
    case MQ_HTTP_NEED_MORE: return MQ_DRIVE_NEED_MORE;

    case MQ_HTTP_CONNECT_DONE: {
        int fd = c->fd;
        c->handed_off = 1;
        conn_detach_read(c);
        l->open_fn(l->core, tgt.host, tgt.host_len, tgt.atype, tgt.port, fd, c,
                   http_open_result);
        return MQ_DRIVE_HANDOFF;
    }

    case MQ_HTTP_UNSUPPORTED: {
        const char *line = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        (void)send(c->fd, line, strlen(line), MSG_NOSIGNAL);
        return MQ_DRIVE_CLOSE;
    }

    case MQ_HTTP_BAD:
    default: {
        const char *line = "HTTP/1.1 400 Bad Request\r\n\r\n";
        (void)send(c->fd, line, strlen(line), MSG_NOSIGNAL);
        return MQ_DRIVE_CLOSE;
    }
    }
}

/* ── open-result callbacks (write app-side reply on local_fd) ───────────────
 *
 * The core owns local_fd at this point. On ok=1 the relay has not closed it; on
 * ok=0 the core closes it AFTER this callback returns, so writing the error
 * reply here still reaches the app. We do NOT close local_fd in either case. */

static void
socks5_open_result(int ok, mq_tcp_err_t err, void *user)
{
    struct mq_conn_state *c = (struct mq_conn_state *)user;
    int fd = c->fd; /* still valid; core hasn't closed it yet */
    uint8_t cr[10];
    uint8_t rep = ok ? 0x00 : mq_socks5_reply_code(err);
    size_t n = mq_socks5_build_connect_reply(cr, rep);
    (void)send(fd, cr, n, MSG_NOSIGNAL);
    /* The fd is owned by the core; do not close. Free our parse state (we no
     * longer read from fd). */
    conn_destroy(c, /*close_fd=*/0);
}

static void
http_open_result(int ok, mq_tcp_err_t err, void *user)
{
    struct mq_conn_state *c = (struct mq_conn_state *)user;
    int fd = c->fd;
    if (ok) {
        char buf[64];
        size_t n = mq_http_build_200(buf, sizeof(buf));
        (void)send(fd, buf, n, MSG_NOSIGNAL);
    } else {
        const char *line = mq_http_status_line(err);
        (void)send(fd, line, strlen(line), MSG_NOSIGNAL);
    }
    conn_destroy(c, /*close_fd=*/0);
}

/* ── read event ─────────────────────────────────────────────────────────── */

static void
on_readable(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    struct mq_conn_state *c = (struct mq_conn_state *)user;

    for (;;) {
        if (c->rxlen >= sizeof(c->rxbuf)) {
            /* Request head too large; treat as protocol error. */
            conn_destroy(c, /*close_fd=*/1);
            return;
        }
        ssize_t n = recv(fd, c->rxbuf + c->rxlen, sizeof(c->rxbuf) - c->rxlen, 0);
        if (n > 0) {
            c->rxlen += (size_t)n;
            mq_drive_result_t r = c->l->drive(c);
            if (r == MQ_DRIVE_HANDOFF) {
                /* open_fn was called; the drive already detached our read event
                 * (conn_detach_read) before the call. `c` may now be freed (if
                 * the result cb fired synchronously) OR still alive awaiting an
                 * async cb. Either way the core owns fd and we must not touch
                 * `c` or fd again here. */
                return;
            }
            if (r == MQ_DRIVE_CLOSE) {
                conn_destroy(c, /*close_fd=*/1);
                return;
            }
            /* NEED_MORE: keep reading in this loop. */
            continue;
        }
        if (n == 0) {
            /* Peer closed before completing the request. */
            conn_destroy(c, /*close_fd=*/1);
            return;
        }
        /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* nothing more right now */
        }
        if (errno == EINTR) {
            continue;
        }
        conn_destroy(c, /*close_fd=*/1);
        return;
    }
}

/* ── accept event ───────────────────────────────────────────────────────── */

static int
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void
on_accept(evutil_socket_t lfd, short what, void *user)
{
    (void)what;
    mq_listener_t *l = (mq_listener_t *)user;

    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            MQ_LOGW("mq_listener: accept failed: %s", strerror(errno));
            return;
        }
        if (set_nonblock(fd) != 0) {
            close(fd);
            continue;
        }

        struct mq_conn_state *c = calloc(1, sizeof(*c));
        if (!c) {
            close(fd);
            continue;
        }
        c->l = l;
        c->fd = fd;
        mq_socks5_parser_init(&c->s5);
        c->next = l->conns;
        l->conns = c;

        c->read_ev = event_new(l->base, fd, EV_READ | EV_PERSIST, on_readable, c);
        if (!c->read_ev) {
            conn_destroy(c, /*close_fd=*/1);
            continue;
        }
        event_add(c->read_ev, NULL);
    }
}

/* ── construction ───────────────────────────────────────────────────────── */

static mq_listener_t *
listener_new(struct event_base *base, const char *bind_ip, uint16_t port,
             mq_tcp_open_fn open_fn, void *core, mq_drive_fn drive)
{
    if (!base || !bind_ip || !open_fn || !drive) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        close(fd);
        return NULL;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return NULL;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return NULL;
    }
    if (set_nonblock(fd) != 0) {
        close(fd);
        return NULL;
    }

    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    uint16_t lport = 0;
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) == 0) {
        lport = ntohs(bound.sin_port);
    }

    mq_listener_t *l = calloc(1, sizeof(*l));
    if (!l) {
        close(fd);
        return NULL;
    }
    l->base = base;
    l->listen_fd = fd;
    l->local_port = lport;
    l->open_fn = open_fn;
    l->core = core;
    l->drive = drive;
    l->conns = NULL;

    l->accept_ev = event_new(base, fd, EV_READ | EV_PERSIST, on_accept, l);
    if (!l->accept_ev) {
        close(fd);
        free(l);
        return NULL;
    }
    event_add(l->accept_ev, NULL);
    return l;
}

mq_listener_t *
mq_socks5_listener_new(struct event_base *base, const char *bind_ip, uint16_t port,
                       mq_tcp_open_fn open_fn, void *core)
{
    return listener_new(base, bind_ip, port, open_fn, core, drive_socks5);
}

mq_listener_t *
mq_http_connect_listener_new(struct event_base *base, const char *bind_ip, uint16_t port,
                             mq_tcp_open_fn open_fn, void *core)
{
    return listener_new(base, bind_ip, port, open_fn, core, drive_http);
}

uint16_t
mq_listener_local_port(const mq_listener_t *l)
{
    return l ? l->local_port : 0;
}

void
mq_listener_free(mq_listener_t *l)
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
    /* Reap any still-pending parse states (not yet handed off). */
    while (l->conns) {
        conn_destroy(l->conns, /*close_fd=*/1);
    }
    free(l);
}
