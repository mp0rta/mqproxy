// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_fetch_listener.c — local fetch-API listener (POST /_mqproxy/fetch).
 *
 * Mirrors mq_listener's socket/bind/listen + EV_READ accept loop, but each
 * connection is a single request/response (Connection: close). After the head
 * parses, body bytes are streamed to the gateway via mq_fetch_cbs_t with
 * backpressure both ways; the gateway writes the response back through the
 * per-conn handle ops.
 *
 * See mq_fetch_listener.h for the fd/handle ownership contract and the request
 * lifecycle.
 */
#include "gateway/mq_fetch_listener.h"

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

/* The request method+path we accept; anything else is a listener-owned 404. */
#define MQ_FETCH_METHOD "POST"
#define MQ_FETCH_PATH   "/_mqproxy/fetch"

/* Output high/low watermarks for the response side. When queued output exceeds
 * the high watermark, mq_fetch_conn_write returns 0 (the gateway stops feeding)
 * and the drain cb fires once the queue falls below the low watermark. */
#define MQ_FETCH_OUT_HIGHWATER (256 * 1024)
#define MQ_FETCH_OUT_LOWWATER  (64 * 1024)

/* Read chunk size for body streaming. */
#define MQ_FETCH_RD_CHUNK 16384

struct mq_fetch_listener_s {
    struct event_base *base;
    int listen_fd;
    struct event *accept_ev;
    uint16_t local_port;
    mq_fetch_cbs_t cbs;
    void *user;
    struct mq_fetch_conn *conns; /* live per-conn list (intrusive) */
};

/* Per-connection state. Phases:
 *   HEAD  — accumulating the request head into rxbuf.
 *   BODY  — head accepted by on_request; streaming body bytes to on_body.
 *   RESP  — body done (or handler rejected): gateway owns the write side; we
 *           just drain output and wait for finish/abort.
 */
typedef enum { MQ_FC_HEAD, MQ_FC_BODY, MQ_FC_RESP } mq_fc_phase_t;

struct mq_fetch_conn {
    mq_fetch_listener_t *l;
    int fd; /* accepted app socket; -1 once closed */
    struct event *read_ev;
    struct event *write_ev; /* on-demand EV_WRITE while output is queued */
    mq_fc_phase_t phase;

    /* HEAD-phase read buffer (capped at MQ_HTTP1_MAX_HEAD). */
    uint8_t *rxbuf;
    size_t rxlen;
    size_t rxcap;

    /* BODY-phase accounting. */
    int64_t body_total;     /* content_length to deliver */
    int64_t body_delivered; /* bytes handed to on_body so far */
    void *req_ctx;          /* handler's per-request context */

    int read_paused; /* gateway asked us to stop reading (backpressure) */
    int detached;    /* finish/abort/on_aborted done: no cbs, handle dead */
    int closing;     /* finish requested: close once output drains */

    /* Growable output queue (response bytes from the gateway). */
    uint8_t *out;
    size_t out_len; /* bytes queued (unsent) */
    size_t out_off; /* bytes already written from out[0..] */
    size_t out_cap;
    int hw_hit; /* high watermark was hit since the last drain */

    void (*drain_cb)(void *);
    void *drain_user;

    struct mq_fetch_conn *next;
};

/* ── per-conn list bookkeeping ──────────────────────────────────────────── */

static void
conn_unlink(mq_fetch_listener_t *l, struct mq_fetch_conn *c)
{
    struct mq_fetch_conn **pp = &l->conns;
    while (*pp) {
        if (*pp == c) {
            *pp = c->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Tear down a per-conn state: free events, close the fd (listener always owns
 * it), free buffers, unlink, free. Never fires cbs. */
static void
conn_destroy(struct mq_fetch_conn *c)
{
    if (!c) return;
    conn_unlink(c->l, c);
    if (c->read_ev) {
        event_free(c->read_ev);
        c->read_ev = NULL;
    }
    if (c->write_ev) {
        event_free(c->write_ev);
        c->write_ev = NULL;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    free(c->rxbuf);
    free(c->out);
    free(c);
}

/* ── output queue / write side ──────────────────────────────────────────── */

/* Queued-but-unsent output bytes. */
static size_t
out_pending(const struct mq_fetch_conn *c)
{
    return c->out_len - c->out_off;
}

/* Append len bytes to the output queue, growing as needed. Returns 0 on OOM. */
static int
out_append(struct mq_fetch_conn *c, const void *p, size_t len)
{
    if (len == 0) return 1;
    /* Compact consumed prefix when it dominates, to bound growth. */
    if (c->out_off > 0 && c->out_off == c->out_len) {
        c->out_len = 0;
        c->out_off = 0;
    } else if (c->out_off >= MQ_FETCH_OUT_LOWWATER) {
        memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
        c->out_len -= c->out_off;
        c->out_off = 0;
    }
    if (c->out_len + len > c->out_cap) {
        size_t ncap = c->out_cap ? c->out_cap : 4096;
        while (ncap < c->out_len + len)
            ncap *= 2;
        uint8_t *nb = realloc(c->out, ncap);
        if (!nb) return 0;
        c->out = nb;
        c->out_cap = ncap;
    }
    memcpy(c->out + c->out_len, p, len);
    c->out_len += len;
    return 1;
}

/* Try to flush queued output to the socket. Returns -1 on hard error (caller
 * destroys the conn), 0 otherwise. Arms/disarms the EV_WRITE event and fires
 * the drain cb when crossing below the low watermark after a high-water hit.
 * If closing and the queue empties, the conn is destroyed (returns -1 sentinel
 * via *destroyed). */
static int
out_flush(struct mq_fetch_conn *c, int *destroyed)
{
    if (destroyed) *destroyed = 0;
    while (out_pending(c) > 0) {
        ssize_t n = send(c->fd, c->out + c->out_off, out_pending(c), MSG_NOSIGNAL);
        if (n > 0) {
            c->out_off += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* Socket full: arm EV_WRITE to resume on the writable edge. */
            if (c->write_ev) event_add(c->write_ev, NULL);
            break;
        }
        if (n < 0 && errno == EINTR) continue;
        /* Hard error. */
        return -1;
    }

    if (out_pending(c) == 0) {
        c->out_len = 0;
        c->out_off = 0;
        if (c->write_ev) event_del(c->write_ev);
        if (c->closing) {
            /* finish() flushed: close now. The handle is already detached. */
            conn_destroy(c);
            if (destroyed) *destroyed = 1;
            return 0;
        }
    }

    /* Drain notification: crossed below the low watermark after a high-water
     * hit. Only meaningful before detach/closing. */
    if (c->hw_hit && !c->detached && !c->closing &&
        out_pending(c) <= MQ_FETCH_OUT_LOWWATER) {
        c->hw_hit = 0;
        if (c->drain_cb) c->drain_cb(c->drain_user);
    }
    return 0;
}

static void
on_writable(evutil_socket_t fd, short what, void *user)
{
    (void)fd;
    (void)what;
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)user;
    int destroyed = 0;
    if (out_flush(c, &destroyed) < 0 && !destroyed) {
        conn_destroy(c);
    }
}

/* ── listener-owned direct error replies ────────────────────────────────── */

/* Build and queue "<status>\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
 * then flush + close. Never fires cbs. */
static void
reply_error_and_close(struct mq_fetch_conn *c, int code, const char *reason)
{
    char buf[128];
    int o = 0, n;
    n = mq_http1_write_status(buf + o, sizeof(buf) - (size_t)o, code, reason);
    if (n > 0) o += n;
    n = mq_http1_write_header(buf + o, sizeof(buf) - (size_t)o, "Connection", "close");
    if (n > 0) o += n;
    n = mq_http1_write_header(buf + o, sizeof(buf) - (size_t)o, "Content-Length", "0");
    if (n > 0) o += n;
    if ((size_t)o + 2 <= sizeof(buf)) {
        buf[o++] = '\r';
        buf[o++] = '\n';
    }
    /* Best-effort blocking-ish send; the head buffer is tiny so a single send
     * almost always takes it. Then close regardless. */
    (void)send(c->fd, buf, (size_t)o, MSG_NOSIGNAL);
    conn_destroy(c);
}

/* ── body streaming ─────────────────────────────────────────────────────── */

/* Deliver body bytes from [p, p+len) to on_body, honoring Content-Length.
 * Returns:
 *    1  delivered (body may now be complete); see *done,
 *    0  on_body asked to pause (read paused); *done set,
 *   -1  the conn was destroyed (oversize abort) — caller MUST stop.
 *
 * Only the in-bounds portion (up to remaining Content-Length) is delivered to
 * on_body in a single call, so cbs observe EXACTLY Content-Length bytes. Any
 * bytes in this chunk beyond Content-Length are a protocol violation by the
 * peer: after on_body_done fires we abort the connection (on_aborted).
 *
 * NOTE: *done is set when the caller must NOT touch `c` afterward — either the
 * read is paused, or the body completed (on_body_done may have finished/aborted
 * the conn), or the conn was destroyed. */
static int
deliver_body(struct mq_fetch_conn *c, const uint8_t *p, size_t len, int *done)
{
    mq_fetch_listener_t *l = c->l;
    if (done) *done = 0;
    if (len == 0) return 1;

    int64_t remain = c->body_total - c->body_delivered;
    size_t take = len;
    int oversize = 0;
    if ((int64_t)take > remain) {
        take = (size_t)remain; /* deliver only up to Content-Length */
        oversize = 1;          /* extra bytes follow: abort after on_body_done */
    }

    if (take > 0 && l->cbs.on_body) {
        int rc = l->cbs.on_body(c->req_ctx, p, take);
        c->body_delivered += (int64_t)take;
        if (rc == -1) {
            /* Backpressure: the chunk IS consumed (consume-on-deliver
             * contract); on_body just wants us to stop reading more body.
             * Pause; the gateway resumes via the handle. (A paused chunk never
             * coincides with oversize: take==remain only when oversize, and a
             * pause there still leaves body incomplete=false — but we honor the
             * pause first; the abort, if any, is moot once we stop reading.) */
            c->read_paused = 1;
            if (c->read_ev) event_del(c->read_ev);
            if (done) *done = 1;
            return 0;
        }
    } else {
        c->body_delivered += (int64_t)take;
    }

    if (c->body_delivered >= c->body_total) {
        /* Exactly Content-Length delivered. Move to RESP, then on_body_done —
         * the gateway now owns the write side and will finish/abort. */
        c->phase = MQ_FC_RESP;
        if (done) *done = 1;
        if (l->cbs.on_body_done) l->cbs.on_body_done(c->req_ctx);

        if (oversize && !c->detached) {
            /* Trailing bytes past Content-Length: protocol violation. The
             * gateway may already have finished/aborted (detached) from
             * on_body_done; only abort if it did not. */
            c->detached = 1;
            if (l->cbs.on_aborted) l->cbs.on_aborted(c->req_ctx);
            conn_destroy(c);
            return -1;
        }
    }
    return 1;
}

/* ── HEAD-phase parse + dispatch ────────────────────────────────────────── */

/* Process whatever is in rxbuf during HEAD phase. Returns -1 if the conn was
 * destroyed (caller must stop), 0 if it survives (may now be in BODY/RESP). */
static int
drive_head(struct mq_fetch_conn *c)
{
    mq_fetch_listener_t *l = c->l;

    mq_http1_req_t req;
    mq_http1_status_t st = mq_http1_parse_req(c->rxbuf, c->rxlen, &req);

    if (st == MQ_HTTP1_NEED_MORE) {
        return 0; /* keep reading */
    }
    if (st == MQ_HTTP1_BAD) {
        reply_error_and_close(c, 400, "Bad Request");
        return -1;
    }

    /* DONE: validate method+path, then policy. */
    if (strcmp(req.method, MQ_FETCH_METHOD) != 0 ||
        strcmp(req.path, MQ_FETCH_PATH) != 0) {
        reply_error_and_close(c, 404, "Not Found");
        return -1;
    }
    if (req.has_chunked_te) {
        reply_error_and_close(c, 411, "Length Required");
        return -1;
    }

    /* Accepted request. Hand it to the gateway. */
    c->phase = MQ_FC_BODY;
    c->body_total = req.content_length > 0 ? req.content_length : 0;
    c->body_delivered = 0;

    void *ctx = NULL;
    int rc = 0;
    if (l->cbs.on_request) {
        rc = l->cbs.on_request(&req, c, l->user, &ctx);
    }
    c->req_ctx = ctx;

    if (rc == -1) {
        /* Handler wrote its own error reply via the handle ops. Flush + close;
         * no body streamed, no further cbs. */
        c->detached = 1;
        c->closing = 1;
        c->phase = MQ_FC_RESP;
        if (c->read_ev) event_del(c->read_ev);
        int destroyed = 0;
        if (out_flush(c, &destroyed) < 0 && !destroyed) {
            conn_destroy(c);
        }
        return -1; /* c may be alive (closing) but HEAD drive is done */
    }

    /* Stream any body bytes already buffered past the head. */
    size_t head_len = req.head_len;
    const uint8_t *body = c->rxbuf + head_len;
    size_t body_buffered = c->rxlen - head_len;

    if (c->body_total <= 0) {
        /* No body: on_body_done immediately. The read event stays armed so the
         * RESP branch notices peer EOF (normal here — the gateway writes the
         * reply via the handle). on_body_done may finish/abort the conn, so
         * stop the HEAD drive afterward (do not touch c). */
        c->phase = MQ_FC_RESP;
        if (l->cbs.on_body_done) l->cbs.on_body_done(c->req_ctx);
        return -1; /* body complete: HEAD drive done, do not loop */
    }

    if (body_buffered > 0) {
        int done = 0;
        int dr = deliver_body(c, body, body_buffered, &done);
        if (dr == -1) return -1; /* destroyed */
        if (done) return -1;     /* paused or body complete: do not loop on c */
    }
    return 0;
}

/* ── read event ─────────────────────────────────────────────────────────── */

static int
ensure_rx_space(struct mq_fetch_conn *c, size_t want)
{
    if (c->rxlen + want <= c->rxcap) return 1;
    size_t ncap = c->rxcap ? c->rxcap : 4096;
    while (ncap < c->rxlen + want)
        ncap *= 2;
    if (ncap > MQ_HTTP1_MAX_HEAD) ncap = MQ_HTTP1_MAX_HEAD;
    if (c->rxlen + want > ncap) return 0; /* would exceed head cap */
    uint8_t *nb = realloc(c->rxbuf, ncap);
    if (!nb) return 0;
    c->rxbuf = nb;
    c->rxcap = ncap;
    return 1;
}

static void
on_readable(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)user;

    for (;;) {
        if (c->read_paused) return; /* gateway asked us to stop */

        if (c->phase == MQ_FC_HEAD) {
            if (!ensure_rx_space(c, MQ_FETCH_RD_CHUNK)) {
                /* Head exceeds cap with no terminator: treat as bad request. */
                reply_error_and_close(c, 400, "Bad Request");
                return;
            }
            ssize_t n = recv(fd, c->rxbuf + c->rxlen, c->rxcap - c->rxlen, 0);
            if (n > 0) {
                c->rxlen += (size_t)n;
                if (drive_head(c) < 0) return; /* destroyed (or closing) */
                continue;
            }
            if (n == 0) {
                /* Peer closed before completing the head: just close. No cbs
                 * fired yet (still HEAD). */
                conn_destroy(c);
                return;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            conn_destroy(c);
            return;
        }

        if (c->phase == MQ_FC_BODY) {
            uint8_t buf[MQ_FETCH_RD_CHUNK];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                int done = 0;
                int dr = deliver_body(c, buf, (size_t)n, &done);
                if (dr == -1) return; /* destroyed (oversize abort) */
                if (done) return;     /* paused or body complete: stop reading */
                continue;
            }
            if (n == 0) {
                /* Peer EOF before content_length bytes: abort (NOT done). */
                c->detached = 1;
                if (c->l->cbs.on_aborted) c->l->cbs.on_aborted(c->req_ctx);
                conn_destroy(c);
                return;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            /* read error before CL: treat as abort. */
            c->detached = 1;
            if (c->l->cbs.on_aborted) c->l->cbs.on_aborted(c->req_ctx);
            conn_destroy(c);
            return;
        }

        /* MQ_FC_RESP: body fully delivered; the gateway owns the write side.
         * Peer EOF here is normal (it finished uploading). We drain/discard any
         * trailing reads but otherwise wait for finish/abort. */
        {
            uint8_t buf[1024];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                /* Unexpected extra bytes after a complete request; ignore them
                 * (keep-alive unsupported). Keep draining. */
                continue;
            }
            if (n == 0) {
                /* Peer closed its write side. If the gateway has already
                 * detached (finish/abort) the conn is gone; otherwise stop
                 * reading and let the gateway finish writing the response. The
                 * gateway will call finish/abort to close. */
                if (c->read_ev) event_del(c->read_ev);
                return;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            if (c->read_ev) event_del(c->read_ev);
            return;
        }
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
    mq_fetch_listener_t *l = (mq_fetch_listener_t *)user;

    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            MQ_LOGW("mq_fetch_listener: accept failed: %s", strerror(errno));
            return;
        }
        if (set_nonblock(fd) != 0) {
            close(fd);
            continue;
        }

        struct mq_fetch_conn *c = calloc(1, sizeof(*c));
        if (!c) {
            close(fd);
            continue;
        }
        c->l = l;
        c->fd = fd;
        c->phase = MQ_FC_HEAD;
        c->body_total = 0;
        c->next = l->conns;
        l->conns = c;

        c->read_ev = event_new(l->base, fd, EV_READ | EV_PERSIST, on_readable, c);
        c->write_ev = event_new(l->base, fd, EV_WRITE | EV_PERSIST, on_writable, c);
        if (!c->read_ev || !c->write_ev) {
            conn_destroy(c);
            continue;
        }
        event_add(c->read_ev, NULL);
    }
}

/* ── construction ───────────────────────────────────────────────────────── */

mq_fetch_listener_t *
mq_fetch_listener_new(struct event_base *base, const char *ip, uint16_t port,
                      const mq_fetch_cbs_t *cbs, void *user)
{
    if (!base || !ip || !cbs) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
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

    mq_fetch_listener_t *l = calloc(1, sizeof(*l));
    if (!l) {
        close(fd);
        return NULL;
    }
    l->base = base;
    l->listen_fd = fd;
    l->local_port = lport;
    l->cbs = *cbs;
    l->user = user;
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

uint16_t
mq_fetch_listener_port(const mq_fetch_listener_t *l)
{
    return l ? l->local_port : 0;
}

void
mq_fetch_listener_free(mq_fetch_listener_t *l)
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
    while (l->conns) {
        conn_destroy(l->conns);
    }
    free(l);
}

/* ── per-connection handle ops ──────────────────────────────────────────── */

void
mq_fetch_conn_pause_read(void *handle)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached) return;
    c->read_paused = 1;
    if (c->read_ev) event_del(c->read_ev);
}

void
mq_fetch_conn_resume_read(void *handle)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached) return;
    if (!c->read_paused) return;
    c->read_paused = 0;
    if (c->read_ev) event_add(c->read_ev, NULL);
    /* Kick the read loop so buffered/ready bytes are processed immediately. */
    on_readable(c->fd, EV_READ, c);
}

int
mq_fetch_conn_write(void *handle, const void *p, size_t len)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached || c->fd < 0) return -1;
    if (!out_append(c, p, len)) return -1;

    int destroyed = 0;
    if (out_flush(c, &destroyed) < 0) {
        if (!destroyed) conn_destroy(c);
        return -1;
    }
    if (destroyed) return -1; /* shouldn't happen unless closing, but be safe */

    if (out_pending(c) > MQ_FETCH_OUT_HIGHWATER) {
        c->hw_hit = 1;
        return 0; /* high watermark: gateway stops feeding */
    }
    return 1; /* accepted */
}

void
mq_fetch_conn_set_drain_cb(void *handle, void (*fn)(void *), void *u)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached) return;
    c->drain_cb = fn;
    c->drain_user = u;
}

void
mq_fetch_conn_finish(void *handle)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached) return;
    /* Detach FIRST: no cbs may fire after finish. Then flush remaining output;
     * close once drained (out_flush destroys the conn when closing+empty). */
    c->detached = 1;
    c->closing = 1;
    c->drain_cb = NULL;
    if (c->read_ev) event_del(c->read_ev);
    int destroyed = 0;
    if (out_flush(c, &destroyed) < 0 && !destroyed) {
        conn_destroy(c);
    }
}

void
mq_fetch_conn_abort(void *handle)
{
    struct mq_fetch_conn *c = (struct mq_fetch_conn *)handle;
    if (!c || c->detached) return;
    c->detached = 1;
    c->drain_cb = NULL;
    conn_destroy(c);
}
