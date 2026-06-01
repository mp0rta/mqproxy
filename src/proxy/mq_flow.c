/* mq_flow.c — shared QUIC-stream ⇄ TCP-fd relay glue. See mq_flow.h. */
#include "proxy/mq_flow.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_relay.h"
#include "util/mq_log.h"

/* Per-flow node. Lifecycle phases:
 *   1. Pre-relay: stream attached, fd being connected by the owner (relay==NULL).
 *   2. Relaying: relay live; persistent EV_READ + on-demand EV_WRITE on the fd
 *      and the stream read/write callbacks drive the relay edges.
 *   3. Reaped: stream closed, fd closed, events freed, relay freed, unlinked.
 */
struct mq_flow_s {
    mq_flow_t **list_head; /* owner's intrusive list head */
    struct event_base *base;

    mq_stream_t *stream; /* A side; NULL'd by the stream on_close callback */
    int fd;              /* B side TCP socket, -1 once closed */
    struct event *rd_ev; /* persistent EV_READ on fd (relay phase) */
    struct event *wr_ev; /* on-demand EV_WRITE on fd */
    mq_relay_t *relay;

    int reaped;
    int graceful;     /* stream finished/owes a FIN: do NOT RESET on reap */
    int fin_sent;     /* a FIN was already sent on the QUIC stream (idempotency) */
    int pending_reap; /* a direction hit EOF (simple-close): reap after this edge */
    int a_fin_armed;  /* B (fd) source EOF'd: coalesce FIN onto the final A write */

    /* Bytes pulled off the stream by the owner BEFORE the relay started (e.g. the
     * download payload that trailed the CONNECT_TCP_RESPONSE in the same read).
     * flow_a_read drains these FIRST so they reach B (the fd) and are not lost. */
    unsigned char *pre;
    size_t pre_len;
    size_t pre_off;

    mq_flow_on_reap_fn on_reap;
    void *user;

    mq_flow_t *next;
};

/* ── list ─────────────────────────────────────────────────────────────────── */
static void
flow_unlink(mq_flow_t *f)
{
    mq_flow_t **pp = f->list_head;
    while (*pp) {
        if (*pp == f) {
            *pp = f->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ── reap ─────────────────────────────────────────────────────────────────── */
void
mq_flow_reap(mq_flow_t *f)
{
    if (!f || f->reaped) {
        return;
    }
    f->reaped = 1;

    if (f->rd_ev) {
        event_free(f->rd_ev);
        f->rd_ev = NULL;
    }
    if (f->wr_ev) {
        event_free(f->wr_ev);
        f->wr_ev = NULL;
    }
    if (f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }
    if (f->stream) {
        /* Detach our callbacks so the imminent stream close_notify does not call
         * back into a freed node. If graceful, a FIN was already sent (or owed)
         * and we must NOT RESET (RESET would discard un-acked stream data);
         * otherwise abort with RESET_STREAM. The mq_stream is freed by the
         * transport's stream_close_notify. */
        mq_stream_set_cbs(f->stream, NULL, NULL, NULL, NULL);
        if (!f->graceful) {
            mq_stream_close(f->stream);
        }
        f->stream = NULL;
    }
    if (f->relay) {
        mq_relay_free(f->relay);
        f->relay = NULL;
    }
    if (f->pre) {
        free(f->pre);
        f->pre = NULL;
        f->pre_len = f->pre_off = 0;
    }

    /* Unlink from the owner's list BEFORE on_reap: on_reap may free the owner
     * object that holds *list_head (e.g. a protocol node whose `flow` field is
     * our list root), so we must not dereference list_head afterward. */
    flow_unlink(f);
    if (f->on_reap) {
        f->on_reap(f, f->user);
    }
    free(f);
}

/* If a direction EOF requested a simple-close reap during the edge that just
 * ran, perform it now (after the relay/libevent callback has fully unwound, so
 * reaping is free of use-after-free). */
static void
flow_drain_pending(mq_flow_t *f)
{
    if (f->pending_reap && !f->reaped) {
        mq_flow_reap(f);
    }
}

/* Stop watching the B-side fd for read/write edges. Called when the origin
 * direction finishes (B EOF) so the level-triggered EV_READ on a half-closed fd
 * cannot re-fire forever (the busy-spin), and on any reap. */
static void
flow_stop_fd_events(mq_flow_t *f)
{
    if (f->rd_ev) {
        event_del(f->rd_ev);
    }
    if (f->wr_ev) {
        event_del(f->wr_ev);
    }
}

/* Send a clean FIN on the QUIC stream (idempotent). The relay guarantees the
 * B->A buffer is drained when this fires, so a zero-length FIN just closes the
 * send direction; the peer then sees stream EOF (never a RESET). Marks the node
 * graceful so reap will NOT RESET. */
static void
flow_send_fin(mq_flow_t *f)
{
    if (f->fin_sent) {
        return;
    }
    f->fin_sent = 1;
    f->graceful = 1;
    if (f->stream) {
        long n = mq_stream_send(f->stream, NULL, 0, /*fin=*/1);
        if (n < 0) {
            MQ_LOGW("mq_flow: stream FIN send failed");
        }
    }
}

/* ── relay callbacks ──────────────────────────────────────────────────────── */
/* Per-direction EOF: propagate a clean shutdown for the finished direction (FIN
 * to A on B EOF; SHUT_WR to B on A FIN), stop watching the dead fd so it cannot
 * busy-spin, and request a reap (simple-close: either direction EOF closes
 * both). MUST NOT free here — the relay/libevent callback that triggered this
 * may still touch the node. The reap runs from flow_drain_pending. */
static void
flow_relay_dir_eof(mq_relay_t *r, mq_relay_dir_t dir, void *user)
{
    (void)r;
    mq_flow_t *f = (mq_flow_t *)user;
    if (dir == MQ_RELAY_DIR_BA) {
        /* B (fd) -> A (stream) finished: fd recv hit EOF and B->A is flushed.
         * Stop the now level-triggered fd read event to kill the busy-spin, then
         * FIN the QUIC stream so A observes a clean EOF with all bytes. */
        flow_stop_fd_events(f);
        flow_send_fin(f);
    } else {
        /* A (stream) -> B (fd) finished: the stream's read side hit FIN and A->B
         * is flushed. Half-close the fd's write side so the app sees EOF, stop
         * the fd read events (closing both under simple-close), and FIN the
         * stream's WRITE side so the bidi stream closes cleanly from this end
         * (e.g. the client end of a download, which never sent data itself).
         * flow_send_fin marks the node graceful so reap will not RESET. */
        if (f->fd >= 0) {
            shutdown(f->fd, SHUT_WR);
        }
        flow_stop_fd_events(f);
        f->graceful = 1;
    }
    f->pending_reap = 1;
}

/* on_done: BOTH directions finished or a hard error. We do NOT free here (the
 * relay touches *r after on_done returns); request a deferred reap. On the clean
 * both-EOF path flow_relay_dir_eof already FIN'd and marked graceful, so reap
 * will not RESET; on a hard error graceful stays 0 → RESET. */
static void
flow_relay_done(mq_relay_t *r, void *user)
{
    (void)r;
    mq_flow_t *f = (mq_flow_t *)user;
    f->pending_reap = 1;
}

/* ── relay I/O adapters ───────────────────────────────────────────────────── */
/* A side = QUIC stream. */
static long
flow_a_read(void *io, unsigned char *buf, size_t cap, int *eof, int *wb)
{
    mq_flow_t *f = (mq_flow_t *)io;
    if (!f->stream) {
        *eof = 1;
        return 0;
    }
    /* Drain owner-prebuffered stream bytes first (see mq_flow_t::pre). */
    if (f->pre && f->pre_off < f->pre_len) {
        size_t avail = f->pre_len - f->pre_off;
        size_t take = avail < cap ? avail : cap;
        memcpy(buf, f->pre + f->pre_off, take);
        f->pre_off += take;
        if (f->pre_off >= f->pre_len) {
            free(f->pre);
            f->pre = NULL;
            f->pre_len = f->pre_off = 0;
        }
        return (long)take;
    }

    int fin = 0;
    long n = mq_stream_recv(f->stream, buf, cap, &fin);
    if (n < 0) {
        return -1;
    }
    if (fin) {
        *eof = 1;
    }
    if (n == 0 && !fin) {
        *wb = 1;
    }
    return n;
}

static long
flow_a_write(void *io, const unsigned char *buf, size_t len, int *wb)
{
    mq_flow_t *f = (mq_flow_t *)io;
    if (!f->stream) {
        return -1;
    }
    /* If B's source has EOF'd, this B->A flush carries the stream's final bytes.
     * Coalesce the FIN onto a write that xquic accepts IN FULL (n == len): xquic
     * only commits the FIN with the data when the whole buffer is taken, so on a
     * partial/blocked accept we send fin=0 and retry (the relay re-calls us). */
    int want_fin = (f->a_fin_armed && len > 0) ? 1 : 0;
    long n = mq_stream_send(f->stream, buf, len, want_fin);
    if (n < 0) {
        return -1;
    }
    if (want_fin && n == (long)len) {
        f->fin_sent = 1; /* the FIN went out coalesced with the last data */
        f->graceful = 1;
    }
    if (n == 0 && len > 0) {
        *wb = 1; /* flow-control blocked; resumes on stream on_writable */
    }
    return n;
}

/* B side = TCP fd. */
static long
flow_b_read(void *io, unsigned char *buf, size_t cap, int *eof, int *wb)
{
    mq_flow_t *f = (mq_flow_t *)io;
    if (f->fd < 0) {
        *eof = 1;
        return 0;
    }
    ssize_t n = recv(f->fd, buf, cap, 0);
    if (n == 0) {
        *eof = 1;
        /* B (fd) source is done: the remaining B->A bytes are the last data the
         * stream will carry. Arm FIN coalescing so the final flow_a_write that
         * drains them carries fin=1 (avoids a standalone zero-length FIN being
         * attached at a flow-control-blocked offset, which truncates data still
         * buffered in xquic — the demo always sends fin WITH the last bytes). */
        f->a_fin_armed = 1;
        return 0;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *wb = 1;
            return 0;
        }
        return -1;
    }
    return (long)n;
}

static long
flow_b_write(void *io, const unsigned char *buf, size_t len, int *wb)
{
    mq_flow_t *f = (mq_flow_t *)io;
    if (f->fd < 0) {
        return -1;
    }
    ssize_t n = send(f->fd, buf, len, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *wb = 1;
            if (f->wr_ev) {
                event_add(f->wr_ev, NULL); /* get a writable edge to resume */
            }
            return 0;
        }
        return -1;
    }
    return (long)n;
}

/* ── edge wiring ──────────────────────────────────────────────────────────── */
static void
flow_stream_readable(mq_stream_t *s, void *user)
{
    (void)s;
    mq_flow_t *f = (mq_flow_t *)user;
    if (f->relay) {
        mq_relay_on_a_readable(f->relay);
        flow_drain_pending(f);
    }
}

static void
flow_stream_writable(mq_stream_t *s, void *user)
{
    (void)s;
    mq_flow_t *f = (mq_flow_t *)user;
    if (f->relay) {
        mq_relay_on_a_writable(f->relay);
        flow_drain_pending(f);
    }
}

static void
flow_stream_closed(mq_stream_t *s, void *user)
{
    (void)s;
    mq_flow_t *f = (mq_flow_t *)user;
    f->stream = NULL; /* the transport frees it after this returns */
    mq_flow_reap(f);
}

static void
flow_fd_readable_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_flow_t *f = (mq_flow_t *)arg;
    if (f->relay) {
        mq_relay_on_b_readable(f->relay);
        flow_drain_pending(f);
    }
}

static void
flow_fd_writable_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_flow_t *f = (mq_flow_t *)arg;
    if (f->relay) {
        mq_relay_on_b_writable(f->relay);
        flow_drain_pending(f);
    }
}

/* ── public ───────────────────────────────────────────────────────────────── */
mq_flow_t *
mq_flow_new(mq_flow_t **list_head, struct event_base *base, mq_stream_t *stream, int fd,
            mq_flow_on_reap_fn on_reap, void *user)
{
    if (!list_head || !base) {
        return NULL;
    }
    mq_flow_t *f = calloc(1, sizeof(*f));
    if (!f) {
        return NULL;
    }
    f->list_head = list_head;
    f->base = base;
    f->stream = stream;
    f->fd = fd;
    f->on_reap = on_reap;
    f->user = user;
    f->next = *list_head;
    *list_head = f;
    return f;
}

int
mq_flow_prebuffer(mq_flow_t *f, const void *data, size_t len)
{
    if (!f || f->relay) {
        return -1; /* must be set before mq_flow_begin_relay */
    }
    if (len == 0) {
        return 0;
    }
    unsigned char *p = malloc(len);
    if (!p) {
        return -1;
    }
    memcpy(p, data, len);
    /* Replace any prior prebuffer (single-use at relay start). */
    free(f->pre);
    f->pre = p;
    f->pre_len = len;
    f->pre_off = 0;
    return 0;
}

int
mq_flow_begin_relay(mq_flow_t *f)
{
    if (!f || !f->stream || f->fd < 0) {
        return -1;
    }

    mq_relay_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.a_io = f;
    cfg.b_io = f;
    cfg.a_read = flow_a_read;
    cfg.a_write = flow_a_write;
    cfg.b_read = flow_b_read;
    cfg.b_write = flow_b_write;
    cfg.on_dir_eof = flow_relay_dir_eof;
    cfg.on_done = flow_relay_done;
    cfg.user = f;

    f->relay = mq_relay_new(&cfg);
    if (!f->relay) {
        MQ_LOGE("mq_flow: relay alloc failed");
        return -1;
    }

    f->rd_ev = event_new(f->base, f->fd, EV_READ | EV_PERSIST, flow_fd_readable_cb, f);
    f->wr_ev = event_new(f->base, f->fd, EV_WRITE, flow_fd_writable_cb, f);
    if (!f->rd_ev || !f->wr_ev) {
        MQ_LOGE("mq_flow: fd event alloc failed");
        mq_relay_free(f->relay);
        f->relay = NULL;
        if (f->rd_ev) {
            event_free(f->rd_ev);
            f->rd_ev = NULL;
        }
        if (f->wr_ev) {
            event_free(f->wr_ev);
            f->wr_ev = NULL;
        }
        return -1;
    }
    event_add(f->rd_ev, NULL);

    /* Re-wire the stream callbacks for the relay phase. */
    mq_stream_set_cbs(f->stream, flow_stream_readable, flow_stream_writable,
                      flow_stream_closed, f);

    /* Pump both directions once: any bytes already buffered on the stream/fd,
     * plus to register interest. A direction may already be at EOF here, so
     * honor a pending simple-close reap afterward. */
    mq_relay_on_a_readable(f->relay);
    mq_relay_on_b_readable(f->relay);
    flow_drain_pending(f);
    return 0;
}
