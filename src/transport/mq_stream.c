/* mq_stream.c — raw MPQUIC stream wrapper.
 *
 * mq_stream stores an xqc_stream_t and registers itself as that stream's
 * user_data (xqc_stream_set_user_data / the user_data arg of
 * xqc_stream_create). xquic's stream_read/write/close notifications recover
 * the mq_stream and forward to owner callbacks.
 */
#include "transport/mq_stream.h"

#include <stdint.h>
#include <stdlib.h>

#include "transport/mq_stream_internal.h"
#include "util/mq_log.h"

mq_stream_t *
mq_stream_wrap(xqc_stream_t *xs)
{
    if (!xs) {
        return NULL;
    }
    mq_stream_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->xs = xs;
    xqc_stream_set_user_data(xs, s);
    return s;
}

mq_stream_t *
mq_stream_alloc(void)
{
    return calloc(1, sizeof(struct mq_stream_s));
}

void
mq_stream_bind(mq_stream_t *s, xqc_stream_t *xs)
{
    if (!s || !xs) {
        return;
    }
    s->xs = xs;
    xqc_stream_set_user_data(xs, s);
}

void
mq_stream_free(mq_stream_t *s)
{
    free(s);
}

void
mq_stream_set_cbs(mq_stream_t *s, mq_stream_on_readable_fn on_readable,
                  mq_stream_on_writable_fn on_writable, mq_stream_on_close_fn on_close,
                  void *user)
{
    if (!s) {
        return;
    }
    s->on_readable = on_readable;
    s->on_writable = on_writable;
    s->on_close = on_close;
    s->cb_user = user;
}

long
mq_stream_send(mq_stream_t *s, const void *buf, size_t len, int fin)
{
    if (!s || !s->xs) {
        return -1;
    }
    /* xqc_stream_send takes a non-const pointer but does not mutate the
     * buffer; cast away const. */
    union {
        const void *cp;
        unsigned char *p;
    } u = {.cp = buf};
    ssize_t r = xqc_stream_send(s->xs, u.p, len, fin ? 1 : 0);
    if (r == -XQC_EAGAIN) {
        return 0; /* flow-control blocked; caller retries on on_writable */
    }
    if (r < 0) {
        MQ_LOGW("mq_stream: send failed: %zd", r);
        return -1;
    }
    return (long)r;
}

long
mq_stream_recv(mq_stream_t *s, void *buf, size_t cap, int *fin)
{
    if (!s || !s->xs) {
        return -1;
    }
    uint8_t xfin = 0;
    ssize_t r = xqc_stream_recv(s->xs, (unsigned char *)buf, cap, &xfin);
    if (r == -XQC_EAGAIN) {
        if (fin) {
            *fin = 0;
        }
        return 0;
    }
    if (r < 0) {
        MQ_LOGW("mq_stream: recv failed: %zd", r);
        return -1;
    }
    if (fin) {
        *fin = xfin ? 1 : 0;
    }
    return (long)r;
}

void
mq_stream_close(mq_stream_t *s)
{
    if (!s || !s->xs) {
        return;
    }
    xqc_stream_close(s->xs);
}

uint64_t
mq_stream_id(const mq_stream_t *s)
{
    if (!s || !s->xs) {
        return 0;
    }
    return xqc_stream_id(s->xs);
}

void *
mq_stream_conn(const mq_stream_t *s)
{
    return s ? s->conn : NULL;
}

void
mq_stream_set_conn(mq_stream_t *s, void *conn)
{
    if (s) {
        s->conn = conn;
    }
}

/* ── xquic stream notify callbacks (used by mq_conn's ALP tables) ───────── */

xqc_int_t
mq_stream_read_notify(xqc_stream_t *stream, void *strm_user_data)
{
    (void)stream;
    mq_stream_t *s = (mq_stream_t *)strm_user_data;
    if (s && s->on_readable) {
        s->on_readable(s, s->cb_user);
    }
    return 0;
}

xqc_int_t
mq_stream_write_notify(xqc_stream_t *stream, void *strm_user_data)
{
    (void)stream;
    mq_stream_t *s = (mq_stream_t *)strm_user_data;
    if (s && s->on_writable) {
        s->on_writable(s, s->cb_user);
    }
    return 0;
}

xqc_int_t
mq_stream_close_notify(xqc_stream_t *stream, void *strm_user_data)
{
    (void)stream;
    mq_stream_t *s = (mq_stream_t *)strm_user_data;
    if (!s) {
        return 0;
    }
    if (s->on_close) {
        s->on_close(s, s->cb_user);
    }
    mq_stream_free(s);
    return 0;
}
