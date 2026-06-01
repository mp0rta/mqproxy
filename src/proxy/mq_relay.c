#include "proxy/mq_relay.h"
#include "util/mq_buf.h"

#include <stdlib.h>

struct mq_relay {
    mq_relay_cfg_t cfg;
    mq_buf_t ab; /* A -> B */
    mq_buf_t ba; /* B -> A */
    int a_eof;   /* A's source hit EOF */
    int b_eof;   /* B's source hit EOF */
    int done;    /* on_done already fired */
    int error;   /* a hard error occurred */
};

mq_relay_t *
mq_relay_new(const mq_relay_cfg_t *cfg)
{
    mq_relay_t *r = (mq_relay_t *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->cfg = *cfg;
    mq_buf_reset(&r->ab);
    mq_buf_reset(&r->ba);
    r->a_eof = 0;
    r->b_eof = 0;
    r->done = 0;
    r->error = 0;
    return r;
}

void
mq_relay_free(mq_relay_t *r)
{
    free(r);
}

/* A direction is finished when its source is at EOF and its buffer is drained. */
static int
dir_finished(int src_eof, const mq_buf_t *buf)
{
    return src_eof && mq_buf_len(buf) == 0;
}

/*
 * Pump a single direction: read from (read_io, read_fn) into `buf`, write
 * `buf` out to (write_io, write_fn).  Honors backpressure: never reads when
 * the buffer is full, never spins on would-block.  Terminates an iteration
 * when neither a read nor a write made progress.
 *
 * Sets *r->error on hard error (read or write returns -1).
 */
static void
pump_dir(mq_relay_t *r, void *read_io, mq_io_read_fn read_fn, void *write_io,
         mq_io_write_fn write_fn, mq_buf_t *buf, int *src_eof)
{
    for (;;) {
        int progress = 0;

        /* --- read into buffer, if room and source still open --- */
        if (!*src_eof && mq_buf_space(buf) > 0) {
            int eof = 0, wb = 0;
            long n =
                read_fn(read_io, mq_buf_write_ptr(buf), mq_buf_space(buf), &eof, &wb);
            if (n < 0) {
                r->error = 1;
                return;
            }
            if (n > 0) {
                mq_buf_commit(buf, (size_t)n);
                progress = 1;
            }
            if (eof) *src_eof = 1;
            /* wb with n==0 just means nothing to read now; stop trying to read */
        }

        /* --- write buffered bytes out --- */
        if (mq_buf_len(buf) > 0) {
            int wb = 0;
            long n = write_fn(write_io, mq_buf_read_ptr(buf), mq_buf_len(buf), &wb);
            if (n < 0) {
                r->error = 1;
                return;
            }
            if (n > 0) {
                mq_buf_consume(buf, (size_t)n);
                progress = 1;
            }
            if (wb) {
                /* destination is full; stop writing this direction.  It resumes
                   on the destination's writable edge.  Don't keep looping. */
                return;
            }
        }

        if (!progress) return; /* nothing read, nothing written: avoid spinning */
    }
}

static void
maybe_done(mq_relay_t *r)
{
    if (r->done) return;
    if (r->error || (dir_finished(r->a_eof, &r->ab) && dir_finished(r->b_eof, &r->ba))) {
        r->done = 1;
        if (r->cfg.on_done) r->cfg.on_done(r, r->cfg.user);
    }
}

/* A->B direction: read from A, write to B. */
static void
pump_ab(mq_relay_t *r)
{
    if (r->done) return;
    pump_dir(r, r->cfg.a_io, r->cfg.a_read, r->cfg.b_io, r->cfg.b_write, &r->ab,
             &r->a_eof);
    maybe_done(r);
}

/* B->A direction: read from B, write to A. */
static void
pump_ba(mq_relay_t *r)
{
    if (r->done) return;
    pump_dir(r, r->cfg.b_io, r->cfg.b_read, r->cfg.a_io, r->cfg.a_write, &r->ba,
             &r->b_eof);
    maybe_done(r);
}

void
mq_relay_on_a_readable(mq_relay_t *r)
{
    pump_ab(r); /* A is the source for A->B */
}

void
mq_relay_on_a_writable(mq_relay_t *r)
{
    pump_ba(r); /* A is the destination for B->A */
}

void
mq_relay_on_b_readable(mq_relay_t *r)
{
    pump_ba(r); /* B is the source for B->A */
}

void
mq_relay_on_b_writable(mq_relay_t *r)
{
    pump_ab(r); /* B is the destination for A->B */
}
