#include "proxy/mq_relay.h"
#include "mqtest.h"
#include <string.h>

/*
 * In-memory I/O double for the relay.
 *
 * Read side:
 *   - `in` holds `in_len` bytes; `in_pos` is the read cursor.
 *   - `read_chunk` caps how many bytes a single read returns (0 = unlimited).
 *   - `read_wb_every`: if >0, every `read_wb_every`-th read call returns a
 *     would-block (no bytes) instead of data, then resumes.  Models a source
 *     that intermittently has nothing ready.
 *   - When `in_pos == in_len`, read reports clean EOF (unless `no_eof`).
 *   - `read_err`: if set, the next read returns a hard error (-1).
 *
 * Write side:
 *   - `out` accumulates written bytes; `out_len` is the count.
 *   - `write_budget`: max bytes this side will accept before would-blocking.
 *     Decremented as bytes are accepted.  When 0, write would-blocks.
 *     Refill by assigning `write_budget` to simulate a writable edge.
 *   - `write_err`: if set, the next write returns a hard error (-1).
 */
typedef struct {
    const unsigned char *in;
    size_t in_len;
    size_t in_pos;
    size_t read_chunk;
    int read_wb_every;
    int read_calls;
    int no_eof;
    int read_err;

    unsigned char out[1024];
    size_t out_len;
    long write_budget;
    int write_err;
} mem_io_t;

static long
mem_read(void *io, unsigned char *buf, size_t cap, int *eof, int *wb)
{
    mem_io_t *m = (mem_io_t *)io;
    m->read_calls++;

    if (m->read_err) {
        return -1;
    }

    if (m->read_wb_every > 0 && (m->read_calls % m->read_wb_every) == 0) {
        *wb = 1;
        return 0;
    }

    size_t avail = m->in_len - m->in_pos;
    if (avail == 0) {
        if (m->no_eof) {
            *wb = 1;
            return 0;
        }
        *eof = 1;
        return 0;
    }

    size_t n = avail;
    if (n > cap) n = cap;
    if (m->read_chunk > 0 && n > m->read_chunk) n = m->read_chunk;

    memcpy(buf, m->in + m->in_pos, n);
    m->in_pos += n;
    return (long)n;
}

static long
mem_write(void *io, const unsigned char *buf, size_t len, int *wb)
{
    mem_io_t *m = (mem_io_t *)io;

    if (m->write_err) {
        return -1;
    }

    if (m->write_budget <= 0) {
        *wb = 1;
        return 0;
    }

    size_t n = len;
    if ((long)n > m->write_budget) n = (size_t)m->write_budget;

    /* guard against overflowing the test buffer */
    if (m->out_len + n > sizeof(m->out)) n = sizeof(m->out) - m->out_len;

    memcpy(m->out + m->out_len, buf, n);
    m->out_len += n;
    m->write_budget -= (long)n;

    if (n < len) *wb = 1; /* accepted some, but budget exhausted */
    return (long)n;
}

static void
mem_init(mem_io_t *m)
{
    memset(m, 0, sizeof(*m));
}

/* ---- on_done counter ---- */
static int g_done_count;
static void
on_done(mq_relay_t *r, void *user)
{
    (void)r;
    (void)user;
    g_done_count++;
}

static mq_relay_t *
make_relay(mem_io_t *a, mem_io_t *b)
{
    mq_relay_cfg_t cfg = {0};
    cfg.a_io = a;
    cfg.b_io = b;
    cfg.a_read = mem_read;
    cfg.b_read = mem_read;
    cfg.a_write = mem_write;
    cfg.b_write = mem_write;
    cfg.on_done = on_done;
    cfg.user = NULL;
    return mq_relay_new(&cfg);
}

/* Case 1: happy path both directions. */
static void
test_happy_both_directions(void)
{
    g_done_count = 0;
    mem_io_t a, b;
    mem_init(&a);
    mem_init(&b);

    static const unsigned char a_in[] = "hello";
    static const unsigned char b_in[] = "world";
    a.in = a_in;
    a.in_len = 5;
    b.in = b_in;
    b.in_len = 5;
    a.write_budget = 1024; /* B->A drains into A's writer */
    b.write_budget = 1024; /* A->B drains into B's writer */

    mq_relay_t *r = make_relay(&a, &b);

    /* drive both readable edges, then both writable edges */
    mq_relay_on_a_readable(r);
    mq_relay_on_b_readable(r);
    mq_relay_on_a_writable(r);
    mq_relay_on_b_writable(r);

    MQ_CHECK_EQ_INT(b.out_len, 5);
    MQ_CHECK_MEM(b.out, "hello", 5); /* A->B */
    MQ_CHECK_EQ_INT(a.out_len, 5);
    MQ_CHECK_MEM(a.out, "world", 5); /* B->A */
    MQ_CHECK_EQ_INT(g_done_count, 1);

    mq_relay_free(r);
}

/* Case 2: backpressure on B's writer. */
static void
test_backpressure(void)
{
    g_done_count = 0;
    mem_io_t a, b;
    mem_init(&a);
    mem_init(&b);

    static unsigned char a_in[100];
    for (int i = 0; i < 100; i++)
        a_in[i] = (unsigned char)i;
    a.in = a_in;
    a.in_len = 100;
    a.no_eof = 1;       /* keep A's source open so direction can't finish yet */
    a.write_budget = 0; /* B->A unused here */

    b.in_len = 0;
    b.no_eof = 1;        /* B never EOFs in this test */
    b.write_budget = 10; /* B accepts only 10 bytes, then would-block */

    mq_relay_t *r = make_relay(&a, &b);

    /* A becomes readable: read all 100 into ab, write 10, then would-block */
    mq_relay_on_a_readable(r);

    MQ_CHECK_EQ_INT(b.out_len, 10); /* only 10 written so far */
    MQ_CHECK_MEM(b.out, a_in, 10);
    MQ_CHECK_EQ_INT(g_done_count, 0); /* not finished */

    /* Restore budget and signal B writable: drain the rest */
    b.write_budget = 1024;
    mq_relay_on_b_writable(r);

    MQ_CHECK_EQ_INT(b.out_len, 100);
    MQ_CHECK_MEM(b.out, a_in, 100);
    MQ_CHECK_EQ_INT(g_done_count, 0); /* sources never EOF, so never done */

    mq_relay_free(r);
}

/* Case 3: EOF one side, other still flowing. */
static void
test_eof_one_side(void)
{
    g_done_count = 0;
    mem_io_t a, b;
    mem_init(&a);
    mem_init(&b);

    static const unsigned char a_in[] = "hi";
    static const unsigned char b_in[] = "morebytes";
    a.in = a_in;
    a.in_len = 2; /* A EOFs after "hi" */
    b.in = b_in;
    b.in_len = 9; /* B still flowing */
    a.write_budget = 1024;
    b.write_budget = 1024;

    mq_relay_t *r = make_relay(&a, &b);

    /* Drive A side fully: A->B finishes (A EOF + drained) */
    mq_relay_on_a_readable(r);
    MQ_CHECK_EQ_INT(b.out_len, 2);
    MQ_CHECK_MEM(b.out, "hi", 2);
    MQ_CHECK_EQ_INT(g_done_count, 0); /* B->A not finished yet */

    /* Now drive B side: B->A finishes too */
    mq_relay_on_b_readable(r);
    MQ_CHECK_EQ_INT(a.out_len, 9);
    MQ_CHECK_MEM(a.out, "morebytes", 9);
    MQ_CHECK_EQ_INT(g_done_count, 1); /* both finished now */

    mq_relay_free(r);
}

/* Case 4: hard write error. */
static void
test_hard_error(void)
{
    g_done_count = 0;
    mem_io_t a, b;
    mem_init(&a);
    mem_init(&b);

    static const unsigned char a_in[] = "data";
    a.in = a_in;
    a.in_len = 4;
    a.no_eof = 0;
    b.write_err = 1; /* B's writer always errors */

    mq_relay_t *r = make_relay(&a, &b);

    mq_relay_on_a_readable(r);
    MQ_CHECK_EQ_INT(g_done_count, 1); /* error -> done once */

    int reads_before = a.read_calls;
    /* further edges are no-ops */
    mq_relay_on_a_readable(r);
    mq_relay_on_b_writable(r);
    MQ_CHECK_EQ_INT(a.read_calls, reads_before); /* no more reads */
    MQ_CHECK_EQ_INT(g_done_count, 1);            /* still exactly once */

    mq_relay_free(r);
}

MQ_TEST_MAIN({
    test_happy_both_directions();
    test_backpressure();
    test_eof_one_side();
    test_hard_error();
})
