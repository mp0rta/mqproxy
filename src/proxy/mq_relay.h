#ifndef MQ_RELAY_H
#define MQ_RELAY_H
#include <stddef.h>

/* read: return >=0 bytes read; set *eof=1 on clean EOF; set *wb=1 if it would block
   (no bytes now). return -1 on hard error. (eof and wb are out-params, preset to 0.)
   write: return >=0 bytes written; set *wb=1 if it would block. return -1 on hard error.
 */
typedef long (*mq_io_read_fn)(void *io, unsigned char *buf, size_t cap, int *eof,
                              int *wb);
typedef long (*mq_io_write_fn)(void *io, const unsigned char *buf, size_t len, int *wb);

typedef struct mq_relay mq_relay_t;
typedef void (*mq_relay_done_fn)(mq_relay_t *r, void *user);

typedef struct {
    void *a_io, *b_io;
    mq_io_read_fn a_read, b_read;
    mq_io_write_fn a_write, b_write;
    mq_relay_done_fn
        on_done; /* called EXACTLY ONCE when both directions finished OR on hard error */
    void *user;
} mq_relay_cfg_t;

mq_relay_t *mq_relay_new(const mq_relay_cfg_t *cfg);
void mq_relay_free(mq_relay_t *r);

/* Edge handlers — the owner calls these when an endpoint becomes readable/writable.
   Each pumps as much as possible without blocking, honoring backpressure. */
void mq_relay_on_a_readable(mq_relay_t *r);
void mq_relay_on_a_writable(mq_relay_t *r);
void mq_relay_on_b_readable(mq_relay_t *r);
void mq_relay_on_b_writable(mq_relay_t *r);
#endif
