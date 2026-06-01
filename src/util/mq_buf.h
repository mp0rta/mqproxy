#ifndef MQ_BUF_H
#define MQ_BUF_H

#include <stddef.h>
#include <stdint.h>

#define MQ_BUF_SIZE 65536

_Static_assert(MQ_BUF_SIZE == 65536, "MQ_BUF_SIZE must be exactly 65536");

typedef struct {
    uint8_t data[MQ_BUF_SIZE];
    size_t r;
    size_t w;
} mq_buf_t;

/* Reset cursors to 0 */
void mq_buf_reset(mq_buf_t *b);

/* Readable bytes = w - r */
size_t mq_buf_len(const mq_buf_t *b);

/* Writable bytes at the tail = MQ_BUF_SIZE - w */
size_t mq_buf_space(const mq_buf_t *b);

/* Pointer to write position: &data[w] */
uint8_t *mq_buf_write_ptr(mq_buf_t *b);

/* Advance write cursor by n (caller guarantees n <= space) */
void mq_buf_commit(mq_buf_t *b, size_t n);

/* Pointer to read position: &data[r] */
const uint8_t *mq_buf_read_ptr(const mq_buf_t *b);

/* Advance read cursor by n; if r == w after, compact (reset both to 0) */
void mq_buf_consume(mq_buf_t *b, size_t n);

#endif /* MQ_BUF_H */
