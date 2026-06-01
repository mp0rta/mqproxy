#include "mq_buf.h"

void
mq_buf_reset(mq_buf_t *b)
{
    b->r = 0;
    b->w = 0;
}

size_t
mq_buf_len(const mq_buf_t *b)
{
    return b->w - b->r;
}

size_t
mq_buf_space(const mq_buf_t *b)
{
    return MQ_BUF_SIZE - b->w;
}

uint8_t *
mq_buf_write_ptr(mq_buf_t *b)
{
    return &b->data[b->w];
}

void
mq_buf_commit(mq_buf_t *b, size_t n)
{
    b->w += n;
}

const uint8_t *
mq_buf_read_ptr(const mq_buf_t *b)
{
    return &b->data[b->r];
}

void
mq_buf_consume(mq_buf_t *b, size_t n)
{
    b->r += n;
    if (b->r == b->w) {
        b->r = 0;
        b->w = 0;
    }
}
