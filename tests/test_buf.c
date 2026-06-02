// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "util/mq_buf.h"
#include "mqtest.h"
#include <string.h>

/* ---- helpers to avoid preprocessor comma splitting in MQ_TEST_MAIN ---- */

static void
test_size_constant(void)
{
    /* Verify MQ_BUF_SIZE is exactly 65536 */
    MQ_CHECK_EQ_INT(MQ_BUF_SIZE, 65536);
}

static void
test_fresh_buf(void)
{
    mq_buf_t b;
    mq_buf_reset(&b);
    MQ_CHECK_EQ_INT(mq_buf_len(&b), 0);
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 65536);
}

static void
test_write_and_read(void)
{
    mq_buf_t b;
    mq_buf_reset(&b);

    /* write 100 bytes via write_ptr + commit */
    static const uint8_t src[100] = {
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100};

    memcpy(mq_buf_write_ptr(&b), src, 100);
    mq_buf_commit(&b, 100);

    MQ_CHECK_EQ_INT(mq_buf_len(&b), 100);
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 65436);
    MQ_CHECK_MEM(mq_buf_read_ptr(&b), src, 100);
}

static void
test_consume_partial(void)
{
    mq_buf_t b;
    mq_buf_reset(&b);

    static const uint8_t src[100] = {
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100};

    memcpy(mq_buf_write_ptr(&b), src, 100);
    mq_buf_commit(&b, 100);

    /* consume 40: 60 readable remain, no compaction */
    mq_buf_consume(&b, 40);
    MQ_CHECK_EQ_INT(mq_buf_len(&b), 60);
    /* space is still 65436 (tail space, not mid-buffer) */
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 65436);
    /* remaining readable bytes are src[40..99] */
    MQ_CHECK_MEM(mq_buf_read_ptr(&b), src + 40, 60);
}

static void
test_consume_all_compacts(void)
{
    mq_buf_t b;
    mq_buf_reset(&b);

    static const uint8_t src[100] = {
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100};

    memcpy(mq_buf_write_ptr(&b), src, 100);
    mq_buf_commit(&b, 100);

    mq_buf_consume(&b, 40);
    /* consume the remaining 60 → full drain → compact */
    mq_buf_consume(&b, 60);
    MQ_CHECK_EQ_INT(mq_buf_len(&b), 0);
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 65536); /* full space after compaction */
}

static void
test_fill_to_capacity(void)
{
    mq_buf_t b;
    mq_buf_reset(&b);

    /* commit the full 65536 bytes */
    mq_buf_commit(&b, 65536);
    MQ_CHECK_EQ_INT(mq_buf_len(&b), 65536);
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 0);

    /* consume all → compact */
    mq_buf_consume(&b, 65536);
    MQ_CHECK_EQ_INT(mq_buf_len(&b), 0);
    MQ_CHECK_EQ_INT(mq_buf_space(&b), 65536);
}

MQ_TEST_MAIN({
    test_size_constant();
    test_fresh_buf();
    test_write_and_read();
    test_consume_partial();
    test_consume_all_compacts();
    test_fill_to_capacity();
})
