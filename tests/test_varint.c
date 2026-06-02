// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "wire/mq_varint.h"
#include "mqtest.h"

static void
roundtrip(uint64_t v, int expect_len)
{
    uint8_t buf[8];
    int n = mq_varint_encode(buf, sizeof buf, v);
    MQ_CHECK_EQ_INT(n, expect_len);
    uint64_t out = 0;
    int m = mq_varint_decode(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, expect_len);
    MQ_CHECK_EQ_INT(out, v);
}

/* Wire-vector tests: encode and compare exact bytes from RFC 9000 §16 */
static void
test_wire_vectors(void)
{
    uint8_t buf[8];

    /* v=37 → 1-byte: 0x25 */
    {
        uint8_t want[] = {0x25};
        MQ_CHECK_EQ_INT(mq_varint_encode(buf, sizeof buf, 37), 1);
        MQ_CHECK_MEM(buf, want, 1);
    }
    /* v=15293 → 2-byte: 0x7B 0xBD */
    {
        uint8_t want[] = {0x7B, 0xBD};
        MQ_CHECK_EQ_INT(mq_varint_encode(buf, sizeof buf, 15293), 2);
        MQ_CHECK_MEM(buf, want, 2);
    }
    /* v=494878333 → 4-byte: 0x9D 0x7F 0x3E 0x7D */
    {
        uint8_t want[] = {0x9D, 0x7F, 0x3E, 0x7D};
        MQ_CHECK_EQ_INT(mq_varint_encode(buf, sizeof buf, 494878333), 4);
        MQ_CHECK_MEM(buf, want, 4);
    }
}

/* mq_varint_len boundary checks */
static void
test_varint_len(void)
{
    MQ_CHECK_EQ_INT(mq_varint_len(63), 1);
    MQ_CHECK_EQ_INT(mq_varint_len(64), 2);
    MQ_CHECK_EQ_INT(mq_varint_len(16384), 4);
    MQ_CHECK_EQ_INT(mq_varint_len(1073741824), 8);
}

MQ_TEST_MAIN({
    roundtrip(0, 1);
    roundtrip(63, 1);
    roundtrip(64, 2);
    roundtrip(16383, 2);
    roundtrip(16384, 4);
    roundtrip(1073741823, 4);
    roundtrip(1073741824, 8);
    roundtrip(4611686018427387903ULL, 8);

    uint8_t buf[8];
    MQ_CHECK_EQ_INT(mq_varint_encode(buf, 0, 5), -1);
    uint64_t out;
    MQ_CHECK_EQ_INT(mq_varint_decode(buf, 0, &out), -1);
    uint8_t two[1] = {0x40};
    MQ_CHECK_EQ_INT(mq_varint_decode(two, 1, &out), -1);

    /* mq_varint_len boundary assertions (RFC 9000 §16) */
    test_varint_len();

    /* Wire-vector assertions: exact bytes from RFC 9000 §16 examples */
    test_wire_vectors();

    /* Out-of-range guard: values > 2^62-1 must return -1 */
    MQ_CHECK_EQ_INT(mq_varint_encode(buf, sizeof buf, 0x4000000000000000ULL), -1);
})
