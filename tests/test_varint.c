#include "wire/mq_varint.h"
#include "mqtest.h"

static void roundtrip(uint64_t v, int expect_len) {
    uint8_t buf[8];
    int n = mq_varint_encode(buf, sizeof buf, v);
    MQ_CHECK_EQ_INT(n, expect_len);
    uint64_t out = 0;
    int m = mq_varint_decode(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, expect_len);
    MQ_CHECK_EQ_INT(out, v);
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
})
