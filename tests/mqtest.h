// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQTEST_H
#define MQTEST_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int mq_test_failures;

#define MQ_CHECK(cond)                                                      \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            mq_test_failures++;                                             \
        }                                                                   \
    } while (0)

#define MQ_CHECK_EQ_INT(a, b)                                                           \
    do {                                                                                \
        long long _a = (long long)(a), _b = (long long)(b);                             \
        if (_a != _b) {                                                                 \
            fprintf(stderr, "FAIL %s:%d: %s (%lld) != %s (%lld)\n", __FILE__, __LINE__, \
                    #a, _a, #b, _b);                                                    \
            mq_test_failures++;                                                         \
        }                                                                               \
    } while (0)

#define MQ_CHECK_MEM(a, b, n)                                                        \
    do {                                                                             \
        if (memcmp((a), (b), (n)) != 0) {                                            \
            fprintf(stderr, "FAIL %s:%d: memcmp %s != %s\n", __FILE__, __LINE__, #a, \
                    #b);                                                             \
            mq_test_failures++;                                                      \
        }                                                                            \
    } while (0)

#define MQ_TEST_MAIN(body)                                        \
    int main(void)                                                \
    {                                                             \
        body;                                                     \
        if (mq_test_failures) {                                   \
            fprintf(stderr, "%d failure(s)\n", mq_test_failures); \
            return 1;                                             \
        }                                                         \
        printf("OK\n");                                           \
        return 0;                                                 \
    }
#endif
