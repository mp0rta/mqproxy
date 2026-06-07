// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "util/mq_backoff.h"
#include "mqtest.h"

#define BASE 250u
#define CAP  30000u

/* ---- 1. Doubling sequence (small attempts, production values) ------------ */
static void
test_doubling_sequence(void)
{
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 0), 250LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 1), 500LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 2), 1000LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 3), 2000LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 4), 4000LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 5), 8000LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(BASE, CAP, 6), 16000LL);
}

/* ---- 2. Saturation: value must be capped at CAP once doubling exceeds it - */
static void
test_saturates_at_cap(void)
{
    /* attempt=7 → 250 << 7 = 32000 > 30000 → saturated */
    MQ_CHECK(mq_backoff_ms(BASE, CAP, 7) == CAP);
    MQ_CHECK(mq_backoff_ms(BASE, CAP, 8) == CAP);
    MQ_CHECK(mq_backoff_ms(BASE, CAP, 10) == CAP);
}

/* ---- 3. No shift-overflow at attempt=31 and attempt=64 ------------------- */
static void
test_no_overflow_large_attempts(void)
{
    /* shift is clamped to 31; 250 << 31 = 536870912000 >> CAP → cap */
    MQ_CHECK(mq_backoff_ms(BASE, CAP, 31) == CAP);
    MQ_CHECK(mq_backoff_ms(BASE, CAP, 64) == CAP);
}

/* ---- 4. Parametric: generic base/cap cross-check ------------------------- */
static void
test_generic(void)
{
    /* base=1, cap=8: sequence 1,2,4,8,8,8 */
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 0), 1LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 1), 2LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 2), 4LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 3), 8LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 4), 8LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(1, 8, 31), 8LL);

    /* base == cap: always returns cap regardless of attempt */
    MQ_CHECK_EQ_INT(mq_backoff_ms(100, 100, 0), 100LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(100, 100, 5), 100LL);
    MQ_CHECK_EQ_INT(mq_backoff_ms(100, 100, 31), 100LL);
}

MQ_TEST_MAIN({
    test_doubling_sequence();
    test_saturates_at_cap();
    test_no_overflow_large_attempts();
    test_generic();
})
