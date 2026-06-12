// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* tests/test_sched.c — mq_sched_from_string / mq_sched_name unit tests. */

#include <string.h>

#include "transport/mq_conn.h"
#include "mqtest.h"

static void
test_valid_schedulers(void)
{
    int ok;

    ok = -1;
    MQ_CHECK_EQ_INT(mq_sched_from_string("minrtt", &ok), MQ_SCHED_MINRTT);
    MQ_CHECK_EQ_INT(ok, 1);

    ok = -1;
    MQ_CHECK_EQ_INT(mq_sched_from_string("backup", &ok), MQ_SCHED_BACKUP);
    MQ_CHECK_EQ_INT(ok, 1);

    ok = -1;
    MQ_CHECK_EQ_INT(mq_sched_from_string("wlb", &ok), MQ_SCHED_WLB);
    MQ_CHECK_EQ_INT(ok, 1);
}

static void
test_invalid_schedulers(void)
{
    int ok;

    ok = -1;
    MQ_CHECK_EQ_INT(mq_sched_from_string("bogus", &ok), MQ_SCHED_DEFAULT);
    MQ_CHECK_EQ_INT(ok, 0);

    ok = -1;
    MQ_CHECK_EQ_INT(mq_sched_from_string(NULL, &ok), MQ_SCHED_DEFAULT);
    MQ_CHECK_EQ_INT(ok, 0);
}

static void
test_null_ok_ptr(void)
{
    /* ok == NULL must not crash */
    MQ_CHECK_EQ_INT(mq_sched_from_string("minrtt", NULL), MQ_SCHED_MINRTT);
}

static void
test_sched_names(void)
{
    MQ_CHECK(strcmp(mq_sched_name(MQ_SCHED_MINRTT), "minrtt") == 0);
    MQ_CHECK(strcmp(mq_sched_name(MQ_SCHED_BACKUP), "backup") == 0);
    MQ_CHECK(strcmp(mq_sched_name(MQ_SCHED_WLB), "wlb") == 0);
}

MQ_TEST_MAIN({
    test_valid_schedulers();
    test_invalid_schedulers();
    test_null_ok_ptr();
    test_sched_names();
})
