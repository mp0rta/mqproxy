// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* tests/test_sched.c — mq_sched_from_string / mq_sched_name unit tests. */

#include <assert.h>
#include <string.h>

#include "transport/mq_conn.h"

int
main(void)
{
    int ok = -1;

    assert(mq_sched_from_string("minrtt", &ok) == MQ_SCHED_MINRTT);
    assert(ok == 1);
    assert(mq_sched_from_string("backup", &ok) == MQ_SCHED_BACKUP);
    assert(ok == 1);
    assert(mq_sched_from_string("wlb", &ok) == MQ_SCHED_WLB);
    assert(ok == 1);

    assert(mq_sched_from_string("bogus", &ok) == MQ_SCHED_DEFAULT);
    assert(ok == 0);
    assert(mq_sched_from_string(NULL, &ok) == MQ_SCHED_DEFAULT);
    assert(ok == 0);
    /* ok == NULL must not crash */
    assert(mq_sched_from_string("minrtt", NULL) == MQ_SCHED_MINRTT);

    assert(strcmp(mq_sched_name(MQ_SCHED_MINRTT), "minrtt") == 0);
    assert(strcmp(mq_sched_name(MQ_SCHED_BACKUP), "backup") == 0);
    assert(strcmp(mq_sched_name(MQ_SCHED_WLB), "wlb") == 0);

    return 0;
}
