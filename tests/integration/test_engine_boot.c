// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_engine_boot.c — Task 8 integration test.
 *
 * Proves that mq_engine boots a client-mode xquic engine wired to a libevent
 * loop, runs the loop, is stopped cleanly from a libevent timer callback, and
 * tears down without leaks (ASan-clean).
 */
#include "mqtest.h"

#include <event2/event.h>

#include "transport/mq_engine.h"

/* Fired ~50ms into the loop; breaks out of event_base_dispatch. */
static void
stop_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_engine_t *e = (mq_engine_t *)arg;
    mq_engine_stop(e);
}

static void
test_engine_boot(void)
{
    mq_engine_t *e = mq_engine_new(/*is_server=*/0, /*base=*/NULL);
    MQ_CHECK(e != NULL);
    if (!e) return;

    MQ_CHECK(mq_engine_xqc(e) != NULL);

    struct event_base *base = mq_engine_base(e);
    MQ_CHECK(base != NULL);

    /* Path-fd registration scaffold (Task 9 consumers). Register then drop. */
    int rc = mq_engine_register_path_fd(e, /*path_id=*/0, /*fd=*/-1);
    MQ_CHECK_EQ_INT(rc, 0);
    mq_engine_unregister_path_fd(e, 0);

    /* Schedule a one-shot timer to stop the loop, then run it. */
    struct timeval tv = {0, 50000}; /* 50ms */
    struct event *ev = evtimer_new(base, stop_cb, e);
    MQ_CHECK(ev != NULL);
    evtimer_add(ev, &tv);

    mq_engine_run(e); /* returns after stop_cb -> loopbreak */

    event_free(ev);
    mq_engine_free(e);
}

MQ_TEST_MAIN(test_engine_boot())
