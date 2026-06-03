// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_engine_boot.c — transport+runtime boot smoke test (Chunk 7).
 *
 * Proves that a client-mode mq_transport plus its libevent mq_runtime construct
 * cleanly, expose the underlying xquic engine + the runtime's event_base, open a
 * primary UDP path, run the loop, are stopped cleanly from a libevent timer, and
 * tear down without leaks (ASan-clean).
 *
 * The pre-cutover engine's register_path_fd / unregister_path_fd scaffold has no
 * runtime successor (the path->fd map is internal to the runtime), so that
 * assertion is replaced by a mq_runtime_open_udp_path success check.
 */
#include "mqtest.h"

#include <event2/event.h>

#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_transport.h"

/* Fired ~50ms into the loop; breaks out of event_base_dispatch. */
static void
stop_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_runtime_t *rt = (mq_runtime_t *)arg;
    mq_runtime_stop(rt);
}

static void
test_engine_boot(void)
{
    /* Construction order: transport first, then the runtime (which installs its
     * callbacks onto the transport as cbs.user). The runtime owns its own base
     * here (base == NULL). */
    mq_transport_t *t = mq_transport_new(/*is_server=*/0);
    MQ_CHECK(t != NULL);
    if (!t) return;

    MQ_CHECK(mq_transport_xqc(t) != NULL);

    mq_runtime_t *rt = mq_runtime_new(t, /*base=*/NULL);
    MQ_CHECK(rt != NULL);
    if (!rt) {
        mq_transport_free(t);
        return;
    }

    struct event_base *base = mq_runtime_base(rt);
    MQ_CHECK(base != NULL);

    /* Open the primary path (replaces the old register_path_fd scaffold, which
     * has no runtime successor — the path->fd map is internal to the runtime). */
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(rt, "127.0.0.1", /*port=*/0), 0);

    /* Schedule a one-shot timer to stop the loop, then run it. */
    struct timeval tv = {0, 50000}; /* 50ms */
    struct event *ev = evtimer_new(base, stop_cb, rt);
    MQ_CHECK(ev != NULL);
    evtimer_add(ev, &tv);

    mq_runtime_run(rt); /* returns after stop_cb -> loopbreak */

    event_free(ev);
    /* Teardown per side: transport first (engine destroy; callbacks land on the
     * still-live runtime), then the runtime (closes the path socket + timer; it
     * owns and frees its base here). */
    mq_transport_free(t);
    mq_runtime_free(rt);
}

MQ_TEST_MAIN(test_engine_boot())
