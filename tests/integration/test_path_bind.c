// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_path_bind.c — runtime primary-path bind smoke test (Chunk 7).
 *
 * Opens the primary UDP path via mq_runtime_open_udp_path on 127.0.0.1:0 against
 * a client-mode transport+runtime, checks the bind succeeds (ephemeral port-0
 * bind yields a usable path), that a bad local IP is rejected without leaking,
 * and that a second open of the (already-bound) primary path is refused. Then it
 * tears everything down cleanly (ASan-clean).
 *
 * The fine-grained mq_path accessors (fd / id / local_addr) are gone; the
 * runtime only exposes open success, so that is what we assert.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_transport.h"

static void
test_path_bind(void)
{
    mq_transport_t *t = mq_transport_new(/*is_server=*/0, /*cbs=*/NULL, /*user=*/NULL);
    MQ_CHECK(t != NULL);
    if (!t) return;

    mq_runtime_t *rt = mq_runtime_new(t, /*base=*/NULL);
    MQ_CHECK(rt != NULL);
    if (!rt) {
        mq_transport_free(t);
        return;
    }

    /* Ephemeral port-0 bind on loopback succeeds and yields a usable path. */
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(rt, "127.0.0.1", /*port=*/0), 0);

    /* A bad local address is rejected without leaking. */
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(rt, "not-an-ip", 0), -1);

    /* The primary path is already open; a second open of it is refused. */
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(rt, "127.0.0.1", 0), -1);

    /* Teardown per side: transport first, then runtime. */
    mq_transport_free(t);
    mq_runtime_free(rt);
}

MQ_TEST_MAIN(test_path_bind())
