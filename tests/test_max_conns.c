// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
//
// Unit test for the mq_transport connection-count cap API (pre-auth DoS).
// Pure counter logic — no handshake, no sockets.

#include "mqtest.h"
#include "transport/mq_transport.h"

MQ_TEST_MAIN({
    mq_transport_t *t = mq_transport_new(/*is_server=*/0);
    MQ_CHECK(t != NULL);

    /* Default: no cap configured -> never at limit. */
    MQ_CHECK_EQ_INT(mq_transport_n_conns(t), 0);
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 0);

    /* Cap of 2: admit two, third is at-limit. */
    mq_transport_set_max_conns(t, 2);
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 0);
    mq_transport_conn_inc(t);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(t), 1);
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 0);
    mq_transport_conn_inc(t);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(t), 2);
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 1); /* full */

    /* Release one -> a slot frees. */
    mq_transport_conn_dec(t);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(t), 1);
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 0);

    /* dec saturates at 0 (never underflows). */
    mq_transport_conn_dec(t);
    mq_transport_conn_dec(t);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(t), 0);

    /* max_conns == 0 disables the cap even at a high count. */
    mq_transport_set_max_conns(t, 0);
    for (int i = 0; i < 100; i++) {
        mq_transport_conn_inc(t);
    }
    MQ_CHECK_EQ_INT(mq_transport_conn_at_limit(t), 0);

    mq_transport_free(t);
});
