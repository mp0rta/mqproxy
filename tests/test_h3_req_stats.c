// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "mqtest.h" /* MQ_CHECK / MQ_TEST_MAIN */
#include "transport/mq_h3.h"

MQ_TEST_MAIN({
    xqc_request_stats_t st;
    MQ_CHECK(mq_h3_req_get_stats(NULL, &st) == -1);
    /* a non-NULL req with NULL inner handle is exercised in the gateway
     * integration (test_gw_server); here we only pin the NULL contract. */
})
