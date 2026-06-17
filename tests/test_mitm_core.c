// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#include "mqtest.h"
#include "mitm/mq_mitm_core.h"

static void
test_spike_links(void)
{
    // create() returns NULL in the skeleton; this only proves the module + the
    // BoringSSL archives link. Real behavior is asserted in later tasks.
    mq_mitm_core_t *c = mq_mitm_core_create("/nonexistent.crt", "/nonexistent.key", NULL);
    MQ_CHECK(c == NULL);
}

MQ_TEST_MAIN(test_spike_links();)
