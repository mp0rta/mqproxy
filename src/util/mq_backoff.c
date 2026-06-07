// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "mq_backoff.h"

uint64_t
mq_backoff_ms(uint64_t base_ms, uint64_t cap_ms, unsigned attempt)
{
    unsigned s = attempt < 31 ? attempt : 31;
    uint64_t v = base_ms << s;
    return v > cap_ms ? cap_ms : v;
}
