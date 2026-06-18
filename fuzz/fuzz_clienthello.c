// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "ingress/mq_clienthello.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_clienthello_t out;
    (void)mq_clienthello_parse(data, size, &out);
    return 0;
}
