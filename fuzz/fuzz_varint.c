// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "wire/mq_varint.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t out = 0;
    (void)mq_varint_decode(data, size, &out);
    return 0;
}
