// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_connect_tcp_req_t out = {0};
    (void)mq_decode_connect_tcp_req(data, size, &out);
    return 0;
}
