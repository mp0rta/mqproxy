// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "ingress/mq_http_connect.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_http_target_t out = {0};
    size_t header_len = 0;
    (void)mq_http_connect_parse(data, size, &out, &header_len);
    return 0;
}
