// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "wire/mq_udp_msg.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_udp_msg_hdr_t out = {0};
    (void)mq_udp_msg_decode_hdr(data, size, &out);
    return 0;
}
