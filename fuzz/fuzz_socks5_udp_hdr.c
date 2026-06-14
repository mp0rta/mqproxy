// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "ingress/mq_socks5.h"
#include <stddef.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_socks5_udp_hdr_t out = {0};
    (void)mq_socks5_parse_udp_hdr(data, size, &out);
    return 0;
}
