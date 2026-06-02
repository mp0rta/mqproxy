// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "mq_varint.h"

int
mq_varint_len(uint64_t v)
{
    if (v <= 0x3FU) return 1;
    if (v <= 0x3FFFU) return 2;
    if (v <= 0x3FFFFFFFU) return 4;
    return 8;
}

int
mq_varint_encode(uint8_t *buf, size_t cap, uint64_t v)
{
    if (v > 0x3FFFFFFFFFFFFFFFULL) return -1;

    int n = mq_varint_len(v);
    if ((size_t)n > cap) return -1;

    switch (n) {
    case 1:
        buf[0] = (uint8_t)(v & 0x3F); /* prefix 00 */
        break;
    case 2:
        buf[0] = (uint8_t)(0x40 | ((v >> 8) & 0x3F));
        buf[1] = (uint8_t)(v & 0xFF);
        break;
    case 4:
        buf[0] = (uint8_t)(0x80 | ((v >> 24) & 0x3F));
        buf[1] = (uint8_t)((v >> 16) & 0xFF);
        buf[2] = (uint8_t)((v >> 8) & 0xFF);
        buf[3] = (uint8_t)(v & 0xFF);
        break;
    case 8:
        buf[0] = (uint8_t)(0xC0 | ((v >> 56) & 0x3F));
        buf[1] = (uint8_t)((v >> 48) & 0xFF);
        buf[2] = (uint8_t)((v >> 40) & 0xFF);
        buf[3] = (uint8_t)((v >> 32) & 0xFF);
        buf[4] = (uint8_t)((v >> 24) & 0xFF);
        buf[5] = (uint8_t)((v >> 16) & 0xFF);
        buf[6] = (uint8_t)((v >> 8) & 0xFF);
        buf[7] = (uint8_t)(v & 0xFF);
        break;
    }
    return n;
}

int
mq_varint_decode(const uint8_t *buf, size_t len, uint64_t *out)
{
    if (len == 0) return -1;

    int prefix = (buf[0] >> 6) & 0x03;
    int n = 1 << prefix; /* 1, 2, 4, or 8 */

    if ((size_t)n > len) return -1;

    uint64_t v = (uint64_t)(buf[0] & 0x3F);
    for (int i = 1; i < n; i++) {
        v = (v << 8) | buf[i];
    }

    *out = v;
    return n;
}
