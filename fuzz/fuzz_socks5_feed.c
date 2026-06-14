// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
//
// Drives mq_socks5_feed exactly as src/ingress/mq_listener.c does: init the
// parser per call, feed bytes, and on GREETING_DONE advance past the consumed
// greeting into the request phase. The loop is bounded by the buffer length so
// a fuzz input can never wedge the harness itself.
#include "ingress/mq_socks5.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);

    /* mutable working copy: the listener consumes from an in-place buffer */
    uint8_t buf[4096];
    if (size > sizeof buf) size = sizeof buf;
    memcpy(buf, data, size);

    size_t off = 0;
    for (size_t guard = 0; guard <= size; guard++) {
        size_t consumed = 0;
        mq_socks5_req_t req = {0};
        mq_socks5_status_t st =
            mq_socks5_feed(&p, buf + off, size - off, &consumed, &req);
        off += consumed;
        if (st == MQ_SOCKS5_NEED_MORE) break; /* would wait for more bytes */
        if (st == MQ_SOCKS5_GREETING_DONE) {
            if (consumed == 0) break; /* no progress guard */
            continue;                 /* advance into request phase */
        }
        break; /* REQUEST_DONE / ASSOCIATE_DONE / UNSUPPORTED* / ERROR are terminal */
    }
    return 0;
}
