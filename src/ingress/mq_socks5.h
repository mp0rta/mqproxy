// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_SOCKS5_H
#define MQ_SOCKS5_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    MQ_SOCKS5_NEED_MORE,     /* incomplete; feed more bytes */
    MQ_SOCKS5_GREETING_DONE, /* parsed greeting; caller should send method reply */
    MQ_SOCKS5_REQUEST_DONE,  /* parsed a CONNECT request; out fields valid */
    MQ_SOCKS5_UNSUPPORTED, /* version/method/cmd/atyp not supported; caller replies error
                            */
    MQ_SOCKS5_ERROR        /* malformed */
} mq_socks5_status_t;

typedef struct {
    int phase; /* 0 = expect greeting, 1 = expect request */
} mq_socks5_parser_t;

typedef struct {
    mq_addr_type_t atype;
    uint8_t host[MQ_MAX_HOST]; /* IPv4: 4 raw bytes; IPv6: 16 raw; domain: name bytes */
    size_t host_len;
    uint16_t port;
} mq_socks5_req_t;

void mq_socks5_parser_init(mq_socks5_parser_t *p);

/* Feed bytes; consumes from buf; sets *consumed to bytes used. Returns a status.
   On GREETING_DONE: greeting parsed (caller sends method reply, then call again
   with request bytes). On REQUEST_DONE: *out is filled. */
mq_socks5_status_t mq_socks5_feed(mq_socks5_parser_t *p, const uint8_t *buf, size_t len,
                                  size_t *consumed, mq_socks5_req_t *out);

/* reply builders */
size_t mq_socks5_build_method_reply(uint8_t out[2], int accepted);
size_t mq_socks5_build_connect_reply(uint8_t out[10], uint8_t rep);
uint8_t mq_socks5_reply_code(mq_tcp_err_t err);

#endif
