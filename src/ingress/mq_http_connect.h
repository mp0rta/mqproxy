// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_HTTP_CONNECT_H
#define MQ_HTTP_CONNECT_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    MQ_HTTP_NEED_MORE,    /* headers not yet complete */
    MQ_HTTP_CONNECT_DONE, /* parsed a CONNECT request; out valid */
    MQ_HTTP_BAD,          /* malformed request line */
    MQ_HTTP_UNSUPPORTED   /* not a CONNECT method */
} mq_http_status_t;

typedef struct {
    mq_addr_type_t atype; /* DOMAIN, or IPV6 for a bracketed literal, or IPV4 for
                             dotted-quad */
    uint8_t host[MQ_MAX_HOST];
    size_t host_len; /* for DOMAIN: the hostname text bytes;
                        for IPV4: 4 raw bytes; for IPV6: 16 raw bytes */
    uint16_t port;
} mq_http_target_t;

/* Feed accumulated request bytes (caller keeps the running buffer and passes the whole
   thing each call). Parses from a single contiguous buffer; returns NEED_MORE if no
   CRLFCRLF yet. On CONNECT_DONE, *out is filled and *header_len is set to the total
   bytes of the request head (through the final CRLFCRLF). */
mq_http_status_t mq_http_connect_parse(const uint8_t *buf, size_t len,
                                       mq_http_target_t *out, size_t *header_len);

/* response builders */
size_t mq_http_build_200(char *out, size_t cap); /* returns len written */
const char *mq_http_status_line(mq_tcp_err_t err);
#endif
