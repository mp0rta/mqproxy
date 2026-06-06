// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_SOCKS5_H
#define MQ_SOCKS5_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    MQ_SOCKS5_NEED_MORE,       /* incomplete; feed more bytes */
    MQ_SOCKS5_GREETING_DONE,   /* parsed greeting; caller should send method reply */
    MQ_SOCKS5_REQUEST_DONE,    /* parsed a CONNECT request; out fields valid */
    MQ_SOCKS5_UNSUPPORTED,     /* greeting: no acceptable auth method; caller sends method
                                  reply 0xFF (NO ACCEPTABLE METHODS) */
    MQ_SOCKS5_UNSUPPORTED_CMD, /* request CMD not CONNECT; caller replies REP 0x07
                                  (command not supported), RFC 1928 §6 */
    MQ_SOCKS5_UNSUPPORTED_ATYP, /* request ATYP not supported; caller replies REP 0x08
                                   (address type not supported), RFC 1928 §6 */
    MQ_SOCKS5_ERROR,            /* malformed */
    MQ_SOCKS5_ASSOCIATE_DONE    /* CMD 0x03 parsed; out is DST (0.0.0.0:0 allowed) */
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
   with request bytes). On REQUEST_DONE or ASSOCIATE_DONE: *out is filled. */
mq_socks5_status_t mq_socks5_feed(mq_socks5_parser_t *p, const uint8_t *buf, size_t len,
                                  size_t *consumed, mq_socks5_req_t *out);

/* reply builders */
size_t mq_socks5_build_method_reply(uint8_t out[2], int accepted);
size_t mq_socks5_build_connect_reply(uint8_t out[10], uint8_t rep);
/* ASSOCIATE success reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR=bnd_ip_be BND.PORT=bnd_port.
   bnd_ip_be is the IPv4 address in network byte order; bnd_port is the port in host
   order. Always writes exactly 10 bytes. */
size_t mq_socks5_build_associate_reply(uint8_t out[10], uint32_t bnd_ip_be,
                                       uint16_t bnd_port);
uint8_t mq_socks5_reply_code(mq_tcp_err_t err);

/* UDP encapsulation header (RFC 1928 §7): RSV(2B) | FRAG(1B) | ATYP(1B) | DST | PORT(2B).
   Returns bytes consumed (>= 0), -1 on malformed/truncated, -2 if FRAG != 0 (caller
   drop). Strict: RSV != 0x0000 is rejected (-1). */
typedef struct {
    mq_socks5_req_t dst;
    size_t hdr_len;
} mq_socks5_udp_hdr_t;

int mq_socks5_parse_udp_hdr(const uint8_t *buf, size_t len, mq_socks5_udp_hdr_t *out);
/* Write UDP encapsulation header with RSV=0 FRAG=0 for given src address.
   Returns bytes written, or -1 if cap is too small. */
int mq_socks5_build_udp_hdr(uint8_t *out, size_t cap, const mq_socks5_req_t *src);

#endif
