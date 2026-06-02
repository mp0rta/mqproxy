// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "ingress/mq_socks5.h"
#include <string.h>

#define SOCKS5_VER           0x05
#define SOCKS5_CMD_CONNECT   0x01
#define SOCKS5_METHOD_NOAUTH 0x00

void
mq_socks5_parser_init(mq_socks5_parser_t *p)
{
    p->phase = 0;
}

/* Parse the greeting from buf[0..len). Sets *consumed.
   Bytes: VER(1) | NMETHODS(1) | METHODS(n). */
static mq_socks5_status_t
parse_greeting(mq_socks5_parser_t *p, const uint8_t *buf, size_t len, size_t *consumed)
{
    *consumed = 0;
    if (len < 2) return MQ_SOCKS5_NEED_MORE;
    if (buf[0] != SOCKS5_VER) return MQ_SOCKS5_ERROR;

    size_t nmethods = buf[1];
    size_t total = 2 + nmethods;
    if (len < total) return MQ_SOCKS5_NEED_MORE;

    int has_noauth = 0;
    for (size_t i = 0; i < nmethods; i++) {
        if (buf[2 + i] == SOCKS5_METHOD_NOAUTH) {
            has_noauth = 1;
            break;
        }
    }

    if (!has_noauth) return MQ_SOCKS5_UNSUPPORTED;
    *consumed = total;
    p->phase = 1;
    return MQ_SOCKS5_GREETING_DONE;
}

/* Parse the CONNECT request from buf[0..len). Sets *consumed and fills out.
   Bytes: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2 BE). */
static mq_socks5_status_t
parse_request(const uint8_t *buf, size_t len, size_t *consumed, mq_socks5_req_t *out)
{
    *consumed = 0;
    if (len < 4) return MQ_SOCKS5_NEED_MORE;
    if (buf[0] != SOCKS5_VER) return MQ_SOCKS5_ERROR;
    if (buf[1] != SOCKS5_CMD_CONNECT)
        return MQ_SOCKS5_UNSUPPORTED; /* caller replies 0x07 cmd-not-supported */
    /* buf[2] RSV ignored */

    uint8_t atype = buf[3];
    size_t addr_off = 4;
    size_t addr_len;
    mq_addr_type_t mapped;

    switch (atype) {
    case MQ_ADDR_IPV4:
        addr_len = 4;
        mapped = MQ_ADDR_IPV4;
        break;
    case MQ_ADDR_IPV6:
        addr_len = 16;
        mapped = MQ_ADDR_IPV6;
        break;
    case MQ_ADDR_DOMAIN: {
        if (len < addr_off + 1) return MQ_SOCKS5_NEED_MORE; /* need the length byte */
        size_t dlen = buf[addr_off];
        addr_off += 1; /* consume LEN byte */
        addr_len = dlen;
        mapped = MQ_ADDR_DOMAIN;
        break;
    }
    default: return MQ_SOCKS5_UNSUPPORTED; /* 0x08 addr-type-not-supported */
    }

    size_t total = addr_off + addr_len + 2; /* +2 for port */
    if (len < total) return MQ_SOCKS5_NEED_MORE;

    /* addr_len <= 255 (IPv4=4, IPv6=16, domain LEN byte <=255) => fits host[]. */
    out->atype = mapped;
    out->host_len = addr_len;
    if (addr_len > 0) memcpy(out->host, buf + addr_off, addr_len);
    out->port =
        (uint16_t)((buf[addr_off + addr_len] << 8) | buf[addr_off + addr_len + 1]);

    *consumed = total;
    return MQ_SOCKS5_REQUEST_DONE;
}

mq_socks5_status_t
mq_socks5_feed(mq_socks5_parser_t *p, const uint8_t *buf, size_t len, size_t *consumed,
               mq_socks5_req_t *out)
{
    if (p->phase == 0) return parse_greeting(p, buf, len, consumed);
    return parse_request(buf, len, consumed, out);
}

size_t
mq_socks5_build_method_reply(uint8_t out[2], int accepted)
{
    out[0] = SOCKS5_VER;
    out[1] = accepted ? 0x00 : 0xFF;
    return 2;
}

size_t
mq_socks5_build_connect_reply(uint8_t out[10], uint8_t rep)
{
    out[0] = SOCKS5_VER; /* VER */
    out[1] = rep;        /* REP */
    out[2] = 0x00;       /* RSV */
    out[3] = 0x01;       /* ATYP = IPv4 */
    out[4] = 0x00;       /* BND.ADDR = 0.0.0.0 */
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0x00; /* BND.PORT = 0 */
    out[9] = 0x00;
    return 10;
}

uint8_t
mq_socks5_reply_code(mq_tcp_err_t err)
{
    switch (err) {
    case MQ_TCP_OK: return 0x00;
    case MQ_TCP_DNS_FAILED: return 0x04;    /* host unreachable */
    case MQ_TCP_CONN_REFUSED: return 0x05;  /* connection refused */
    case MQ_TCP_TIMEOUT: return 0x06;       /* TTL expired */
    case MQ_TCP_POLICY_DENIED: return 0x02; /* connection not allowed by ruleset */
    }
    return 0x01; /* general SOCKS server failure */
}
