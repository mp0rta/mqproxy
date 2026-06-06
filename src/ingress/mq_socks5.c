// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "ingress/mq_socks5.h"
#include <string.h>

#define SOCKS5_VER           0x05
#define SOCKS5_CMD_CONNECT   0x01
#define SOCKS5_CMD_ASSOCIATE 0x03
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

/* Parse the CONNECT/ASSOCIATE request from buf[0..len). Sets *consumed and fills out.
   Bytes: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2 BE). */
static mq_socks5_status_t
parse_request(const uint8_t *buf, size_t len, size_t *consumed, mq_socks5_req_t *out)
{
    *consumed = 0;
    if (len < 4) return MQ_SOCKS5_NEED_MORE;
    if (buf[0] != SOCKS5_VER) return MQ_SOCKS5_ERROR;
    if (buf[1] != SOCKS5_CMD_CONNECT && buf[1] != SOCKS5_CMD_ASSOCIATE)
        return MQ_SOCKS5_UNSUPPORTED_CMD; /* BIND => REP 0x07 */
    /* buf[2] RSV ignored (RFC 1928 says 0x00, but be permissive on receive) */

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
    default: return MQ_SOCKS5_UNSUPPORTED_ATYP; /* unknown ATYP => REP 0x08 */
    }

    size_t total = addr_off + addr_len + 2; /* +2 for port */
    if (len < total) return MQ_SOCKS5_NEED_MORE;

    /* exact fit (MQ_MAX_HOST == 255; no NUL terminator — host_len carries the length) */
    out->atype = mapped;
    out->host_len = addr_len;
    if (addr_len > 0) memcpy(out->host, buf + addr_off, addr_len);
    out->port =
        (uint16_t)((buf[addr_off + addr_len] << 8) | buf[addr_off + addr_len + 1]);

    *consumed = total;
    return (buf[1] == SOCKS5_CMD_ASSOCIATE) ? MQ_SOCKS5_ASSOCIATE_DONE
                                            : MQ_SOCKS5_REQUEST_DONE;
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

/* Shared 10-byte reply builder: VER=5 REP=rep RSV=0 ATYP=1 BND.ADDR BND.PORT. */
static size_t
build_reply10(uint8_t out[10], uint8_t rep, uint32_t bnd_ip_be, uint16_t bnd_port)
{
    out[0] = SOCKS5_VER;
    out[1] = rep;
    out[2] = 0x00; /* RSV */
    out[3] = 0x01; /* ATYP = IPv4 */
    out[4] = (uint8_t)(bnd_ip_be >> 24);
    out[5] = (uint8_t)(bnd_ip_be >> 16);
    out[6] = (uint8_t)(bnd_ip_be >> 8);
    out[7] = (uint8_t)(bnd_ip_be);
    out[8] = (uint8_t)(bnd_port >> 8);
    out[9] = (uint8_t)(bnd_port);
    return 10;
}

size_t
mq_socks5_build_connect_reply(uint8_t out[10], uint8_t rep)
{
    return build_reply10(out, rep, 0, 0);
}

size_t
mq_socks5_build_associate_reply(uint8_t out[10], uint32_t bnd_ip_host, uint16_t bnd_port)
{
    return build_reply10(out, 0x00, bnd_ip_host, bnd_port);
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

/* Parse UDP encapsulation header (RFC 1928 §7):
 *   RSV(2B) | FRAG(1B) | ATYP(1B) | DST.ADDR | DST.PORT(2B BE)
 *
 * Returns bytes consumed (>= 0) and fills *out, or:
 *   -1  malformed / truncated / RSV != 0x0000 (strict — untrusted input)
 *   -2  FRAG != 0 (fragmented datagram; caller must drop)
 */
int
mq_socks5_parse_udp_hdr(const uint8_t *buf, size_t len, mq_socks5_udp_hdr_t *out)
{
    /* Minimum: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10 bytes */
    if (len < 4) return -1;

    /* RSV must be 0x0000 (strict reject for untrusted input) */
    if (buf[0] != 0x00 || buf[1] != 0x00) return -1;

    /* FRAG: non-zero means fragmented datagram — caller must drop */
    if (buf[2] != 0x00) return -2;

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
        if (len < addr_off + 1) return -1; /* need the length byte */
        size_t dlen = buf[addr_off];
        addr_off += 1;
        addr_len = dlen;
        mapped = MQ_ADDR_DOMAIN;
        break;
    }
    default: return -1; /* unknown ATYP */
    }

    size_t total = addr_off + addr_len + 2; /* +2 for port */
    if (len < total) return -1;

    /* exact fit (MQ_MAX_HOST == 255; no NUL terminator — host_len carries the length) */
    out->dst.atype = mapped;
    out->dst.host_len = addr_len;
    if (addr_len > 0) memcpy(out->dst.host, buf + addr_off, addr_len);
    out->dst.port =
        (uint16_t)((buf[addr_off + addr_len] << 8) | buf[addr_off + addr_len + 1]);
    out->hdr_len = total;

    return (int)total;
}

/* Write UDP encapsulation header (RSV=0, FRAG=0) for the given src address.
 * Returns bytes written, or -1 if cap is too small.
 */
int
mq_socks5_build_udp_hdr(uint8_t *out, size_t cap, const mq_socks5_req_t *src)
{
    /* Calculate required size first */
    size_t addr_off = 4; /* RSV(2) + FRAG(1) + ATYP(1) */
    size_t addr_len = src->host_len;
    size_t extra_len = 0; /* domain prefix byte */

    if (src->atype == MQ_ADDR_DOMAIN) extra_len = 1;

    size_t needed = addr_off + extra_len + addr_len + 2;
    if (cap < needed) return -1;

    out[0] = 0x00;                /* RSV high */
    out[1] = 0x00;                /* RSV low */
    out[2] = 0x00;                /* FRAG */
    out[3] = (uint8_t)src->atype; /* ATYP */

    size_t pos = 4;
    if (src->atype == MQ_ADDR_DOMAIN) {
        out[pos++] = (uint8_t)addr_len; /* LEN byte */
    }
    if (addr_len > 0) memcpy(out + pos, src->host, addr_len);
    pos += addr_len;
    out[pos] = (uint8_t)(src->port >> 8);
    out[pos + 1] = (uint8_t)(src->port);

    return (int)needed;
}
