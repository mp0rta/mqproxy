// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "wire/mq_wire.h"

#include <string.h>

#include "wire/mq_varint.h"

/* All multibyte fixed ints are big-endian. String fields are a varint
 * length prefix followed by that many raw bytes. Every read is bounds-checked
 * against the remaining buffer length because this parses untrusted input. */

/* ---- internal helpers ---- */

/* Encode a varint at buf[off..cap). Returns new offset, or -1 on overflow. */
static int
put_varint(uint8_t *buf, size_t cap, size_t off, uint64_t v)
{
    if (off > cap) return -1;
    int n = mq_varint_encode(buf + off, cap - off, v);
    if (n < 0) return -1;
    return (int)(off + (size_t)n);
}

/* Decode a varint at buf[off..len). Stores value in *v. Returns new offset,
 * or -1 on truncation. */
static int
get_varint(const uint8_t *buf, size_t len, size_t off, uint64_t *v)
{
    if (off > len) return -1;
    int n = mq_varint_decode(buf + off, len - off, v);
    if (n < 0) return -1;
    return (int)(off + (size_t)n);
}

/* Encode a big-endian uint16 at buf[off..cap). Returns new offset, or -1. */
static int
put_u16(uint8_t *buf, size_t cap, size_t off, uint16_t v)
{
    if (off + 2 > cap) return -1;
    buf[off] = (uint8_t)((v >> 8) & 0xFF);
    buf[off + 1] = (uint8_t)(v & 0xFF);
    return (int)(off + 2);
}

/* Decode a big-endian uint16 at buf[off..len). Returns new offset, or -1. */
static int
get_u16(const uint8_t *buf, size_t len, size_t off, uint16_t *v)
{
    if (off + 2 > len) return -1;
    *v = (uint16_t)(((uint16_t)buf[off] << 8) | (uint16_t)buf[off + 1]);
    return (int)(off + 2);
}

/* Encode a string: varint length + bytes. Returns new offset, or -1. */
static int
put_string(uint8_t *buf, size_t cap, size_t off, const uint8_t *s, size_t slen)
{
    int r = put_varint(buf, cap, off, (uint64_t)slen);
    if (r < 0) return -1;
    off = (size_t)r;
    if (off + slen > cap) return -1;
    if (slen > 0) memcpy(buf + off, s, slen);
    return (int)(off + slen);
}

/* Decode a string into dst (capacity dst_cap, NOT counting any NUL the caller
 * adds). The declared length must be <= dst_cap and fit in the buffer.
 * Stores length in *out_len and (optionally) copies bytes into dst.
 * Returns new offset, or -1 on truncation / over-long field. */
static int
get_string(const uint8_t *buf, size_t len, size_t off, uint8_t *dst, size_t dst_cap,
           size_t *out_len)
{
    uint64_t slen64;
    int r = get_varint(buf, len, off, &slen64);
    if (r < 0) return -1;
    off = (size_t)r;
    if (slen64 > dst_cap) return -1;
    size_t slen = (size_t)slen64;
    if (off + slen > len) return -1;
    if (slen > 0) memcpy(dst, buf + off, slen);
    *out_len = slen;
    return (int)(off + slen);
}

/* Emit a padding_length of 0 (encoders never pad). Returns new offset, or -1. */
static int
put_zero_padding(uint8_t *buf, size_t cap, size_t off)
{
    return put_varint(buf, cap, off, 0);
}

/* Read padding_length and skip that many bytes (bounds-checked).
 * Returns new offset (end of frame), or -1 if it overflows the buffer. */
static int
skip_padding(const uint8_t *buf, size_t len, size_t off)
{
    uint64_t pad;
    int r = get_varint(buf, len, off, &pad);
    if (r < 0) return -1;
    off = (size_t)r;
    if (pad > len - off) /* off <= len guaranteed by get_varint */
        return -1;
    return (int)(off + (size_t)pad);
}

/* ---- AUTH_REQUEST ----
 * varint version | string client_id | string auth_token | varint features
 * | varint padding_length | padding
 */
int
mq_encode_auth_req(uint8_t *buf, size_t cap, const mq_auth_req_t *f)
{
    int r = put_varint(buf, cap, 0, f->version);
    if (r < 0) return -1;
    r = put_string(buf, cap, (size_t)r, (const uint8_t *)f->client_id,
                   strlen(f->client_id));
    if (r < 0) return -1;
    r = put_string(buf, cap, (size_t)r, (const uint8_t *)f->auth_token,
                   strlen(f->auth_token));
    if (r < 0) return -1;
    r = put_varint(buf, cap, (size_t)r, f->features);
    if (r < 0) return -1;
    r = put_zero_padding(buf, cap, (size_t)r);
    return r;
}

int
mq_decode_auth_req(const uint8_t *buf, size_t len, mq_auth_req_t *out)
{
    memset(out, 0, sizeof *out);
    int r = get_varint(buf, len, 0, &out->version);
    if (r < 0) return -1;

    size_t slen;
    /* client_id: <=63 bytes + NUL into [64] */
    r = get_string(buf, len, (size_t)r, (uint8_t *)out->client_id,
                   sizeof out->client_id - 1, &slen);
    if (r < 0) return -1;
    out->client_id[slen] = '\0';

    /* auth_token: <=255 bytes + NUL into [256] */
    r = get_string(buf, len, (size_t)r, (uint8_t *)out->auth_token,
                   sizeof out->auth_token - 1, &slen);
    if (r < 0) return -1;
    out->auth_token[slen] = '\0';

    r = get_varint(buf, len, (size_t)r, &out->features);
    if (r < 0) return -1;
    return skip_padding(buf, len, (size_t)r);
}

/* ---- AUTH_RESPONSE ----
 * uint8 status | varint error_code | string server_id | varint features
 * | varint padding_length | padding
 */
int
mq_encode_auth_resp(uint8_t *buf, size_t cap, const mq_auth_resp_t *f)
{
    if (cap < 1) return -1;
    buf[0] = (uint8_t)f->status;
    int r = put_varint(buf, cap, 1, (uint64_t)f->error_code);
    if (r < 0) return -1;
    r = put_string(buf, cap, (size_t)r, (const uint8_t *)f->server_id,
                   strlen(f->server_id));
    if (r < 0) return -1;
    r = put_varint(buf, cap, (size_t)r, f->features);
    if (r < 0) return -1;
    return put_zero_padding(buf, cap, (size_t)r);
}

int
mq_decode_auth_resp(const uint8_t *buf, size_t len, mq_auth_resp_t *out)
{
    memset(out, 0, sizeof *out);
    if (len < 1) return -1;
    out->status = (mq_status_t)buf[0];

    uint64_t err;
    int r = get_varint(buf, len, 1, &err);
    if (r < 0) return -1;
    out->error_code = (mq_auth_err_t)err;

    size_t slen;
    r = get_string(buf, len, (size_t)r, (uint8_t *)out->server_id,
                   sizeof out->server_id - 1, &slen);
    if (r < 0) return -1;
    out->server_id[slen] = '\0';

    r = get_varint(buf, len, (size_t)r, &out->features);
    if (r < 0) return -1;
    return skip_padding(buf, len, (size_t)r);
}

/* ---- CONNECT_TCP_REQUEST ----
 * varint flags | uint8 address_type | string target_host | uint16 target_port
 * | varint padding_length | padding
 */
static int
addr_type_valid(unsigned t)
{
    return t == MQ_ADDR_IPV4 || t == MQ_ADDR_DOMAIN || t == MQ_ADDR_IPV6;
}

int
mq_encode_connect_tcp_req(uint8_t *buf, size_t cap, const mq_connect_tcp_req_t *f)
{
    if (f->host_len > MQ_MAX_HOST) return -1;
    if (!addr_type_valid((unsigned)f->address_type)) return -1;

    int r = put_varint(buf, cap, 0, f->flags);
    if (r < 0) return -1;
    size_t off = (size_t)r;
    if (off + 1 > cap) return -1;
    buf[off++] = (uint8_t)f->address_type;

    r = put_string(buf, cap, off, f->host, f->host_len);
    if (r < 0) return -1;
    r = put_u16(buf, cap, (size_t)r, f->port);
    if (r < 0) return -1;
    return put_zero_padding(buf, cap, (size_t)r);
}

int
mq_decode_connect_tcp_req(const uint8_t *buf, size_t len, mq_connect_tcp_req_t *out)
{
    memset(out, 0, sizeof *out);
    int r = get_varint(buf, len, 0, &out->flags);
    if (r < 0) return -1;
    size_t off = (size_t)r;
    if (off + 1 > len) return -1;
    uint8_t at = buf[off++];
    if (!addr_type_valid((unsigned)at)) return -1;
    out->address_type = (mq_addr_type_t)at;

    r = get_string(buf, len, off, out->host, sizeof out->host, &out->host_len);
    if (r < 0) return -1;
    r = get_u16(buf, len, (size_t)r, &out->port);
    if (r < 0) return -1;
    return skip_padding(buf, len, (size_t)r);
}

/* ---- CONNECT_TCP_RESPONSE ----
 * uint8 status | varint error_code | string message | varint padding_length | padding
 */
int
mq_encode_connect_tcp_resp(uint8_t *buf, size_t cap, const mq_connect_tcp_resp_t *f)
{
    if (cap < 1) return -1;
    buf[0] = (uint8_t)f->status;
    int r = put_varint(buf, cap, 1, (uint64_t)f->error_code);
    if (r < 0) return -1;
    r = put_string(buf, cap, (size_t)r, (const uint8_t *)f->message, strlen(f->message));
    if (r < 0) return -1;
    return put_zero_padding(buf, cap, (size_t)r);
}

int
mq_decode_connect_tcp_resp(const uint8_t *buf, size_t len, mq_connect_tcp_resp_t *out)
{
    memset(out, 0, sizeof *out);
    if (len < 1) return -1;
    out->status = (mq_status_t)buf[0];

    uint64_t err;
    int r = get_varint(buf, len, 1, &err);
    if (r < 0) return -1;
    out->error_code = (mq_tcp_err_t)err;

    r = get_string(buf, len, (size_t)r, (uint8_t *)out->message, sizeof out->message - 1,
                   &out->message_len);
    if (r < 0) return -1;
    out->message[out->message_len] = '\0';

    return skip_padding(buf, len, (size_t)r);
}
