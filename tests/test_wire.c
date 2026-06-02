// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "wire/mq_wire.h"
#include "wire/mq_varint.h"
#include "mqtest.h"

/* ---- AUTH_REQUEST round-trip ---- */
static void
test_auth_req_roundtrip(void)
{
    uint8_t buf[512];
    mq_auth_req_t in;
    memset(&in, 0, sizeof in);
    in.version = 1;
    strcpy(in.client_id, "client-abc");
    strcpy(in.auth_token, "secrettoken-1234567890");
    in.features = 0xDEADBEEF;

    int n = mq_encode_auth_req(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_auth_req_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_auth_req(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT(out.version, in.version);
    MQ_CHECK(strcmp(out.client_id, in.client_id) == 0);
    MQ_CHECK(strcmp(out.auth_token, in.auth_token) == 0);
    MQ_CHECK_EQ_INT(out.features, in.features);
}

/* ---- AUTH_RESPONSE round-trip for all error codes ---- */
static void
auth_resp_roundtrip_one(mq_status_t status, mq_auth_err_t err)
{
    uint8_t buf[512];
    mq_auth_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = status;
    in.error_code = err;
    strcpy(in.server_id, "server-xyz");
    in.features = 0x12345;

    int n = mq_encode_auth_resp(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_auth_resp_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_auth_resp(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT(out.status, in.status);
    MQ_CHECK_EQ_INT(out.error_code, in.error_code);
    MQ_CHECK(strcmp(out.server_id, in.server_id) == 0);
    MQ_CHECK_EQ_INT(out.features, in.features);
}

static void
test_auth_resp_roundtrip(void)
{
    auth_resp_roundtrip_one(MQ_STATUS_OK, MQ_AUTH_OK);
    auth_resp_roundtrip_one(MQ_STATUS_ERROR, MQ_AUTH_FAILED);
    auth_resp_roundtrip_one(MQ_STATUS_ERROR, MQ_AUTH_TOKEN_EXPIRED);
    auth_resp_roundtrip_one(MQ_STATUS_ERROR, MQ_AUTH_POLICY_DENIED);
}

/* ---- CONNECT_TCP_REQUEST round-trip, all 3 address types ---- */
static void
connect_tcp_req_roundtrip(mq_addr_type_t at, const uint8_t *host, size_t host_len)
{
    uint8_t buf[512];
    mq_connect_tcp_req_t in;
    memset(&in, 0, sizeof in);
    in.flags = 0xAA55;
    in.address_type = at;
    memcpy(in.host, host, host_len);
    in.host_len = host_len;
    in.port = 8443;

    int n = mq_encode_connect_tcp_req(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_connect_tcp_req_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_connect_tcp_req(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT(out.flags, in.flags);
    MQ_CHECK_EQ_INT(out.address_type, in.address_type);
    MQ_CHECK_EQ_INT(out.host_len, in.host_len);
    MQ_CHECK_MEM(out.host, in.host, host_len);
    MQ_CHECK_EQ_INT(out.port, in.port);
}

static void
test_connect_tcp_req_roundtrip(void)
{
    uint8_t v4[4] = {192, 168, 0, 1};
    connect_tcp_req_roundtrip(MQ_ADDR_IPV4, v4, sizeof v4);

    const char *dom = "example.com";
    connect_tcp_req_roundtrip(MQ_ADDR_DOMAIN, (const uint8_t *)dom, strlen(dom));

    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    connect_tcp_req_roundtrip(MQ_ADDR_IPV6, v6, sizeof v6);
}

/* ---- CONNECT_TCP_RESPONSE round-trip ---- */
static void
connect_tcp_resp_roundtrip(mq_status_t status, mq_tcp_err_t err, const char *msg)
{
    uint8_t buf[512];
    mq_connect_tcp_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = status;
    in.error_code = err;
    strcpy(in.message, msg);
    in.message_len = strlen(msg);

    int n = mq_encode_connect_tcp_resp(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_connect_tcp_resp_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_connect_tcp_resp(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT(out.status, in.status);
    MQ_CHECK_EQ_INT(out.error_code, in.error_code);
    MQ_CHECK_EQ_INT(out.message_len, in.message_len);
    MQ_CHECK(strcmp(out.message, in.message) == 0);
}

static void
test_connect_tcp_resp_roundtrip(void)
{
    connect_tcp_resp_roundtrip(MQ_STATUS_OK, MQ_TCP_OK, "connected");
    connect_tcp_resp_roundtrip(MQ_STATUS_ERROR, MQ_TCP_DNS_FAILED, "dns lookup failed");
    connect_tcp_resp_roundtrip(MQ_STATUS_ERROR, MQ_TCP_CONN_REFUSED, "refused");
}

/* ---- Malformed: truncation ---- */
static void
test_truncation(void)
{
    uint8_t buf[512];
    mq_auth_req_t in;
    memset(&in, 0, sizeof in);
    in.version = 1;
    strcpy(in.client_id, "abc");
    strcpy(in.auth_token, "token");
    in.features = 7;
    int n = mq_encode_auth_req(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_auth_req_t out;
    /* every strictly shorter prefix must fail */
    for (int k = 0; k < n; k++) {
        MQ_CHECK_EQ_INT(mq_decode_auth_req(buf, (size_t)k, &out), -1);
    }
}

/* ---- Malformed: host length field > MQ_MAX_HOST ---- */
static void
test_host_too_long(void)
{
    /* hand-craft CONNECT_TCP_REQUEST with declared host length 256 (>255). */
    uint8_t buf[64];
    size_t off = 0;
    int r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = MQ_ADDR_DOMAIN;                            /* address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 256); /* host length 256 */
    off += (size_t)r;
    /* no need to supply all the bytes; decoder must reject on the length cap */

    mq_connect_tcp_req_t out;
    MQ_CHECK_EQ_INT(mq_decode_connect_tcp_req(buf, off, &out), -1);
}

/* ---- Malformed: invalid address_type 0x02 ---- */
static void
test_bad_addr_type(void)
{
    uint8_t buf[64];
    size_t off = 0;
    int r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = 0x02;                                    /* invalid address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* host length */
    off += (size_t)r;
    buf[off++] = 10;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x01;                                    /* port hi */
    buf[off++] = 0xBB;                                    /* port lo */
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length */
    off += (size_t)r;

    mq_connect_tcp_req_t out;
    MQ_CHECK_EQ_INT(mq_decode_connect_tcp_req(buf, off, &out), -1);
}

/* ---- Forward-compat: non-zero padding_length + trailing pad bytes ---- */
static void
test_padding_skipped(void)
{
    uint8_t buf[64];
    size_t off = 0;
    int r = mq_varint_encode(buf + off, sizeof buf - off, 0xAA55); /* flags */
    off += (size_t)r;
    buf[off++] = MQ_ADDR_IPV4;
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* host len */
    off += (size_t)r;
    buf[off++] = 192;
    buf[off++] = 168;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x20;                                    /* port 8443 hi */
    buf[off++] = 0xFB;                                    /* port 8443 lo */
    r = mq_varint_encode(buf + off, sizeof buf - off, 5); /* padding_length = 5 */
    off += (size_t)r;
    for (int i = 0; i < 5; i++)
        buf[off++] = 0xEE; /* pad bytes */

    mq_connect_tcp_req_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_connect_tcp_req(buf, off, &out);
    MQ_CHECK_EQ_INT(m, (int)off); /* consumes everything incl. padding */
    MQ_CHECK_EQ_INT(out.flags, 0xAA55);
    MQ_CHECK_EQ_INT(out.address_type, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.host_len, 4);
    MQ_CHECK_EQ_INT(out.port, 8443);
    uint8_t want[4] = {192, 168, 0, 1};
    MQ_CHECK_MEM(out.host, want, 4);
}

/* ---- Forward-compat: padding_length overflowing buffer is rejected ---- */
static void
test_padding_overflow(void)
{
    uint8_t buf[64];
    size_t off = 0;
    int r = mq_varint_encode(buf + off, sizeof buf - off, 0);
    off += (size_t)r;
    buf[off++] = MQ_ADDR_IPV4;
    r = mq_varint_encode(buf + off, sizeof buf - off, 4);
    off += (size_t)r;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 0x00;
    buf[off++] = 0x50;
    r = mq_varint_encode(buf + off, sizeof buf - off, 99); /* claims 99 pad bytes */
    off += (size_t)r;
    /* but supply none */

    mq_connect_tcp_req_t out;
    MQ_CHECK_EQ_INT(mq_decode_connect_tcp_req(buf, off, &out), -1);
}

MQ_TEST_MAIN({
    test_auth_req_roundtrip();
    test_auth_resp_roundtrip();
    test_connect_tcp_req_roundtrip();
    test_connect_tcp_resp_roundtrip();
    test_truncation();
    test_host_too_long();
    test_bad_addr_type();
    test_padding_skipped();
    test_padding_overflow();
})
