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
    connect_tcp_resp_roundtrip(MQ_STATUS_ERROR, MQ_TCP_TIMEOUT, "timed out");
    connect_tcp_resp_roundtrip(MQ_STATUS_ERROR, MQ_TCP_POLICY_DENIED, "denied by policy");
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

/* ---- UDP_SESSION_OPEN round-trip, all 3 address types ---- */
static void
udp_session_open_roundtrip(mq_addr_type_t at, const uint8_t *host, size_t host_len)
{
    uint8_t buf[512];
    mq_udp_session_open_t in;
    memset(&in, 0, sizeof in);
    in.session_id = 0xDEAD1234U;
    in.flags = 0;
    in.address_type = at;
    memcpy(in.host, host, host_len);
    in.host_len = host_len;
    in.port = 5353;
    in.idle_timeout_ms = 30000;

    int n = mq_encode_udp_session_open(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_udp_session_open_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_udp_session_open(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT((long long)out.session_id, (long long)in.session_id);
    MQ_CHECK_EQ_INT((long long)out.flags, (long long)in.flags);
    MQ_CHECK_EQ_INT(out.address_type, in.address_type);
    MQ_CHECK_EQ_INT((long long)out.host_len, (long long)in.host_len);
    MQ_CHECK_MEM(out.host, in.host, host_len);
    MQ_CHECK_EQ_INT(out.port, in.port);
    MQ_CHECK_EQ_INT((long long)out.idle_timeout_ms, (long long)in.idle_timeout_ms);
}

static void
test_udp_session_open_roundtrip(void)
{
    uint8_t v4[4] = {8, 8, 8, 8};
    udp_session_open_roundtrip(MQ_ADDR_IPV4, v4, sizeof v4);

    const char *dom = "dns.example.com";
    udp_session_open_roundtrip(MQ_ADDR_DOMAIN, (const uint8_t *)dom, strlen(dom));

    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    udp_session_open_roundtrip(MQ_ADDR_IPV6, v6, sizeof v6);

    /* idle_timeout_ms = 0 (server default) */
    uint8_t v4b[4] = {1, 2, 3, 4};
    mq_udp_session_open_t in;
    memset(&in, 0, sizeof in);
    in.session_id = 1;
    in.address_type = MQ_ADDR_IPV4;
    memcpy(in.host, v4b, 4);
    in.host_len = 4;
    in.port = 53;
    in.idle_timeout_ms = 0;
    uint8_t buf[512];
    int n = mq_encode_udp_session_open(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);
    mq_udp_session_open_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_udp_session_open(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT((long long)out.idle_timeout_ms, 0LL);
}

/* ---- UDP_SESSION_RESP round-trip, including non-empty message ---- */
static void
udp_session_resp_roundtrip(mq_status_t status, mq_udp_err_t err, const char *msg,
                           uint64_t idle_ms)
{
    uint8_t buf[512];
    mq_udp_session_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = status;
    in.error_code = err;
    in.message_len = strlen(msg);
    memcpy(in.message, msg, in.message_len);
    in.idle_timeout_ms = idle_ms;

    int n = mq_encode_udp_session_resp(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_udp_session_resp_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_udp_session_resp(buf, (size_t)n, &out);
    MQ_CHECK_EQ_INT(m, n);
    MQ_CHECK_EQ_INT(out.status, in.status);
    MQ_CHECK_EQ_INT(out.error_code, in.error_code);
    MQ_CHECK_EQ_INT((long long)out.message_len, (long long)in.message_len);
    MQ_CHECK_MEM(out.message, in.message, in.message_len);
    MQ_CHECK_EQ_INT((long long)out.idle_timeout_ms, (long long)in.idle_timeout_ms);
}

static void
test_udp_session_resp_roundtrip(void)
{
    /* empty message */
    udp_session_resp_roundtrip(MQ_STATUS_OK, MQ_UDP_OK, "", 60000);
    /* non-empty message — fixes variable-length string codec */
    udp_session_resp_roundtrip(MQ_STATUS_ERROR, MQ_UDP_DNS_FAILED,
                               "dns lookup failed for host", 0);
    udp_session_resp_roundtrip(MQ_STATUS_ERROR, MQ_UDP_SOCKET_FAILED, "socket bind error",
                               0);
    udp_session_resp_roundtrip(MQ_STATUS_ERROR, MQ_UDP_POLICY_DENIED, "denied by policy",
                               0);
    udp_session_resp_roundtrip(MQ_STATUS_ERROR, MQ_UDP_SESSION_LIMIT,
                               "session limit reached", 0);
    /* non-empty message with OK status and server-applied timeout */
    udp_session_resp_roundtrip(MQ_STATUS_OK, MQ_UDP_OK, "udp relay ready", 45000);
}

/* ---- Truncation: UDP_SESSION_OPEN all offsets ---- */
static void
test_udp_session_open_truncation(void)
{
    uint8_t buf[512];
    mq_udp_session_open_t in;
    memset(&in, 0, sizeof in);
    in.session_id = 42;
    in.flags = 0;
    in.address_type = MQ_ADDR_DOMAIN;
    const char *dom = "example.org";
    memcpy(in.host, dom, strlen(dom));
    in.host_len = strlen(dom);
    in.port = 5353;
    in.idle_timeout_ms = 10000;

    int n = mq_encode_udp_session_open(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_udp_session_open_t out;
    for (int k = 0; k < n; k++) {
        MQ_CHECK_EQ_INT(mq_decode_udp_session_open(buf, (size_t)k, &out), -1);
    }
}

/* ---- Truncation: UDP_SESSION_RESP all offsets ---- */
static void
test_udp_session_resp_truncation(void)
{
    uint8_t buf[512];
    mq_udp_session_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = MQ_STATUS_ERROR;
    in.error_code = MQ_UDP_DNS_FAILED;
    const char *msg = "dns error";
    in.message_len = strlen(msg);
    memcpy(in.message, msg, in.message_len);
    in.idle_timeout_ms = 0;

    int n = mq_encode_udp_session_resp(buf, sizeof buf, &in);
    MQ_CHECK(n > 0);

    mq_udp_session_resp_t out;
    for (int k = 0; k < n; k++) {
        MQ_CHECK_EQ_INT(mq_decode_udp_session_resp(buf, (size_t)k, &out), -1);
    }
}

/* ---- host_len > 255 rejected by encoder ---- */
static void
test_udp_session_open_host_too_long(void)
{
    uint8_t buf[512];
    mq_udp_session_open_t in;
    memset(&in, 0, sizeof in);
    in.session_id = 1;
    in.address_type = MQ_ADDR_DOMAIN;
    in.host_len = 256; /* > MQ_MAX_HOST */
    in.port = 53;
    MQ_CHECK_EQ_INT(mq_encode_udp_session_open(buf, sizeof buf, &in), -1);
}

/* ---- host_len > 255 in wire rejected by decoder ---- */
static void
test_udp_session_open_decode_host_too_long(void)
{
    uint8_t buf[64];
    size_t off = 0;
    int r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 1); /* session_id */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = MQ_ADDR_DOMAIN;                            /* address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 256); /* host len 256 */
    off += (size_t)r;
    /* no host bytes needed — decoder rejects on cap */

    mq_udp_session_open_t out;
    MQ_CHECK_EQ_INT(mq_decode_udp_session_open(buf, off, &out), -1);
}

/* ---- Strict session_id decode: session_id > UINT32_MAX is rejected ---- */
static void
test_udp_session_open_session_id_overflow(void)
{
    /* Hand-craft an OPEN frame where session_id = 0x100000000 (UINT32_MAX+1).
     * The decoder must reject this with -1 instead of silently truncating. */
    uint8_t buf[128];
    size_t off = 0;
    int r;
    r = mq_varint_encode(buf + off, sizeof buf - off,
                         0x100000000ULL); /* session_id = UINT32_MAX + 1 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = MQ_ADDR_IPV4;                            /* address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* host len */
    off += (size_t)r;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 0x00;
    buf[off++] = 0x50;                                       /* port 80 */
    r = mq_varint_encode(buf + off, sizeof buf - off, 5000); /* idle_timeout_ms */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length */
    off += (size_t)r;

    mq_udp_session_open_t out;
    MQ_CHECK_EQ_INT(mq_decode_udp_session_open(buf, off, &out), -1);
}

/* ---- Malformed: invalid address_type in UDP_SESSION_OPEN is rejected ---- */
static void
test_udp_session_open_bad_addr_type(void)
{
    uint8_t buf[64];
    size_t off = 0;
    int r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 1); /* session_id */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = 0x05;                                    /* invalid address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* host len */
    off += (size_t)r;
    buf[off++] = 10;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 1;
    buf[off++] = 0x01;                                    /* port hi */
    buf[off++] = 0xBB;                                    /* port lo */
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* idle_timeout_ms */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length */
    off += (size_t)r;

    mq_udp_session_open_t out;
    MQ_CHECK_EQ_INT(mq_decode_udp_session_open(buf, off, &out), -1);
}

/* ---- Padding skip: UDP_SESSION_OPEN decoder accepts non-zero padding ---- */
static void
test_udp_session_open_padding_skipped(void)
{
    /* Hand-craft an OPEN frame with padding_length = 3 */
    uint8_t buf[128];
    size_t off = 0;
    int r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 7); /* session_id */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* flags */
    off += (size_t)r;
    buf[off++] = MQ_ADDR_IPV4;                            /* address_type */
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* host len */
    off += (size_t)r;
    buf[off++] = 1;
    buf[off++] = 2;
    buf[off++] = 3;
    buf[off++] = 4;
    buf[off++] = 0x00;
    buf[off++] = 0x35;                                       /* port 53 */
    r = mq_varint_encode(buf + off, sizeof buf - off, 5000); /* idle_timeout_ms */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 3); /* padding_length = 3 */
    off += (size_t)r;
    buf[off++] = 0xAA;
    buf[off++] = 0xBB;
    buf[off++] = 0xCC;

    mq_udp_session_open_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_udp_session_open(buf, off, &out);
    MQ_CHECK_EQ_INT(m, (int)off);
    MQ_CHECK_EQ_INT((long long)out.session_id, 7LL);
    MQ_CHECK_EQ_INT(out.address_type, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.port, 53);
    MQ_CHECK_EQ_INT((long long)out.idle_timeout_ms, 5000LL);
}

/* ---- Padding skip: UDP_SESSION_RESP decoder accepts non-zero padding ---- */
static void
test_udp_session_resp_padding_skipped(void)
{
    uint8_t buf[128];
    size_t off = 0;
    int r;
    buf[off++] = (uint8_t)MQ_STATUS_OK;                           /* status */
    r = mq_varint_encode(buf + off, sizeof buf - off, MQ_UDP_OK); /* error_code */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 2); /* msg len = 2 */
    off += (size_t)r;
    buf[off++] = 'O';
    buf[off++] = 'K';
    r = mq_varint_encode(buf + off, sizeof buf - off, 60000); /* idle_timeout_ms */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 4); /* padding_length = 4 */
    off += (size_t)r;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = 0;

    mq_udp_session_resp_t out;
    memset(&out, 0, sizeof out);
    int m = mq_decode_udp_session_resp(buf, off, &out);
    MQ_CHECK_EQ_INT(m, (int)off);
    MQ_CHECK_EQ_INT(out.status, MQ_STATUS_OK);
    MQ_CHECK_EQ_INT(out.error_code, MQ_UDP_OK);
    MQ_CHECK_EQ_INT((long long)out.message_len, 2LL);
    MQ_CHECK_EQ_INT((long long)out.idle_timeout_ms, 60000LL);
}

/* ---- Boundary: wire leak prevention ---- */

/* Case 1: encode with error_code == MQ_UDP_CLOSED must return -1 */
static void
test_udp_resp_encode_closed_rejected(void)
{
    uint8_t buf[512];
    mq_udp_session_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = MQ_STATUS_ERROR;
    in.error_code = MQ_UDP_CLOSED; /* must not go on wire */
    MQ_CHECK_EQ_INT(mq_encode_udp_session_resp(buf, sizeof buf, &in), -1);
}

/* Case 2: decode with wire error_code >= 5 must return -1 */
static void
test_udp_resp_decode_error_code_oor(void)
{
    uint8_t buf[128];
    size_t off = 0;
    int r;
    buf[off++] = (uint8_t)MQ_STATUS_ERROR;
    r = mq_varint_encode(buf + off, sizeof buf - off,
                         5); /* error_code = 5, out of range */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* msg len 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* idle_timeout_ms 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length 0 */
    off += (size_t)r;

    mq_udp_session_resp_t out;
    MQ_CHECK_EQ_INT(mq_decode_udp_session_resp(buf, off, &out), -1);
}

/* Case 3a: status/error_code inconsistency — MQ_STATUS_OK + error != OK */
static void
test_udp_resp_encode_status_mismatch_ok_with_error(void)
{
    uint8_t buf[512];
    mq_udp_session_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = MQ_STATUS_OK;
    in.error_code = MQ_UDP_DNS_FAILED; /* mismatch: OK + non-zero error */
    MQ_CHECK_EQ_INT(mq_encode_udp_session_resp(buf, sizeof buf, &in), -1);
}

/* Case 3b: MQ_STATUS_ERROR + MQ_UDP_OK mismatch */
static void
test_udp_resp_encode_status_mismatch_error_with_ok(void)
{
    uint8_t buf[512];
    mq_udp_session_resp_t in;
    memset(&in, 0, sizeof in);
    in.status = MQ_STATUS_ERROR;
    in.error_code = MQ_UDP_OK; /* mismatch: ERROR + ok error_code */
    MQ_CHECK_EQ_INT(mq_encode_udp_session_resp(buf, sizeof buf, &in), -1);
}

/* Case 3c: decode mismatch — MQ_STATUS_OK + error != OK on wire */
static void
test_udp_resp_decode_status_mismatch(void)
{
    uint8_t buf[128];
    size_t off = 0;
    int r;

    /* OK status but error_code = 1 */
    buf[off++] = (uint8_t)MQ_STATUS_OK;
    r = mq_varint_encode(buf + off, sizeof buf - off, 1); /* MQ_UDP_DNS_FAILED */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* msg len 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* idle_timeout_ms 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length 0 */
    off += (size_t)r;

    mq_udp_session_resp_t out;
    MQ_CHECK_EQ_INT(mq_decode_udp_session_resp(buf, off, &out), -1);

    /* ERROR status but error_code = 0 */
    off = 0;
    buf[off++] = (uint8_t)MQ_STATUS_ERROR;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* MQ_UDP_OK */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* msg len 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* idle_timeout_ms 0 */
    off += (size_t)r;
    r = mq_varint_encode(buf + off, sizeof buf - off, 0); /* padding_length 0 */
    off += (size_t)r;

    MQ_CHECK_EQ_INT(mq_decode_udp_session_resp(buf, off, &out), -1);
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
    test_udp_session_open_roundtrip();
    test_udp_session_resp_roundtrip();
    test_udp_session_open_truncation();
    test_udp_session_resp_truncation();
    test_udp_session_open_host_too_long();
    test_udp_session_open_decode_host_too_long();
    test_udp_session_open_session_id_overflow();
    test_udp_session_open_bad_addr_type();
    test_udp_session_open_padding_skipped();
    test_udp_session_resp_padding_skipped();
    test_udp_resp_encode_closed_rejected();
    test_udp_resp_decode_error_code_oor();
    test_udp_resp_encode_status_mismatch_ok_with_error();
    test_udp_resp_encode_status_mismatch_error_with_ok();
    test_udp_resp_decode_status_mismatch();
})
