// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "ingress/mq_socks5.h"
#include "mqtest.h"

/* ---- byte-array helpers ---- */
static const uint8_t GREETING_OK[] = {0x05, 0x01, 0x00};
static const uint8_t GREETING_MULTI_OK[] = {0x05, 0x02, 0x02, 0x00};
static const uint8_t GREETING_NO_NOAUTH[] = {0x05, 0x01, 0x02};
static const uint8_t GREETING_BADVER[] = {0x04, 0x01, 0x00};

static const uint8_t REQ_IPV4[] = {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
static const uint8_t IPV4_HOST[] = {1, 2, 3, 4};

static const uint8_t REQ_DOMAIN[] = {0x05, 0x01, 0x00, 0x03, 11,  'e', 'x', 'a',  'm',
                                     'p',  'l',  'e',  '.',  'c', 'o', 'm', 0x01, 0xBB};

static const uint8_t REQ_IPV6[] = {0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8,
                                   0,    0,    0,    0,    0,    0,    0,    0,
                                   0,    0,    0,    1,    0x1F, 0x90};
static const uint8_t IPV6_HOST[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                    0,    0,    0,    0,    0, 0, 0, 1};

static const uint8_t REQ_CMD_BIND[] = {0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};

/* ATYP=0x02 is reserved/unassigned — must be MQ_SOCKS5_UNSUPPORTED */
static const uint8_t REQ_BAD_ATYP[] = {0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0x00, 0x50};

/* request with wrong VER (0x04) — must be MQ_SOCKS5_ERROR */
static const uint8_t REQ_BADVER[] = {0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};

/* ---- greeting ---- */
static void
test_greeting_ok(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t out;
    mq_socks5_status_t st =
        mq_socks5_feed(&p, GREETING_OK, sizeof GREETING_OK, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_GREETING_DONE);
    MQ_CHECK_EQ_INT(consumed, sizeof GREETING_OK);
}

static void
test_greeting_multi_method_ok(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t out;
    mq_socks5_status_t st =
        mq_socks5_feed(&p, GREETING_MULTI_OK, sizeof GREETING_MULTI_OK, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_GREETING_DONE);
    MQ_CHECK_EQ_INT(consumed, sizeof GREETING_MULTI_OK);
}

static void
test_greeting_no_noauth(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t out;
    mq_socks5_status_t st = mq_socks5_feed(&p, GREETING_NO_NOAUTH,
                                           sizeof GREETING_NO_NOAUTH, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_UNSUPPORTED);
}

static void
test_greeting_bad_version(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t out;
    mq_socks5_status_t st =
        mq_socks5_feed(&p, GREETING_BADVER, sizeof GREETING_BADVER, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ERROR);
}

static void
test_greeting_need_more(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 99;
    mq_socks5_req_t out;
    /* VER + NMETHODS=1 but methods byte missing */
    mq_socks5_status_t st = mq_socks5_feed(&p, GREETING_OK, 2, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_NEED_MORE);
    MQ_CHECK_EQ_INT(consumed, 0);
}

/* ---- requests (greeting first) ---- */
static mq_socks5_status_t
do_request(const uint8_t *buf, size_t len, mq_socks5_req_t *out)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t g;
    mq_socks5_status_t st =
        mq_socks5_feed(&p, GREETING_OK, sizeof GREETING_OK, &consumed, &g);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_GREETING_DONE);
    consumed = 0;
    return mq_socks5_feed(&p, buf, len, &consumed, out);
}

static void
test_request_ipv4(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_IPV4, sizeof REQ_IPV4, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_REQUEST_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.host_len, 4);
    MQ_CHECK_MEM(out.host, IPV4_HOST, 4);
    MQ_CHECK_EQ_INT(out.port, 80);
}

static void
test_request_domain(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_DOMAIN, sizeof REQ_DOMAIN, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_REQUEST_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(out.host_len, 11);
    MQ_CHECK_MEM(out.host, "example.com", 11);
    MQ_CHECK_EQ_INT(out.port, 443);
}

static void
test_request_ipv6(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_IPV6, sizeof REQ_IPV6, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_REQUEST_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT(out.host_len, 16);
    MQ_CHECK_MEM(out.host, IPV6_HOST, 16);
    MQ_CHECK_EQ_INT(out.port, 0x1F90);
}

static void
test_request_fragmented(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 0;
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st =
        mq_socks5_feed(&p, GREETING_OK, sizeof GREETING_OK, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_GREETING_DONE);

    /* first slice: 5 bytes of a 10-byte IPv4 request */
    consumed = 99;
    st = mq_socks5_feed(&p, REQ_IPV4, 5, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_NEED_MORE);
    MQ_CHECK_EQ_INT(consumed, 0);

    /* second slice: whole request now available */
    consumed = 0;
    st = mq_socks5_feed(&p, REQ_IPV4, sizeof REQ_IPV4, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_REQUEST_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV4);
    MQ_CHECK_MEM(out.host, IPV4_HOST, 4);
    MQ_CHECK_EQ_INT(out.port, 80);
}

static void
test_request_cmd_unsupported(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_CMD_BIND, sizeof REQ_CMD_BIND, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_UNSUPPORTED_CMD);
}

static void
test_request_bad_atyp(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_BAD_ATYP, sizeof REQ_BAD_ATYP, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_UNSUPPORTED_ATYP);
}

static void
test_request_bad_version(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_BADVER, sizeof REQ_BADVER, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ERROR);
}

static void
test_greeting_one_byte(void)
{
    mq_socks5_parser_t p;
    mq_socks5_parser_init(&p);
    size_t consumed = 99;
    mq_socks5_req_t out;
    /* feed only 1 byte — must need more, consuming nothing */
    mq_socks5_status_t st = mq_socks5_feed(&p, GREETING_OK, 1, &consumed, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_NEED_MORE);
    MQ_CHECK_EQ_INT(consumed, 0);
}

/* ---- reply builders ---- */
static void
test_method_reply(void)
{
    uint8_t out[2];
    size_t n = mq_socks5_build_method_reply(out, 1);
    MQ_CHECK_EQ_INT(n, 2);
    MQ_CHECK_EQ_INT(out[0], 0x05);
    MQ_CHECK_EQ_INT(out[1], 0x00);

    n = mq_socks5_build_method_reply(out, 0);
    MQ_CHECK_EQ_INT(n, 2);
    MQ_CHECK_EQ_INT(out[0], 0x05);
    MQ_CHECK_EQ_INT(out[1], 0xFF);
}

static void
test_connect_reply(void)
{
    uint8_t out[10];
    static const uint8_t expect[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    size_t n = mq_socks5_build_connect_reply(out, 0x00);
    MQ_CHECK_EQ_INT(n, 10);
    MQ_CHECK_MEM(out, expect, 10);

    n = mq_socks5_build_connect_reply(out, 0x05);
    MQ_CHECK_EQ_INT(n, 10);
    MQ_CHECK_EQ_INT(out[1], 0x05);
    MQ_CHECK_EQ_INT(out[3], 0x01);
}

static void
test_reply_code(void)
{
    MQ_CHECK_EQ_INT(mq_socks5_reply_code(MQ_TCP_OK), 0x00);
    MQ_CHECK_EQ_INT(mq_socks5_reply_code(MQ_TCP_CONN_REFUSED), 0x05);
    MQ_CHECK_EQ_INT(mq_socks5_reply_code(MQ_TCP_DNS_FAILED), 0x04);
    MQ_CHECK_EQ_INT(mq_socks5_reply_code(MQ_TCP_TIMEOUT), 0x06);
    MQ_CHECK_EQ_INT(mq_socks5_reply_code(MQ_TCP_POLICY_DENIED), 0x02);
}

MQ_TEST_MAIN({
    test_greeting_ok();
    test_greeting_multi_method_ok();
    test_greeting_no_noauth();
    test_greeting_bad_version();
    test_greeting_need_more();
    test_request_ipv4();
    test_request_domain();
    test_request_ipv6();
    test_request_fragmented();
    test_request_cmd_unsupported();
    test_request_bad_atyp();
    test_request_bad_version();
    test_greeting_one_byte();
    test_method_reply();
    test_connect_reply();
    test_reply_code();
})
