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

/* ---- ASSOCIATE (CMD 0x03) ---- */

/* CMD=0x03, DST=0.0.0.0:0 (typical client sends zeros) */
static const uint8_t REQ_ASSOCIATE_V4_ZERO[] = {0x05, 0x03, 0x00, 0x01, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00};
/* CMD=0x03, DST=192.168.1.1:1234 */
static const uint8_t REQ_ASSOCIATE_V4[] = {0x05, 0x03, 0x00, 0x01, 192,
                                           168,  1,    1,    0x04, 0xD2};
/* CMD=0x03, DST=domain "example.com":443 */
static const uint8_t REQ_ASSOCIATE_DOMAIN[] = {0x05, 0x03, 0x00, 0x03, 11,   'e',
                                               'x',  'a',  'm',  'p',  'l',  'e',
                                               '.',  'c',  'o',  'm',  0x01, 0xBB};
/* CMD=0x03, DST=IPv6 2001:db8::1:8080 */
static const uint8_t REQ_ASSOCIATE_V6[] = {0x05, 0x03, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8,
                                           0,    0,    0,    0,    0,    0,    0,    0,
                                           0,    0,    0,    0x01, 0x1F, 0x90};

static void
test_associate_ipv4_zero_dst(void)
{
    mq_socks5_req_t out;
    memset(&out, 0xFF, sizeof out);
    mq_socks5_status_t st =
        do_request(REQ_ASSOCIATE_V4_ZERO, sizeof REQ_ASSOCIATE_V4_ZERO, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ASSOCIATE_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.host_len, 4);
    MQ_CHECK_EQ_INT(out.port, 0);
    static const uint8_t zeros[4] = {0, 0, 0, 0};
    MQ_CHECK_MEM(out.host, zeros, 4);
}

static void
test_associate_ipv4_dst(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_ASSOCIATE_V4, sizeof REQ_ASSOCIATE_V4, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ASSOCIATE_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.host_len, 4);
    static const uint8_t ip[] = {192, 168, 1, 1};
    MQ_CHECK_MEM(out.host, ip, 4);
    MQ_CHECK_EQ_INT(out.port, 1234);
}

static void
test_associate_domain_dst(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st =
        do_request(REQ_ASSOCIATE_DOMAIN, sizeof REQ_ASSOCIATE_DOMAIN, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ASSOCIATE_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(out.host_len, 11);
    MQ_CHECK_MEM(out.host, "example.com", 11);
    MQ_CHECK_EQ_INT(out.port, 443);
}

static void
test_associate_ipv6_dst(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_ASSOCIATE_V6, sizeof REQ_ASSOCIATE_V6, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_ASSOCIATE_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT(out.host_len, 16);
    static const uint8_t ipv6[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 0x01};
    MQ_CHECK_MEM(out.host, ipv6, 16);
    MQ_CHECK_EQ_INT(out.port, 0x1F90);
}

/* CMD=0x02 (BIND) is still unsupported — not ASSOCIATE */
static void
test_request_bind_still_unsupported(void)
{
    mq_socks5_req_t out;
    memset(&out, 0, sizeof out);
    mq_socks5_status_t st = do_request(REQ_CMD_BIND, sizeof REQ_CMD_BIND, &out);
    MQ_CHECK_EQ_INT(st, MQ_SOCKS5_UNSUPPORTED_CMD);
}

/* ---- ASSOCIATE reply ---- */
static void
test_associate_reply_zero(void)
{
    uint8_t out[10];
    memset(out, 0xFF, sizeof out);
    size_t n = mq_socks5_build_associate_reply(out, 0, 0);
    MQ_CHECK_EQ_INT(n, 10);
    static const uint8_t expect[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    MQ_CHECK_MEM(out, expect, 10);
}

static void
test_associate_reply_with_addr(void)
{
    uint8_t out[10];
    memset(out, 0xFF, sizeof out);
    /* BND.ADDR = 10.0.0.1 (0x0A000001 big-endian), BND.PORT = 1080 (0x0438) */
    size_t n = mq_socks5_build_associate_reply(out, 0x0A000001u, 1080);
    MQ_CHECK_EQ_INT(n, 10);
    MQ_CHECK_EQ_INT(out[0], 0x05); /* VER */
    MQ_CHECK_EQ_INT(out[1], 0x00); /* REP=success */
    MQ_CHECK_EQ_INT(out[2], 0x00); /* RSV */
    MQ_CHECK_EQ_INT(out[3], 0x01); /* ATYP=IPv4 */
    MQ_CHECK_EQ_INT(out[4], 0x0A); /* 10 */
    MQ_CHECK_EQ_INT(out[5], 0x00); /* 0 */
    MQ_CHECK_EQ_INT(out[6], 0x00); /* 0 */
    MQ_CHECK_EQ_INT(out[7], 0x01); /* 1 */
    MQ_CHECK_EQ_INT(out[8], 0x04); /* port high */
    MQ_CHECK_EQ_INT(out[9], 0x38); /* port low */
}

/* connect_reply is unaffected by refactor */
static void
test_connect_reply_unchanged(void)
{
    uint8_t out[10];
    static const uint8_t expect[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    size_t n = mq_socks5_build_connect_reply(out, 0x00);
    MQ_CHECK_EQ_INT(n, 10);
    MQ_CHECK_MEM(out, expect, 10);
}

/* ---- UDP encapsulation header ---- */

/* IPv4 UDP header: RSV=0 FRAG=0 ATYP=1 ADDR=1.2.3.4 PORT=80 */
static const uint8_t UDP_HDR_IPV4[] = {
    0x00, 0x00,             /* RSV */
    0x00,                   /* FRAG */
    0x01,                   /* ATYP=IPv4 */
    0x01, 0x02, 0x03, 0x04, /* ADDR */
    0x00, 0x50              /* PORT=80 */
};

/* IPv6 UDP header */
static const uint8_t UDP_HDR_IPV6[] = {
    0x00, 0x00,                                                 /* RSV */
    0x00,                                                       /* FRAG */
    0x04,                                                       /* ATYP=IPv6 */
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, /* ADDR */
    0x1F, 0x90                                                  /* PORT=8080 */
};

/* Domain UDP header */
static const uint8_t UDP_HDR_DOMAIN[] = {
    0x00, 0x00,                                              /* RSV */
    0x00,                                                    /* FRAG */
    0x03,                                                    /* ATYP=domain */
    0x0B,                                                    /* LEN=11 */
    'e',  'x',  'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', /* ADDR */
    0x01, 0xBB                                               /* PORT=443 */
};

static void
test_parse_udp_hdr_ipv4(void)
{
    mq_socks5_udp_hdr_t h;
    memset(&h, 0, sizeof h);
    int n = mq_socks5_parse_udp_hdr(UDP_HDR_IPV4, sizeof UDP_HDR_IPV4, &h);
    MQ_CHECK_EQ_INT(n, (int)sizeof UDP_HDR_IPV4);
    MQ_CHECK_EQ_INT(h.hdr_len, sizeof UDP_HDR_IPV4);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(h.dst.host_len, 4);
    static const uint8_t addr[] = {1, 2, 3, 4};
    MQ_CHECK_MEM(h.dst.host, addr, 4);
    MQ_CHECK_EQ_INT(h.dst.port, 80);
}

static void
test_parse_udp_hdr_ipv6(void)
{
    mq_socks5_udp_hdr_t h;
    memset(&h, 0, sizeof h);
    int n = mq_socks5_parse_udp_hdr(UDP_HDR_IPV6, sizeof UDP_HDR_IPV6, &h);
    MQ_CHECK_EQ_INT(n, (int)sizeof UDP_HDR_IPV6);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT(h.dst.host_len, 16);
    static const uint8_t addr[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 1};
    MQ_CHECK_MEM(h.dst.host, addr, 16);
    MQ_CHECK_EQ_INT(h.dst.port, 0x1F90);
}

static void
test_parse_udp_hdr_domain(void)
{
    mq_socks5_udp_hdr_t h;
    memset(&h, 0, sizeof h);
    int n = mq_socks5_parse_udp_hdr(UDP_HDR_DOMAIN, sizeof UDP_HDR_DOMAIN, &h);
    MQ_CHECK_EQ_INT(n, (int)sizeof UDP_HDR_DOMAIN);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(h.dst.host_len, 11);
    MQ_CHECK_MEM(h.dst.host, "example.com", 11);
    MQ_CHECK_EQ_INT(h.dst.port, 443);
}

static void
test_parse_udp_hdr_frag_nonzero(void)
{
    /* FRAG=1: must return -2 */
    static const uint8_t buf[] = {0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    mq_socks5_udp_hdr_t h;
    int n = mq_socks5_parse_udp_hdr(buf, sizeof buf, &h);
    MQ_CHECK_EQ_INT(n, -2);
}

static void
test_parse_udp_hdr_rsv_nonzero(void)
{
    /* RSV=0x0001: must return -1 (strict reject) */
    static const uint8_t buf[] = {0x00, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    mq_socks5_udp_hdr_t h;
    int n = mq_socks5_parse_udp_hdr(buf, sizeof buf, &h);
    MQ_CHECK_EQ_INT(n, -1);
}

static void
test_parse_udp_hdr_rsv_high_nonzero(void)
{
    /* RSV=0x0100: must return -1 */
    static const uint8_t buf[] = {0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50};
    mq_socks5_udp_hdr_t h;
    int n = mq_socks5_parse_udp_hdr(buf, sizeof buf, &h);
    MQ_CHECK_EQ_INT(n, -1);
}

/* Truncation sweep: feed 0..N-1 bytes of a valid IPv4 header, all must return -1 */
static void
test_parse_udp_hdr_truncation_sweep_ipv4(void)
{
    mq_socks5_udp_hdr_t h;
    for (size_t i = 0; i < sizeof UDP_HDR_IPV4; i++) {
        int n = mq_socks5_parse_udp_hdr(UDP_HDR_IPV4, i, &h);
        MQ_CHECK_EQ_INT(n, -1);
    }
}

/* Truncation sweep for domain header (variable-length, more interesting) */
static void
test_parse_udp_hdr_truncation_sweep_domain(void)
{
    mq_socks5_udp_hdr_t h;
    for (size_t i = 0; i < sizeof UDP_HDR_DOMAIN; i++) {
        int n = mq_socks5_parse_udp_hdr(UDP_HDR_DOMAIN, i, &h);
        MQ_CHECK_EQ_INT(n, -1);
    }
}

/* Truncation sweep: feed 0..N-1 bytes of a valid IPv6 header, all must return -1 */
static void
test_parse_udp_hdr_truncation_sweep_ipv6(void)
{
    mq_socks5_udp_hdr_t h;
    for (size_t i = 0; i < sizeof UDP_HDR_IPV6; i++) {
        int n = mq_socks5_parse_udp_hdr(UDP_HDR_IPV6, i, &h);
        MQ_CHECK_EQ_INT(n, -1);
    }
}

/* Bad ATYP in UDP header */
static void
test_parse_udp_hdr_bad_atyp(void)
{
    static const uint8_t buf[] = {0x00, 0x00, 0x00, 0x02, 1, 2, 3, 4, 0x00, 0x50};
    mq_socks5_udp_hdr_t h;
    int n = mq_socks5_parse_udp_hdr(buf, sizeof buf, &h);
    MQ_CHECK_EQ_INT(n, -1);
}

/* ---- build_udp_hdr ---- */
static void
test_build_udp_hdr_ipv4_roundtrip(void)
{
    /* build then parse — should recover the same dst */
    mq_socks5_req_t src;
    src.atype = MQ_ADDR_IPV4;
    src.host_len = 4;
    src.host[0] = 10;
    src.host[1] = 0;
    src.host[2] = 0;
    src.host[3] = 1;
    src.port = 53;

    uint8_t buf[32];
    int n = mq_socks5_build_udp_hdr(buf, sizeof buf, &src);
    MQ_CHECK_EQ_INT(n, 10); /* RSV(2)+FRAG(1)+ATYP(1)+IPv4(4)+PORT(2) */

    mq_socks5_udp_hdr_t h;
    int n2 = mq_socks5_parse_udp_hdr(buf, (size_t)n, &h);
    MQ_CHECK_EQ_INT(n2, n);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(h.dst.host_len, 4);
    MQ_CHECK_MEM(h.dst.host, src.host, 4);
    MQ_CHECK_EQ_INT(h.dst.port, 53);
}

static void
test_build_udp_hdr_ipv6_roundtrip(void)
{
    mq_socks5_req_t src;
    src.atype = MQ_ADDR_IPV6;
    src.host_len = 16;
    for (int i = 0; i < 16; i++)
        src.host[i] = (uint8_t)i;
    src.port = 12345;

    uint8_t buf[64];
    int n = mq_socks5_build_udp_hdr(buf, sizeof buf, &src);
    MQ_CHECK_EQ_INT(n, 22); /* RSV(2)+FRAG(1)+ATYP(1)+IPv6(16)+PORT(2) */

    mq_socks5_udp_hdr_t h;
    int n2 = mq_socks5_parse_udp_hdr(buf, (size_t)n, &h);
    MQ_CHECK_EQ_INT(n2, n);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT(h.dst.host_len, 16);
    MQ_CHECK_MEM(h.dst.host, src.host, 16);
    MQ_CHECK_EQ_INT(h.dst.port, 12345);
}

static void
test_build_udp_hdr_domain_roundtrip(void)
{
    mq_socks5_req_t src;
    src.atype = MQ_ADDR_DOMAIN;
    src.host_len = 7;
    memcpy(src.host, "foo.bar", 7);
    src.port = 8080;

    uint8_t buf[64];
    int n = mq_socks5_build_udp_hdr(buf, sizeof buf, &src);
    MQ_CHECK_EQ_INT(n, 14); /* RSV(2)+FRAG(1)+ATYP(1)+LEN(1)+7+PORT(2) */

    mq_socks5_udp_hdr_t h;
    int n2 = mq_socks5_parse_udp_hdr(buf, (size_t)n, &h);
    MQ_CHECK_EQ_INT(n2, n);
    MQ_CHECK_EQ_INT(h.dst.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(h.dst.host_len, 7);
    MQ_CHECK_MEM(h.dst.host, "foo.bar", 7);
    MQ_CHECK_EQ_INT(h.dst.port, 8080);
}

static void
test_build_udp_hdr_cap_too_small(void)
{
    mq_socks5_req_t src;
    src.atype = MQ_ADDR_IPV4;
    src.host_len = 4;
    src.host[0] = 1;
    src.host[1] = 2;
    src.host[2] = 3;
    src.host[3] = 4;
    src.port = 80;

    uint8_t buf[9]; /* need 10, have 9 */
    int n = mq_socks5_build_udp_hdr(buf, sizeof buf, &src);
    MQ_CHECK_EQ_INT(n, -1);
}

/* check RSV=0 and FRAG=0 in built header */
static void
test_build_udp_hdr_rsv_frag_zero(void)
{
    mq_socks5_req_t src;
    src.atype = MQ_ADDR_IPV4;
    src.host_len = 4;
    src.host[0] = 0;
    src.host[1] = 0;
    src.host[2] = 0;
    src.host[3] = 0;
    src.port = 0;

    uint8_t buf[16];
    int n = mq_socks5_build_udp_hdr(buf, sizeof buf, &src);
    MQ_CHECK_EQ_INT(n, 10);
    MQ_CHECK_EQ_INT(buf[0], 0x00); /* RSV high */
    MQ_CHECK_EQ_INT(buf[1], 0x00); /* RSV low */
    MQ_CHECK_EQ_INT(buf[2], 0x00); /* FRAG */
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
    /* ASSOCIATE parse */
    test_associate_ipv4_zero_dst();
    test_associate_ipv4_dst();
    test_associate_domain_dst();
    test_associate_ipv6_dst();
    test_request_bind_still_unsupported();
    /* ASSOCIATE reply */
    test_associate_reply_zero();
    test_associate_reply_with_addr();
    test_connect_reply_unchanged();
    /* UDP encapsulation header parse */
    test_parse_udp_hdr_ipv4();
    test_parse_udp_hdr_ipv6();
    test_parse_udp_hdr_domain();
    test_parse_udp_hdr_frag_nonzero();
    test_parse_udp_hdr_rsv_nonzero();
    test_parse_udp_hdr_rsv_high_nonzero();
    test_parse_udp_hdr_truncation_sweep_ipv4();
    test_parse_udp_hdr_truncation_sweep_domain();
    test_parse_udp_hdr_truncation_sweep_ipv6();
    test_parse_udp_hdr_bad_atyp();
    /* build_udp_hdr */
    test_build_udp_hdr_ipv4_roundtrip();
    test_build_udp_hdr_ipv6_roundtrip();
    test_build_udp_hdr_domain_roundtrip();
    test_build_udp_hdr_cap_too_small();
    test_build_udp_hdr_rsv_frag_zero();
})
