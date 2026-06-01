#include "ingress/mq_http_connect.h"
#include "mqtest.h"
#include <arpa/inet.h>
#include <string.h>

/* ---- request fixtures ---- */
static const char REQ_DOMAIN[] =
    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
static const char REQ_IPV6[] = "CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n";
static const char REQ_IPV4[] = "CONNECT 93.184.216.34:80 HTTP/1.1\r\n\r\n";
static const char REQ_NOTERM[] = "CONNECT example.com:443 HTTP/1.1\r\n";
static const char REQ_GET[] = "GET / HTTP/1.1\r\n\r\n";
static const char REQ_NOPORT[] = "CONNECT example.com HTTP/1.1\r\n\r\n";

static void
test_domain(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st = mq_http_connect_parse((const uint8_t *)REQ_DOMAIN,
                                                strlen(REQ_DOMAIN), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(out.host_len, 11);
    MQ_CHECK_MEM(out.host, "example.com", 11);
    MQ_CHECK_EQ_INT(out.port, 443);
    MQ_CHECK_EQ_INT(hlen, strlen(REQ_DOMAIN));
}

static void
test_ipv6(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st =
        mq_http_connect_parse((const uint8_t *)REQ_IPV6, strlen(REQ_IPV6), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT(out.host_len, 16);
    MQ_CHECK_EQ_INT(out.port, 443);

    uint8_t expect[16];
    MQ_CHECK_EQ_INT(inet_pton(AF_INET6, "2001:db8::1", expect), 1);
    MQ_CHECK_MEM(out.host, expect, 16);
}

static void
test_ipv4(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st =
        mq_http_connect_parse((const uint8_t *)REQ_IPV4, strlen(REQ_IPV4), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(out.host_len, 4);
    static const uint8_t expect[4] = {93, 184, 216, 34};
    MQ_CHECK_MEM(out.host, expect, 4);
    MQ_CHECK_EQ_INT(out.port, 80);
}

static void
test_fragmented(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st = mq_http_connect_parse((const uint8_t *)REQ_NOTERM,
                                                strlen(REQ_NOTERM), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_NEED_MORE);

    st = mq_http_connect_parse((const uint8_t *)REQ_DOMAIN, strlen(REQ_DOMAIN), &out,
                               &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.port, 443);
}

static void
test_unsupported(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st =
        mq_http_connect_parse((const uint8_t *)REQ_GET, strlen(REQ_GET), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_UNSUPPORTED);
}

static void
test_missing_port(void)
{
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st = mq_http_connect_parse((const uint8_t *)REQ_NOPORT,
                                                strlen(REQ_NOPORT), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_BAD);
}

/* Fix #1 (TDD-RED): unclosed bracket must be BAD */
static void
test_unclosed_bracket(void)
{
    /* "[::1:443" — starts with '[' but closing ']' is absent */
    static const char req[] = "CONNECT [::1:443 HTTP/1.1\r\n\r\n";
    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st =
        mq_http_connect_parse((const uint8_t *)req, strlen(req), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_BAD);
}

/* Over-long domain: 256-char host > MQ_MAX_HOST=255 → BAD */
static void
test_overlong_domain(void)
{
    /* Build "CONNECT <256 a's>:443 HTTP/1.1\r\n\r\n" */
    char req[512];
    memset(req, 0, sizeof req);
    int n = snprintf(req, sizeof req, "CONNECT ");
    for (int i = 0; i < 256; i++)
        req[n++] = 'a';
    n += snprintf(req + n, sizeof req - (size_t)n, ":443 HTTP/1.1\r\n\r\n");

    mq_http_target_t out;
    memset(&out, 0, sizeof out);
    size_t hlen = 0;
    mq_http_status_t st =
        mq_http_connect_parse((const uint8_t *)req, (size_t)n, &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_BAD);
}

/* Port boundaries */
static void
test_port_boundaries(void)
{
    mq_http_target_t out;
    size_t hlen;
    mq_http_status_t st;

    /* :1 — minimum valid port → DONE */
    static const char req_min[] = "CONNECT example.com:1 HTTP/1.1\r\n\r\n";
    memset(&out, 0, sizeof out);
    hlen = 0;
    st = mq_http_connect_parse((const uint8_t *)req_min, strlen(req_min), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.port, 1);

    /* :65535 — maximum valid port → DONE */
    static const char req_max[] = "CONNECT example.com:65535 HTTP/1.1\r\n\r\n";
    memset(&out, 0, sizeof out);
    hlen = 0;
    st = mq_http_connect_parse((const uint8_t *)req_max, strlen(req_max), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_CONNECT_DONE);
    MQ_CHECK_EQ_INT(out.port, 65535);

    /* :65536 — invalid port → BAD */
    static const char req_over[] = "CONNECT example.com:65536 HTTP/1.1\r\n\r\n";
    memset(&out, 0, sizeof out);
    hlen = 0;
    st = mq_http_connect_parse((const uint8_t *)req_over, strlen(req_over), &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_BAD);

    /* empty port (host: before space) → BAD */
    static const char req_empty_port[] = "CONNECT example.com: HTTP/1.1\r\n\r\n";
    memset(&out, 0, sizeof out);
    hlen = 0;
    st = mq_http_connect_parse((const uint8_t *)req_empty_port, strlen(req_empty_port),
                               &out, &hlen);
    MQ_CHECK_EQ_INT(st, MQ_HTTP_BAD);
}

/* mq_http_build_200 with cap one byte too small → returns 0, writes nothing */
static void
test_build_200_too_small(void)
{
    static const char expect[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    size_t full = strlen(expect);
    char buf[64];
    memset(buf, 0xAB, sizeof buf); /* sentinel pattern */
    size_t n = mq_http_build_200(buf, full - 1);
    MQ_CHECK_EQ_INT(n, 0);
    /* No byte past cap should have been written — check the sentinel. */
    unsigned char sentinel = 0xAB;
    MQ_CHECK_EQ_INT((unsigned char)buf[0], sentinel);
}

/* mq_http_status_line(MQ_TCP_DNS_FAILED) must contain "502" */
static void
test_status_line_dns_failed(void)
{
    const char *line = mq_http_status_line(MQ_TCP_DNS_FAILED);
    MQ_CHECK(strstr(line, "502") != NULL);
}

static void
test_build_200(void)
{
    char buf[64];
    size_t n = mq_http_build_200(buf, sizeof buf);
    static const char expect[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    MQ_CHECK_EQ_INT(n, strlen(expect));
    MQ_CHECK_MEM(buf, expect, n);
}

static void
test_status_line(void)
{
    const char *line = mq_http_status_line(MQ_TCP_TIMEOUT);
    MQ_CHECK(strstr(line, "504") != NULL);
    MQ_CHECK(strstr(mq_http_status_line(MQ_TCP_POLICY_DENIED), "403") != NULL);
    MQ_CHECK(strstr(mq_http_status_line(MQ_TCP_CONN_REFUSED), "502") != NULL);
}

MQ_TEST_MAIN({
    test_domain();
    test_ipv6();
    test_ipv4();
    test_fragmented();
    test_unsupported();
    test_missing_port();
    test_unclosed_bracket();
    test_overlong_domain();
    test_port_boundaries();
    test_build_200();
    test_build_200_too_small();
    test_status_line();
    test_status_line_dns_failed();
})
