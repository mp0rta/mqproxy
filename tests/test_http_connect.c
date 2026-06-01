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
    test_build_200();
    test_status_line();
})
