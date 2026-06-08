#include "mqtest.h" /* MQ_CHECK / MQ_TEST_MAIN (NOT C assert — vacuous under -DNDEBUG) */
#include "gateway/mq_gw_metrics.h"

static mq_gw_req_metrics_t
base(void)
{
    mq_gw_req_metrics_t m = {
        .method = "GET",
        .status = 200,
        .authority = "example.com",
        .path = "/big.bin",
        .req_bytes = 0,
        .resp_bytes = 104857600,
        .ttfb_ms = 42,
        .duration_ms = 1200,
        .origin_protocol = "h2",
        .origin_tls = "ok",
        .cache = "bypass",
        .origin_reuse = 0,
        .mp_state = 1,
        .completion_ms = 1201,
        .reset_reason = "",
    };
    return m;
}

static void
test_clean(void)
{
    char buf[MQ_GW_REQ_LINE_CAP];
    mq_gw_req_metrics_t m = base();
    int n = mq_gw_format_req_line(buf, sizeof(buf), "ab12", 42, &m);
    MQ_CHECK(n > 0);
    MQ_CHECK(strstr(buf, "mq.req cid=ab12 sid=42 ") == buf);
    MQ_CHECK(strstr(buf, "method=GET status=200"));
    MQ_CHECK(strstr(buf, "authority=\"example.com\""));
    MQ_CHECK(strstr(buf, "path=\"/big.bin\""));
    MQ_CHECK(strstr(buf, "resp_bytes=104857600"));
    MQ_CHECK(strstr(buf, "ttfb_ms=42 duration_ms=1200"));
    MQ_CHECK(strstr(buf, "origin_protocol=h2 origin_tls=ok"));
    MQ_CHECK(strstr(buf, "cache=bypass origin_reuse=0"));
    MQ_CHECK(strstr(buf, "mp_state=1 completion_ms=1201"));
    MQ_CHECK(strstr(buf, "reset=\"\""));
}

static void
test_unknowns_and_reset(void)
{
    char buf[MQ_GW_REQ_LINE_CAP];
    mq_gw_req_metrics_t m = base();
    m.method = "-";
    m.status = 0;
    m.authority = "-";
    m.path = "-";
    m.ttfb_ms = -1;
    m.duration_ms = -1;
    m.completion_ms = -1;
    m.origin_protocol = "none";
    m.origin_tls = "connect_fail";
    m.reset_reason = "client-reset";
    int n = mq_gw_format_req_line(buf, sizeof(buf), "0", 7, &m);
    MQ_CHECK(n > 0);
    MQ_CHECK(strstr(buf, "ttfb_ms=-1 duration_ms=-1"));
    MQ_CHECK(strstr(buf, "reset=\"client-reset\""));
    MQ_CHECK(strstr(buf, "origin_tls=connect_fail"));
}

static void
test_quote_escape(void)
{
    char buf[MQ_GW_REQ_LINE_CAP];
    mq_gw_req_metrics_t m = base();
    m.path = "/a\"b"; /* embedded quote must be escaped */
    int n = mq_gw_format_req_line(buf, sizeof(buf), "0", 1, &m);
    MQ_CHECK(n > 0);
    MQ_CHECK(strstr(buf, "path=\"/a\\\"b\""));
}

static void
test_truncation(void)
{
    char buf[40]; /* far too small */
    mq_gw_req_metrics_t m = base();
    int n = mq_gw_format_req_line(buf, sizeof(buf), "ab12", 42, &m);
    MQ_CHECK(n == -1);
}

static void
test_path_cap(void)
{
    char buf[MQ_GW_REQ_LINE_CAP];
    char longpath[MQ_GW_REQ_PATH_CAP + 100];
    memset(longpath, 'x', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';
    mq_gw_req_metrics_t m = base();
    m.path = longpath;
    int n = mq_gw_format_req_line(buf, sizeof(buf), "0", 1, &m);
    MQ_CHECK(n > 0); /* capped, NOT truncated to -1 */
    MQ_CHECK(strstr(buf, "\xE2\x80\xA6") || strstr(buf, "...")); /* truncation marker */
}

MQ_TEST_MAIN({
    test_clean();
    test_unknowns_and_reset();
    test_quote_escape();
    test_truncation();
    test_path_cap();
})
