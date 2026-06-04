// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_gw_server.c — integration tests for mq_origin_curl (Task 4.2), the
 * libcurl-multi origin client wired into a libevent loop. An in-process libevent
 * evhttp server stands in for the upstream origin over plain loopback HTTP/1.1;
 * the mq_origin_* API drives requests against it on the SAME event_base.
 *
 * Origin routes (127.0.0.1:0, ephemeral):
 *   GET  /blob  → 200, N bytes of a deterministic pattern + x-origin-tag header
 *   GET  /slow  → 200 (empty) after a 300ms evtimer (lets a request be aborted
 *                 in-flight before the reply arrives)
 *   PUT  /up    → drain the request body, reply 200 with body "len=<n>"
 *   (default)   → 404
 *
 * Cases:
 *   1. GET 1 MiB: on_status 200 once; x-origin-tag via on_header; on_body total
 *      == 1 MiB byte-exact; on_done CURLE_OK, http_ver = HTTP/1.1.
 *   2. download PAUSE/resume: on_body accepts 0 after the first chunk → no
 *      further on_body until mq_origin_resume_body; then byte-exact + OK.
 *   3. upload PUT 256 KiB via pull_body (16 KiB chunks, PAUSE once mid-way then
 *      resume via mq_origin_resume_pull): origin replies "len=262144"; on_done OK.
 *   4. NXDOMAIN → on_done CURLE_COULDNT_RESOLVE_HOST (== MQ_GW_CURL_RESOLVE).
 *   5. connection refused → on_done CURLE_COULDNT_CONNECT (== MQ_GW_CURL_CONNECT).
 *   6. abort mid-flight (GET /slow, abort before reply): no on_done, no crash.
 *   7. 1xx skip: evhttp can't easily emit a 100-continue, so we unit-test the
 *      factored status-line parser (mq_origin_parse_status_line) directly with
 *      synthetic 1xx/final lines. Expect: suppression keeps 100s off the wire in
 *      practice; see the design note in mq_origin_curl.c header_cb.
 *
 * The event loop is pumped non-blocking with millisecond deadlines, like the
 * other integration tests.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <curl/curl.h> /* CURL_HTTP_VERSION_1_1 for the on_done http_ver assert */
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include "gateway/mq_gw_headers.h" /* MQ_GW_CURL_* mirrors */
#include "gateway/mq_origin_curl.h"

/* ── timing helpers (mirror the other integration tests) ────────────────────*/
static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Pump the base non-blocking until *flag != 0 or the budget elapses. Returns the
 * final flag value. */
static int
pump_until(struct event_base *base, const volatile int *flag, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (!*flag && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    return *flag;
}

static void
pump_a_bit(struct event_base *base, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (now_ms() < deadline)
        event_base_loop(base, EVLOOP_NONBLOCK);
}

/* ── deterministic blob pattern ─────────────────────────────────────────────*/
static uint8_t
pat_byte(size_t i)
{
    return (uint8_t)((i * 131u + 7u) & 0xff);
}

/* ── in-process evhttp origin ───────────────────────────────────────────────*/
typedef struct {
    struct evhttp *http;
    uint16_t port;
    size_t blob_len; /* size served by GET /blob */
} origin_t;

static void
origin_cb_blob(struct evhttp_request *req, void *arg)
{
    origin_t *o = (origin_t *)arg;
    struct evbuffer *out = evbuffer_new();
    for (size_t i = 0; i < o->blob_len; i++) {
        uint8_t b = pat_byte(i);
        evbuffer_add(out, &b, 1);
    }
    evhttp_add_header(evhttp_request_get_output_headers(req), "x-origin-tag", "blobby");
    evhttp_send_reply(req, 200, "OK", out);
    evbuffer_free(out);
}

/* GET /slow: reply after a 300ms timer (so a request can be aborted first). */
typedef struct {
    struct evhttp_request *req;
    struct event *timer;
} slow_ctx_t;

static void
slow_fire(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    slow_ctx_t *sc = (slow_ctx_t *)arg;
    struct evbuffer *out = evbuffer_new();
    evhttp_send_reply(sc->req, 200, "OK", out);
    evbuffer_free(out);
    event_free(sc->timer);
    free(sc);
}

static struct event_base *g_origin_base; /* for arming the slow timer */

static void
origin_cb_slow(struct evhttp_request *req, void *arg)
{
    (void)arg;
    slow_ctx_t *sc = (slow_ctx_t *)calloc(1, sizeof(*sc));
    sc->req = req;
    struct timeval tv = {0, 300 * 1000};
    sc->timer = evtimer_new(g_origin_base, slow_fire, sc);
    evtimer_add(sc->timer, &tv);
}

/* PUT /up: drain the request body, reply 200 with "len=<n>". */
static void
origin_cb_up(struct evhttp_request *req, void *arg)
{
    (void)arg;
    struct evbuffer *in = evhttp_request_get_input_buffer(req);
    size_t n = in ? evbuffer_get_length(in) : 0;
    if (in) evbuffer_drain(in, n);
    char body[64];
    int bn = snprintf(body, sizeof(body), "len=%zu", n);
    struct evbuffer *out = evbuffer_new();
    evbuffer_add(out, body, (size_t)bn);
    evhttp_send_reply(req, 200, "OK", out);
    evbuffer_free(out);
}

static void
origin_cb_404(struct evhttp_request *req, void *arg)
{
    (void)arg;
    evhttp_send_reply(req, 404, "Not Found", NULL);
}

static int
origin_up(struct event_base *base, origin_t *o, size_t blob_len)
{
    memset(o, 0, sizeof(*o));
    o->blob_len = blob_len;
    o->http = evhttp_new(base);
    if (!o->http) return -1;
    g_origin_base = base;
    evhttp_set_cb(o->http, "/blob", origin_cb_blob, o);
    evhttp_set_cb(o->http, "/slow", origin_cb_slow, o);
    evhttp_set_cb(o->http, "/up", origin_cb_up, o);
    evhttp_set_gencb(o->http, origin_cb_404, o);

    struct evhttp_bound_socket *bs =
        evhttp_bind_socket_with_handle(o->http, "127.0.0.1", 0);
    if (!bs) return -1;
    evutil_socket_t fd = evhttp_bound_socket_get_fd(bs);
    struct sockaddr_storage ss;
    ev_socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) != 0) return -1;
    o->port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
    return o->port ? 0 : -1;
}

static void
origin_down(origin_t *o)
{
    if (o->http) evhttp_free(o->http);
    o->http = NULL;
}

/* ── shared per-request capture ─────────────────────────────────────────────*/
typedef struct {
    int status;
    int status_calls;
    int saw_tag; /* x-origin-tag observed via on_header */

    uint8_t *body;
    size_t body_cap;
    size_t body_len;
    int body_calls;

    /* download pause control */
    int pause_dl_once; /* return 0 from the next on_body, then clear */
    int dl_paused;     /* set when we requested a pause */

    /* upload source */
    const uint8_t *up_src;
    size_t up_total;
    size_t up_sent;
    int pause_ul_at;      /* byte offset at which to pause once (0 = never) */
    int ul_paused;        /* set when we requested an upload pause */
    mq_origin_req_t *req; /* so callbacks can request a resume */

    int done;
    int done_result;
    long done_http_ver;
} cap_t;

static void
cap_on_status(int status, void *u)
{
    cap_t *c = (cap_t *)u;
    c->status = status;
    c->status_calls++;
}

static void
cap_on_header(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    cap_t *c = (cap_t *)u;
    if (nl == strlen("x-origin-tag") && strncasecmp(n, "x-origin-tag", nl) == 0 &&
        vl == strlen("blobby") && memcmp(v, "blobby", vl) == 0) {
        c->saw_tag = 1;
    }
}

static long
cap_on_body(const uint8_t *p, size_t len, void *u)
{
    cap_t *c = (cap_t *)u;
    if (c->pause_dl_once) {
        c->pause_dl_once = 0;
        c->dl_paused = 1;
        return 0; /* accept nothing → PAUSE */
    }
    if (c->body_len + len <= c->body_cap) {
        memcpy(c->body + c->body_len, p, len);
    }
    c->body_len += len;
    c->body_calls++;
    return (long)len; /* accept all */
}

static long
cap_pull_body(uint8_t *buf, size_t cap, void *u)
{
    cap_t *c = (cap_t *)u;
    if (c->up_sent >= c->up_total) return -1; /* EOF */
    /* Pause once when we cross the configured offset. */
    if (c->pause_ul_at > 0 && (int)c->up_sent >= c->pause_ul_at) {
        c->pause_ul_at = 0; /* one-shot */
        c->ul_paused = 1;
        return 0; /* PAUSE */
    }
    size_t want = c->up_total - c->up_sent;
    size_t chunk = 16 * 1024;
    if (want > chunk) want = chunk;
    if (want > cap) want = cap;
    memcpy(buf, c->up_src + c->up_sent, want);
    c->up_sent += want;
    return (long)want;
}

static void
cap_on_done(int result, long http_ver, void *u)
{
    cap_t *c = (cap_t *)u;
    c->done = 1;
    c->done_result = result;
    c->done_http_ver = http_ver;
}

static mq_origin_cbs_t
cap_cbs(void)
{
    mq_origin_cbs_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.on_status = cap_on_status;
    cbs.on_header = cap_on_header;
    cbs.on_body = cap_on_body;
    cbs.pull_body = cap_pull_body;
    cbs.on_done = cap_on_done;
    return cbs;
}

static void
cap_init(cap_t *c, size_t body_cap)
{
    memset(c, 0, sizeof(*c));
    if (body_cap) {
        c->body = malloc(body_cap);
        c->body_cap = body_cap;
    }
}

static void
cap_free(cap_t *c)
{
    free(c->body);
    c->body = NULL;
}

static char *
make_url(uint16_t port, const char *path)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "http://127.0.0.1:%u%s", (unsigned)port, path);
    return buf;
}

/* ── Case 1: GET 1 MiB byte-exact ───────────────────────────────────────────*/
static void
test_get_blob(struct event_base *base)
{
    const size_t N = 1024 * 1024;
    origin_t o;
    MQ_CHECK(origin_up(base, &o, N) == 0);

    mq_origin_t *org = mq_origin_new(base, NULL, 10);
    MQ_CHECK(org != NULL);

    cap_t c;
    cap_init(&c, N);
    mq_origin_cbs_t cbs = cap_cbs();
    mq_origin_req_t *r =
        mq_origin_start(org, make_url(o.port, "/blob"), "GET", NULL, 0, -1, &cbs, &c);
    MQ_CHECK(r != NULL);

    pump_until(base, &c.done, 10000);
    MQ_CHECK_EQ_INT(c.done, 1);
    MQ_CHECK_EQ_INT(c.done_result, 0); /* CURLE_OK */
    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK_EQ_INT(c.status_calls, 1);
    MQ_CHECK_EQ_INT(c.saw_tag, 1);
    MQ_CHECK_EQ_INT((long long)c.body_len, (long long)N);
    MQ_CHECK_EQ_INT(c.done_http_ver, CURL_HTTP_VERSION_1_1);

    /* Byte-exact pattern check. */
    int ok = 1;
    for (size_t i = 0; i < N && ok; i++)
        if (c.body[i] != pat_byte(i)) ok = 0;
    MQ_CHECK(ok);

    mq_origin_free(org);
    origin_down(&o);
    cap_free(&c);
}

/* ── Case 2: download PAUSE / resume ────────────────────────────────────────*/
static void
test_download_pause(struct event_base *base)
{
    const size_t N = 512 * 1024;
    origin_t o;
    MQ_CHECK(origin_up(base, &o, N) == 0);

    mq_origin_t *org = mq_origin_new(base, NULL, 10);
    MQ_CHECK(org != NULL);

    cap_t c;
    cap_init(&c, N);
    c.pause_dl_once = 1;
    mq_origin_cbs_t cbs = cap_cbs();
    mq_origin_req_t *r =
        mq_origin_start(org, make_url(o.port, "/blob"), "GET", NULL, 0, -1, &cbs, &c);
    MQ_CHECK(r != NULL);

    /* Pump until the pause fires (first on_body returns 0). */
    pump_until(base, &c.dl_paused, 5000);
    MQ_CHECK_EQ_INT(c.dl_paused, 1);
    MQ_CHECK_EQ_INT(c.done, 0); /* not finished while paused */

    /* While paused, no further on_body / no completion even after pumping. */
    int calls_at_pause = c.body_calls;
    size_t len_at_pause = c.body_len;
    pump_a_bit(base, 200);
    MQ_CHECK_EQ_INT(c.body_calls, calls_at_pause);
    MQ_CHECK_EQ_INT((long long)c.body_len, (long long)len_at_pause);
    MQ_CHECK_EQ_INT(c.done, 0);

    /* Resume → completes byte-exact. */
    mq_origin_resume_body(r);
    pump_until(base, &c.done, 10000);
    MQ_CHECK_EQ_INT(c.done, 1);
    MQ_CHECK_EQ_INT(c.done_result, 0);
    MQ_CHECK_EQ_INT((long long)c.body_len, (long long)N);
    int ok = 1;
    for (size_t i = 0; i < N && ok; i++)
        if (c.body[i] != pat_byte(i)) ok = 0;
    MQ_CHECK(ok);

    mq_origin_free(org);
    origin_down(&o);
    cap_free(&c);
}

/* ── Case 3: upload PUT 256 KiB with pull-side PAUSE / resume ────────────────*/
static void
test_upload_pause(struct event_base *base)
{
    const size_t N = 256 * 1024;
    origin_t o;
    MQ_CHECK(origin_up(base, &o, 0) == 0);

    mq_origin_t *org = mq_origin_new(base, NULL, 10);
    MQ_CHECK(org != NULL);

    uint8_t *src = malloc(N);
    for (size_t i = 0; i < N; i++)
        src[i] = pat_byte(i);

    cap_t c;
    cap_init(&c, 256); /* small body buffer: reply is just "len=262144" */
    c.up_src = src;
    c.up_total = N;
    c.pause_ul_at = 128 * 1024; /* pause once around the midpoint */
    mq_origin_cbs_t cbs = cap_cbs();
    mq_origin_req_t *r = mq_origin_start(org, make_url(o.port, "/up"), "PUT", NULL, 0,
                                         (int64_t)N, &cbs, &c);
    MQ_CHECK(r != NULL);
    c.req = r;

    /* Pump until the upload pause fires. */
    pump_until(base, &c.ul_paused, 5000);
    MQ_CHECK_EQ_INT(c.ul_paused, 1);
    MQ_CHECK_EQ_INT(c.done, 0);
    size_t sent_at_pause = c.up_sent;
    MQ_CHECK(sent_at_pause >= (size_t)(128 * 1024));
    MQ_CHECK(sent_at_pause < N); /* not all sent yet */

    /* Resume the upload → completes. */
    mq_origin_resume_pull(r);
    pump_until(base, &c.done, 10000);
    MQ_CHECK_EQ_INT(c.done, 1);
    MQ_CHECK_EQ_INT(c.done_result, 0);
    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK_EQ_INT((long long)c.up_sent, (long long)N);
    /* Origin echoes the received length. */
    c.body[c.body_len < c.body_cap ? c.body_len : c.body_cap - 1] = '\0';
    MQ_CHECK(strstr((char *)c.body, "len=262144") != NULL);

    mq_origin_free(org);
    origin_down(&o);
    cap_free(&c);
    free(src);
}

/* ── Case 4: NXDOMAIN → CURLE_COULDNT_RESOLVE_HOST ──────────────────────────*/
static void
test_nxdomain(struct event_base *base)
{
    mq_origin_t *org = mq_origin_new(base, NULL, 5);
    MQ_CHECK(org != NULL);

    cap_t c;
    cap_init(&c, 0);
    mq_origin_cbs_t cbs = cap_cbs();
    mq_origin_req_t *r = mq_origin_start(org, "http://nxdomain-mqproxy-test.invalid/",
                                         "GET", NULL, 0, -1, &cbs, &c);
    MQ_CHECK(r != NULL);

    pump_until(base, &c.done, 10000);
    MQ_CHECK_EQ_INT(c.done, 1);
    MQ_CHECK_EQ_INT(c.done_result, MQ_GW_CURL_RESOLVE); /* CURLE_COULDNT_RESOLVE_HOST */

    mq_origin_free(org);
    cap_free(&c);
}

/* ── Case 5: connection refused → CURLE_COULDNT_CONNECT ─────────────────────*/
static void
test_conn_refused(struct event_base *base)
{
    mq_origin_t *org = mq_origin_new(base, NULL, 5);
    MQ_CHECK(org != NULL);

    cap_t c;
    cap_init(&c, 0);
    mq_origin_cbs_t cbs = cap_cbs();
    /* Port 1 on loopback: nothing listens → ECONNREFUSED. */
    mq_origin_req_t *r =
        mq_origin_start(org, "http://127.0.0.1:1/", "GET", NULL, 0, -1, &cbs, &c);
    MQ_CHECK(r != NULL);

    pump_until(base, &c.done, 10000);
    MQ_CHECK_EQ_INT(c.done, 1);
    /* Mirror constant: refused surfaces as CURLE_COULDNT_CONNECT (7). */
    MQ_CHECK_EQ_INT(c.done_result, MQ_GW_CURL_CONNECT);

    mq_origin_free(org);
    cap_free(&c);
}

/* ── Case 6: abort mid-flight (no on_done, no crash) ────────────────────────*/
static void
test_abort_midflight(struct event_base *base)
{
    origin_t o;
    MQ_CHECK(origin_up(base, &o, 0) == 0);

    mq_origin_t *org = mq_origin_new(base, NULL, 10);
    MQ_CHECK(org != NULL);

    cap_t c;
    cap_init(&c, 0);
    mq_origin_cbs_t cbs = cap_cbs();
    mq_origin_req_t *r =
        mq_origin_start(org, make_url(o.port, "/slow"), "GET", NULL, 0, -1, &cbs, &c);
    MQ_CHECK(r != NULL);

    /* Let the request connect + send, but abort before the 300ms reply timer. */
    pump_a_bit(base, 80);
    MQ_CHECK_EQ_INT(c.done, 0); /* reply not yet sent */
    mq_origin_abort(r);

    /* Pump well past the origin's reply timer: on_done must NOT fire and the
     * loop must drain cleanly (no crash / UAF — verified under ASan). */
    pump_a_bit(base, 500);
    MQ_CHECK_EQ_INT(c.done, 0);

    mq_origin_free(org);
    origin_down(&o);
    cap_free(&c);
}

/* ── Case 7: 1xx-skip parser (status-line parsing, unit) ────────────────────*/
static void
test_status_line_parser(void)
{
    /* Final-status lines. */
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.1 200 OK", 15), 200);
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.0 404 Not Found", 22), 404);
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/2 503", 10), 503);
    /* 1xx lines parse to a 1xx code (header_cb routes these into the skip path). */
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.1 100 Continue", 21), 100);
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.1 103 Early Hints", 24), 103);
    /* Non-status (field) lines → -1. */
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("Content-Length: 5", 17), -1);
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("x-origin-tag: blobby", 20), -1);
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.1 ", 9), -1);      /* no code */
    MQ_CHECK_EQ_INT(mq_origin_parse_status_line("HTTP/1.1 99 x", 13), -1); /* <100 */
}

int
main(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return 1;

    test_get_blob(base);
    test_download_pause(base);
    test_upload_pause(base);
    test_nxdomain(base);
    test_conn_refused(base);
    test_abort_midflight(base);
    test_status_line_parser();

    event_base_free(base);

    if (mq_test_failures) {
        fprintf(stderr, "%d failure(s)\n", mq_test_failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
