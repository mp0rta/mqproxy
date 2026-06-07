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
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <curl/curl.h> /* CURL_HTTP_VERSION_1_1 for the on_done http_ver assert */
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include "gateway/mq_gw_headers.h" /* MQ_GW_CURL_* mirrors */
#include "gateway/mq_gw_server.h"
#include "gateway/mq_origin_curl.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_h3.h"
#include "transport/mq_transport.h"

#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

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

    /* Captured request headers from the most recent /blob request (for the
     * gw_server forwarding asserts: NO x-mq-* reach the origin; custom header
     * forwarded). */
    int saw_xmq;            /* any x-mq-* request header seen */
    int saw_custom;         /* x-custom-hdr: keepme seen */
    char custom_val[64];    /* its value */
    int saw_content_length; /* content-length request header seen (upload tests) */
} origin_t;

/* Scan the request headers: flag any x-mq-*, capture x-custom-hdr, and note
 * whether a content-length header reached the origin (used by chunked-upload
 * assert to confirm the gw_server stripped it before forwarding). */
static void
origin_capture_req_hdrs(struct evhttp_request *req, origin_t *o)
{
    struct evkeyvalq *h = evhttp_request_get_input_headers(req);
    if (!h) return;
    struct evkeyval *kv;
    TAILQ_FOREACH(kv, h, next)
    {
        if (strncasecmp(kv->key, "x-mq-", 5) == 0) o->saw_xmq = 1;
        if (strcasecmp(kv->key, "x-custom-hdr") == 0) {
            o->saw_custom = 1;
            snprintf(o->custom_val, sizeof(o->custom_val), "%s", kv->value);
        }
        if (strcasecmp(kv->key, "content-length") == 0) o->saw_content_length = 1;
    }
}

static void
origin_cb_blob(struct evhttp_request *req, void *arg)
{
    origin_t *o = (origin_t *)arg;
    origin_capture_req_hdrs(req, o);
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

/* Outstanding /slow context so origin_down can free a still-pending timer (the
 * gw_server teardown case frees the fixture BEFORE the 300ms timer fires; without
 * this the slow_ctx + its timer would leak under LSan). Single-slot is enough —
 * these tests have at most one /slow request in flight. */
static slow_ctx_t *g_pending_slow;

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
    if (g_pending_slow == sc) g_pending_slow = NULL;
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
    g_pending_slow = sc;
}

/* PUT /up: drain the request body, reply 200 with "len=<n>". */
static void
origin_cb_up(struct evhttp_request *req, void *arg)
{
    origin_t *o = (origin_t *)arg;
    origin_capture_req_hdrs(req, o);
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

/* GET /bighdr: reply 200 with a pathologically large response header VALUE
 * (1500 bytes). Used to drive the gw_server's fail-closed path for an oversized
 * ORIGIN response header (>1023 = the per-request arena value slot). */
static void
origin_cb_bighdr(struct evhttp_request *req, void *arg)
{
    (void)arg;
    char big[1501];
    memset(big, 'B', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    evhttp_add_header(evhttp_request_get_output_headers(req), "x-origin-big", big);
    evhttp_send_reply(req, 200, "OK", NULL);
}

/* GET /manyhdr: reply 200 with 70 distinct small response headers (x-h-00 ..
 * x-h-69). Used to drive the gw_server's fail-closed path for a response
 * header-COUNT overflow (> MQ_GWS_MAX_HDRS = 64). */
static void
origin_cb_manyhdr(struct evhttp_request *req, void *arg)
{
    (void)arg;
    struct evkeyvalq *outh = evhttp_request_get_output_headers(req);
    for (int i = 0; i < 70; i++) {
        char name[16];
        snprintf(name, sizeof(name), "x-h-%02d", i);
        evhttp_add_header(outh, name, "v");
    }
    evhttp_send_reply(req, 200, "OK", NULL);
}

/* GET /boundary64: reply 200 with exactly MQ_GWS_MAX_HDRS(64) forwardable
 * headers followed by an x-mq-origin-protocol header.
 *
 * The 64 forwardable headers are composed of:
 *   3 explicitly pre-set standard headers that would otherwise be auto-added by
 *   evhttp (Date, Content-Length, Content-Type) — pre-setting them ensures they
 *   appear FIRST in the wire order, before the x-h-NN set, and prevents evhttp
 *   from appending duplicates.
 *   61 custom x-h-NN headers.
 * Together that is exactly 64 forwardable (non-hop-by-hop, non-x-mq-origin-
 * protocol) headers.  Then x-mq-origin-protocol: fake is added AFTER the 64.
 *
 * evhttp still appends "Connection: close" automatically; that header is in the
 * hop-by-hop strip list and is therefore not counted.
 *
 * Before the fix: origin_on_header checks the count (n_hdrs >= 64) BEFORE the
 * x-mq-origin-protocol drop, so the 65th call with x-mq-origin-protocol trips
 * hdrs_overflow = 1 → gateway returns 502 (false positive).
 * After the fix: x-mq-origin-protocol is dropped first; the 64 forwardable
 * headers fit exactly; gateway returns 200 with x-mq-origin-protocol set to
 * "http/1.1" (the gateway's own synthesis) and all 64 headers forwarded. */
static void
origin_cb_boundary64(struct evhttp_request *req, void *arg)
{
    (void)arg;
    struct evkeyvalq *outh = evhttp_request_get_output_headers(req);
    /* Pre-set the 3 headers evhttp would auto-add so they appear first and
     * are not duplicated; they count toward the 64 forwardable total. */
    evhttp_add_header(outh, "Date", "Thu, 01 Jan 2026 00:00:00 GMT");
    evhttp_add_header(outh, "Content-Length", "0");
    evhttp_add_header(outh, "Content-Type", "text/plain");
    /* 61 custom x-h-NN headers (3 + 61 = 64 forwardable total). */
    for (int i = 0; i < 61; i++) {
        char name[16];
        snprintf(name, sizeof(name), "x-h-%02d", i);
        evhttp_add_header(outh, name, "v");
    }
    /* This is the (would-be) 65th header in the current buggy order; it must be
     * dropped without being counted against the capacity. */
    evhttp_add_header(outh, "x-mq-origin-protocol", "fake");
    evhttp_send_reply(req, 200, "OK", NULL);
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
    evhttp_set_cb(o->http, "/bighdr", origin_cb_bighdr, o);
    evhttp_set_cb(o->http, "/manyhdr", origin_cb_manyhdr, o);
    evhttp_set_cb(o->http, "/boundary64", origin_cb_boundary64, o);
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
    /* Free a /slow timer that never fired (fixture torn down before the 300ms
     * reply). evhttp_free above already released the bound request, so only our
     * own ctx + timer remain. */
    if (g_pending_slow) {
        if (g_pending_slow->timer) event_free(g_pending_slow->timer);
        free(g_pending_slow);
        g_pending_slow = NULL;
    }
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

/* ════════════════════════════════════════════════════════════════════════════
 * Gateway SERVER (Task 4.3): H3 request → origin execution → H3 response.
 *
 * These stand up a REAL in-process H3 tunnel over loopback UDP plus the evhttp
 * origin (reused from above):
 *   - the gw_server under test: server transport (TLS) + runtime + mq_gw_server
 *     (which mq_h3_init's its own hooks). The evhttp origin is on the SAME base.
 *   - a fake H3 CLIENT: client transport + runtime + mq_h3 (NULL hooks) that
 *     opens an H3 request, forwards the pseudo-headers + x-mq-auth + arbitrary
 *     headers, optionally uploads a body, and captures the H3 response.
 * ════════════════════════════════════════════════════════════════════════════ */

/* Reserve an ephemeral loopback UDP port (bind :0, read it, close). */
static uint16_t
reserve_udp_port(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return 0;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        close(fd);
        return 0;
    }
    uint16_t port = ntohs(sa.sin_port);
    close(fd);
    return port;
}

/* ── client-side H3 response capture ────────────────────────────────────────*/

#define CLI_MAX_HDRS 32
#define CLI_HDR_LEN  512

typedef struct {
    char name[CLI_HDR_LEN];
    char value[CLI_HDR_LEN];
} cli_hdr_t;

typedef struct {
    mq_h3_req_t *req;

    /* response captured from the gw_server */
    int got_headers;
    int status; /* parsed :status */
    cli_hdr_t hdrs[CLI_MAX_HDRS];
    int n_hdrs;

    uint8_t *body;
    size_t body_cap;
    size_t body_len;
    int saw_fin;
    int closed;

    /* upload source (set before sending the request) */
    const uint8_t *up_src;
    size_t up_total;
    size_t up_sent;
    int up_fin_sent;

    /* control: reset the request once we have received `reset_after` body bytes */
    int reset_after; /* >0 = reset mid-download after this many bytes */
    int did_reset;
} cli_req_t;

static void
cli_capture_hdr(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    cli_req_t *c = (cli_req_t *)u;
    if (nl == 7 && memcmp(n, ":status", 7) == 0) {
        int code = 0;
        for (size_t i = 0; i < vl && v[i] >= '0' && v[i] <= '9'; i++)
            code = code * 10 + (v[i] - '0');
        c->status = code;
        return;
    }
    if (c->n_hdrs >= CLI_MAX_HDRS) return;
    cli_hdr_t *h = &c->hdrs[c->n_hdrs++];
    size_t cn = nl < CLI_HDR_LEN - 1 ? nl : CLI_HDR_LEN - 1;
    size_t cv = vl < CLI_HDR_LEN - 1 ? vl : CLI_HDR_LEN - 1;
    memcpy(h->name, n, cn);
    h->name[cn] = '\0';
    memcpy(h->value, v, cv);
    h->value[cv] = '\0';
}

static const char *
cli_find_hdr(const cli_req_t *c, const char *name)
{
    for (int i = 0; i < c->n_hdrs; i++)
        if (strcasecmp(c->hdrs[i].name, name) == 0) return c->hdrs[i].value;
    return NULL;
}

/* Push as much of the pending upload as xquic accepts, riding fin on the last
 * byte; EAGAIN remainder retried from cli_on_write. */
static void
cli_upload_pump(cli_req_t *c)
{
    if (!c->req || c->up_fin_sent) return;
    while (c->up_sent < c->up_total) {
        long acc = mq_h3_req_send_body(c->req, c->up_src + c->up_sent,
                                       c->up_total - c->up_sent, /*fin=*/1);
        if (acc <= 0) return; /* EAGAIN: resume on next on_write */
        c->up_sent += (size_t)acc;
        if (c->up_sent >= c->up_total) {
            c->up_fin_sent = 1;
            return;
        }
    }
    if (c->up_total == 0) {
        mq_h3_req_finish(c->req);
        c->up_fin_sent = 1;
    }
}

static void
cli_on_read(mq_h3_req_t *r, int flag, void *user)
{
    cli_req_t *c = (cli_req_t *)user;
    if (flag & (XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_TRAILER)) {
        int fin = 0;
        int n = mq_h3_req_recv_headers(r, cli_capture_hdr, c, &fin);
        if (n >= 0) c->got_headers = 1;
        if (fin) c->saw_fin = 1;
    }
    for (;;) {
        int fin = 0;
        size_t room = c->body_cap > c->body_len ? c->body_cap - c->body_len : 0;
        uint8_t scratch[4096];
        uint8_t *dst = c->body ? c->body + c->body_len : scratch;
        size_t cap = c->body ? room : sizeof(scratch);
        if (cap == 0) {
            dst = scratch;
            cap = sizeof(scratch);
        }
        long n = mq_h3_req_recv_body(r, dst, cap, &fin);
        if (n > 0 && c->body && room > 0)
            c->body_len += ((size_t)n < room ? (size_t)n : room);
        if (fin) c->saw_fin = 1;
        /* Mid-download reset trigger (case 7). */
        if (c->reset_after > 0 && !c->did_reset &&
            c->body_len >= (size_t)c->reset_after) {
            c->did_reset = 1;
            mq_h3_req_reset(c->req);
            c->req = NULL;
            return;
        }
        if (n <= 0) break;
    }
}

static void
cli_on_write(mq_h3_req_t *r, void *user)
{
    (void)r;
    cli_req_t *c = (cli_req_t *)user;
    cli_upload_pump(c);
}

static void
cli_on_close(mq_h3_req_t *r, void *user)
{
    (void)r;
    cli_req_t *c = (cli_req_t *)user;
    c->closed = 1;
    c->req = NULL;
}

/* ── gw_server fixture ──────────────────────────────────────────────────────*/

typedef struct {
    struct event_base *base;
    origin_t origin;
    mq_transport_t *srv_t;
    mq_runtime_t *srv_rt;
    mq_gw_server_t *gw;

    mq_transport_t *cli_t;
    mq_runtime_t *cli_rt;
    mq_h3_t *cli_h3;
    mq_h3_conn_t *cli_conn;
    int cli_conn_up;
} gws_fixture_t;

static void
gws_cli_conn_state(mq_h3_conn_t *cn, int established, void *user)
{
    (void)cn;
    gws_fixture_t *f = (gws_fixture_t *)user;
    if (established)
        f->cli_conn_up = 1;
    else
        f->cli_conn_up = 0;
}

static int
gws_fixture_up(gws_fixture_t *f, const char *token, size_t blob_len)
{
    memset(f, 0, sizeof(*f));

    f->base = event_base_new();
    if (!f->base) return -1;

    /* evhttp origin on the shared base. */
    if (origin_up(f->base, &f->origin, blob_len) != 0) return -1;

    uint16_t srv_port = reserve_udp_port();
    if (!srv_port) return -1;

    /* Server transport + runtime + gw_server (mq_h3_init done inside gw_server). */
    f->srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    if (!f->srv_t) return -1;
    f->srv_rt = mq_runtime_new(f->srv_t, f->base);
    if (!f->srv_rt) return -1;

    xqc_conn_settings_t srv_settings;
    memset(&srv_settings, 0, sizeof(srv_settings));
    srv_settings.proto_version = XQC_VERSION_V1;
    srv_settings.pacing_on = 1;
    mq_conn_apply_mp_settings(&srv_settings, /*is_server=*/1, MQ_CC_BBR2);
    xqc_server_set_conn_settings(mq_transport_xqc(f->srv_t), &srv_settings);

    f->gw = mq_gw_server_new(f->srv_t, f->srv_rt, token, NULL, 10);
    if (!f->gw) return -1;
    if (mq_runtime_open_udp_path(f->srv_rt, "127.0.0.1", srv_port) != 0) return -1;

    /* Client transport + runtime + h3 (pure client). */
    f->cli_t = mq_transport_new(0);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    if (!f->cli_rt) return -1;
    if (mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0) != 0) return -1;
    f->cli_h3 = mq_h3_init(f->cli_t, NULL, NULL, NULL);
    if (!f->cli_h3) return -1;

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(srv_port);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
    f->cli_conn =
        mq_h3_connect(f->cli_h3, (struct sockaddr *)&peer, sizeof(peer), MQ_CC_BBR2,
                      /*keepalive_idle_ms=*/0, gws_cli_conn_state, f);
    if (!f->cli_conn) return -1;

    /* Pump until the client conn is established. */
    uint64_t deadline = now_ms() + 5000;
    while (!f->cli_conn_up && now_ms() < deadline)
        event_base_loop(f->base, EVLOOP_NONBLOCK);
    return f->cli_conn_up ? 0 : -1;
}

static void
gws_fixture_down(gws_fixture_t *f)
{
    /* SANCTIONED TEARDOWN ORDER (mq_gw_server.h): capture the server h3 BEFORE
     * gw_server_free (the accessor reads the freed struct otherwise), then
     * gw_server_free FIRST (aborts in-flight origin + detaches H3 cbs against the
     * LIVE engine), THEN mq_h3_free (both sides), THEN transport_free. */
    mq_h3_t *srv_h3 = mq_gw_server_h3(f->gw);
    if (f->gw) mq_gw_server_free(f->gw);
    if (f->cli_h3) mq_h3_free(f->cli_h3);
    if (srv_h3) mq_h3_free(srv_h3);
    if (f->cli_t) mq_transport_free(f->cli_t);
    if (f->srv_t) mq_transport_free(f->srv_t);
    if (f->cli_rt) mq_runtime_free(f->cli_rt);
    if (f->srv_rt) mq_runtime_free(f->srv_rt);
    origin_down(&f->origin);
    if (f->base) event_base_free(f->base);
}

/* Open + send an H3 request at the gw_server. `extra` headers are appended after
 * the standard pseudo+auth set. Returns 0 on success (request open + headers
 * sent). The caller wires cli cbs first via the returned cli_req. */
static int
gws_send_request(gws_fixture_t *f, cli_req_t *c, const char *method, const char *scheme,
                 const char *authority, const char *path, const char *auth,
                 const mq_h3_header_t *extra, size_t n_extra, int has_body,
                 const char *content_length)
{
    mq_h3_req_t *hr = mq_h3_req_open(f->cli_conn);
    if (!hr) return -1;
    c->req = hr;
    mq_h3_req_set_cbs(hr, cli_on_read, cli_on_write, cli_on_close, c);

    mq_h3_header_t hs[CLI_MAX_HDRS];
    size_t nh = 0;
    if (method) {
        hs[nh].name = ":method";
        hs[nh].value = method;
        nh++;
    }
    if (scheme) {
        hs[nh].name = ":scheme";
        hs[nh].value = scheme;
        nh++;
    }
    if (authority) {
        hs[nh].name = ":authority";
        hs[nh].value = authority;
        nh++;
    }
    if (path) {
        hs[nh].name = ":path";
        hs[nh].value = path;
        nh++;
    }
    if (auth) {
        hs[nh].name = "x-mq-auth";
        hs[nh].value = auth;
        nh++;
    }
    if (has_body && content_length) {
        hs[nh].name = "content-length";
        hs[nh].value = content_length;
        nh++;
    }
    for (size_t i = 0; i < n_extra && nh < CLI_MAX_HDRS; i++)
        hs[nh++] = extra[i];

    long sh = mq_h3_req_send_headers(hr, hs, nh, has_body ? 0 : 1);
    if (sh <= 0) return -1;
    if (has_body) cli_upload_pump(c);
    return 0;
}

/* Build an authority string "127.0.0.1:<port>". */
static const char *
origin_authority(const origin_t *o)
{
    static char buf[64];
    snprintf(buf, sizeof(buf), "127.0.0.1:%u", (unsigned)o->port);
    return buf;
}

/* ── gw_server Case 1: GET happy path ───────────────────────────────────────*/
static void
test_gws_get(void)
{
    const size_t N = 64 * 1024;
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", N) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(N);
    c.body_cap = N;

    mq_h3_header_t extra[] = {{"x-custom-hdr", "keepme"}};
    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/blob",
                              "Bearer sekrit", extra, 1, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 10000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK(c.got_headers);
    MQ_CHECK_EQ_INT((long long)c.body_len, (long long)N);
    /* Byte-exact vs the origin pattern. */
    int ok = 1;
    for (size_t i = 0; i < N && i < c.body_len && ok; i++)
        if (c.body[i] != pat_byte(i)) ok = 0;
    MQ_CHECK(ok);
    /* x-mq-origin-protocol present (origin is HTTP/1.1). */
    const char *prot = cli_find_hdr(&c, "x-mq-origin-protocol");
    MQ_CHECK(prot && strcmp(prot, "http/1.1") == 0);
    /* The origin saw NO x-mq-* headers, but DID see the forwarded custom header. */
    MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0);
    MQ_CHECK_EQ_INT(f.origin.saw_custom, 1);
    MQ_CHECK(strcmp(f.origin.custom_val, "keepme") == 0);
    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), 1);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 2: x-mq-class forwarded + logged (request completes) ─────*/
static void
test_gws_class(void)
{
    const size_t N = 4096;
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", N) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(N);
    c.body_cap = N;

    /* x-mq-class is stripped server-side before the origin; the gw logs it at
     * INFO (manual evidence in test output). We just assert the request
     * completes 200 and the origin saw NO x-mq-* (class included). */
    mq_h3_header_t extra[] = {{"x-mq-class", "bulk"}};
    printf("[case2] sending x-mq-class: bulk (expect an INFO log line from gw_server)\n");
    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/blob",
                              "Bearer sekrit", extra, 1, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 10000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK_EQ_INT((long long)c.body_len, (long long)N);
    MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0); /* x-mq-class did NOT reach the origin */
    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), 1);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 3: 403 on a wrong token (no origin contact) ─────────────*/
static void
test_gws_403(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));

    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/blob",
                              "Bearer WRONG", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 403);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "auth-failed") == 0);
    /* No origin contact: the origin never saw a request. */
    MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0);
    MQ_CHECK_EQ_INT(f.origin.saw_custom, 0);

    gws_fixture_down(&f);
}

/* ── gw_server Case 4: 400 on a missing :authority ──────────────────────────*/
static void
test_gws_400(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));

    /* Omit :authority (pass NULL). */
    int rc = gws_send_request(&f, &c, "GET", "http", NULL, "/blob", "Bearer sekrit", NULL,
                              0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 400);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "bad-request") == 0);
    MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0);

    gws_fixture_down(&f);
}

/* ── gw_server Case 4b: 400 on control bytes in a forwarded header / :path ───*/
static void
test_gws_bad_header(void)
{
    /* 4b-i: a forwarded header VALUE with a control byte (CR) → 400 bad-header. */
    {
        gws_fixture_t f;
        if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
            gws_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        mq_h3_header_t extra[] = {{"x-evil", "a\r\nInjected: 1"}};
        int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                                  "/blob", "Bearer sekrit", extra, 1, 0, NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 5000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        MQ_CHECK_EQ_INT(c.status, 400);
        const char *err = cli_find_hdr(&c, "x-mq-error");
        MQ_CHECK(err && strcmp(err, "bad-header") == 0);
        /* The request never reached the origin. */
        MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0);
        gws_fixture_down(&f);
    }
    /* 4b-ii: a :path with a control byte → 400 bad-target. */
    {
        gws_fixture_t f;
        if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
            gws_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                                  "/bl\tob", "Bearer sekrit", NULL, 0, 0, NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 5000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        MQ_CHECK_EQ_INT(c.status, 400);
        const char *err = cli_find_hdr(&c, "x-mq-error");
        MQ_CHECK(err && strcmp(err, "bad-target") == 0);
        gws_fixture_down(&f);
    }
}

/* ── gw_server Case 5: 502 on NXDOMAIN authority + on refused ───────────────*/
static void
test_gws_502(void)
{
    /* 5a: NXDOMAIN authority → curl:6 (CURLE_COULDNT_RESOLVE_HOST) → 502. */
    {
        gws_fixture_t f;
        if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
            gws_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        int rc = gws_send_request(&f, &c, "GET", "http", "nxdomain-mqproxy-test.invalid",
                                  "/x", "Bearer sekrit", NULL, 0, 0, NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 10000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        MQ_CHECK_EQ_INT(c.status, 502);
        const char *err = cli_find_hdr(&c, "x-mq-error");
        char want[16];
        snprintf(want, sizeof(want), "curl:%d", MQ_GW_CURL_RESOLVE);
        MQ_CHECK(err && strcmp(err, want) == 0);
        gws_fixture_down(&f);
    }
    /* 5b: connection refused (127.0.0.1:1) → curl:7 → 502. */
    {
        gws_fixture_t f;
        if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
            gws_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        int rc = gws_send_request(&f, &c, "GET", "http", "127.0.0.1:1", "/x",
                                  "Bearer sekrit", NULL, 0, 0, NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 10000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        MQ_CHECK_EQ_INT(c.status, 502);
        const char *err = cli_find_hdr(&c, "x-mq-error");
        char want[16];
        snprintf(want, sizeof(want), "curl:%d", MQ_GW_CURL_CONNECT);
        MQ_CHECK(err && strcmp(err, want) == 0);
        gws_fixture_down(&f);
    }
}

/* ── gw_server Case 6: upload PUT 64 KiB+ → origin echoes len=<n> ────────────*/
static void
test_gws_upload(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    const size_t N = 96 * 1024;
    uint8_t *src = malloc(N);
    for (size_t i = 0; i < N; i++)
        src[i] = pat_byte(i);

    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(256);
    c.body_cap = 256;
    c.up_src = src;
    c.up_total = N;

    char cl[32];
    snprintf(cl, sizeof(cl), "%zu", N);
    int rc = gws_send_request(&f, &c, "PUT", "http", origin_authority(&f.origin), "/up",
                              "Bearer sekrit", NULL, 0, 1, cl);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 15000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK_EQ_INT((long long)c.up_sent, (long long)N);
    /* Origin replied "len=<N>". */
    c.body[c.body_len < c.body_cap ? c.body_len : c.body_cap - 1] = '\0';
    char want[32];
    snprintf(want, sizeof(want), "len=%zu", N);
    MQ_CHECK(strstr((char *)c.body, want) != NULL);

    free(src);
    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 6b: chunked upload PUT 32 KiB (NO content-length header) ─
 *
 * The client sends a PUT with has_body=1 but omits content-length from the H3
 * request.  gw_server detects has_body && CL absent → upload_len = CHUNKED →
 * libcurl uses chunked Transfer-Encoding toward the origin.
 *
 * Assert:
 *   - H3 response status == 200.
 *   - Origin reply body contains "len=32768" (origin drained the full 32 KiB).
 *   - origin.saw_content_length == 0: the gw_server never forwarded a
 *     content-length request header (it is stripped before the origin, even when
 *     the client had sent one; in this test the client never sends one either).
 *     NOTE: evhttp on the origin side reassembles the chunked body and does NOT
 *     synthesize a content-length in the parsed request headers, so the assert
 *     is reliable without special evhttp configuration.
 */
static void
test_gws_chunked_upload(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    const size_t N = 32 * 1024;
    uint8_t *src = malloc(N);
    for (size_t i = 0; i < N; i++)
        src[i] = pat_byte(i);

    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(256);
    c.body_cap = 256;
    c.up_src = src;
    c.up_total = N;

    /* has_body=1, content_length=NULL → no CL header on the H3 request; the
     * gw_server must classify this as CHUNKED and use chunked TE toward origin. */
    int rc = gws_send_request(&f, &c, "PUT", "http", origin_authority(&f.origin), "/up",
                              "Bearer sekrit", NULL, 0, /*has_body=*/1, /*cl=*/NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    uint64_t deadline = now_ms() + 15000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 200);
    MQ_CHECK_EQ_INT((long long)c.up_sent, (long long)N);

    /* Origin echoes the received byte count. */
    c.body[c.body_len < c.body_cap ? c.body_len : c.body_cap - 1] = '\0';
    char want[32];
    snprintf(want, sizeof(want), "len=%zu", N);
    MQ_CHECK(strstr((char *)c.body, want) != NULL);

    /* gw_server must NOT have forwarded a content-length request header.
     * evhttp natively handles chunked requests so origin sees no synthesized CL. */
    MQ_CHECK_EQ_INT(f.origin.saw_content_length, 0);

    free(src);
    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 7: mid-download client reset → origin reaped, gw survives ─*/
static void
test_gws_mid_reset(void)
{
    const size_t N = 1024 * 1024; /* big enough that a reset lands mid-body */
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", N) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(N);
    c.body_cap = N;
    c.reset_after = 16 * 1024; /* reset once 16 KiB has arrived */

    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/blob",
                              "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    /* Pump until our reset fires + a settle so the gw reaps the origin handle. */
    uint64_t deadline = now_ms() + 10000;
    while (!c.did_reset && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);
    MQ_CHECK_EQ_INT(c.did_reset, 1);
    pump_a_bit(f.base, 500); /* let the gw's on_close abort the origin */

    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), 1);

    /* A subsequent request on the same conn still works (gw did not crash / wedge).
     * Reuse the origin's /up route as a quick 0-byte round-trip. */
    f.origin.saw_xmq = 0;
    cli_req_t c2;
    memset(&c2, 0, sizeof(c2));
    c2.body = malloc(256);
    c2.body_cap = 256;
    int rc2 = gws_send_request(&f, &c2, "GET", "http", origin_authority(&f.origin),
                               "/blob", "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc2, 0);
    deadline = now_ms() + 10000;
    while (!c2.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);
    MQ_CHECK_EQ_INT(c2.status, 200);
    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), 2);

    free(c.body);
    free(c2.body);
    gws_fixture_down(&f);
}

/* Helper: send ONE request with the given pseudo-headers, pump to close, and
 * return the captured H3 :status (0 if the request never produced a response).
 * `*err_out` (if non-NULL) receives a copy of the x-mq-error value. */
static int
gws_one_status(gws_fixture_t *f, const char *method, const char *scheme,
               const char *authority, const char *path, char *err_out, size_t err_cap)
{
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;
    int rc = gws_send_request(f, &c, method, scheme, authority, path, "Bearer sekrit",
                              NULL, 0, 0, NULL);
    if (rc != 0) {
        free(c.body);
        return -1;
    }
    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f->base, EVLOOP_NONBLOCK);
    if (err_out) {
        const char *e = cli_find_hdr(&c, "x-mq-error");
        snprintf(err_out, err_cap, "%s", e ? e : "");
    }
    int st = c.status;
    free(c.body);
    return st;
}

/* ── gw_server Case 10: :method validated server-side (smuggling defense) ────
 *
 * curl does NOT sanitize CURLOPT_CUSTOMREQUEST, so an unvalidated :method from a
 * direct H3 peer is a request-line-injection surface. The gw_server must validate
 * with mq_gw_parse_method BEFORE use: token chars only, <=15, uppercased. */
static void
test_gws_method_validation(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    const char *auth = origin_authority(&f.origin);
    char err[64];

    /* :method with an embedded space → 400 bad-request. */
    MQ_CHECK_EQ_INT(gws_one_status(&f, "GE T", "http", auth, "/blob", err, sizeof(err)),
                    400);
    MQ_CHECK(strcmp(err, "bad-request") == 0);

    /* :method with a CR → 400 bad-request. */
    MQ_CHECK_EQ_INT(gws_one_status(&f, "GET\r", "http", auth, "/blob", err, sizeof(err)),
                    400);
    MQ_CHECK(strcmp(err, "bad-request") == 0);

    /* :method 16+ chars (overlong, would be silently clipped) → 400. */
    MQ_CHECK_EQ_INT(gws_one_status(&f, "AAAAAAAAAAAAAAAAAAAA", "http", auth, "/blob", err,
                                   sizeof(err)),
                    400);
    MQ_CHECK(strcmp(err, "bad-request") == 0);

    /* lowercase "get" → accepted (uppercased): request reaches the origin → 200,
     * and the origin sees GET. */
    f.origin.saw_xmq = 0;
    MQ_CHECK_EQ_INT(gws_one_status(&f, "get", "http", auth, "/blob", err, sizeof(err)),
                    200);

    /* :authority 256+ bytes (overlong — silent truncation changes the target!)
     * → 400 bad-target. */
    {
        char big[300];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        MQ_CHECK_EQ_INT(gws_one_status(&f, "GET", "http", big, "/blob", err, sizeof(err)),
                        400);
        MQ_CHECK(strcmp(err, "bad-target") == 0);
    }

    gws_fixture_down(&f);
}

/* ── gw_server Case 11b: forwarded-header COUNT overflow rejected ────────────
 *
 * More forwardable headers than the per-request arena holds (MQ_GWS_MAX_HDRS=64)
 * sets ctx.bad in req_each_header — but pre-fix that flag was never read, so the
 * request was forwarded to the origin with a SILENTLY TRUNCATED header set. The
 * gw_server must instead reject with 400 bad-request and never contact the
 * origin. We send 70 distinct forwardable headers, one of them an identifiable
 * x-custom-hdr: the origin must NOT see it (request uncontacted). */
static void
test_gws_header_count_overflow(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;

    /* Build pseudo + auth + 70 forwardable headers directly (gws_send_request
     * caps at CLI_MAX_HDRS=32, too small here). */
    const int NEXTRA = 70;
    enum { NAMES_CAP = 4 + 5 + 70 };
    mq_h3_header_t hs[NAMES_CAP];
    static char names[70][32];
    size_t nh = 0;
    hs[nh].name = ":method";
    hs[nh++].value = "GET";
    hs[nh].name = ":scheme";
    hs[nh++].value = "http";
    hs[nh].name = ":authority";
    hs[nh++].value = origin_authority(&f.origin);
    hs[nh].name = ":path";
    hs[nh++].value = "/blob";
    hs[nh].name = "x-mq-auth";
    hs[nh++].value = "Bearer sekrit";
    for (int i = 0; i < NEXTRA; i++) {
        if (i == 0) {
            hs[nh].name = "x-custom-hdr";
            hs[nh++].value = "keepme";
        } else {
            snprintf(names[i], sizeof(names[i]), "x-fill-hdr-%02d", i);
            hs[nh].name = names[i];
            hs[nh++].value = "v";
        }
    }

    mq_h3_req_t *hr = mq_h3_req_open(f.cli_conn);
    MQ_CHECK(hr != NULL);
    c.req = hr;
    mq_h3_req_set_cbs(hr, cli_on_read, cli_on_write, cli_on_close, &c);
    long sh = mq_h3_req_send_headers(hr, hs, nh, /*fin=*/1);
    MQ_CHECK(sh > 0);

    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 400);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "bad-request") == 0);
    /* Origin uncontacted: it never saw the forwardable custom header. */
    MQ_CHECK_EQ_INT(f.origin.saw_custom, 0);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 12: oversized forwarded header rejected (not truncated) ──
 *
 * A forwarded header VALUE >= 1024 bytes (the arena slot) would be silently
 * clamped by copy_z, changing what reaches the origin. The gw_server must reject
 * with 400 bad-header instead. */
static void
test_gws_oversized_header(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;

    char big[1501];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    mq_h3_header_t extra[] = {{"x-big-hdr", big}};
    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/blob",
                              "Bearer sekrit", extra, 1, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);
    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 400);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "bad-header") == 0);
    /* The request never reached the origin. */
    MQ_CHECK_EQ_INT(f.origin.saw_xmq, 0);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 11: strict content-length parse on the tunnel side ──────
 *
 * Mirror mq_http1's strictness: an overflowing / non-digit / duplicated
 * content-length on a bodied H3 request must be rejected (400 bad-request), not
 * silently unset (which would fall back to chunked) or last-win. A request body
 * is required so the CL is actually consulted. */
static void
test_gws_content_length_strict(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    const char *auth = origin_authority(&f.origin);

    struct {
        const char *cl;     /* content-length value */
        const char *cl_dup; /* second content-length value, or NULL */
        int want_status;
        const char *desc;
    } cases[] = {
        {"9999999999999999999999", NULL, 400, "overflow"},
        {"12a", NULL, 400, "non-digit"},
        {"", NULL, 400, "empty"},
        {"5", "5", 400, "duplicate (identical)"},
        {"5", "6", 400, "duplicate (differing)"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        c.body = malloc(4096);
        c.body_cap = 4096;

        mq_h3_header_t extra[2];
        size_t ne = 0;
        extra[ne].name = "content-length";
        extra[ne].value = cases[i].cl;
        ne++;
        if (cases[i].cl_dup) {
            extra[ne].name = "content-length";
            extra[ne].value = cases[i].cl_dup;
            ne++;
        }
        /* has_body=1, content_length param NULL (we supply CL via `extra`). We do
         * not stream a body — the reject lands on the header section. */
        int rc = gws_send_request(&f, &c, "PUT", "http", auth, "/up", "Bearer sekrit",
                                  extra, ne, /*has_body=*/1, /*cl=*/NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 5000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        printf("[case11] CL=%s -> %d (want %d)\n", cases[i].desc, c.status,
               cases[i].want_status);
        MQ_CHECK_EQ_INT(c.status, cases[i].want_status);
        const char *err = cli_find_hdr(&c, "x-mq-error");
        MQ_CHECK(err && strcmp(err, "bad-request") == 0);
        free(c.body);
    }

    gws_fixture_down(&f);
}

/* ── gw_server Case 12b: oversized ORIGIN response header → 502 fail-closed ──
 *
 * Symmetric to the client-side dl_each_header fail-closed: an origin RESPONSE
 * header whose name (>127) or value (>1023) overflows the per-request arena slot
 * must NOT be silently clamped (a clipped header corrupts the downstream
 * response). The gw_server must fail the response closed — synthesize 502 +
 * x-mq-error: upstream-protocol — since no response header has reached the H3
 * client yet. The origin /bighdr route emits a 1500-byte response header value. */
static void
test_gws_oversized_origin_header(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;

    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                              "/bighdr", "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);
    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    MQ_CHECK_EQ_INT(c.status, 502);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "upstream-protocol") == 0);
    /* The oversized origin header was NOT forwarded (truncated) to the client. */
    MQ_CHECK(cli_find_hdr(&c, "x-origin-big") == NULL);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 12c: origin response header-COUNT overflow → 502 fail-closed
 *
 * When an origin replies with more than MQ_GWS_MAX_HDRS (64) non-hop-by-hop
 * response headers, origin_on_header sets r->hdrs_overflow after the 64th.
 * download_send_headers MUST check hdrs_overflow (symmetric to hdr_oversized)
 * and fail closed with 502 + x-mq-error: upstream-protocol before any header
 * reaches the H3 client.
 *
 * The origin /manyhdr route returns 200 with 70 distinct x-h-NN headers.
 * Expected: gateway returns 502 + x-mq-error: upstream-protocol; no x-h-*
 * header forwarded to the client. */
static void
test_gws_resp_header_count_overflow(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;

    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                              "/manyhdr", "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);
    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    /* Fail closed: gateway must synthesize 502 + x-mq-error: upstream-protocol.
     * No x-h-* origin headers must reach the H3 client. */
    MQ_CHECK_EQ_INT(c.status, 502);
    const char *err = cli_find_hdr(&c, "x-mq-error");
    MQ_CHECK(err && strcmp(err, "upstream-protocol") == 0);
    /* Confirm that none of the 70 origin x-h-NN headers were forwarded. */
    MQ_CHECK(cli_find_hdr(&c, "x-h-00") == NULL);
    MQ_CHECK(cli_find_hdr(&c, "x-h-63") == NULL);
    MQ_CHECK(cli_find_hdr(&c, "x-h-64") == NULL);
    MQ_CHECK(cli_find_hdr(&c, "x-h-69") == NULL);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 12d: x-mq-origin-protocol from origin dropped before count
 *
 * Bug: origin_on_header checked the header-count overflow BEFORE dropping
 * x-mq-origin-protocol.  When the origin replied with exactly 64 forwardable
 * headers (fitting within MQ_GWS_MAX_HDRS) followed by x-mq-origin-protocol,
 * the count was already 64 when x-mq-origin-protocol arrived, so the overflow
 * check tripped even though that header would merely be dropped — producing a
 * false-positive 502.
 *
 * Fix: move the x-mq-origin-protocol drop ABOVE the count check so that drop-
 * class checks run before capacity checks; dropped headers must not count
 * toward capacity.
 *
 * The /boundary64 origin route emits exactly 64 forwardable headers (3 pre-set
 * standard headers + 61 x-h-NN) followed by x-mq-origin-protocol: fake.
 * Expected post-fix: 200, all 64 headers forwarded, x-mq-origin-protocol
 * overwritten to "http/1.1" (the gateway's synthesis). */
static void
test_gws_xmq_origin_protocol_drop_before_count(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));
    c.body = malloc(4096);
    c.body_cap = 4096;

    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                              "/boundary64", "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);
    uint64_t deadline = now_ms() + 5000;
    while (!c.closed && now_ms() < deadline)
        event_base_loop(f.base, EVLOOP_NONBLOCK);

    /* Post-fix: the 64 forwardable headers fit; x-mq-origin-protocol is dropped
     * (not counted) → no overflow → 200.  Pre-fix: 502 + upstream-protocol. */
    MQ_CHECK_EQ_INT(c.status, 200);

    /* x-mq-origin-protocol must be the gateway's own synthesis ("http/1.1"),
     * NOT the origin's "fake" value, confirming the drop + re-synthesis.
     * Guard the strcmp to avoid a crash on the NULL that the bug produces. */
    const char *prot = cli_find_hdr(&c, "x-mq-origin-protocol");
    MQ_CHECK(prot != NULL);
    if (prot) MQ_CHECK(strcmp(prot, "http/1.1") == 0);

    /* Spot-check that x-h-NN headers are forwarded.  CLI_MAX_HDRS=32 limits the
     * client-side capture to 32 non-status headers (x-mq-origin-protocol, Date,
     * Content-Length, Content-Type occupy slots 0-3; x-h-00..x-h-27 fill 4-31).
     * We check x-h-00 (first custom) and x-h-27 (last in the capture window);
     * headers beyond x-h-27 are silently capped by the test fixture, but the
     * 200 status already confirms no overflow was triggered. */
    MQ_CHECK(cli_find_hdr(&c, "x-h-00") != NULL);
    MQ_CHECK(cli_find_hdr(&c, "x-h-27") != NULL);

    /* No x-mq-error (was "upstream-protocol" under the bug). */
    MQ_CHECK(cli_find_hdr(&c, "x-mq-error") == NULL);

    free(c.body);
    gws_fixture_down(&f);
}

/* ── gw_server Case 9: rejected requests reclaim per-request state ──────────
 *
 * Regression for the no-origin reject state leak: a request rejected BEFORE the
 * origin side ever exists (wrong token → 403, bad header/target → 400) had
 * oreq==NULL && origin_dead==0, so h3_on_close never flipped origin_dead and
 * gw_req_maybe_free never freed the state — it stayed linked in s->reqs forever.
 * Send N wrong-token requests sequentially on one conn, then assert the live
 * per-request count is 0 once all close + the loop drains. */
static void
test_gws_reject_no_leak(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 4096) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    const int N = 8;
    for (int i = 0; i < N; i++) {
        cli_req_t c;
        memset(&c, 0, sizeof(c));
        int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin),
                                  "/blob", "Bearer WRONG", NULL, 0, 0, NULL);
        MQ_CHECK_EQ_INT(rc, 0);
        uint64_t deadline = now_ms() + 5000;
        while (!c.closed && now_ms() < deadline)
            event_base_loop(f.base, EVLOOP_NONBLOCK);
        MQ_CHECK_EQ_INT(c.status, 403);
    }

    /* All N rejected requests have closed; let any deferred on_close drain. */
    pump_a_bit(f.base, 300);

    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), (unsigned)N);
    /* The leak shows here: pre-fix this returns N (8); post-fix it must be 0. */
    MQ_CHECK_EQ_INT(mq_gw_server_live_reqs(f.gw), 0);

    gws_fixture_down(&f);
}

/* ── gw_server Case 8: teardown with a request in flight (origin /slow) ──────*/
static void
test_gws_teardown_inflight(void)
{
    gws_fixture_t f;
    if (gws_fixture_up(&f, "sekrit", 0) != 0) {
        gws_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    cli_req_t c;
    memset(&c, 0, sizeof(c));

    /* /slow replies only after a 300ms origin timer — so at teardown the gw holds
     * a live in-flight origin request. */
    int rc = gws_send_request(&f, &c, "GET", "http", origin_authority(&f.origin), "/slow",
                              "Bearer sekrit", NULL, 0, 0, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    /* Pump enough to forward the request + start the origin (but NOT the 300ms
     * reply). The gw now has a live origin request. */
    pump_a_bit(f.base, 80);
    MQ_CHECK_EQ_INT(c.closed, 0); /* not done yet */
    MQ_CHECK_EQ_INT(mq_gw_server_requests(f.gw), 1);

    /* Tear down mid-request, sanctioned order. Must be ASan / LSan clean. */
    gws_fixture_down(&f);
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

    /* Gateway-server (Task 4.3) cases — each owns its own base + transports. */
    test_gws_get();
    test_gws_class();
    test_gws_403();
    test_gws_400();
    test_gws_bad_header();
    test_gws_502();
    test_gws_upload();
    test_gws_chunked_upload();
    test_gws_mid_reset();
    test_gws_reject_no_leak();
    test_gws_method_validation();
    test_gws_content_length_strict();
    test_gws_header_count_overflow();
    test_gws_oversized_header();
    test_gws_oversized_origin_header();
    test_gws_resp_header_count_overflow();
    test_gws_xmq_origin_protocol_drop_before_count();
    test_gws_teardown_inflight();

    if (mq_test_failures) {
        fprintf(stderr, "%d failure(s)\n", mq_test_failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
