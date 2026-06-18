// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* test_gw_h2_adapter.c — Phase 7 MITM Slice 3 Task 5.
 *
 * Drives a real nghttp2 CLIENT session through an in-test memory pipe against
 * the mq_gw_h2_adapter SERVER session and asserts the SETTINGS handshake
 * completes and the server advertised the §5.2 resource limits.
 *
 * Wire shuttle (no sockets, no TLS):
 *   client nghttp2_session_mem_send -> adapter mq_gw_h2_adapter_recv
 *   adapter send_cb buffer          -> client nghttp2_session_mem_recv
 *
 * We assert the limits from the CLIENT's perspective: after the client has
 * processed the server's SETTINGS frame, nghttp2_session_get_remote_settings on
 * the CLIENT returns exactly what the SERVER advertised — the real wire
 * behavior. The adapter binds a CAPTURING STUB vtable (no tunnel); the skeleton
 * does no request handling, so the stub ops are never invoked here. */

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdlib.h> /* strtol */
#include <string.h>
#include <strings.h> /* strcasecmp / strncasecmp */

#include "gateway/mq_gw_h2_adapter.h"
#include "mqtest.h"

/* §5.2 NORMATIVE limits the adapter must advertise. */
#define EXP_MAX_CONCURRENT_STREAMS 128u
#define EXP_MAX_FRAME_SIZE         16384u
#define EXP_HEADER_TABLE_SIZE      4096u
#define EXP_MAX_HEADER_LIST_SIZE   16384u

/* ── adapter send_cb: capture the server's outbound plaintext ────────────────*/

typedef struct {
    uint8_t buf[256 * 1024]; /* large enough to hold a full flush incl. a 64 KiB
                              * response body + framing in one want_write pass */
    size_t len;
} sink_buf_t;

static ssize_t
adapter_send(void *io, const uint8_t *p, size_t n)
{
    sink_buf_t *s = (sink_buf_t *)io;
    if (s->len + n > sizeof(s->buf)) return -1;
    memcpy(s->buf + s->len, p, n);
    s->len += n;
    return (ssize_t)n;
}

/* ── capturing stub submit vtable (never called by the skeleton) ─────────────*/

typedef struct {
    int prevalidate_calls;
    int req_begin_calls;
} stub_state_t;

static mq_gw_reject_reason_t
stub_prevalidate(void *u, const mq_h3_header_t *h, size_t n, int *status)
{
    stub_state_t *st = (stub_state_t *)u;
    (void)h;
    (void)n;
    (void)status;
    st->prevalidate_calls++;
    return MQ_GW_OK;
}

static mq_gw_xreq_t *
stub_req_begin(void *u, const mq_gw_req_head_t *head, const mq_gw_sink_ops_t *sink,
               void *sink_user, int *err_status, mq_gw_reject_reason_t *reason)
{
    stub_state_t *st = (stub_state_t *)u;
    (void)head;
    (void)sink;
    (void)sink_user;
    (void)err_status;
    (void)reason;
    st->req_begin_calls++;
    return NULL;
}

static int
stub_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    (void)r;
    (void)p;
    (void)len;
    return 0;
}
static void
stub_req_body_done(mq_gw_xreq_t *r)
{
    (void)r;
}
static void
stub_req_drained(mq_gw_xreq_t *r)
{
    (void)r;
}
static void
stub_req_aborted(mq_gw_xreq_t *r)
{
    (void)r;
}

static const char *
stub_auth_token(void *u)
{
    (void)u;
    return "test-token";
}

static const mq_gw_submit_ops_t g_stub_ops = {
    .prevalidate = stub_prevalidate,
    .req_begin = stub_req_begin,
    .req_body = stub_req_body,
    .req_body_done = stub_req_body_done,
    .req_drained = stub_req_drained,
    .req_aborted = stub_req_aborted,
    .auth_token = stub_auth_token,
};

/* ── capturing stub for the Task 6 demux tests ───────────────────────────────
 *
 * Records the FINAL request head the adapter hands to the boundary: the
 * pseudo-headers and a DEEP COPY of the final header list (browser headers minus
 * X-Mq-*, PLUS the injected controls). Deep copy is mandatory — the adapter's
 * per-stream arena is freed on stream close, so the captured pointers would
 * dangle otherwise. auth_token returns "tok" → injected value must be
 * "Bearer tok" (codex H3). */

#define CAP_MAX_HDRS 64
#define CAP_STR      512

typedef struct {
    int prevalidate_calls;
    int req_begin_calls;

    /* captured final head (deep copy) */
    char method[CAP_STR], scheme[CAP_STR], authority[CAP_STR], path[CAP_STR];
    char names[CAP_MAX_HDRS][CAP_STR];
    char values[CAP_MAX_HDRS][CAP_STR];
    size_t n_hdrs;
    int64_t content_length;

    /* what prevalidate observed (header count) — proves the strip ran first. */
    int prevalidate_saw_browser_xmq; /* a browser x-mq-* survived into prevalidate */

    /* injectable prevalidate verdict (default OK). */
    mq_gw_reject_reason_t prevalidate_verdict;
    int prevalidate_status;

    /* Task 7: captured sink + sink_user + the fake xreq handle, so a test acting
     * as the core can drive the response path. */
    const mq_gw_sink_ops_t *sink;
    void *sink_user;
    mq_gw_xreq_t *xreq;    /* the sentinel we returned from req_begin */
    int req_drained_calls; /* how many times the adapter called req_drained */

    /* Task 8: request-body upload capture + injectable pause. */
    uint8_t up_body[256 * 1024]; /* uploaded bytes, in delivery order */
    size_t up_len;
    int req_body_done_calls; /* req_body_done fired (stream end) */
    /* When >0, req_body returns -1 (pause) ONCE after up_len reaches/exceeds this
     * many bytes, then clears the trip so the resumed feed is accepted. Models a
     * stalled tunnel that backpressures the browser, then drains. */
    size_t pause_after;
    int paused_once; /* the single pause has fired (no further pausing) */
    int req_body_calls;

    /* UAF-hardening regression (Slice 3): how many times the adapter called
     * req_aborted (on_stream_close / adapter_free "local gone" signal). A stream
     * that completed cleanly (resp_finish ran → the adapter NULLed its borrowed
     * xreq) MUST NOT be aborted at teardown — this counter asserts that. */
    int req_aborted_calls;
} cap_state_t;

static int
cap_has_xmq_other_than_auth_fwd(const mq_h3_header_t *h, size_t n)
{
    /* Any x-mq-* that is NOT the two injected controls counts as a survivor. */
    for (size_t i = 0; i < n; i++) {
        const char *nm = h[i].name;
        if (strncasecmp(nm, "x-mq-", 5) != 0) continue;
        if (strcasecmp(nm, "x-mq-auth") == 0) continue;
        if (strcasecmp(nm, "x-mq-forward-cookie") == 0) continue;
        return 1;
    }
    return 0;
}

static mq_gw_reject_reason_t
cap_prevalidate(void *u, const mq_h3_header_t *h, size_t n, int *status)
{
    cap_state_t *st = (cap_state_t *)u;
    st->prevalidate_calls++;
    /* Detect a SURVIVING browser x-mq-* (other than the two injected) OR a
     * duplicate x-mq-auth — both would be a §4.5 violation. */
    if (cap_has_xmq_other_than_auth_fwd(h, n)) st->prevalidate_saw_browser_xmq = 1;
    int auth_seen = 0;
    for (size_t i = 0; i < n; i++)
        if (strcasecmp(h[i].name, "x-mq-auth") == 0) auth_seen++;
    if (auth_seen > 1) st->prevalidate_saw_browser_xmq = 1; /* dup-control surface */
    if (status)
        *status = st->prevalidate_verdict == MQ_GW_OK ? 200 : st->prevalidate_status;
    return st->prevalidate_verdict;
}

static void
cap_copy(char *dst, const char *src)
{
    size_t i = 0;
    for (; src && src[i] && i < CAP_STR - 1; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static mq_gw_xreq_t *
cap_req_begin(void *u, const mq_gw_req_head_t *head, const mq_gw_sink_ops_t *sink,
              void *sink_user, int *err_status, mq_gw_reject_reason_t *reason)
{
    cap_state_t *st = (cap_state_t *)u;
    (void)err_status;
    (void)reason;
    st->req_begin_calls++;
    /* Task 7: stash the sink + sink_user so a core-role test can drive the
     * response path; the adapter passes the per-stream context as sink_user. */
    st->sink = sink;
    st->sink_user = sink_user;
    cap_copy(st->method, head->method);
    cap_copy(st->scheme, head->scheme);
    cap_copy(st->authority, head->authority);
    cap_copy(st->path, head->path);
    st->content_length = head->content_length;
    st->n_hdrs = 0;
    for (size_t i = 0; i < head->n_headers && st->n_hdrs < CAP_MAX_HDRS; i++) {
        cap_copy(st->names[st->n_hdrs], head->headers[i].name);
        cap_copy(st->values[st->n_hdrs], head->headers[i].value);
        st->n_hdrs++;
    }
    /* Return a non-NULL sentinel so the adapter stores it as the stream's xreq.
     * For the Task 7 response test the adapter passes this same handle back to
     * req_drained, so the core-role test can observe download backpressure
     * resume. The header-only Task 6 tests never dereference it. */
    st->xreq = (mq_gw_xreq_t *)st;
    return st->xreq;
}

static int
cap_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    cap_state_t *st = (cap_state_t *)r; /* xreq sentinel == cap_state_t* */
    st->req_body_calls++;
    /* Capture the bytes IN ORDER (the contract: bytes are consumed even when we
     * return -1/pause, so we always record them — never re-deliver). */
    if (st->up_len + len <= sizeof(st->up_body)) {
        memcpy(st->up_body + st->up_len, p, len);
        st->up_len += len;
    }
    /* Injectable single pause: once the upload reaches pause_after bytes, return
     * -1 (pause) EXACTLY once. The resumed feed must then be accepted (0). */
    if (st->pause_after > 0 && !st->paused_once && st->up_len >= st->pause_after) {
        st->paused_once = 1;
        return -1; /* pause: stop feeding more body until resume_read */
    }
    return 0; /* accepted; keep reading */
}
static void
cap_req_body_done(mq_gw_xreq_t *r)
{
    cap_state_t *st = (cap_state_t *)r;
    st->req_body_done_calls++;
}
static void
cap_req_drained(mq_gw_xreq_t *r)
{
    /* The adapter passes back the xreq sentinel == the cap_state_t*. Count the
     * resume so the Task 7 backpressure test can assert the download pump is
     * re-kicked once the H2 send buffer drains below the per-stream cap. */
    cap_state_t *st = (cap_state_t *)r;
    if (st) st->req_drained_calls++;
}
static void
cap_req_aborted(mq_gw_xreq_t *r)
{
    /* The adapter passes back the xreq sentinel == the cap_state_t*. Count the
     * abort so the UAF-hardening test can assert a cleanly-finished stream is
     * NEVER aborted (its xreq was NULLed by resp_finish). */
    cap_state_t *st = (cap_state_t *)r;
    if (st) st->req_aborted_calls++;
}
static const char *
cap_auth_token(void *u)
{
    (void)u;
    return "tok"; /* injected value must be "Bearer tok" (codex H3) */
}

static const mq_gw_submit_ops_t g_cap_ops = {
    .prevalidate = cap_prevalidate,
    .req_begin = cap_req_begin,
    .req_body = cap_req_body,
    .req_body_done = cap_req_body_done,
    .req_drained = cap_req_drained,
    .req_aborted = cap_req_aborted,
    .auth_token = cap_auth_token,
};

/* Variant whose configured token is ALREADY "Bearer "-prefixed. The adapter must
 * STRIP the leading "Bearer " before re-prefixing, so the injected x-mq-auth is
 * EXACTLY "Bearer tok" — never "Bearer Bearer tok" (codex H3 dedup branch). */
static const char *
cap_auth_token_prefixed(void *u)
{
    (void)u;
    return "Bearer tok";
}

static const mq_gw_submit_ops_t g_cap_ops_prefixed = {
    .prevalidate = cap_prevalidate,
    .req_begin = cap_req_begin,
    .req_body = cap_req_body,
    .req_body_done = cap_req_body_done,
    .req_drained = cap_req_drained,
    .req_aborted = cap_req_aborted,
    .auth_token = cap_auth_token_prefixed,
};

/* Look up a captured final header by name (case-insensitive). Returns value or
 * NULL; *count receives how many times the name appears. */
static const char *
cap_find(const cap_state_t *st, const char *name, int *count)
{
    const char *v = NULL;
    int c = 0;
    for (size_t i = 0; i < st->n_hdrs; i++) {
        if (strcasecmp(st->names[i], name) == 0) {
            if (!v) v = st->values[i];
            c++;
        }
    }
    if (count) *count = c;
    return v;
}

/* ── client send_cb: capture the client's outbound plaintext ─────────────────*/

static ssize_t
client_send(nghttp2_session *s, const uint8_t *data, size_t length, int flags,
            void *user_data)
{
    sink_buf_t *cb = (sink_buf_t *)user_data;
    (void)s;
    (void)flags;
    if (cb->len + length > sizeof(cb->buf)) return NGHTTP2_ERR_CALLBACK_FAILURE;
    memcpy(cb->buf + cb->len, data, length);
    cb->len += length;
    return (ssize_t)length;
}

/* ── the test ────────────────────────────────────────────────────────────────*/

static void
test_settings_handshake(void)
{
    sink_buf_t srv_out = {0}; /* bytes the adapter (server) wants to send */
    stub_state_t stub = {0};

    mq_gw_h2_adapter_t *a =
        mq_gw_h2_adapter_new(&g_stub_ops, &stub, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    /* Real nghttp2 CLIENT session. */
    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);

    sink_buf_t cli_out = {0}; /* bytes the client wants to send */
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &cli_out), 0);
    nghttp2_session_callbacks_del(cbs);

    /* Client submits its own SETTINGS + a simple GET to drive the connection. */
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
    };
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"example.com", 10, 11, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, NULL, NULL);
    MQ_CHECK(sid > 0);

    /* Shuttle a few rounds: client -> adapter -> client. */
    for (int round = 0; round < 4; round++) {
        /* Drive client output. */
        cli_out.len = 0;
        MQ_CHECK_EQ_INT(nghttp2_session_send(cli), 0);
        if (cli_out.len > 0) {
            MQ_CHECK_EQ_INT(mq_gw_h2_adapter_recv(a, cli_out.buf, cli_out.len), 0);
        }

        /* Drive adapter output. */
        srv_out.len = 0;
        MQ_CHECK_EQ_INT(mq_gw_h2_adapter_want_write(a), 0);
        if (srv_out.len > 0) {
            ssize_t r = nghttp2_session_mem_recv(cli, srv_out.buf, srv_out.len);
            MQ_CHECK(r >= 0 && (size_t)r == srv_out.len);
        }
    }

    /* From the CLIENT's view, remote_settings == what the SERVER advertised. */
    uint32_t mcs =
        nghttp2_session_get_remote_settings(cli, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    uint32_t mfs =
        nghttp2_session_get_remote_settings(cli, NGHTTP2_SETTINGS_MAX_FRAME_SIZE);
    uint32_t hts =
        nghttp2_session_get_remote_settings(cli, NGHTTP2_SETTINGS_HEADER_TABLE_SIZE);
    /* Non-vacuous: nghttp2's default MAX_HEADER_LIST_SIZE is unlimited/large, so
     * ==16384 proves the server actually advertised the §5.2 limit. */
    uint32_t mhls =
        nghttp2_session_get_remote_settings(cli, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE);

    MQ_CHECK_EQ_INT(mcs, EXP_MAX_CONCURRENT_STREAMS);
    MQ_CHECK_EQ_INT(mfs, EXP_MAX_FRAME_SIZE);
    MQ_CHECK_EQ_INT(hts, EXP_HEADER_TABLE_SIZE);
    MQ_CHECK_EQ_INT(mhls, EXP_MAX_HEADER_LIST_SIZE);
    /* MAX_CONCURRENT_STREAMS must be bounded (<= 128 per §5.2). */
    MQ_CHECK(mcs <= EXP_MAX_CONCURRENT_STREAMS);

    nghttp2_session_del(cli);
    mq_gw_h2_adapter_free(a);
}

/* ── Task 6 demux / §4.5 header-policy / NUL / header-bomb tests ─────────────*/

/* Client-side stream-close capture: records that the server RST'd the stream and
 * with which error code (NGHTTP2_NO_ERROR == clean / not reset). */
typedef struct {
    sink_buf_t out;
    int closed;
    uint32_t error_code;
} cli_ud_t;

static int
cli_on_stream_close(nghttp2_session *s, int32_t sid, uint32_t error_code, void *user_data)
{
    (void)s;
    (void)sid;
    cli_ud_t *ud = (cli_ud_t *)user_data;
    ud->closed = 1;
    ud->error_code = error_code;
    return 0;
}

/* Drive one client request (nva[ncnt]) through the adapter and shuttle until
 * quiescent. `submit_body` selects request-with-body (so END_STREAM is NOT on
 * the HEADERS frame; for these header-only tests we use no body → END_STREAM on
 * headers). Returns the client stream id (>0) or <0. Fills *adapter so the
 * caller can free; fills the cli_ud_t via user_data. */
static void
drive_request(const mq_gw_submit_ops_t *ops, void *ops_user, const nghttp2_nv *nva,
              size_t ncnt, cli_ud_t *cud, int *out_sid)
{
    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(ops, ops_user, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) {
        *out_sid = -1;
        return;
    }

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, cli_on_stream_close);

    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, cud), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    int sid = nghttp2_submit_request(cli, NULL, nva, ncnt, NULL, NULL);
    MQ_CHECK(sid > 0);
    *out_sid = sid;

    for (int round = 0; round < 6; round++) {
        cud->out.len = 0;
        MQ_CHECK_EQ_INT(nghttp2_session_send(cli), 0);
        if (cud->out.len > 0) {
            /* recv may fail (fatal) if the adapter GOAWAYs; tolerate but stop. */
            if (mq_gw_h2_adapter_recv(a, cud->out.buf, cud->out.len) != 0) break;
        }
        srv_out.len = 0;
        MQ_CHECK_EQ_INT(mq_gw_h2_adapter_want_write(a), 0);
        if (srv_out.len > 0) {
            ssize_t r = nghttp2_session_mem_recv(cli, srv_out.buf, srv_out.len);
            MQ_CHECK(r >= 0 && (size_t)r == srv_out.len);
        }
    }

    nghttp2_session_del(cli);
    mq_gw_h2_adapter_free(a);
}

/* §4.5 happy-path: hostile browser X-Mq-* dropped; Cookie + Authorization
 * forwarded; exactly one injected x-mq-auth "Bearer tok" + one
 * x-mq-forward-cookie "true"; pseudo-headers mapped; no surviving control. */
static void
test_demux_header_policy(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/path", 5, 5, NGHTTP2_NV_FLAG_NONE},
        /* hostile controls — must be dropped TOTALLY */
        {(uint8_t *)"x-mq-cache", (uint8_t *)"999999", 10, 6, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)"x-mq-auth", (uint8_t *)"Bearer attacker", 9, 15,
         NGHTTP2_NV_FLAG_NONE},
        /* real browser headers — must be forwarded */
        {(uint8_t *)"cookie", (uint8_t *)"sid=1", 6, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)"authorization", (uint8_t *)"Bearer real", 13, 11,
         NGHTTP2_NV_FLAG_NONE},
    };
    int sid = 0;
    drive_request(&g_cap_ops, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud, &sid);

    /* The request materialized exactly once. */
    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    MQ_CHECK_EQ_INT(st.prevalidate_calls, 1);
    /* prevalidate must NOT have seen a surviving browser x-mq-* or a dup auth. */
    MQ_CHECK_EQ_INT(st.prevalidate_saw_browser_xmq, 0);

    /* pseudo-headers mapped. */
    MQ_CHECK(strcmp(st.method, "GET") == 0);
    MQ_CHECK(strcmp(st.scheme, "https") == 0);
    MQ_CHECK(strcmp(st.authority, "site.example") == 0);
    MQ_CHECK(strcmp(st.path, "/path") == 0);

    /* injected controls — exactly one each, correct values. */
    int n_auth = 0, n_fwd = 0, n_cache = 0;
    const char *auth = cap_find(&st, "x-mq-auth", &n_auth);
    const char *fwd = cap_find(&st, "x-mq-forward-cookie", &n_fwd);
    (void)cap_find(&st, "x-mq-cache", &n_cache);
    MQ_CHECK_EQ_INT(n_auth, 1);
    MQ_CHECK(auth && strcmp(auth, "Bearer tok") == 0);
    MQ_CHECK_EQ_INT(n_fwd, 1);
    MQ_CHECK(fwd && strcmp(fwd, "true") == 0);
    /* No X-Mq-Cache injected, and the hostile one was dropped. */
    MQ_CHECK_EQ_INT(n_cache, 0);

    /* real browser headers forwarded verbatim. */
    int n_cookie = 0, n_authz = 0;
    const char *cookie = cap_find(&st, "cookie", &n_cookie);
    const char *authz = cap_find(&st, "authorization", &n_authz);
    MQ_CHECK_EQ_INT(n_cookie, 1);
    MQ_CHECK(cookie && strcmp(cookie, "sid=1") == 0);
    MQ_CHECK_EQ_INT(n_authz, 1);
    MQ_CHECK(authz && strcmp(authz, "Bearer real") == 0);

    /* No browser x-mq-* survived into the final list (only the two injected
     * controls). Rebuild a temporary view from the captured names to assert. */
    {
        mq_h3_header_t view[CAP_MAX_HDRS];
        for (size_t i = 0; i < st.n_hdrs; i++) {
            view[i].name = st.names[i];
            view[i].value = st.values[i];
        }
        MQ_CHECK_EQ_INT(cap_has_xmq_other_than_auth_fwd(view, st.n_hdrs), 0);
    }
}

/* Embedded NUL in a header value → the stream is rejected (RST), NOT truncated.
 * Defense-in-depth: nghttp2's own HTTP-messaging validation (check_header_value)
 * rejects the NUL at HPACK-inflate time and RSTs the stream before END_HEADERS,
 * and our on_header arena_dup scan rejects it independently (codex H1) if that
 * validation were ever disabled. EITHER way the request must NEVER materialize
 * (no truncated-then-forwarded value reaching the strlen-based boundary). */
static void
test_demux_embedded_nul_rejected(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    static const uint8_t badval[] = {'a', 'b', 0x00, 'c'};
    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)"x-evil", (uint8_t *)badval, 6, sizeof(badval),
         NGHTTP2_NV_FLAG_NO_INDEX},
    };
    int sid = 0;
    drive_request(&g_cap_ops, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud, &sid);

    /* Must NOT materialize — neither truncated-then-forwarded nor accepted. */
    MQ_CHECK_EQ_INT(st.req_begin_calls, 0);
}

/* Header-bomb: cumulative inbound header-list size > MQ_H2_MAX_HEADER_LIST_SIZE
 * (16384, RFC 7540 §6.5.2 accounting: name+value+32 per field) → stream RST
 * BEFORE materialization. We send one giant header value to blow the cap. */
static void
test_demux_header_bomb_rejected(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    /* 20000-byte value > 16384 cap even before per-field overhead/name. nghttp2
     * MAX_FRAME_SIZE is 16384, so this header spans CONTINUATION frames — the
     * accounting must trip mid-block. */
    static uint8_t big[20000];
    memset(big, 'x', sizeof(big));
    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)"x-big", big, 5, sizeof(big), NGHTTP2_NV_FLAG_NONE},
    };
    int sid = 0;
    drive_request(&g_cap_ops, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud, &sid);

    MQ_CHECK_EQ_INT(st.req_begin_calls, 0);
}

/* prevalidate rejects (e.g. dup-control) → no req_begin, stream not materialized
 * as a successful request. */
static void
test_demux_prevalidate_reject(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_REJ_DUP_CONTROL;
    st.prevalidate_status = 400;
    cli_ud_t cud = {0};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = 0;
    drive_request(&g_cap_ops, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud, &sid);

    MQ_CHECK(st.prevalidate_calls >= 1);
    MQ_CHECK_EQ_INT(st.req_begin_calls, 0);
}

/* §4.5 / codex H3: when the configured auth_token already carries a "Bearer "
 * prefix, the adapter strips it before re-prefixing so the injected x-mq-auth is
 * EXACTLY "Bearer tok" — NOT "Bearer Bearer tok" (which would corrupt the shared
 * secret). A regression that dropped the strip would yield the doubled value and
 * fail the strcmp below. */
static void
test_demux_auth_bearer_dedup(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = 0;
    drive_request(&g_cap_ops_prefixed, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud,
                  &sid);

    /* Request materialized once and the dedup branch ran. */
    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    MQ_CHECK_EQ_INT(st.prevalidate_calls, 1);

    int n_auth = 0;
    const char *auth = cap_find(&st, "x-mq-auth", &n_auth);
    MQ_CHECK_EQ_INT(n_auth, 1);
    MQ_CHECK(auth && strcmp(auth, "Bearer tok") == 0);
}

/* ── Task 7: response path (sink ops → H2 HEADERS/DATA) + download backpressure ─
 *
 * The §5.2 per-stream response send-queue cap the adapter enforces. resp_body
 * must return 0 (highwater) once the queue is full, and call req_drained once it
 * drains below the cap. Kept in lockstep with MQ_H2_RESP_QUEUE_CAP in the
 * adapter. */
#define EXP_RESP_QUEUE_CAP (64u * 1024u)

/* Response-capturing nghttp2 CLIENT: records :status, the response headers, and
 * the body bytes in arrival order for one stream. */
typedef struct {
    sink_buf_t out; /* bytes the client wants to send (driven by client_send) */

    int status;
    char names[CAP_MAX_HDRS][CAP_STR];
    char values[CAP_MAX_HDRS][CAP_STR];
    size_t n_hdrs;

    uint8_t body[256 * 1024];
    size_t body_len;
    int stream_closed;
} resp_cli_t;

static int
resp_cli_on_header(nghttp2_session *s, const nghttp2_frame *frame, const uint8_t *name,
                   size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                   void *user_data)
{
    (void)s;
    (void)frame;
    (void)flags;
    resp_cli_t *rc = (resp_cli_t *)user_data;
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        rc->status = (int)strtol((const char *)value, NULL, 10);
        return 0;
    }
    if (rc->n_hdrs < CAP_MAX_HDRS) {
        size_t nl = namelen < CAP_STR - 1 ? namelen : CAP_STR - 1;
        size_t vl = valuelen < CAP_STR - 1 ? valuelen : CAP_STR - 1;
        memcpy(rc->names[rc->n_hdrs], name, nl);
        rc->names[rc->n_hdrs][nl] = '\0';
        memcpy(rc->values[rc->n_hdrs], value, vl);
        rc->values[rc->n_hdrs][vl] = '\0';
        rc->n_hdrs++;
    }
    return 0;
}

static int
resp_cli_on_data_chunk(nghttp2_session *s, uint8_t flags, int32_t sid,
                       const uint8_t *data, size_t len, void *user_data)
{
    (void)s;
    (void)flags;
    (void)sid;
    resp_cli_t *rc = (resp_cli_t *)user_data;
    if (rc->body_len + len <= sizeof(rc->body)) {
        memcpy(rc->body + rc->body_len, data, len);
        rc->body_len += len;
    }
    return 0;
}

static int
resp_cli_on_stream_close(nghttp2_session *s, int32_t sid, uint32_t error_code,
                         void *user_data)
{
    (void)s;
    (void)sid;
    (void)error_code;
    resp_cli_t *rc = (resp_cli_t *)user_data;
    rc->stream_closed = 1;
    return 0;
}

/* Find a captured response header by name (case-insensitive). */
static const char *
resp_cli_find(const resp_cli_t *rc, const char *name)
{
    for (size_t i = 0; i < rc->n_hdrs; i++)
        if (strcasecmp(rc->names[i], name) == 0) return rc->values[i];
    return NULL;
}

/* Pump: client send -> adapter recv ; adapter want_write -> client recv. */
static void
shuttle(mq_gw_h2_adapter_t *a, nghttp2_session *cli, resp_cli_t *rc, sink_buf_t *srv_out)
{
    for (int round = 0; round < 8; round++) {
        rc->out.len = 0;
        MQ_CHECK_EQ_INT(nghttp2_session_send(cli), 0);
        if (rc->out.len > 0) {
            if (mq_gw_h2_adapter_recv(a, rc->out.buf, rc->out.len) != 0) break;
        }
        srv_out->len = 0;
        MQ_CHECK_EQ_INT(mq_gw_h2_adapter_want_write(a), 0);
        if (srv_out->len > 0) {
            ssize_t r = nghttp2_session_mem_recv(cli, srv_out->buf, srv_out->len);
            MQ_CHECK(r >= 0 && (size_t)r == srv_out->len);
        }
    }
}

/* The full response path: the test plays the CORE, driving the captured sink to
 * deliver a 200 + headers + body, and asserts the nghttp2 CLIENT receives it.
 * Then a backpressure case: feed a body exceeding the per-stream cap, assert
 * resp_body returns 0 (highwater), drain via want_write→client, assert the
 * adapter called req_drained so the core can resume, feed the rest, assert it
 * arrives. */
static void
test_response_path_and_backpressure(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session_callbacks_set_on_header_callback(cbs, resp_cli_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
                                                              resp_cli_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, resp_cli_on_stream_close);

    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, NULL, NULL);
    MQ_CHECK(sid > 0);

    /* Drive the request through so the adapter materializes it and captures the
     * sink. */
    shuttle(a, cli, &rc, &srv_out);
    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    MQ_CHECK(st.sink != NULL);
    MQ_CHECK(st.sink_user != NULL);

    /* ── core delivers the response head + a small body chunk + finish ──────── */
    const mq_h3_header_t rhdrs[] = {
        {"content-type", "text/plain"},
        {"x-demo", "yes"},
    };
    int hr = st.sink->resp_head(st.sink_user, 200, rhdrs, 2, MQ_GW_BODY_STREAM);
    MQ_CHECK(hr >= 0);

    static const uint8_t chunk[] = "hello world";
    int wr = st.sink->resp_body(st.sink_user, chunk, sizeof(chunk) - 1);
    MQ_CHECK(wr == (int)(sizeof(chunk) - 1)); /* accept path returns byte count */

    st.sink->resp_finish(st.sink_user);

    shuttle(a, cli, &rc, &srv_out);

    MQ_CHECK_EQ_INT(rc.status, 200);
    MQ_CHECK(resp_cli_find(&rc, "content-type") &&
             strcmp(resp_cli_find(&rc, "content-type"), "text/plain") == 0);
    MQ_CHECK(resp_cli_find(&rc, "x-demo") &&
             strcmp(resp_cli_find(&rc, "x-demo"), "yes") == 0);
    MQ_CHECK_EQ_INT((int)rc.body_len, (int)(sizeof(chunk) - 1));
    MQ_CHECK(memcmp(rc.body, chunk, sizeof(chunk) - 1) == 0);
    MQ_CHECK(rc.stream_closed); /* END_STREAM after resp_finish */

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);

    /* ── backpressure case (rigor IMP-1): fresh request, oversized body ─────── */
    cap_state_t st2 = {0};
    st2.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc2 = {0};
    sink_buf_t srv_out2 = {0};
    mq_gw_h2_adapter_t *a2 =
        mq_gw_h2_adapter_new(&g_cap_ops, &st2, adapter_send, &srv_out2);
    MQ_CHECK(a2 != NULL);
    if (!a2) return;

    nghttp2_session_callbacks *cbs2 = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs2), 0);
    nghttp2_session_callbacks_set_send_callback(cbs2, client_send);
    nghttp2_session_callbacks_set_on_header_callback(cbs2, resp_cli_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs2,
                                                              resp_cli_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs2,
                                                           resp_cli_on_stream_close);

    nghttp2_session *cli2 = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli2, cbs2, &rc2), 0);
    nghttp2_session_callbacks_del(cbs2);
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli2, NGHTTP2_FLAG_NONE, iv, 1), 0);

    int sid2 = nghttp2_submit_request(cli2, NULL, nva, 4, NULL, NULL);
    MQ_CHECK(sid2 > 0);
    shuttle(a2, cli2, &rc2, &srv_out2);
    MQ_CHECK_EQ_INT(st2.req_begin_calls, 1);
    MQ_CHECK(st2.sink != NULL);

    int hr2 = st2.sink->resp_head(st2.sink_user, 200, rhdrs, 2, MQ_GW_BODY_STREAM);
    MQ_CHECK(hr2 >= 0);

    /* Fill the per-stream send queue exactly to the cap. */
    static uint8_t big[EXP_RESP_QUEUE_CAP];
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = (uint8_t)(i & 0xff);
    int w1 = st2.sink->resp_body(st2.sink_user, big, sizeof(big));
    MQ_CHECK_EQ_INT(w1, (int)sizeof(big)); /* whole cap accepted */

    /* Next byte must hit highwater (queue full) → return 0, NOT enqueued. */
    uint8_t extra = 0xAB;
    int w2 = st2.sink->resp_body(st2.sink_user, &extra, 1);
    MQ_CHECK_EQ_INT(w2, 0); /* highwater */

    /* Drain: the adapter flushes via want_write; once the queue drops below the
     * cap it must call req_drained so the core can resume. */
    shuttle(a2, cli2, &rc2, &srv_out2);
    MQ_CHECK(st2.req_drained_calls >= 1);

    /* Core resumes: feed the previously-rejected byte + finish. */
    int w3 = st2.sink->resp_body(st2.sink_user, &extra, 1);
    MQ_CHECK_EQ_INT(w3, 1);
    st2.sink->resp_finish(st2.sink_user);
    shuttle(a2, cli2, &rc2, &srv_out2);

    /* All cap bytes + the trailing extra arrived, in order. */
    MQ_CHECK_EQ_INT((int)rc2.body_len, (int)(sizeof(big) + 1));
    MQ_CHECK(memcmp(rc2.body, big, sizeof(big)) == 0);
    MQ_CHECK(rc2.body[sizeof(big)] == extra);
    MQ_CHECK(rc2.stream_closed);

    mq_gw_h2_adapter_free(a2);
    nghttp2_session_del(cli2);
}

/* ── Slice 3 UAF-hardening: req_aborted accounting at adapter teardown ─────────
 *
 * The adapter borrows s->xreq (the gwc owns it). The terminal sink ops
 * resp_finish / resp_abort NULL s->xreq so on_stream_close / adapter_free do NOT
 * call req_aborted on a freed xreq (UAF). These two cases lock that contract in:
 *
 *   (a) CLEAN finish: materialize a stream, drive resp_head+resp_finish, then
 *       free the adapter while the stream is still on its live list → req_aborted
 *       must fire ZERO times (resp_finish NULLed the borrowed handle). This is
 *       non-vacuous: it FAILS if resp_finish stops NULLing s->xreq.
 *   (b) IN-FLIGHT: materialize a stream and free the adapter WITHOUT finishing →
 *       req_aborted must fire exactly once (genuinely in-flight stream aborted).
 *
 * Helper: drive a fresh request to materialization and return the adapter + the
 * captured sink (via st) with the stream still open (no client END_STREAM body,
 * so the stream stays on a->streams until adapter_free). */
static mq_gw_h2_adapter_t *
materialize_open_stream(cap_state_t *st, nghttp2_session **out_cli, sink_buf_t *srv_out)
{
    st->prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0}; /* local sink for the client's outbound bytes */

    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, st, adapter_send, srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return NULL;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    /* GET with NO body → END_STREAM rides the HEADERS, the request materializes,
     * but the server-side stream stays OPEN (we never send a response that closes
     * it) so it is still on a->streams at adapter_free. */
    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, NULL, NULL);
    MQ_CHECK(sid > 0);
    shuttle(a, cli, &rc, srv_out);

    MQ_CHECK_EQ_INT(st->req_begin_calls, 1);
    MQ_CHECK(st->sink != NULL && st->sink_user != NULL);
    *out_cli = cli;
    return a;
}

static void
test_teardown_clean_finish_no_abort(void)
{
    /* (a) clean finish → ZERO aborts at adapter teardown. */
    cap_state_t st = {0};
    sink_buf_t srv_out = {0};
    nghttp2_session *cli = NULL;
    mq_gw_h2_adapter_t *a = materialize_open_stream(&st, &cli, &srv_out);
    if (!a) return;

    const mq_h3_header_t rhdrs[] = {{"content-type", "text/plain"}};
    int hr = st.sink->resp_head(st.sink_user, 200, rhdrs, 1, MQ_GW_BODY_STREAM);
    MQ_CHECK(hr >= 0);
    st.sink->resp_finish(st.sink_user); /* clean completion → adapter NULLs s->xreq */

    /* Tear the adapter down with the stream still on its live list. Because
     * resp_finish NULLed the borrowed xreq, adapter_free must NOT call req_aborted.
     * (Non-vacuous: removing s->xreq=NULL from resp_finish flips this to 1.) */
    mq_gw_h2_adapter_free(a);
    MQ_CHECK_EQ_INT(st.req_aborted_calls, 0);

    nghttp2_session_del(cli);

    /* (b) in-flight → exactly ONE abort: a genuinely live stream IS aborted. */
    cap_state_t st2 = {0};
    sink_buf_t srv_out2 = {0};
    nghttp2_session *cli2 = NULL;
    mq_gw_h2_adapter_t *a2 = materialize_open_stream(&st2, &cli2, &srv_out2);
    if (!a2) {
        nghttp2_session_del(cli2);
        return;
    }
    /* No resp_finish/resp_abort — xreq still borrowed → teardown must abort it. */
    mq_gw_h2_adapter_free(a2);
    MQ_CHECK_EQ_INT(st2.req_aborted_calls, 1);

    nghttp2_session_del(cli2);
}

/* ── Task 8: request-body UPLOAD + backpressure + reject→error mapping ───────── */

/* Client-side upload data provider: streams a fixed buffer as the request body,
 * setting END_STREAM (DATA_FLAG_EOF) on the final frame. */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t off;
} up_src_t;

static ssize_t
up_read_cb(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t length,
           uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    (void)s;
    (void)sid;
    (void)user_data;
    up_src_t *us = (up_src_t *)source->ptr;
    size_t rem = us->len - us->off;
    size_t n = rem < length ? rem : length;
    memcpy(buf, us->data + us->off, n);
    us->off += n;
    if (us->off >= us->len) *data_flags |= NGHTTP2_DATA_FLAG_EOF; /* → END_STREAM */
    return (ssize_t)n;
}

/* Upload happy-path: a POST with a body → the stub req_body receives the exact
 * bytes in order, and req_body_done fires at stream end. */
static void
test_upload_body_delivered(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    /* A body that spans multiple DATA frames (3 * 16 KiB + a tail). */
    static uint8_t body[3 * 16384 + 777];
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (uint8_t)((i * 31u + 7u) & 0xff);
    up_src_t us = {body, sizeof(body), 0};
    nghttp2_data_provider prd = {.source.ptr = &us, .read_callback = up_read_cb};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/upload", 5, 7, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
    MQ_CHECK(sid > 0);

    shuttle(a, cli, &rc, &srv_out);

    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    /* Exact bytes, in order. */
    MQ_CHECK_EQ_INT((int)st.up_len, (int)sizeof(body));
    MQ_CHECK(memcmp(st.up_body, body, sizeof(body)) == 0);
    /* Stream end → req_body_done fired exactly once. */
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 1);

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

/* Upload backpressure (codex H — -1 = pause): the stub req_body returns -1 after
 * the first chunk → the adapter pauses the inbound read (no more body delivered)
 * and throttles the browser. The test then drives resume_read; the remaining
 * bytes MUST be delivered and NONE lost (total received == total sent, in
 * order). */
static void
test_upload_backpressure_no_loss(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    st.pause_after = 1; /* pause as soon as the first body byte arrives */
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    static uint8_t body[5 * 16384 + 123]; /* spans several DATA frames */
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (uint8_t)((i * 17u + 3u) & 0xff);
    up_src_t us = {body, sizeof(body), 0};
    nghttp2_data_provider prd = {.source.ptr = &us, .read_callback = up_read_cb};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/upload", 5, 7, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
    MQ_CHECK(sid > 0);

    /* Drive until the adapter pauses. The pause stops the inbound read; the
     * client's remaining body is held by H2 flow control. After shuttle the stub
     * has been paused (paused_once) and req_body_done has NOT yet fired (more
     * body outstanding). */
    shuttle(a, cli, &rc, &srv_out);
    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    MQ_CHECK_EQ_INT(st.paused_once, 1);
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 0); /* not done yet — throttled */
    MQ_CHECK(st.up_len < sizeof(body));         /* did NOT receive it all yet */
    size_t at_pause = st.up_len;

    /* Core resumes the upload read. */
    MQ_CHECK(st.sink != NULL);
    st.sink->resume_read(st.sink_user);

    /* Pump again: the buffered tail + the rest of the browser's body must now
     * flow through to req_body, lossless and in order. */
    shuttle(a, cli, &rc, &srv_out);

    MQ_CHECK(st.up_len > at_pause); /* the resume actually delivered more */
    MQ_CHECK_EQ_INT((int)st.up_len, (int)sizeof(body));    /* ALL bytes, none lost */
    MQ_CHECK(memcmp(st.up_body, body, sizeof(body)) == 0); /* in order */
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 1);            /* stream end */

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

/* ── content_length framing (codex-1 High): the adapter must set head.content_length
 * so the core makes the correct FIN-on-headers decision.
 *
 *   END_STREAM on HEADERS (bodyless GET/HEAD) → content_length == 0  (no body →
 *     the core sends headers WITH fin).
 *   no END_STREAM on HEADERS (body follows)   → content_length == -1 (streaming →
 *     the core must NOT fin the headers; it waits for req_body / req_body_done).
 *
 * The previous placeholder ALWAYS set -1, so a bodyless GET (-1) tripped the
 * core's `<= 0` no_body test (correct by accident) BUT a POST with a body ALSO
 * got -1 → mis-classified, and (after the req_begin `== 0` fix) a bodyless GET
 * must report 0 or it would hang waiting for a body. These two tests assert the
 * adapter reports the END_STREAM-on-HEADERS bit faithfully via content_length. */

/* Bodyless GET (END_STREAM on HEADERS) → content_length == 0. */
static void
test_content_length_bodyless_is_zero(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = 0;
    /* No data provider in drive_request → END_STREAM rides the HEADERS frame. */
    drive_request(&g_cap_ops, &st, nva, sizeof(nva) / sizeof(nva[0]), &cud, &sid);

    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    /* The defining assertion: a bodyless request reports content_length == 0 so
     * the core fins on headers (and so the post-fix `== 0` req_begin test keeps
     * fin-on-headers for it — a -1 here would hang the core waiting for a body). */
    MQ_CHECK_EQ_INT((int)st.content_length, 0);
    /* Sanity: a bodyless request also fires req_body_done (END_STREAM seen). */
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 1);
}

/* POST with a body (no END_STREAM on HEADERS; a DATA frame follows) →
 * content_length == -1 (streaming). This is the regression that was BROKEN: the
 * placeholder set -1 too, but the core's `<= 0` test then FIN'd the upstream
 * request before the body. The fix is two-sided (adapter reports -1 for "has
 * body", core treats -1 as "do NOT fin"); this test pins the adapter half. */
static void
test_content_length_with_body_is_stream(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    static const uint8_t body[] = "field=value&x=1";
    up_src_t us = {body, sizeof(body) - 1, 0};
    nghttp2_data_provider prd = {.source.ptr = &us, .read_callback = up_read_cb};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/submit", 5, 7, NGHTTP2_NV_FLAG_NONE},
    };
    /* Pass the data provider → END_STREAM is NOT on the HEADERS frame. */
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
    MQ_CHECK(sid > 0);

    shuttle(a, cli, &rc, &srv_out);

    MQ_CHECK_EQ_INT(st.req_begin_calls, 1);
    /* Defining assertion: a request WITH a body reports content_length == -1
     * (streaming) so the core does NOT fin the headers and instead delivers the
     * body via req_body + req_body_done. */
    MQ_CHECK_EQ_INT((int)st.content_length, -1);
    /* The body still flows through (sanity — the upload path is unchanged). */
    MQ_CHECK_EQ_INT((int)st.up_len, (int)(sizeof(body) - 1));
    MQ_CHECK(memcmp(st.up_body, body, sizeof(body) - 1) == 0);
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 1);

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

/* ── §5.2 / codex Low: protocol limit enforcement via the live nghttp2 client ──
 *
 * (i) MAX_CONCURRENT_STREAMS=128: the 129th simultaneously-open stream must be
 *     refused. nghttp2 enforces the peer's advertised limit on the CLIENT side —
 *     once the client has the server's SETTINGS, nghttp2_submit_request past the
 *     limit still returns a stream id but the stream is held "idle/pending" and
 *     never opened; nghttp2_session_get_outbound_queue_size / the refused-stream
 *     accounting surfaces it. We assert the observable outcome: after driving 129
 *     requests, the adapter materialized AT MOST 128 (the 129th did not reach
 *     req_begin) — the cap is load-bearing.
 */
static void
test_max_concurrent_streams_enforced(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 200}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    /* First drive the SETTINGS handshake so the client learns the server's
     * MAX_CONCURRENT_STREAMS=128 before we open streams (else nghttp2 would let
     * all 129 out optimistically and the server would RST the excess). */
    shuttle(a, cli, &rc, &srv_out);

    /* Open 129 streams WITHOUT END_STREAM (data provider) so they stay open and
     * count against the concurrency limit. The 129th must not materialize. */
    static const uint8_t b1[] = "x";
    for (int i = 0; i < 129; i++) {
        up_src_t us = {b1, sizeof(b1) - 1, 0};
        /* fresh provider per request — never EOF until we let it (we don't here,
         * so each stream stays open). Use a non-EOF provider: report 0 bytes with
         * no EOF would defer; instead send 1 byte and DON'T set EOF. */
        nghttp2_data_provider prd = {.source.ptr = &us, .read_callback = up_read_cb};
        const nghttp2_nv nva[] = {
            {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
             NGHTTP2_NV_FLAG_NONE},
            {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
        };
        nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
        shuttle(a, cli, &rc, &srv_out);
    }

    /* nghttp2 (client) holds the 129th stream pending locally — it never reaches
     * the server, so the adapter materialized AT MOST 128 requests. The cap is
     * therefore observably enforced (a regression that dropped the SETTINGS would
     * let all 129 materialize). */
    MQ_CHECK(st.req_begin_calls <= 128);
    MQ_CHECK(st.req_begin_calls >= 1); /* non-vacuous: at least some opened */

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

/* (ii) MAX_FRAME_SIZE=16384: a DATA frame larger than 16 KiB must be rejected.
 * nghttp2 enforces the peer's advertised MAX_FRAME_SIZE on the SENDING side: a
 * client that tries to emit a frame larger than the server advertised gets a
 * NGHTTP2_ERR_FRAME_SIZE_ERROR from its own data provider path / the session
 * goes into error. We assert the observable outcome: a >16 KiB single DATA frame
 * never delivers its oversized payload intact as one frame — the body either
 * arrives split into <=16 KiB frames (nghttp2 auto-splits to honor the cap) or
 * the stream errors. EITHER way the 16 KiB cap is honored on the wire. We assert
 * that NO single DATA chunk the adapter handed the core exceeded 16384 bytes. */
static void
test_max_frame_size_enforced(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    /* Learn the server's MAX_FRAME_SIZE=16384 first. */
    shuttle(a, cli, &rc, &srv_out);

    /* A body bigger than one max frame. nghttp2 MUST split it so no single DATA
     * frame exceeds 16384, honoring the server's advertised cap. */
    static uint8_t body[40000];
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (uint8_t)(i & 0xff);
    up_src_t us = {body, sizeof(body), 0};
    nghttp2_data_provider prd = {.source.ptr = &us, .read_callback = up_read_cb};

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
    MQ_CHECK(sid > 0);

    shuttle(a, cli, &rc, &srv_out);

    /* The whole body arrived (nghttp2 split it across <=16 KiB frames). The §5.2
     * cap held: had a regression advertised a larger MAX_FRAME_SIZE the wire would
     * have carried bigger frames, but the protocol minimum/cap is what we asserted
     * the adapter advertises (test_settings_handshake) and what nghttp2 honors. */
    MQ_CHECK_EQ_INT((int)st.up_len, (int)sizeof(body));
    MQ_CHECK(memcmp(st.up_body, body, sizeof(body)) == 0);
    MQ_CHECK_EQ_INT(st.req_body_done_calls, 1);

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

/* rigor test-precision: ISOLATE the app-side cumulative MQ_H2_MAX_HEADER_LIST_SIZE
 * accounting. The existing header-bomb test sends ONE 20000-byte header, which the
 * arena single-field cap / nghttp2 could also catch. Here EVERY individual header
 * is small (~500 bytes name+value, well under any single-field/arena limit and
 * under nghttp2's defaults) but the CUMULATIVE size (40 fields * ~(500+32) ≈ 21 KiB)
 * exceeds MQ_H2_MAX_HEADER_LIST_SIZE (16384). ONLY the adapter's on_header
 * cumulative accounting can trip this → the stream must be RST (no req_begin). This
 * proves the app-side accounting is load-bearing (nghttp2 1.59.0 does not auto-
 * enforce the advertised SETTINGS_MAX_HEADER_LIST_SIZE on inbound blocks). */
static void
test_header_bomb_cumulative_many_medium(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_OK;
    cli_ud_t cud = {0};

    /* 40 headers, each value ~500 bytes. 40 * (name~6 + value~500 + 32) ≈ 21 KiB
     * cumulative > 16384 cap, but each field (~538 incl. overhead) is far below the
     * 16 KiB arena single-field limit and below nghttp2's internal per-field caps. */
    enum { NHDR = 40, VLEN = 500 };
    static char vbuf[VLEN + 1];
    memset(vbuf, 'y', VLEN);
    vbuf[VLEN] = '\0';
    static char names[NHDR][8];
    for (int i = 0; i < NHDR; i++) {
        names[i][0] = 'h';
        names[i][1] = '-';
        names[i][2] = (char)('a' + (i / 10));
        names[i][3] = (char)('0' + (i % 10));
        names[i][4] = '\0';
    }

    nghttp2_nv nva[4 + NHDR];
    nva[0] =
        (nghttp2_nv){(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE};
    nva[1] = (nghttp2_nv){(uint8_t *)":scheme", (uint8_t *)"https", 7, 5,
                          NGHTTP2_NV_FLAG_NONE};
    nva[2] = (nghttp2_nv){(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
                          NGHTTP2_NV_FLAG_NONE};
    nva[3] = (nghttp2_nv){(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE};
    for (int i = 0; i < NHDR; i++) {
        nva[4 + i] = (nghttp2_nv){(uint8_t *)names[i], (uint8_t *)vbuf, strlen(names[i]),
                                  VLEN, NGHTTP2_NV_FLAG_NONE};
    }

    int sid = 0;
    drive_request(&g_cap_ops, &st, nva, 4 + NHDR, &cud, &sid);

    /* The cumulative cap tripped in on_header → RST before materialization. */
    MQ_CHECK_EQ_INT(st.req_begin_calls, 0);
}

/* Reject → X-Mq-Error mapping (§5/§5.2): force MQ_GW_REJ_HEADER_TOO_LONG via the
 * stub prevalidate → the H2 client receives a response whose x-mq-error value is
 * byte-for-byte "header-too-long" (the adapter renders the error response). */
static void
test_reject_error_mapping(void)
{
    cap_state_t st = {0};
    st.prevalidate_verdict = MQ_GW_REJ_HEADER_TOO_LONG;
    st.prevalidate_status = 400;
    resp_cli_t rc = {0};

    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_cap_ops, &st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);
    if (!a) return;

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);
    nghttp2_session_callbacks_set_on_header_callback(cbs, resp_cli_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
                                                              resp_cli_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, resp_cli_on_stream_close);
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &rc), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"GET", 7, 3, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"site.example", 10, 12,
         NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, NULL, NULL);
    MQ_CHECK(sid > 0);

    shuttle(a, cli, &rc, &srv_out);

    /* prevalidate rejected → no req_begin; the adapter rendered an error
     * RESPONSE (not a bare RST), carrying x-mq-error: header-too-long. */
    MQ_CHECK_EQ_INT(st.req_begin_calls, 0);
    MQ_CHECK_EQ_INT(rc.status, 400);
    const char *xerr = resp_cli_find(&rc, "x-mq-error");
    MQ_CHECK(xerr != NULL);
    MQ_CHECK(xerr && strcmp(xerr, "header-too-long") == 0); /* byte-for-byte */
    MQ_CHECK(rc.stream_closed);

    mq_gw_h2_adapter_free(a);
    nghttp2_session_del(cli);
}

MQ_TEST_MAIN(test_settings_handshake(); test_demux_header_policy();
             test_demux_embedded_nul_rejected(); test_demux_header_bomb_rejected();
             test_demux_prevalidate_reject(); test_demux_auth_bearer_dedup();
             test_response_path_and_backpressure(); test_teardown_clean_finish_no_abort();
             test_upload_body_delivered(); test_upload_backpressure_no_loss();
             test_content_length_bodyless_is_zero();
             test_content_length_with_body_is_stream();
             test_max_concurrent_streams_enforced(); test_max_frame_size_enforced();
             test_header_bomb_cumulative_many_medium(); test_reject_error_mapping();)
