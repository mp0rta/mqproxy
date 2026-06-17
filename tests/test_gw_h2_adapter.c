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
    uint8_t buf[64 * 1024];
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
    (void)sink;
    (void)sink_user;
    (void)err_status;
    (void)reason;
    st->req_begin_calls++;
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
     * The boundary ops (body/drain/abort) are never driven in these header-only
     * tests, so the pointer is never dereferenced. */
    return (mq_gw_xreq_t *)st;
}

static int
cap_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    (void)r;
    (void)p;
    (void)len;
    return 0;
}
static void
cap_req_body_done(mq_gw_xreq_t *r)
{
    (void)r;
}
static void
cap_req_drained(mq_gw_xreq_t *r)
{
    (void)r;
}
static void
cap_req_aborted(mq_gw_xreq_t *r)
{
    (void)r;
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

MQ_TEST_MAIN(test_settings_handshake(); test_demux_header_policy();
             test_demux_embedded_nul_rejected(); test_demux_header_bomb_rejected();
             test_demux_prevalidate_reject(); test_demux_auth_bearer_dedup();)
