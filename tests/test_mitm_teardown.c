// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// Unit tests for the LIVE MITM conn registry + ordered teardown + re-entrancy
// (Phase 7 Slice 3 Task 11), WITHOUT a real TLS handshake.
//
// We build N real mq_gw_h2_adapter SERVER sessions, drive a real nghttp2 CLIENT
// request through each so each adapter holds ONE in-flight stream with a non-NULL
// xreq (a request WITH a body but NO END_STREAM → the stream stays open). Then we
// register each adapter in a live MITM conn via mq_mitm_conn_make_live_for_test
// and call mq_mitm_ctx_free.
//
// ASSERTION: mq_mitm_ctx_free drains the registry; each conn's teardown frees its
// H2 adapter, and mq_gw_h2_adapter_free drives submit->req_aborted on every
// in-flight xreq EXACTLY ONCE (the adapter→core "local gone" direction, codex
// H8). ASan/LSan must be clean (no UAF, no leak, no double-free) — which is the
// real point of the test.
//
// The SSL is NULL in this seam (no real handshake): the teardown path tolerates a
// NULL ssl (SSL_free(NULL) is a no-op) and a real local_fd from a socketpair
// (closed in teardown). The live TLS handshake itself is covered by the e2e.
#include "mqtest.h"

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "gateway/mq_gw_h2_adapter.h"
#include "mitm/mq_mitm_conn.h"
#include "wire/mq_wire.h"

#include <event2/event.h>

// ── per-stub state: counts req_aborted per fake xreq ─────────────────────────
//
// One stub_state_t per adapter. Its address is the xreq sentinel returned from
// req_begin, so cap_req_aborted(r) can bump the right counter and we can assert
// "exactly once per stream".

typedef struct {
    int aborted_calls; // how many times req_aborted fired on THIS xreq
} stub_state_t;

static mq_gw_reject_reason_t
stub_prevalidate(void *u, const mq_h3_header_t *h, size_t n, int *status)
{
    (void)u;
    (void)h;
    (void)n;
    if (status) *status = 200;
    return MQ_GW_OK;
}

static mq_gw_xreq_t *
stub_req_begin(void *u, const mq_gw_req_head_t *head, const mq_gw_sink_ops_t *sink,
               void *sink_user, int *err_status, mq_gw_reject_reason_t *reason)
{
    (void)head;
    (void)sink;
    (void)sink_user;
    (void)err_status;
    (void)reason;
    // Return the stub_state_t* as the xreq sentinel.
    return (mq_gw_xreq_t *)u;
}

static int
stub_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    (void)r;
    (void)p;
    (void)len;
    return 0; // accept; never pause
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
    stub_state_t *st = (stub_state_t *)r;
    if (st) st->aborted_calls++;
}
static const char *
stub_auth_token(void *u)
{
    (void)u;
    return "tok";
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

// ── byte shuttle (no sockets/TLS for the adapter itself) ─────────────────────

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

// A deferred data provider: the client request carries a body that never ends, so
// the server-side stream stays OPEN (in-flight) — never END_STREAM, never closed.
static ssize_t
defer_body(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t length,
           uint32_t *data_flags, nghttp2_data_source *src, void *ud)
{
    (void)s;
    (void)sid;
    (void)buf;
    (void)length;
    (void)data_flags;
    (void)src;
    (void)ud;
    return NGHTTP2_ERR_DEFERRED; // nothing to send yet → stream stays open
}

// Build one adapter holding one in-flight stream whose xreq == &st. Returns the
// adapter (caller hands it to a live conn).
static mq_gw_h2_adapter_t *
make_inflight_adapter(stub_state_t *st)
{
    sink_buf_t srv_out = {0};
    mq_gw_h2_adapter_t *a = mq_gw_h2_adapter_new(&g_stub_ops, st, adapter_send, &srv_out);
    MQ_CHECK(a != NULL);

    nghttp2_session_callbacks *cbs = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_callbacks_new(&cbs), 0);
    nghttp2_session_callbacks_set_send_callback(cbs, client_send);

    sink_buf_t cli_out = {0};
    nghttp2_session *cli = NULL;
    MQ_CHECK_EQ_INT(nghttp2_session_client_new(&cli, cbs, &cli_out), 0);
    nghttp2_session_callbacks_del(cbs);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    MQ_CHECK_EQ_INT(nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, iv, 1), 0);

    const nghttp2_nv nva[] = {
        {(uint8_t *)":method", (uint8_t *)"POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":authority", (uint8_t *)"example.com", 10, 11, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *)":path", (uint8_t *)"/", 5, 1, NGHTTP2_NV_FLAG_NONE},
    };
    nghttp2_data_provider prd = {.source = {.ptr = NULL}, .read_callback = defer_body};
    int sid = nghttp2_submit_request(cli, NULL, nva, 4, &prd, NULL);
    MQ_CHECK(sid > 0);

    // Shuttle until the adapter has materialized the request (req_begin → xreq set).
    for (int round = 0; round < 6; round++) {
        cli_out.len = 0;
        MQ_CHECK_EQ_INT(nghttp2_session_send(cli), 0);
        if (cli_out.len > 0)
            MQ_CHECK_EQ_INT(mq_gw_h2_adapter_recv(a, cli_out.buf, cli_out.len), 0);

        srv_out.len = 0;
        MQ_CHECK_EQ_INT(mq_gw_h2_adapter_want_write(a), 0);
        if (srv_out.len > 0) {
            ssize_t r = nghttp2_session_mem_recv(cli, srv_out.buf, srv_out.len);
            MQ_CHECK(r >= 0 && (size_t)r == srv_out.len);
        }
    }

    nghttp2_session_del(cli);
    return a;
}

// Stub opaque_open (never invoked in these MITM-only tests, but required by
// mq_mitm_ctx_new).
static void
stub_opaque_open(void *core, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                 uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
                 void *user, mq_tcp_open_cb cb)
{
    (void)core;
    (void)host;
    (void)host_len;
    (void)atype;
    (void)port;
    (void)local_fd;
    (void)prebuf;
    (void)prebuf_len;
    (void)user;
    (void)cb;
}

// N live MITM conns, each with one in-flight stream → mq_mitm_ctx_free → each
// stream's req_aborted fires exactly once; clean teardown (ASan/LSan).
static void
test_ctx_free_aborts_each_inflight_once(void)
{
    enum { N = 4 };
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);

    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL, base);
    MQ_CHECK(ctx != NULL);

    stub_state_t st[N] = {{0}};
    int fds[N];

    for (int i = 0; i < N; i++) {
        mq_gw_h2_adapter_t *a = make_inflight_adapter(&st[i]);
        MQ_CHECK(a != NULL);
        // A real fd (socketpair end) so teardown's close() touches a valid fd.
        int sp[2];
        MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
        fds[i] = sp[1];
        close(sp[0]); // we only need the conn-owned end to be a real fd
        MQ_CHECK_EQ_INT(mq_mitm_conn_make_live_for_test(ctx, a, /*ssl=*/NULL, fds[i]), 0);
    }

    // Tear everything down. Each conn: adapter_free (→ req_aborted per stream) →
    // SSL_free(NULL) → close(fd) → unlink → free.
    mq_mitm_ctx_free(ctx);

    for (int i = 0; i < N; i++)
        MQ_CHECK_EQ_INT(st[i].aborted_calls, 1); // exactly once per in-flight stream

    event_base_free(base);
}

// A live conn with NO adapter and fd=-1 still tears down cleanly (exercises the
// NULL-adapter / no-fd branch of conn_destroy).
static void
test_ctx_free_empty_conn(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL, base);
    MQ_CHECK(ctx != NULL);

    MQ_CHECK_EQ_INT(
        mq_mitm_conn_make_live_for_test(ctx, /*adapter=*/NULL, /*ssl=*/NULL, /*fd=*/-1),
        0);
    mq_mitm_ctx_free(ctx);
    event_base_free(base);
}

// H-1: the LIVE-phase idle timer fires → conn teardown via conn_close (deferred
// free). We build N live conns (each with one in-flight stream), arm the idle
// timer with a zero timeout, then run the loop: on_idle fires for each, routes
// through conn_close (deferred), and the next loop iteration reaps via free_ev.
// ASSERTION: each conn was actually torn down by the idle path (req_aborted fired
// exactly once per in-flight stream), and ASan/LSan is clean (no UAF from the
// timer firing into the conn, no leak).
static void
test_live_idle_timeout_tears_down(void)
{
    enum { N = 3 };
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);

    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL, base);
    MQ_CHECK(ctx != NULL);

    stub_state_t st[N] = {{0}};
    for (int i = 0; i < N; i++) {
        mq_gw_h2_adapter_t *a = make_inflight_adapter(&st[i]);
        MQ_CHECK(a != NULL);
        int sp[2];
        MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
        close(sp[0]);
        MQ_CHECK_EQ_INT(mq_mitm_conn_make_live_for_test(ctx, a, /*ssl=*/NULL, sp[1]), 0);
    }

    // Arm the idle timer (zero timeout) on every live conn.
    MQ_CHECK_EQ_INT(mq_mitm_conn_arm_idle_now_for_test(ctx), N);

    // Drive expiry: first pass fires each on_idle → conn_close (queues deferred
    // free + activates free_ev); subsequent passes reap via free_ev. Loop until
    // the base is idle so both the timers AND the deferred reap have run.
    for (int i = 0; i < 8 && event_base_loop(base, EVLOOP_NONBLOCK) == 0; i++) {
        // event_base_loop returns 1 when no events remain pending — stop then.
        if (event_base_get_num_events(base, EVENT_BASE_COUNT_ACTIVE |
                                                EVENT_BASE_COUNT_ADDED) == 0)
            break;
    }

    // Every in-flight stream was aborted exactly once → teardown ran via the idle
    // path. (If the idle timer had NOT torn the conn down, these would be 0.)
    for (int i = 0; i < N; i++)
        MQ_CHECK_EQ_INT(st[i].aborted_calls, 1);

    // ctx_free now has an empty registry (all conns reaped). Still must be clean.
    mq_mitm_ctx_free(ctx);
    event_base_free(base);
}

MQ_TEST_MAIN({
    test_ctx_free_aborts_each_inflight_once();
    test_ctx_free_empty_conn();
    test_live_idle_timeout_tears_down();
})
