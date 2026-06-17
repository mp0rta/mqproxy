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

MQ_TEST_MAIN(test_settings_handshake();)
