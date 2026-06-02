// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_conn_handshake.c — Task 10 integration test.
 *
 * Drives a real loopback MPQUIC handshake between two engines sharing one
 * libevent base:
 *   - a server-mode mq_engine with a self-signed cert/key, ALPN
 *     "mqproxy-tcp/1" registered, bound to 127.0.0.1:<ephemeral> via mq_path;
 *   - a client-mode mq_engine + mq_path that mq_conn_connect()s to the
 *     server's bound address.
 *
 * The loop is pumped (EVLOOP_NONBLOCK) under a bounded wall-clock budget
 * until the client's on_state callback reports ESTABLISHED. Then everything
 * is torn down and the test must be ASan-clean.
 *
 * No application stream data is exchanged — this validates handshake only.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <event2/event.h>

#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "transport/mq_path.h"
#include "transport/mq_stream.h"

#define TEST_ALPN "mqproxy-tcp/1"

/* Cert/key paths injected by CMake (generated at build time if missing). */
#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

static int g_client_established;
static int g_client_closed;

static void
on_client_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    (void)user;
    if (st == MQ_CONN_ESTABLISHED) {
        g_client_established = 1;
    } else if (st == MQ_CONN_CLOSED) {
        g_client_closed = 1;
    }
}

/* Server-side: accepted connections surface here (Task 11/12 consumes this). */
static int g_server_conn_seen;
static void
on_server_conn(mq_conn_t *c, void *user)
{
    (void)c;
    (void)user;
    g_server_conn_seen = 1;
}

static int g_server_stream_seen;
static void
on_server_stream(mq_stream_t *s, void *user)
{
    (void)s;
    (void)user;
    g_server_stream_seen = 1;
}

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void
test_conn_handshake(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    /* ── Server ── */
    mq_engine_t *srv = mq_engine_new_server(base, TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv != NULL);

    int rc =
        mq_conn_register_alpn(srv, TEST_ALPN, on_server_conn, on_server_stream, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    mq_path_t *srv_path = mq_path_open(srv, /*path_id=*/0, "127.0.0.1", /*port=*/0);
    MQ_CHECK(srv_path != NULL);

    struct sockaddr_storage srv_addr;
    socklen_t srv_addrlen = 0;
    MQ_CHECK_EQ_INT(mq_path_local_addr(srv_path, &srv_addr, &srv_addrlen), 0);

    /* ── Client ── */
    mq_engine_t *cli = mq_engine_new(/*is_server=*/0, base);
    MQ_CHECK(cli != NULL);

    rc = mq_conn_register_alpn(cli, TEST_ALPN, NULL, NULL, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    mq_path_t *cli_path = mq_path_open(cli, /*path_id=*/0, "127.0.0.1", /*port=*/0);
    MQ_CHECK(cli_path != NULL);

    if (!srv || !cli || !srv_path || !cli_path) {
        goto cleanup;
    }

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;

    mq_conn_t *conn = mq_conn_connect(cli, (struct sockaddr *)&srv_addr, srv_addrlen,
                                      TEST_ALPN, &settings, NULL);
    MQ_CHECK(conn != NULL);
    if (!conn) goto cleanup;

    mq_conn_set_on_state(conn, on_client_state, NULL);

    /* Pump both engines (shared base) until established or 3s budget. */
    uint64_t deadline = now_ms() + 3000;
    while (!g_client_established && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }

    MQ_CHECK(g_client_established);
    MQ_CHECK(g_server_conn_seen);

    /* Bonus: open one client stream and confirm the server's
     * stream_create_notify fires (validates the mq_stream wrappers + the ALP
     * stream callback wiring). A short send forces the stream to be opened on
     * the wire. */
    mq_stream_t *cs = mq_conn_open_stream(conn);
    MQ_CHECK(cs != NULL);
    if (cs) {
        static const unsigned char hello[] = "hi";
        long sent = mq_stream_send(cs, hello, sizeof(hello), /*fin=*/1);
        MQ_CHECK(sent >= 0);
    }

    uint64_t stream_deadline = now_ms() + 1000;
    while (!g_server_stream_seen && now_ms() < stream_deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK(g_server_stream_seen);

    mq_conn_close(conn);

    /* Pump briefly so close frames flush and callbacks fire. */
    uint64_t close_deadline = now_ms() + 500;
    while (now_ms() < close_deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }

cleanup:
    if (cli_path) mq_path_close(cli_path);
    if (srv_path) mq_path_close(srv_path);
    if (cli) mq_engine_free(cli);
    if (srv) mq_engine_free(srv);
    event_base_free(base);
}

MQ_TEST_MAIN(test_conn_handshake())
