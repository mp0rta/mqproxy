// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_conn_handshake.c — loopback MPQUIC handshake over mq_transport+mq_runtime.
 *
 * Drives a real loopback MPQUIC handshake between two transport cores sharing one
 * libevent base:
 *   - a server-mode mq_transport with a self-signed cert/key, ALPN
 *     "mqproxy-tcp/1" registered, whose runtime binds the primary path to
 *     127.0.0.1:<reserved ephemeral port>;
 *   - a client-mode mq_transport whose runtime binds 127.0.0.1:0 and whose
 *     mq_conn_connect()s to the server's bound address.
 *
 * Both runtimes BORROW the shared base; the test pumps it with
 * event_base_loop(EVLOOP_NONBLOCK) under a bounded wall-clock budget until the
 * client's on_state callback reports ESTABLISHED. Then everything is torn down
 * and the test must be ASan-clean.
 *
 * No application stream data is exchanged beyond a tiny stream to validate the
 * stream callback wiring — this validates handshake only.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"

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

/* Server-side: accepted connections surface here. */
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

/* Reserve an ephemeral loopback UDP port: bind a temp socket to :0, read the
 * assigned port, then close it so the runtime can bind that fixed port. The
 * runtime no longer exposes the bound port of an ephemeral (:0) bind, so the
 * test pins a concrete port for the server up front. */
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

static void
test_conn_handshake(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    uint16_t srv_port = reserve_udp_port();
    MQ_CHECK(srv_port != 0);

    /* ── Server: transport (with TLS) + runtime borrowing the shared base ── */
    mq_transport_t *srv_t = mq_transport_new_server(/*cbs=*/NULL, /*user=*/NULL,
                                                    TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv_t != NULL);
    mq_runtime_t *srv_rt = srv_t ? mq_runtime_new(srv_t, base) : NULL;
    MQ_CHECK(srv_rt != NULL);

    int rc = srv_t ? mq_conn_register_alpn(srv_t, TEST_ALPN, on_server_conn,
                                           on_server_stream, NULL)
                   : -1;
    MQ_CHECK_EQ_INT(rc, 0);

    int srv_bound = srv_rt ? mq_runtime_open_udp_path(srv_rt, "127.0.0.1", srv_port) : -1;
    MQ_CHECK_EQ_INT(srv_bound, 0);

    /* ── Client: transport + runtime borrowing the SAME shared base ── */
    mq_transport_t *cli_t =
        mq_transport_new(/*is_server=*/0, /*cbs=*/NULL, /*user=*/NULL);
    MQ_CHECK(cli_t != NULL);
    mq_runtime_t *cli_rt = cli_t ? mq_runtime_new(cli_t, base) : NULL;
    MQ_CHECK(cli_rt != NULL);

    rc = cli_t ? mq_conn_register_alpn(cli_t, TEST_ALPN, NULL, NULL, NULL) : -1;
    MQ_CHECK_EQ_INT(rc, 0);

    int cli_bound = cli_rt ? mq_runtime_open_udp_path(cli_rt, "127.0.0.1", 0) : -1;
    MQ_CHECK_EQ_INT(cli_bound, 0);

    if (!srv_t || !srv_rt || !cli_t || !cli_rt || srv_bound != 0 || cli_bound != 0) {
        goto cleanup;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port = htons(srv_port);

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;

    mq_conn_t *conn = mq_conn_connect(cli_t, (struct sockaddr *)&srv_addr,
                                      sizeof(srv_addr), TEST_ALPN, &settings, NULL);
    MQ_CHECK(conn != NULL);
    if (!conn) goto cleanup;

    mq_conn_set_on_state(conn, on_client_state, NULL);

    /* Pump both sides (shared base) until established or 3s budget. */
    uint64_t deadline = now_ms() + 3000;
    while (!g_client_established && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }

    MQ_CHECK(g_client_established);
    MQ_CHECK(g_server_conn_seen);

    /* Bonus: open one client stream and confirm the server's
     * stream_create_notify fires (validates the mq_stream wrappers + the ALP
     * stream callback wiring). A short send forces the stream open on the wire. */
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
    /* Per side: free the transport first (engine destroy; callbacks land on the
     * still-live runtime), then the runtime (which BORROWED the base, so it does
     * NOT free it). The test owns the shared base and frees it last. */
    if (cli_t) mq_transport_free(cli_t);
    if (srv_t) mq_transport_free(srv_t);
    if (cli_rt) mq_runtime_free(cli_rt);
    if (srv_rt) mq_runtime_free(srv_rt);
    event_base_free(base);
}

MQ_TEST_MAIN(test_conn_handshake())
