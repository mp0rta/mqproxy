// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_metrics_active_conn.c — Phase 5c Task 3: mq_server_active_conn lifecycle.
 *
 * Stands up one real mq_client + one real mq_server on a single shared libevent
 * base (loopback), runs the handshake + AUTH, and asserts:
 *   1. After auth, mq_server_active_conn(server) is non-NULL (set in
 *      srv_on_new_conn).
 *   2. mq_conn_dump_stats() on that pointer does not crash/leak (ASan smoke;
 *      the CLI in Task 4 will call this on the server side).
 *   3. After the client conn closes, the server's clear-if-self guard fires and
 *      mq_server_active_conn(server) returns NULL — i.e. the observability
 *      pointer is never left dangling (UAF guard).
 *
 * Client reconnect is disabled before start: default-on reconnect would re-dial
 * after the close, re-setting last_conn non-NULL and racing the == NULL assert.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_transport.h"

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Reserve an ephemeral loopback UDP port: bind a temp socket to :0, read the
 * assigned port, then close it so the server runtime can bind that fixed port. */
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

static int g_auth_fired;
static int g_auth_ok;

static void
on_auth(int ok, mq_auth_err_t err, void *user)
{
    (void)err;
    (void)user;
    g_auth_fired = 1;
    g_auth_ok = ok;
}

/* Shared-base client+server fixture (mirrors test_client_server.c). */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
} fixture_t;

static int
fixture_up(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

    uint16_t port = reserve_udp_port();
    MQ_CHECK(port != 0);
    if (!port) return -1;

    /* Server: transport (TLS) + runtime borrowing the shared base. */
    f->srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(f->srv_t != NULL);
    if (!f->srv_t) return -1;
    f->srv_rt = mq_runtime_new(f->srv_t, f->base);
    MQ_CHECK(f->srv_rt != NULL);
    if (!f->srv_rt) return -1;
    f->server = mq_server_new(f->srv_t, f->srv_rt, "secret", MQ_CC_BBR2, 60000, 1);
    MQ_CHECK(f->server != NULL);
    if (!f->server) return -1;

    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(f->srv_rt, "127.0.0.1", port), 0);

    /* Client: transport + runtime borrowing the SAME shared base. */
    f->cli_t = mq_transport_new(0);
    MQ_CHECK(f->cli_t != NULL);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    MQ_CHECK(f->cli_rt != NULL);
    if (!f->cli_rt) return -1;

    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0), 0);

    f->client = mq_client_new(f->cli_t, f->cli_rt, "127.0.0.1", port, "client-1",
                              "secret", MQ_CC_BBR2);
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;
    mq_client_set_on_auth(f->client, on_auth, NULL);
    /* CRITICAL: disable reconnect before start. Default-on reconnect would
     * re-dial after the close below, re-setting last_conn non-NULL and racing
     * the == NULL assertion. */
    mq_client_set_reconnect(f->client, 0, 30000);

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Per side: free the transport FIRST (engine destroy fires conn_close_notify
     * -> the client/server state callbacks), so the runtime + client + server
     * must outlive the transport. Then the runtimes (which BORROWED the shared
     * base, so they do NOT free it), then the proxy objects. The test owns the
     * shared base and frees it last. */
    if (f->cli_t) mq_transport_free(f->cli_t);
    if (f->srv_t) mq_transport_free(f->srv_t);
    if (f->cli_rt) mq_runtime_free(f->cli_rt);
    if (f->srv_rt) mq_runtime_free(f->srv_rt);
    if (f->client) mq_client_free(f->client);
    if (f->server) mq_server_free(f->server);
    if (f->base) event_base_free(f->base);
}

static void
pump_until(struct event_base *base, int *flag, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while ((!flag || !*flag) && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

/* Pump until the server's active-conn accessor goes NULL (or the budget runs
 * out). Cannot use pump_until's int* flag form since the predicate is an
 * accessor call, so spin a bounded loop directly. */
static void
pump_until_active_null(fixture_t *f, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (mq_server_active_conn(f->server) != NULL && now_ms() < deadline) {
        event_base_loop(f->base, EVLOOP_NONBLOCK);
    }
}

static void
test_active_conn_lifecycle(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    /* Pump until the client has authed → the server has accepted the conn. */
    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_fired);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);

    /* (1) The server tracks the accepted conn. */
    mq_conn_t *active = mq_server_active_conn(f.server);
    MQ_CHECK(active != NULL);

    /* (2) ASan smoke: dumping stats on the live conn must not crash/leak. This
     * is exactly what the Task 4 CLI will call on the server side. */
    mq_conn_dump_stats(mq_server_active_conn(f.server));

    /* (3) Close the client conn; pump until the server observes MQ_CONN_CLOSED
     * and the clear-if-self guard NULLs last_conn. Reconnect is off, so there is
     * no re-dial to re-set it. */
    mq_conn_close(mq_client_conn(f.client));
    pump_until_active_null(&f, 3000);

    MQ_CHECK(mq_server_active_conn(f.server) == NULL);

    fixture_down(&f);
}

MQ_TEST_MAIN(test_active_conn_lifecycle())
