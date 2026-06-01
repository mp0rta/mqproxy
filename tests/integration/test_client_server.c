/* test_client_server.c — Task 11 integration test: control-stream AUTH.
 *
 * Two engines (server with cert/key + client) share one libevent base on
 * loopback. The client opens the control stream (first client-initiated bidi
 * stream) and sends AUTH_REQUEST; the server replies AUTH_RESPONSE on the same
 * stream.
 *
 * This task tests ONLY the auth FAILURE path + control-stream identification:
 *   Case A — wrong token: on_auth fires ok==0 / MQ_AUTH_FAILED and the client
 *            connection subsequently closes.
 *   Case B — matching token: on_auth fires ok==1, and the server ran auth on
 *            exactly the first stream (auth-attempt counter == 1) even though
 *            the client opens a second (data) stream afterward.
 *
 * Happy-path data exchange is covered by Tasks 12/13.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <event2/event.h>

#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "transport/mq_path.h"
#include "transport/mq_stream.h"

#define TEST_ALPN "mqproxy-tcp/1"

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

/* ── auth-callback bookkeeping ──────────────────────────────────────────── */
static int g_auth_fired;
static int g_auth_ok;
static mq_auth_err_t g_auth_err;

static void
on_auth(int ok, mq_auth_err_t err, void *user)
{
    (void)user;
    g_auth_fired = 1;
    g_auth_ok = ok;
    g_auth_err = err;
}

static int g_client_closed;
static void
on_client_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    (void)user;
    if (st == MQ_CONN_CLOSED) {
        g_client_closed = 1;
    }
}

/* Stand up a server+client on a shared base, run the handshake + auth, and
 * report the auth outcome. Returns the mq_server (so the caller can read the
 * auth-attempt counter) via out_server; client conn via out_conn. */
typedef struct {
    struct event_base *base;
    mq_engine_t *srv;
    mq_engine_t *cli;
    mq_path_t *srv_path;
    mq_path_t *cli_path;
    mq_server_t *server;
    mq_client_t *client;
} fixture_t;

static int
fixture_up(fixture_t *f, const char *client_token)
{
    memset(f, 0, sizeof(*f));
    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

    /* Server */
    f->srv = mq_engine_new_server(f->base, TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(f->srv != NULL);
    if (!f->srv) return -1;
    f->server = mq_server_new(f->srv, "secret");
    MQ_CHECK(f->server != NULL);
    if (!f->server) return -1;

    f->srv_path = mq_path_open(f->srv, 0, "127.0.0.1", 0);
    MQ_CHECK(f->srv_path != NULL);
    if (!f->srv_path) return -1;

    struct sockaddr_storage srv_addr;
    socklen_t srv_addrlen = 0;
    MQ_CHECK_EQ_INT(mq_path_local_addr(f->srv_path, &srv_addr, &srv_addrlen), 0);
    uint16_t port = ntohs(((struct sockaddr_in *)&srv_addr)->sin_port);

    /* Client */
    f->cli = mq_engine_new(0, f->base);
    MQ_CHECK(f->cli != NULL);
    if (!f->cli) return -1;

    f->client = mq_client_new(f->cli, "127.0.0.1", port, "client-1", client_token);
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;
    mq_client_set_on_auth(f->client, on_auth, NULL);

    f->cli_path = mq_path_open(f->cli, 0, "127.0.0.1", 0);
    MQ_CHECK(f->cli_path != NULL);
    if (!f->cli_path) return -1;

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    mq_client_set_on_state(f->client, on_client_state, NULL);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Tear down in dependency order: paths first, then engines. Freeing an
     * engine destroys its connections, firing conn_close_notify which invokes
     * the client/server state callbacks (whose `user` is the mq_client /
     * mq_server). So those must outlive the engine — free them LAST. */
    if (f->cli_path) mq_path_close(f->cli_path);
    if (f->srv_path) mq_path_close(f->srv_path);
    if (f->cli) mq_engine_free(f->cli);
    if (f->srv) mq_engine_free(f->srv);
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

/* ── Case A: wrong token → auth FAILED + conn closes ────────────────────── */
static void
test_auth_wrong_token(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_OK;
    g_client_closed = 0;

    fixture_t f;
    if (fixture_up(&f, "wrong") != 0) {
        fixture_down(&f);
        return;
    }

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_fired);
    MQ_CHECK_EQ_INT(g_auth_ok, 0);
    MQ_CHECK_EQ_INT((int)g_auth_err, (int)MQ_AUTH_FAILED);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 0);

    /* Server closes the connection after rejecting; client should observe it. */
    pump_until(f.base, &g_client_closed, 2000);
    MQ_CHECK(g_client_closed);

    fixture_down(&f);
}

/* ── Case B: matching token → auth OK + auth ran on exactly one stream ──── */
static void
test_auth_matching_token(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_FAILED;
    g_client_closed = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_fired);
    MQ_CHECK_EQ_INT(g_auth_ok, 1);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);

    /* Open a SECOND (non-control) stream afterward; the server must NOT run
     * auth on it. Give the loop time to deliver it. */
    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);
    if (conn) {
        mq_stream_t *s2 = mq_conn_open_stream(conn);
        MQ_CHECK(s2 != NULL);
        if (s2) {
            static const unsigned char data[] = "data";
            (void)mq_stream_send(s2, data, sizeof(data), 0);
        }
    }
    pump_until(f.base, NULL, 800);

    MQ_CHECK_EQ_INT(mq_server_auth_attempts(f.server), 1);

    fixture_down(&f);
}

static void
test_client_server(void)
{
    test_auth_wrong_token();
    test_auth_matching_token();
}

MQ_TEST_MAIN(test_client_server())
