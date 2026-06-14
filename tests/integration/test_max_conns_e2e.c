// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_max_conns_e2e.c — falsifiable proof of the engine-wide connection cap.
 *
 * Stands up one real mq_server (--max-conns 1 equivalent) and several real
 * mq_clients on a single shared libevent base (loopback), and asserts, against
 * the live mq_transport_n_conns(server_transport) accessor:
 *   A. Client A connects + auths   -> n_conns == 1.
 *   B. Client B (concurrent) is REFUSED at server_accept (CONNECTION_REFUSED,
 *      pre-handshake) -> B never auths and n_conns stays 1.
 *   C. Close A                     -> n_conns == 0 (the counted-flag decrement).
 *   D. Client C connects + auths   -> n_conns == 1 (the freed slot is reusable).
 *
 * FALSIFIABILITY: with mq_transport_set_max_conns(srv_t, 0) (unlimited) instead
 * of 1, B establishes and n_conns reaches 2 -> assertion B fails. This proves
 * the test rides the cap path, not an unrelated reject.
 *
 * Reconnect is disabled on every client: default-on reconnect would re-dial a
 * refused/closed conn and race the counts.
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

/* Reserve an ephemeral loopback UDP port, then close it so the server runtime
 * can bind that fixed port (mirrors test_metrics_active_conn.c). */
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

/* Per-client auth state, passed as the on_auth user pointer so each client's
 * result is tracked independently. */
typedef struct {
    int fired;
    int ok;
} auth_state_t;

static void
on_auth_cb(int ok, mq_auth_err_t err, void *user)
{
    (void)err;
    auth_state_t *s = (auth_state_t *)user;
    s->fired = 1;
    s->ok = ok;
}

/* One client on the shared base: its own transport + runtime + UDP path. */
typedef struct {
    mq_transport_t *t;
    mq_runtime_t *rt;
    mq_client_t *cli;
    auth_state_t auth;
} client_t;

static int
client_up(client_t *c, struct event_base *base, uint16_t srv_port, const char *name)
{
    memset(c, 0, sizeof(*c));
    c->t = mq_transport_new(0);
    MQ_CHECK(c->t != NULL);
    if (!c->t) return -1;
    c->rt = mq_runtime_new(c->t, base);
    MQ_CHECK(c->rt != NULL);
    if (!c->rt) return -1;
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(c->rt, "127.0.0.1", 0), 0);
    c->cli =
        mq_client_new(c->t, c->rt, "127.0.0.1", srv_port, name, "secret", MQ_CC_BBR2);
    MQ_CHECK(c->cli != NULL);
    if (!c->cli) return -1;
    mq_client_set_on_auth(c->cli, on_auth_cb, &c->auth);
    mq_client_set_reconnect(c->cli, 0, 30000); /* no re-dial: would race the counts */
    MQ_CHECK_EQ_INT(mq_client_start(c->cli), 0);
    return 0;
}

static void
client_down(client_t *c)
{
    /* Transport first (engine destroy fires close_notify), then runtime, then the
     * client object (mirrors test_metrics_active_conn fixture_down ordering). */
    if (c->t) mq_transport_free(c->t);
    if (c->rt) mq_runtime_free(c->rt);
    if (c->cli) mq_client_free(c->cli);
}

static void
pump_until_flag(struct event_base *base, int *flag, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (!*flag && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

static void
pump_until_nconns(struct event_base *base, mq_transport_t *srv_t, uint32_t target,
                  uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (mq_transport_n_conns(srv_t) != target && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

static void
pump_fixed(struct event_base *base, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

static void
test_max_conns_refuses_and_frees(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    uint16_t port = reserve_udp_port();
    MQ_CHECK(port != 0);
    if (!port) {
        event_base_free(base);
        return;
    }

    /* Declared (zero-init) before any goto so no jump bypasses their init. */
    client_t a = {0}, b = {0}, cc = {0};

    /* Server with an engine-wide cap of 1 (flip to 0 to falsify — see header). */
    mq_transport_t *srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv_t != NULL);
    mq_runtime_t *srv_rt = srv_t ? mq_runtime_new(srv_t, base) : NULL;
    MQ_CHECK(srv_rt != NULL);
    mq_server_t *server =
        srv_rt ? mq_server_new(srv_t, srv_rt, "secret", MQ_CC_BBR2, 60000, 1) : NULL;
    MQ_CHECK(server != NULL);
    if (!server) goto out_srv;
    mq_transport_set_max_conns(srv_t, 1);
    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(srv_rt, "127.0.0.1", port), 0);

    /* (A) First client connects + auths -> exactly one established conn. */
    if (client_up(&a, base, port, "client-a") != 0) goto out_a;
    pump_until_flag(base, &a.auth.fired, 4000);
    MQ_CHECK(a.auth.fired);
    MQ_CHECK(a.auth.ok);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(srv_t), 1);

    /* (B) Second concurrent client is refused at the cap; it never auths and the
     * established count stays at 1. */
    if (client_up(&b, base, port, "client-b") != 0) goto out_b;
    pump_fixed(base, 2000);
    MQ_CHECK(!b.auth.ok);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(srv_t), 1);

    /* (C) Close A -> the counted-flag decrement frees the slot. */
    mq_conn_close(mq_client_conn(a.cli));
    pump_until_nconns(base, srv_t, 0, 3000);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(srv_t), 0);

    /* (D) A new client now fits in the freed slot (decrement is real + reusable). */
    if (client_up(&cc, base, port, "client-c") != 0) goto out_c;
    pump_until_flag(base, &cc.auth.fired, 4000);
    MQ_CHECK(cc.auth.fired);
    MQ_CHECK(cc.auth.ok);
    MQ_CHECK_EQ_INT(mq_transport_n_conns(srv_t), 1);

out_c:
    client_down(&cc);
out_b:
    client_down(&b);
out_a:
    client_down(&a);
out_srv:
    if (srv_t) mq_transport_free(srv_t);
    if (srv_rt) mq_runtime_free(srv_rt);
    if (server) mq_server_free(server);
    event_base_free(base);
}

MQ_TEST_MAIN(test_max_conns_refuses_and_frees())
