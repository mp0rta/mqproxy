// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_client_reconnect.c — Task 4.3 (Phase 5b): positive coverage that the
 * in-process client reconnect + keepalive paths work END-TO-END.
 *
 * Same in-process harness shape as test_client_server.c / test_udp_relay.c: a
 * REAL mq_client + REAL mq_server share one libevent base over loopback, plus a
 * local TCP echo origin (TCP cases) and a local UDP echo origin (UDP cases).
 *
 * The DIFFERENCE from those fixtures: here reconnect is ENABLED (the Phase 5b
 * default) with a SHORT max-backoff so a deterministic conn drop recovers fast.
 *
 * The conn-drop mechanism is mq_conn_close(mq_client_conn(client)): it closes
 * the client's tunnel conn. The client sees MQ_CONN_CLOSED → (reconnect on)
 * arms the backoff timer → the timer fires → client_issue_connect re-dials the
 * SAME still-up server fixture → re-accept → re-auth → SERVING.
 *
 * Detecting "reconnected + re-authed": mq_client's on_auth fires once PER conn
 * and its auth_reported latch is reset on the reconnect path (mq_client.c
 * client_on_state CLOSED branch), so on_auth fires AGAIN after each reconnect.
 * We count on_auth invocations: count>=2 ⇒ reconnected AND re-authed. Every case
 * then asserts an end-to-end FLOW completes on the reconnected conn (not merely
 * "reconnect happened").
 *
 * Cases (see the per-function headers):
 *   1. TCP reconnect (+ kill-during-auth variant) → new TCP flow echoes.
 *   2. UDP reconnect → new datagram echoes byte-exact (mq_udp_cli rebind).
 *   3. open DURING the backoff window → enqueued, completes after re-auth.
 *   4. queue carry-over: open right after close → completes after re-auth.
 *   5. mq_client_free while RECONNECTING → no crash / no late reconnect (ASan).
 *   6. keepalive: short idle timeout set, idle under it, conn stays up + flow OK.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"
#include "wire/mq_wire.h"

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

/* Short reconnect max-backoff. mq_client floors max-backoff to 1000ms (anti
 * busy-spin), so 1000 is the smallest deterministic value; with full-jitter the
 * actual first delay is in [base, min(cap, base*2^attempt)] anyway. */
#define RECONNECT_MAX_BACKOFF_MS 1000
/* Generous per-cycle budget: backoff (<=1s) + handshake + re-auth on loopback. */
#define RECONNECT_BUDGET_MS 8000

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

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
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ── auth bookkeeping: COUNT invocations (re-auth fires on_auth again) ────── */
static int g_auth_count; /* total on_auth fires across reconnect cycles */
static int g_auth_ok;    /* most-recent ok */

static void
on_auth(int ok, mq_auth_err_t err, void *user)
{
    (void)err;
    (void)user;
    g_auth_count++;
    g_auth_ok = ok;
}

/* ── fixture: real client + real server on a shared base, RECONNECT ENABLED ── */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
} fixture_t;

/* Stand the fixture up. keepalive_ms == 0 leaves the client default (30s); a
 * positive value is applied via mq_client_set_keepalive before start. Reconnect
 * is ENABLED with the short max-backoff (the whole point of this test). */
static int
fixture_up(fixture_t *f, uint64_t keepalive_ms)
{
    memset(f, 0, sizeof(*f));
    g_auth_count = 0;
    g_auth_ok = 0;

    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

    uint16_t port = reserve_udp_port();
    MQ_CHECK(port != 0);
    if (!port) return -1;

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
    /* RECONNECT ENABLED (default) with a short max-backoff for fast recovery. */
    mq_client_set_reconnect(f->client, 1, RECONNECT_MAX_BACKOFF_MS);
    if (keepalive_ms) mq_client_set_keepalive(f->client, keepalive_ms);

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
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

static void
pump_for(struct event_base *base, uint64_t ms)
{
    uint64_t deadline = now_ms() + ms;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

/* Pump until on_auth has fired at least `target` times (poll a local flag). */
static void
pump_until_auth_count(struct event_base *base, int target, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (g_auth_count < target && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

/* mq_conn_close() is ASYNC: it initiates close (CLOSING) and MQ_CONN_CLOSED
 * fires later when xquic destroys the conn, at which point mq_client nulls
 * c->conn and arms the backoff timer. Pump until that has happened — i.e. the
 * client is in the backoff window (conn == NULL) — bounded by budget_ms. The
 * backoff floor is 1000ms, so a few hundred ms of pumping lands here reliably
 * WITHOUT overshooting into a completed reconnect. */
static void
pump_until_conn_null(fixture_t *f, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (mq_client_conn(f->client) != NULL && now_ms() < deadline) {
        event_base_loop(f->base, EVLOOP_NONBLOCK);
    }
}

/* ── local TCP echo origin (mirrors test_client_server.c) ────────────────── */
typedef struct {
    struct event_base *base;
    int listen_fd;
    int conn_fd;
    struct event *listen_ev;
    struct event *conn_ev;
} echo_origin_t;

static void
echo_conn_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    echo_origin_t *o = (echo_origin_t *)arg;
    unsigned char buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            if (o->conn_ev) {
                event_free(o->conn_ev);
                o->conn_ev = NULL;
            }
            close(fd);
            o->conn_fd = -1;
        }
        return;
    }
    ssize_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, (size_t)(n - off), 0);
        if (w <= 0) break;
        off += w;
    }
}

static void
echo_accept_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    echo_origin_t *o = (echo_origin_t *)arg;
    int c = accept(fd, NULL, NULL);
    if (c < 0) return;
    set_nonblock(c);
    /* Replace any prior accepted conn's read event (each reconnected flow dials
     * a fresh origin connection; keep only the newest). */
    if (o->conn_ev) {
        event_free(o->conn_ev);
        o->conn_ev = NULL;
    }
    if (o->conn_fd >= 0) close(o->conn_fd);
    o->conn_fd = c;
    o->conn_ev = event_new(o->base, c, EV_READ | EV_PERSIST, echo_conn_cb, o);
    event_add(o->conn_ev, NULL);
}

static int
echo_origin_up(echo_origin_t *o, struct event_base *base, uint16_t *out_port)
{
    memset(o, 0, sizeof(*o));
    o->base = base;
    o->conn_fd = -1;
    o->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (o->listen_fd < 0) return -1;
    int one = 1;
    setsockopt(o->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(o->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    if (listen(o->listen_fd, 4) != 0) return -1;
    socklen_t sl = sizeof(sa);
    if (getsockname(o->listen_fd, (struct sockaddr *)&sa, &sl) != 0) return -1;
    *out_port = ntohs(sa.sin_port);
    set_nonblock(o->listen_fd);
    o->listen_ev = event_new(base, o->listen_fd, EV_READ | EV_PERSIST, echo_accept_cb, o);
    event_add(o->listen_ev, NULL);
    return 0;
}

static void
echo_origin_down(echo_origin_t *o)
{
    if (o->conn_ev) event_free(o->conn_ev);
    if (o->listen_ev) event_free(o->listen_ev);
    if (o->conn_fd >= 0) close(o->conn_fd);
    if (o->listen_fd >= 0) close(o->listen_fd);
}

/* ── local UDP echo origin (mirrors test_udp_relay.c) ────────────────────── */
typedef struct {
    struct event_base *base;
    int fd;
    struct event *ev;
    int rx_count;
} udp_echo_t;

static void
udp_echo_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    udp_echo_t *e = (udp_echo_t *)arg;
    for (;;) {
        unsigned char buf[65535];
        struct sockaddr_storage from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) break;
        e->rx_count++;
        (void)sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fl);
    }
}

static int
udp_echo_up(udp_echo_t *e, struct event_base *base, uint16_t *out_port)
{
    memset(e, 0, sizeof(*e));
    e->base = base;
    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (e->fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(e->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    socklen_t sl = sizeof(sa);
    if (getsockname(e->fd, (struct sockaddr *)&sa, &sl) != 0) return -1;
    *out_port = ntohs(sa.sin_port);
    set_nonblock(e->fd);
    e->ev = event_new(base, e->fd, EV_READ | EV_PERSIST, udp_echo_cb, e);
    event_add(e->ev, NULL);
    return 0;
}

static void
udp_echo_down(udp_echo_t *e)
{
    if (e->ev) event_free(e->ev);
    if (e->fd >= 0) close(e->fd);
}

/* ── TCP flow helper: mq_client_tcp_open over a socketpair, drive "ping" echo ──
 *
 * Returns 0 if the round-trip "ping"→echo completed, -1 otherwise. The client
 * takes ownership of local_fd; the test owns/closes app_fd. */
typedef struct {
    int fired;
    int ok;
    mq_tcp_err_t err;
} open_result_t;

static void
on_tcp_open(int ok, mq_tcp_err_t err, void *user)
{
    open_result_t *r = (open_result_t *)user;
    r->fired = 1;
    r->ok = ok;
    r->err = err;
}

static void
v4_loopback(uint8_t host[4])
{
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(host, &v4, 4);
}

/* Run ONE full TCP echo flow on the client's CURRENT conn: open → ping → echo.
 * Asserts each step. Returns 0 on byte-exact echo, -1 on any failure. */
static int
run_tcp_echo_flow(fixture_t *f, uint16_t origin_port)
{
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    set_nonblock(sp[0]);
    set_nonblock(sp[1]);
    int app_fd = sp[0];
    int local_fd = sp[1]; /* handed to the client */

    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f->client), host, 4, MQ_ADDR_IPV4,
                       origin_port, local_fd, NULL, 0, &res, on_tcp_open);

    pump_until(f->base, &res.fired, 4000);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 1);
    if (!res.fired || !res.ok) {
        close(app_fd);
        return -1;
    }

    if (write(app_fd, "ping", 4) != 4) {
        close(app_fd);
        return -1;
    }
    char rx[16];
    size_t got = 0;
    uint64_t deadline = now_ms() + 4000;
    while (got < 4 && now_ms() < deadline) {
        event_base_loop(f->base, EVLOOP_NONBLOCK);
        ssize_t n = recv(app_fd, rx + got, sizeof(rx) - got, 0);
        if (n > 0) got += (size_t)n;
    }
    close(app_fd);
    MQ_CHECK_EQ_INT((int)got, 4);
    if (got != 4) return -1;
    MQ_CHECK(memcmp(rx, "ping", 4) == 0);
    return (got == 4 && memcmp(rx, "ping", 4) == 0) ? 0 : -1;
}

/* ── UDP flow helpers (client-role boundary, mirrors test_udp_relay.c) ────── */
typedef struct {
    uint8_t rx[4096];
    size_t rxlen;
    int rx_done;
    int err_fired;
    mq_udp_err_t err;
} cli_rx_t;

static void
cli_on_rx(const uint8_t *payload, size_t len, void *user)
{
    cli_rx_t *c = (cli_rx_t *)user;
    if (c->rx_done) return;
    size_t n = len > sizeof(c->rx) ? sizeof(c->rx) : len;
    memcpy(c->rx, payload, n);
    c->rxlen = n;
    c->rx_done = 1;
}

static void
cli_on_err(void *session, mq_udp_err_t err, void *user)
{
    (void)session;
    cli_rx_t *c = (cli_rx_t *)user;
    c->err_fired = 1;
    c->err = err;
}

static void *
cli_open_v4(mq_client_t *client, uint16_t port, cli_rx_t *cap)
{
    uint8_t host[4];
    v4_loopback(host);
    mq_udp_open_fn open_fn = mq_client_udp_open_fn();
    void *core = mq_client_udp_open_core(client);
    return open_fn(core, host, 4, MQ_ADDR_IPV4, port, cli_on_rx, cli_on_err, cap);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 1: TCP reconnect (+ kill-during-auth variant + in-flight reap note).
 * ════════════════════════════════════════════════════════════════════════ */
/* (1) Establish + run a baseline TCP echo. (a) Open an in-flight flow then drop
 * the conn mid-flight: the open's cb must fire with an error (failed cleanly, no
 * hang). Pump until reconnected+re-authed (auth_count>=2). Then run a NEW TCP
 * echo on the reconnected conn → byte-exact. */
static void
test_case1_tcp_reconnect(void)
{
    fixture_t f;
    if (fixture_up(&f, 0) != 0) {
        fixture_down(&f);
        return;
    }
    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    /* Establish + baseline flow. */
    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(run_tcp_echo_flow(&f, origin_port), 0);

    /* (a) Start an in-flight flow, then drop the conn before completing it. The
     * open cb must fire with an error (in-flight flows do NOT survive a tunnel
     * loss — design §Non-goal — but must fail CLEANLY, never hang). */
    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    set_nonblock(sp[0]);
    set_nonblock(sp[1]);
    open_result_t inflight;
    memset(&inflight, 0, sizeof(inflight));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       origin_port, sp[1], NULL, 0, &inflight, on_tcp_open);
    /* Drop the conn immediately (likely before the CONNECT_TCP_RESPONSE). */
    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);
    mq_conn_close(conn);
    /* The in-flight open must reach a terminal cb (ok=0) — clean failure. */
    pump_until(f.base, &inflight.fired, RECONNECT_BUDGET_MS);
    MQ_CHECK(inflight.fired);
    MQ_CHECK_EQ_INT(inflight.ok, 0); /* failed, not hung */
    close(sp[0]);                    /* client owns sp[1], closes it on reap */

    /* Pump until reconnected + RE-AUTHED (on_auth fires a 2nd time). */
    pump_until_auth_count(f.base, 2, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_auth_count, 2);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);
    MQ_CHECK(mq_client_conn(f.client) != NULL);

    /* NEW flow on the reconnected conn → byte-exact echo (the real assertion). */
    MQ_CHECK_EQ_INT(run_tcp_echo_flow(&f, origin_port), 0);

    /* (b) Kill-during-auth variant: drop the conn again, then drop AGAIN as soon
     * as the next connect re-establishes (kill near the AUTH cycle). The client
     * must keep recovering (reconnect, not terminal) and re-auth once more. */
    int auth_before = g_auth_count; /* == 2 */
    mq_conn_close(mq_client_conn(f.client));
    /* Pump a touch, then attempt a SECOND drop of the fresh conn. NOTE: this is a
     * best-effort second drop that MAY OR MAY NOT land during the auth cycle — if
     * c2 is NULL we're mid-backoff and skip it. So this exercises double-loss
     * recovery deterministically; it does NOT deterministically hit a
     * kill-DURING-auth point (that would require closing from inside on_auth).
     * The recovery assertion below is sound regardless. */
    pump_for(f.base, 50);
    mq_conn_t *c2 = mq_client_conn(f.client);
    if (c2) mq_conn_close(c2); /* may be NULL mid-backoff — that's fine */
    /* Despite the double drop, the client must recover + re-auth. */
    pump_until_auth_count(f.base, auth_before + 1, RECONNECT_BUDGET_MS * 2);
    MQ_CHECK(g_auth_count >= auth_before + 1);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);
    /* And a flow still completes after that recovery. */
    MQ_CHECK_EQ_INT(run_tcp_echo_flow(&f, origin_port), 0);

    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 2: UDP reconnect → new datagram echoes byte-exact (mq_udp_cli rebind).
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case2_udp_reconnect(void)
{
    fixture_t f;
    if (fixture_up(&f, 0) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_udp_available(f.client), 1);

    /* Baseline UDP round-trip. */
    cli_rx_t cap1;
    memset(&cap1, 0, sizeof(cap1));
    void *sess1 = cli_open_v4(f.client, echo_port, &cap1);
    MQ_CHECK(sess1 != NULL);
    uint8_t p1[256];
    for (int i = 0; i < 256; i++)
        p1[i] = (uint8_t)((i * 37 + 5) & 0xff);
    mq_client_udp_send_fn()(sess1, p1, sizeof(p1));
    pump_until(f.base, &cap1.rx_done, 4000);
    MQ_CHECK(cap1.rx_done);
    MQ_CHECK_EQ_INT((int)cap1.rxlen, 256);
    if (cap1.rx_done) MQ_CHECK_MEM(cap1.rx, p1, 256);
    /* The pre-loss session handle dies with the conn; close it now. */
    mq_client_udp_close_fn()(sess1);

    /* Drop the conn; pump until reconnected + re-authed. */
    mq_conn_close(mq_client_conn(f.client));
    pump_until_auth_count(f.base, 2, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_auth_count, 2);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_udp_available(f.client), 1);

    /* NEW session on the reconnected conn → byte-exact echo proves mq_udp_cli
     * rebind (mq_udp_cli_set_conn) worked end-to-end through the real reconnect. */
    cli_rx_t cap2;
    memset(&cap2, 0, sizeof(cap2));
    void *sess2 = cli_open_v4(f.client, echo_port, &cap2);
    MQ_CHECK(sess2 != NULL);
    uint8_t p2[300];
    for (int i = 0; i < 300; i++)
        p2[i] = (uint8_t)((i * 91 + 13) & 0xff);
    mq_client_udp_send_fn()(sess2, p2, sizeof(p2));
    pump_until(f.base, &cap2.rx_done, RECONNECT_BUDGET_MS);
    MQ_CHECK(cap2.rx_done);
    MQ_CHECK_EQ_INT((int)cap2.rxlen, 300);
    if (cap2.rx_done) MQ_CHECK_MEM(cap2.rx, p2, 300);
    MQ_CHECK_EQ_INT(cap2.err_fired, 0);

    mq_client_udp_close_fn()(sess2);
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 3: open DURING the reconnect window → enqueued (no NULL-conn crash),
 *         completes byte-exact AFTER re-auth. Both TCP and UDP variants.
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case3_open_during_window(void)
{
    fixture_t f;
    if (fixture_up(&f, 0) != 0) {
        fixture_down(&f);
        return;
    }
    echo_origin_t tcp_origin;
    uint16_t tcp_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&tcp_origin, f.base, &tcp_port), 0);
    udp_echo_t udp_origin;
    uint16_t udp_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&udp_origin, f.base, &udp_port), 0);

    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);

    /* Drop the conn and enter the backoff window: pump until CLOSED is processed
     * (conn nulled, backoff armed). The backoff floor is 1000ms, so this lands in
     * the window without overshooting into a completed reconnect. */
    mq_conn_close(mq_client_conn(f.client));
    pump_until_conn_null(&f, 4000);
    MQ_CHECK(mq_client_conn(f.client) == NULL); /* in the backoff window */

    /* TCP open DURING the window: must enqueue (not crash on NULL conn, not fail
     * immediately). The cb must NOT have fired yet. */
    int tsp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, tsp), 0);
    set_nonblock(tsp[0]);
    set_nonblock(tsp[1]);
    open_result_t tres;
    memset(&tres, 0, sizeof(tres));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4, tcp_port,
                       tsp[1], NULL, 0, &tres, on_tcp_open);
    MQ_CHECK_EQ_INT(tres.fired, 0); /* queued across the loss, not failed */

    /* UDP open DURING the window: handle returned (queued), no crash. */
    cli_rx_t ucap;
    memset(&ucap, 0, sizeof(ucap));
    void *usess = cli_open_v4(f.client, udp_port, &ucap);
    MQ_CHECK(usess != NULL);
    uint8_t up[200];
    for (int i = 0; i < 200; i++)
        up[i] = (uint8_t)((i * 53 + 17) & 0xff);
    mq_client_udp_send_fn()(usess, up, sizeof(up)); /* queued */

    /* Let the reconnect + re-auth complete; the queued opens then drain. */
    pump_until_auth_count(f.base, 2, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_auth_count, 2);
    MQ_CHECK(g_auth_ok);

    /* TCP queued open completes byte-exact AFTER re-auth. */
    pump_until(f.base, &tres.fired, RECONNECT_BUDGET_MS);
    MQ_CHECK(tres.fired);
    MQ_CHECK_EQ_INT(tres.ok, 1);
    MQ_CHECK_EQ_INT((int)write(tsp[0], "ping", 4), 4);
    char rx[16];
    size_t got = 0;
    uint64_t deadline = now_ms() + 4000;
    while (got < 4 && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        ssize_t n = recv(tsp[0], rx + got, sizeof(rx) - got, 0);
        if (n > 0) got += (size_t)n;
    }
    MQ_CHECK_EQ_INT((int)got, 4);
    if (got == 4) MQ_CHECK(memcmp(rx, "ping", 4) == 0);
    close(tsp[0]);

    /* UDP queued open echoes byte-exact AFTER re-auth. */
    pump_until(f.base, &ucap.rx_done, RECONNECT_BUDGET_MS);
    MQ_CHECK(ucap.rx_done);
    MQ_CHECK_EQ_INT((int)ucap.rxlen, 200);
    if (ucap.rx_done) MQ_CHECK_MEM(ucap.rx, up, 200);

    mq_client_udp_close_fn()(usess);
    udp_echo_down(&udp_origin);
    echo_origin_down(&tcp_origin);
    fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 4: queue carry-over — once the conn loss is registered, an open is
 *         carried in the queue across the loss (no manual re-open) and its echo
 *         completes after re-auth. (Distinct from case 3: single TCP flow, the
 *         pure queue-survives-the-loss path with no mid-window cb-not-fired check
 *         and no UDP variant.)
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case4_queue_carryover(void)
{
    fixture_t f;
    if (fixture_up(&f, 0) != 0) {
        fixture_down(&f);
        return;
    }
    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);

    /* Close and let the loss register (CLOSED processed: authed→0, conn→NULL).
     * NOTE: mq_conn_close is async, so opening in the SAME turn would still see
     * authed==1 + a (closing) conn and issue on the dying conn (fails). The
     * carry-over contract is: once the loss is registered (authed==0), an open is
     * ENQUEUED and drains on the next re-auth with NO manual re-open. */
    mq_conn_close(mq_client_conn(f.client));
    pump_until_conn_null(&f, 4000);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 0); /* loss registered */
    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    set_nonblock(sp[0]);
    set_nonblock(sp[1]);
    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       origin_port, sp[1], NULL, 0, &res, on_tcp_open);

    /* Pump through reconnect + re-auth + queue drain → echo completes. */
    pump_until_auth_count(f.base, 2, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_auth_count, 2);
    pump_until(f.base, &res.fired, RECONNECT_BUDGET_MS);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 1);

    MQ_CHECK_EQ_INT((int)write(sp[0], "ping", 4), 4);
    char rx[16];
    size_t got = 0;
    uint64_t deadline = now_ms() + 4000;
    while (got < 4 && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        ssize_t n = recv(sp[0], rx + got, sizeof(rx) - got, 0);
        if (n > 0) got += (size_t)n;
    }
    MQ_CHECK_EQ_INT((int)got, 4);
    if (got == 4) MQ_CHECK(memcmp(rx, "ping", 4) == 0);
    close(sp[0]);

    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 5: shutdown vs loss — mq_client_free while RECONNECTING. No crash, no
 *         late reconnect fires, leak-free (must pass under ASan).
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case5_free_while_reconnecting(void)
{
    fixture_t f;
    if (fixture_up(&f, 0) != 0) {
        fixture_down(&f);
        return;
    }
    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);

    /* Drop the conn and enter the backoff window (conn nulled, backoff armed),
     * but do NOT pump long enough to reconnect (backoff floor 1000ms). */
    mq_conn_close(mq_client_conn(f.client));
    pump_until_conn_null(&f, 4000);
    MQ_CHECK(mq_client_conn(f.client) == NULL); /* reconnecting (backoff armed) */

    int auth_at_free = g_auth_count; /* == 1 */

    /* Free the client mid-reconnect: mq_client_free sets shutting_down first +
     * disarms/frees the backoff timer, so no reconnect fires after free. */
    mq_client_free(f.client);
    f.client = NULL; /* prevent double-free in fixture_down */

    /* Pump well past the backoff window: NO reconnect must occur (on_auth must
     * NOT fire again) and no crash / UAF (caught by ASan). */
    pump_for(f.base, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_auth_count, auth_at_free); /* no late reconnect */

    fixture_down(&f); /* client already freed; frees the rest cleanly */
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 6: keepalive — a short idle-timeout is set; the conn stays up across an
 *         idle window and a flow opened afterward still works.
 *
 * NOTE on semantics: xquic's keepalive PING cadence is a FIXED 15000ms
 * (XQC_PING_TIMEOUT), independent of idle_time_out. Proving the PING actually
 * REFRESHES the idle timer would require an idle wait > 15s (too slow for CI).
 * So this case sets a keepalive idle of 4000ms and idles ~1500ms (< idle) while
 * pumping, then asserts the conn is STILL up (not idle-closed) and a fresh flow
 * completes — i.e. the keepalive idle-timeout setter is wired and traffic is
 * held open across realistic idle. (The literal "<500ms idle" form is infeasible
 * here: a sub-15s idle_time_out cannot be PING-refreshed, so it would close.)
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case6_keepalive_holds(void)
{
    fixture_t f;
    if (fixture_up(&f, 4000) != 0) { /* keepalive idle = 4000ms */
        fixture_down(&f);
        return;
    }
    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until_auth_count(f.base, 1, 4000);
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK(mq_client_conn(f.client) != NULL);

    /* Idle ~1500ms (< 4000ms idle timeout) with NO traffic, pumping the loop. */
    pump_for(f.base, 1500);

    /* The conn must still be up (NOT idle-closed) and NOT have reconnected:
     * on_auth must NOT have fired a 2nd time (a drop+reconnect would bump it). */
    MQ_CHECK_EQ_INT(g_auth_count, 1);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);
    MQ_CHECK(mq_client_conn(f.client) != NULL);

    /* A flow opened after the idle period still works end-to-end. */
    MQ_CHECK_EQ_INT(run_tcp_echo_flow(&f, origin_port), 0);

    echo_origin_down(&origin);
    fixture_down(&f);
}

static void
test_client_reconnect(void)
{
    /* Writes to a socketpair whose peer was closed (e.g. a flow torn down by a
     * conn drop) can raise SIGPIPE; ignore it so such a write returns EPIPE. */
    signal(SIGPIPE, SIG_IGN);
    test_case1_tcp_reconnect();
    test_case2_udp_reconnect();
    test_case3_open_during_window();
    test_case4_queue_carryover();
    test_case5_free_while_reconnecting();
    test_case6_keepalive_holds();
}

MQ_TEST_MAIN(test_client_reconnect())
