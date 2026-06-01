/* test_two_paths.c — Task 17: a SECOND MPQUIC path comes up.
 *
 * Brings up an AUTHED client+server over loopback (single libevent base, one
 * process). After auth, the client adds a SECOND loopback path (a distinct
 * ephemeral local UDP port) via mq_conn_add_path() and asserts:
 *   1. mq_conn_add_path returns a NEW, distinct path_id (!= 0, the primary).
 *   2. Driving the loop a bounded time, the second path reaches xquic's
 *      ACTIVE path-state (path validated) — proving it COMES UP.
 *   3. With two paths registered, a small end-to-end transfer still succeeds
 *      (the connection still works).
 *
 * Throughput / aggregation is Task 19; this test only proves the second path
 * validates and the conn is still usable.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "ingress/mq_listener.h"
#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "transport/mq_path.h"

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

static void
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Window constants must mirror xquic's ceiling and the 8MB/16MB BDP target. */
static void
test_window_constants(void)
{
    /* These are compile-time asserts in mq_conn.h; re-check at runtime so the
     * test fails loudly if the header drifts. */
    MQ_CHECK_EQ_INT(MQ_STREAM_WINDOW, 8 * 1024 * 1024);
    MQ_CHECK_EQ_INT(MQ_CONN_WINDOW, 16 * 1024 * 1024);
    MQ_CHECK(MQ_CONN_WINDOW <= MQ_XQUIC_MAX_RECV_WINDOW);
}

/* ── full-stack fixture (mirrors test_e2e_single_path) ───────────────────── */
typedef struct {
    struct event_base *base;
    mq_engine_t *srv;
    mq_engine_t *cli;
    mq_path_t *srv_path;
    mq_path_t *cli_path;
    mq_server_t *server;
    mq_client_t *client;
    mq_listener_t *socks5;
    mq_path_t *cli_path2; /* second client path (Task 17) */
} fixture_t;

static int
fixture_up(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

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

    f->cli = mq_engine_new(0, f->base);
    MQ_CHECK(f->cli != NULL);
    if (!f->cli) return -1;

    f->client = mq_client_new(f->cli, "127.0.0.1", port, "client-1", "secret");
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;

    f->cli_path = mq_path_open(f->cli, 0, "127.0.0.1", 0);
    MQ_CHECK(f->cli_path != NULL);
    if (!f->cli_path) return -1;

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);

    void *core = mq_client_tcp_open_core(f->client);
    f->socks5 =
        mq_socks5_listener_new(f->base, "127.0.0.1", 0, mq_client_tcp_open_fn(), core);
    MQ_CHECK(f->socks5 != NULL);
    if (!f->socks5) return -1;
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    if (f->socks5) mq_listener_free(f->socks5);
    if (f->cli_path2) mq_path_close(f->cli_path2);
    if (f->cli_path) mq_path_close(f->cli_path);
    if (f->srv_path) mq_path_close(f->srv_path);
    if (f->cli) mq_engine_free(f->cli);
    if (f->srv) mq_engine_free(f->srv);
    if (f->client) mq_client_free(f->client);
    if (f->server) mq_server_free(f->server);
    if (f->base) event_base_free(f->base);
}

/* Pump the base until pred() returns non-zero or the budget expires. */
static int
pump_until(struct event_base *base, int (*pred)(void *), void *arg, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (now_ms() < deadline) {
        if (pred(arg)) return 1;
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    return pred(arg);
}

static int
pred_authed(void *arg)
{
    return mq_client_is_authed((const mq_client_t *)arg);
}

static int
pred_mp_ready(void *arg)
{
    return mq_conn_mp_ready((const mq_conn_t *)arg);
}

struct path_up_ctx {
    mq_conn_t *conn;
    uint64_t path_id;
};

static int
pred_path_active(void *arg)
{
    struct path_up_ctx *c = (struct path_up_ctx *)arg;
    /* xquic XQC_PATH_STATE_ACTIVE == 2 (private xqc_multipath.h). */
    return mq_conn_path_state(c->conn, c->path_id) == 2;
}

/* ── client-socket helpers (subset of test_e2e_single_path) ──────────────── */
static int
dial_nb(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (r != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

static int
send_all_nb(struct event_base *base, int fd, const uint8_t *buf, size_t len,
            uint64_t budget_ms)
{
    size_t off = 0;
    uint64_t deadline = now_ms() + budget_ms;
    while (off < len && now_ms() < deadline) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            event_base_loop(base, EVLOOP_NONBLOCK);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    return off == len ? 0 : -1;
}

static size_t
recv_exact(struct event_base *base, int fd, uint8_t *out, size_t want, uint64_t budget_ms)
{
    size_t got = 0;
    uint64_t deadline = now_ms() + budget_ms;
    while (got < want && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        ssize_t n = recv(fd, out + got, want - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n == 0) {
            break;
        }
    }
    return got;
}

static int
socks5_greet(struct event_base *base, int fd)
{
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (send_all_nb(base, fd, greeting, sizeof(greeting), 1000) != 0) return -1;
    uint8_t mreply[2] = {0};
    if (recv_exact(base, fd, mreply, 2, 2000) != 2) return -1;
    if (mreply[0] != 0x05 || mreply[1] != 0x00) return -1;
    return 0;
}

static int
socks5_connect_v4(struct event_base *base, int fd, uint16_t port)
{
    uint8_t req[10];
    size_t i = 0;
    req[i++] = 0x05;
    req[i++] = 0x01;
    req[i++] = 0x00;
    req[i++] = 0x01;
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(req + i, &v4, 4);
    i += 4;
    req[i++] = (uint8_t)(port >> 8);
    req[i++] = (uint8_t)(port & 0xff);
    return send_all_nb(base, fd, req, i, 1000);
}

/* ── in-process echo origin ──────────────────────────────────────────────── */
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
    unsigned char buf[8192];
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
        ssize_t w = send(fd, buf + off, (size_t)(n - off), MSG_NOSIGNAL);
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

/* ── the test: second path comes up, conn still works ────────────────────── */
static void
test_second_path_comes_up(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    /* 1. Wait for auth to complete. */
    MQ_CHECK(pump_until(f.base, pred_authed, f.client, 8000));
    MQ_CHECK(mq_client_is_authed(f.client));

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);
    if (!conn) {
        fixture_down(&f);
        return;
    }

    /* 2. Wait until xquic signals it can create a path (cids exchanged). */
    MQ_CHECK(pump_until(f.base, pred_mp_ready, conn, 8000));
    MQ_CHECK(mq_conn_mp_ready(conn));

    /* 3. Add a SECOND loopback path on a distinct ephemeral local port. */
    int pid = mq_conn_add_path(conn, "127.0.0.1", 0);
    MQ_CHECK(pid > 0); /* distinct from primary path_id 0 */
    if (pid <= 0) {
        fixture_down(&f);
        return;
    }

    /* 4. Drive the loop until the second path reaches ACTIVE (validated). */
    struct path_up_ctx pctx = {.conn = conn, .path_id = (uint64_t)pid};
    MQ_CHECK(pump_until(f.base, pred_path_active, &pctx, 8000));
    MQ_CHECK_EQ_INT(mq_conn_path_state(conn, (uint64_t)pid), 2);

    /* 5. With two paths registered, a small e2e transfer still succeeds. */
    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    int c = dial_nb(mq_listener_local_port(f.socks5));
    MQ_CHECK(c >= 0);
    if (c < 0) {
        echo_origin_down(&origin);
        fixture_down(&f);
        return;
    }

    MQ_CHECK_EQ_INT(socks5_greet(f.base, c), 0);
    MQ_CHECK_EQ_INT(socks5_connect_v4(f.base, c, origin_port), 0);

    uint8_t reply[10] = {0};
    MQ_CHECK_EQ_INT((int)recv_exact(f.base, c, reply, 10, 8000), 10);
    MQ_CHECK_EQ_INT(reply[0], 0x05);
    MQ_CHECK_EQ_INT(reply[1], 0x00);

    const size_t M = 4096;
    uint8_t *payload = malloc(M);
    uint8_t *back = malloc(M);
    MQ_CHECK(payload != NULL && back != NULL);
    for (size_t i = 0; i < M; i++)
        payload[i] = (uint8_t)((i * 31 + 7) & 0xff);
    MQ_CHECK_EQ_INT(send_all_nb(f.base, c, payload, M, 4000), 0);
    size_t got = recv_exact(f.base, c, back, M, 8000);
    MQ_CHECK_EQ_INT((long long)got, (long long)M);
    MQ_CHECK(memcmp(payload, back, M) == 0);

    free(payload);
    free(back);
    close(c);
    echo_origin_down(&origin);
    fixture_down(&f);
}

static void
test_two_paths(void)
{
    test_window_constants();
    test_second_path_comes_up();
}

MQ_TEST_MAIN(test_two_paths())
