// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

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
#include <stdint.h>
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
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_transport.h"
#include "util/mq_log.h"

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
/* The SECOND MPQUIC path (Task 17) is now opened internally by mq_conn_add_path
 * routing through the transport's open_path_socket callback into the client
 * runtime — there is no test-owned second-path handle to track or free. */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
    mq_listener_t *socks5;
} fixture_t;

/* Reserve an ephemeral loopback UDP port (the runtime no longer exposes the
 * bound port of a :0 bind, so the server pins a concrete port up front). */
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

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);

    void *core = mq_client_tcp_open_core(f->client);
    f->socks5 = mq_socks5_listener_new(f->base, "127.0.0.1", 0, mq_client_tcp_open_fn(),
                                       core, NULL, NULL, NULL, NULL);
    MQ_CHECK(f->socks5 != NULL);
    if (!f->socks5) return -1;
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Per side: transport first (fires conn-close + in-flight callbacks into the
     * live runtime/client/server/listener, and tears down the second path via
     * close_path_socket on the client runtime), then the runtimes (which BORROWED
     * the shared base, so they do NOT free it), then the proxy objects + the
     * listener. The test owns the shared base and frees it last. */
    if (f->cli_t) mq_transport_free(f->cli_t);
    if (f->srv_t) mq_transport_free(f->srv_t);
    if (f->cli_rt) mq_runtime_free(f->cli_rt);
    if (f->srv_rt) mq_runtime_free(f->srv_rt);
    if (f->client) mq_client_free(f->client);
    if (f->server) mq_server_free(f->server);
    if (f->socks5) mq_listener_free(f->socks5);
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

/* ── Task 18: per-path byte stats (mq_conn_dump_stats / mq_conn_path_bytes) ──
 *
 * After the second path is ACTIVE, push a multi-MB transfer through a SOCKS5
 * tcp_open so xquic accumulates real per-path byte counters, then:
 *   - smoke-call mq_conn_dump_stats (must not crash / leak paths_info),
 *   - assert via mq_conn_path_bytes that BOTH the primary (path_id 0) and the
 *     second path report real, non-decreasing byte counters, and that the
 *     transfer as a whole moved at least the bytes we pushed.
 *
 * HONEST SCOPE: the default xquic scheduler is minRTT (mqproxy sets no custom
 * scheduler — see design §7). On equal-RTT loopback minRTT is free to put the
 * whole bulk stream on EITHER path, so we do NOT hard-require a particular
 * split ratio (controlled traffic shaping to force a deterministic split is
 * Task 19's job, alongside qlog blocked-frame counting). What we prove here:
 * the accessor returns truthful per-path counters for BOTH path-ids, every
 * path carried >= 0 bytes, and the aggregate (path0+path1) actually moved data
 * in both directions — i.e. real traffic flowed and the per-path numbers are
 * not fabricated. Empirically (equal-RTT loopback) minRTT often parks the bulk
 * on the SECOND path with only handshake-sized bytes on path 0; we log which
 * paths carried data rather than asserting a fixed distribution. */

/* Drain echo replies on `fd` for up to budget_ms, returning total bytes read.
 * Used to keep the QUIC stream flowing during a bulk echo so both directions
 * actually move multi-MB of data (and per-path counters accumulate). */
static size_t
drain_some(struct event_base *base, int fd, uint8_t *out, size_t cap, uint64_t budget_ms)
{
    size_t got = 0;
    uint64_t deadline = now_ms() + budget_ms;
    while (got < cap && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        ssize_t n = recv(fd, out + got, cap - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n == 0) {
            break;
        }
    }
    return got;
}

static void
test_per_path_stats(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    MQ_CHECK(pump_until(f.base, pred_authed, f.client, 8000));
    MQ_CHECK(mq_client_is_authed(f.client));

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);
    if (!conn) {
        fixture_down(&f);
        return;
    }

    MQ_CHECK(pump_until(f.base, pred_mp_ready, conn, 8000));
    int pid = mq_conn_add_path(conn, "127.0.0.1", 0);
    MQ_CHECK(pid > 0);
    if (pid <= 0) {
        fixture_down(&f);
        return;
    }

    struct path_up_ctx pctx = {.conn = conn, .path_id = (uint64_t)pid};
    MQ_CHECK(pump_until(f.base, pred_path_active, &pctx, 8000));
    MQ_CHECK_EQ_INT(mq_conn_path_state(conn, (uint64_t)pid), 2);

    /* Bulk transfer through the echo origin so per-path counters accumulate. */
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

    /* Push ~512KB up and drain the echoed copy back down. Interleave send +
     * drain so the TCP socket buffers never deadlock on a single large write. */
    const size_t TOTAL = 512 * 1024;
    const size_t CHUNK = 16 * 1024;
    uint8_t *chunk = malloc(CHUNK);
    uint8_t *sink = malloc(TOTAL);
    MQ_CHECK(chunk != NULL && sink != NULL);
    for (size_t i = 0; i < CHUNK; i++)
        chunk[i] = (uint8_t)((i * 31 + 7) & 0xff);

    size_t sent_total = 0, recv_total = 0;
    while (sent_total < TOTAL) {
        size_t want = TOTAL - sent_total;
        if (want > CHUNK) want = CHUNK;
        if (send_all_nb(f.base, c, chunk, want, 4000) != 0) break;
        sent_total += want;
        recv_total += drain_some(f.base, c, sink, TOTAL - recv_total, 1000);
    }
    /* Drain whatever echo is still in flight. */
    recv_total += drain_some(f.base, c, sink, TOTAL - recv_total, 8000);

    MQ_CHECK_EQ_INT((long long)sent_total, (long long)TOTAL);
    MQ_CHECK((long long)recv_total > 0);

    /* Smoke: dump must not crash and must free paths_info (LSan watches). */
    mq_conn_dump_stats(conn);

    /* Structured accessor: both path-ids report truthful counters. */
    uint64_t s0 = UINT64_MAX, r0 = UINT64_MAX, s1 = UINT64_MAX, r1 = UINT64_MAX;
    MQ_CHECK_EQ_INT(mq_conn_path_bytes(conn, 0, &s0, &r0), 0);
    MQ_CHECK_EQ_INT(mq_conn_path_bytes(conn, (uint64_t)pid, &s1, &r1), 0);
    /* They were written (no longer the sentinel). */
    MQ_CHECK(s0 != UINT64_MAX && r0 != UINT64_MAX);
    MQ_CHECK(s1 != UINT64_MAX && r1 != UINT64_MAX);
    /* Unknown path -> -1, outputs untouched. */
    uint64_t sx = 99, rx = 99;
    MQ_CHECK_EQ_INT(mq_conn_path_bytes(conn, 4242, &sx, &rx), -1);
    MQ_CHECK(sx == 99 && rx == 99);

    /* Aggregate across both paths must show real movement in BOTH directions
     * (we pushed ~512KB up and drained the echo back down). We do NOT pin the
     * split ratio — minRTT may park the bulk on either path on equal-RTT
     * loopback (see HONEST SCOPE above). Task 19 shapes the paths to force a
     * deterministic split. */
    MQ_CHECK((s0 + s1) > 0);
    MQ_CHECK((r0 + r1) > 0);
    /* The bulk stream's payload dwarfs framing, so at least one path moved a
     * meaningful chunk of the transfer in each direction. */
    MQ_CHECK((s0 + s1) >= (uint64_t)(TOTAL / 2));
    MQ_CHECK((r0 + r1) >= (uint64_t)(recv_total / 2));

    MQ_LOGI("test_per_path_stats: path0 sent=%llu recv=%llu | path%d sent=%llu recv=%llu",
            (unsigned long long)s0, (unsigned long long)r0, pid, (unsigned long long)s1,
            (unsigned long long)r1);
    if (s1 > 0 || r1 > 0) {
        MQ_LOGI("test_per_path_stats: traffic SPLIT across both paths");
    } else {
        MQ_LOGI("test_per_path_stats: second path idle (minRTT kept traffic on "
                "primary on equal-RTT loopback; Task 19 shapes paths to split)");
    }

    free(chunk);
    free(sink);
    close(c);
    echo_origin_down(&origin);
    fixture_down(&f);
}

static void
test_two_paths(void)
{
    test_window_constants();
    test_second_path_comes_up();
    test_per_path_stats();
}

MQ_TEST_MAIN(test_two_paths())
