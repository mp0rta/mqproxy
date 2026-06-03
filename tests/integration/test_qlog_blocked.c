// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_qlog_blocked.c — Task 19: validate the qlog "not window-limited" instrument.
 *
 * The 1-B multipath aggregation benchmark (e2e_multipath.sh) proves aggregation
 * is not flow-control limited by counting DATA_BLOCKED / STREAM_DATA_BLOCKED
 * frames in the client's qlog: zero blocked frames == "not window-limited". That
 * benchmark needs traffic shaping (tc/netem) and CANNOT run in this sandbox
 * (no NET_ADMIN). This in-process test validates the MEASUREMENT INSTRUMENT the
 * script relies on, which CAN run here:
 *
 *   1. Enable xquic qlog at EVENT_IMPORTANCE_EXTRA on the client engine, writing
 *      to a tmp file (mq_transport_enable_qlog).
 *   2. Bring up an authed client+server over a single loopback path and run a
 *      clean multi-hundred-KB download through a real SOCKS5 tcp_open. The 16MB
 *      flow-control window dwarfs the loopback BDP, so the transfer is NEVER
 *      window-limited → ZERO blocked frames are emitted.
 *   3. Assert on the rendered qlog file:
 *        - grep -c 'frames_processed'                  > 0  (EXTRA importance is
 *                                                            actually on — proves
 *                                                            the sink works)
 *        - grep -c 'xqc_parse_data_blocked_frame'      == 0 (conn-level not blocked)
 *        - grep -c 'xqc_parse_stream_data_blocked_frame'==0 (stream-level not blocked)
 *
 * This is exactly the read the .sh performs over a real shaped 2-path run; here
 * we prove the tokens are absent on an unblocked transfer and that the qlog is
 * actually populated. ASan/LSan-clean; the tmp qlog is removed on exit.
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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
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

/* ── full-stack fixture (mirrors test_two_paths, qlog armed on the client) ── */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
    mq_listener_t *socks5;
    char qlog_dir[256];
    char qlog_path[320]; /* fixture-owned copy (transport's borrow is freed early) */
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
    f->server = mq_server_new(f->srv_t, f->srv_rt, "secret");
    MQ_CHECK(f->server != NULL);
    if (!f->server) return -1;

    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(f->srv_rt, "127.0.0.1", port), 0);

    f->cli_t = mq_transport_new(0);
    MQ_CHECK(f->cli_t != NULL);
    if (!f->cli_t) return -1;

    /* Arm qlog on the CLIENT transport to a per-pid tmp dir BEFORE any traffic. */
    snprintf(f->qlog_dir, sizeof(f->qlog_dir), "/tmp/mqproxy_qlog_test_%d",
             (int)getpid());
    if (mkdir(f->qlog_dir, 0700) != 0 && errno != EEXIST) {
        MQ_LOGE("test_qlog_blocked: mkdir(%s) failed: %s", f->qlog_dir, strerror(errno));
        return -1;
    }
    const char *qpath = NULL;
    MQ_CHECK_EQ_INT(mq_transport_enable_qlog(f->cli_t, f->qlog_dir, &qpath), 0);
    MQ_CHECK(qpath != NULL);
    if (qpath) snprintf(f->qlog_path, sizeof(f->qlog_path), "%s", qpath);

    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    MQ_CHECK(f->cli_rt != NULL);
    if (!f->cli_rt) return -1;

    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0), 0);

    f->client =
        mq_client_new(f->cli_t, f->cli_rt, "127.0.0.1", port, "client-1", "secret");
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;

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
    /* Per side: transport first (flushes + closes the qlog fd; fires conn-close +
     * in-flight callbacks into the live runtime/client/server/listener), then the
     * runtimes (which BORROWED the shared base, so they do NOT free it), then the
     * proxy objects + listener. The test owns the shared base and frees it last.
     * Guarded so it is safe after the early client-side teardown below NULLs the
     * already-freed members. */
    if (f->cli_t) mq_transport_free(f->cli_t); /* closes + flushes the qlog fd */
    if (f->srv_t) mq_transport_free(f->srv_t);
    if (f->cli_rt) mq_runtime_free(f->cli_rt);
    if (f->srv_rt) mq_runtime_free(f->srv_rt);
    if (f->client) mq_client_free(f->client);
    if (f->server) mq_server_free(f->server);
    if (f->socks5) mq_listener_free(f->socks5);
    if (f->base) event_base_free(f->base);
    /* Remove the tmp qlog file + dir (best effort). */
    if (f->qlog_path[0]) unlink(f->qlog_path);
    if (f->qlog_dir[0]) rmdir(f->qlog_dir);
}

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

/* ── client-socket helpers (subset of test_two_paths) ────────────────────── */
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

/* ── in-process echo origin (identical to test_two_paths) ─────────────────── */
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

/* ── qlog token counter (the exact greps the .sh runs) ────────────────────── */
/* Count NON-OVERLAPPING occurrences of needle in the file. The two blocked-frame
 * tokens are distinct full strings (xqc_parse_data_blocked_frame is NOT a
 * substring of xqc_parse_stream_data_blocked_frame at a matching position once
 * counted independently), matching the .sh's two separate grep -c calls. */
static long
count_token_in_file(const char *path, const char *needle)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[rd] = '\0';

    long count = 0;
    size_t nlen = strlen(needle);
    if (nlen == 0) {
        free(buf);
        return 0;
    }
    const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) {
        count++;
        p += nlen; /* non-overlapping */
    }
    free(buf);
    return count;
}

/* ── the test ─────────────────────────────────────────────────────────────── */
static void
test_qlog_unblocked_transfer(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    MQ_CHECK(pump_until(f.base, pred_authed, f.client, 8000));
    MQ_CHECK(mq_client_is_authed(f.client));

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

    /* Push ~768KB up and drain the echoed copy back down. Well within the 16MB
     * window over loopback (sub-ms RTT), so NO flow-control blocking occurs. */
    const size_t TOTAL = 768 * 1024;
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
    recv_total += drain_some(f.base, c, sink, TOTAL - recv_total, 8000);

    MQ_CHECK_EQ_INT((long long)sent_total, (long long)TOTAL);
    MQ_CHECK((long long)recv_total > 0);

    free(chunk);
    free(sink);
    close(c);
    echo_origin_down(&origin);

    /* Tear the CLIENT side down FIRST so all qlog lines are flushed and the qlog
     * fd closed, while keeping the file on disk for the grep below. The qlog file
     * is fully written once the client transport (which owns the xqc engine +
     * qlog sink) is destroyed. Free in the verified order — transport (fires the
     * conn-close + in-flight callbacks into the live runtime/client/listener),
     * then runtime (borrowed base, not freed), then client, then listener — and
     * NULL each so fixture_down does not double-free. The server side stays alive
     * until fixture_down. */
    if (f.cli_t) {
        mq_transport_free(f.cli_t); /* flushes + closes the qlog fd */
        f.cli_t = NULL;
    }
    if (f.cli_rt) {
        mq_runtime_free(f.cli_rt);
        f.cli_rt = NULL;
    }
    if (f.client) {
        mq_client_free(f.client);
        f.client = NULL;
    }
    if (f.socks5) {
        mq_listener_free(f.socks5);
        f.socks5 = NULL;
    }

    /* Now grep the rendered qlog — the exact reads the .sh performs. */
    long frames = count_token_in_file(f.qlog_path, "frames_processed");
    long blocked_conn = count_token_in_file(f.qlog_path, "xqc_parse_data_blocked_frame");
    long blocked_stream =
        count_token_in_file(f.qlog_path, "xqc_parse_stream_data_blocked_frame");

    MQ_LOGI("test_qlog_blocked: frames_processed=%ld data_blocked=%ld "
            "stream_data_blocked=%ld (qlog=%s)",
            frames, blocked_conn, blocked_stream, f.qlog_path);

    /* EXTRA importance is actually on → the qlog is populated. */
    MQ_CHECK(frames > 0);
    /* An unblocked loopback transfer emits ZERO blocked frames in either form. */
    MQ_CHECK_EQ_INT((int)blocked_conn, 0);
    MQ_CHECK_EQ_INT((int)blocked_stream, 0);

    fixture_down(&f);
}

static void
test_qlog_blocked(void)
{
    test_qlog_unblocked_transfer();
}

MQ_TEST_MAIN(test_qlog_blocked())
