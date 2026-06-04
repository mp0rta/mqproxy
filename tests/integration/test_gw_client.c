// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_gw_client.c — integration tests for the local fetch-API listener
 * (mq_fetch_listener, Task 2.2). Drives the loopback HTTP/1.1 accept loop with
 * FAKE gateway callbacks over real loopback sockets + a manually pumped
 * event_base. No QUIC / transports are involved.
 *
 * This file is shared with the gateway client (Task 3.2), which will append
 * its own scenarios. The cases here exercise the listener in isolation:
 *
 *   1. echo roundtrip: POST /_mqproxy/fetch with a CL body; fake on_request
 *      accepts, on_body accumulates, on_body_done writes a 200 + body back via
 *      the handle ops, then finish. Assert body byte-exact, on_body_done fired,
 *      reply parsed 200.
 *   2. 404: GET /other -> listener's own 404, no cbs fired.
 *   3. 411: chunked Transfer-Encoding -> 411, no cbs fired.
 *   4. 400: malformed head -> 400.
 *   5. mid-body abort: CL=1000 but only 10 bytes then close -> on_aborted (not
 *      on_body_done).
 *   6. backpressure smoke: on_body returns -1 once -> listener pauses; resume
 *      via the handle; full body still delivered (pause asserted via a flag).
 *   7. oversize body: CL bytes + extra trailing garbage -> conn aborted; cbs
 *      saw exactly CL body bytes; no crash.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "gateway/mq_fetch_listener.h"
#include "gateway/mq_gw_client.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_h3.h"
#include "transport/mq_transport.h"

#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

/* ── fake gateway state ─────────────────────────────────────────────────── */
struct fake_gw {
    int on_request_called;
    int on_body_done_called;
    int on_aborted_called;
    void *handle; /* captured per-conn handle */

    uint8_t body[4096];
    size_t body_len;

    /* backpressure control */
    int pause_once;  /* return -1 from the next on_body, then clear */
    int paused_flag; /* set to 1 when we asked for a pause */

    /* what on_body_done should do */
    int write_echo_reply;        /* on done, write 200 + accumulated body, finish */
    int write_small_200_on_done; /* on done, write a small empty-body 200, finish */
    int write_big_on_done;       /* on done, stream a large body to exercise hw */
    int reject;                  /* on_request returns -1 (handler-owned reply) */

    /* high-watermark / drain bookkeeping (write_big_on_done path) */
    int saw_zero_return; /* mq_fetch_conn_write returned 0 at least once */
    int drain_fired;     /* drain_cb invoked */
    size_t big_total;    /* bytes to stream */
    size_t big_sent;     /* bytes accepted so far */
};

static int
fake_on_request(const mq_http1_req_t *req, void *handle, void *user, void **req_ctx)
{
    (void)req;
    struct fake_gw *g = (struct fake_gw *)user;
    g->on_request_called++;
    g->handle = handle;
    *req_ctx = g;

    if (g->reject) {
        const char *r = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n"
                        "Content-Length: 0\r\n\r\n";
        mq_fetch_conn_write(handle, r, strlen(r));
        return -1;
    }
    return 0;
}

static int
fake_on_body(void *req_ctx, const uint8_t *p, size_t len)
{
    struct fake_gw *g = (struct fake_gw *)req_ctx;
    if (g->body_len + len <= sizeof(g->body)) {
        memcpy(g->body + g->body_len, p, len);
    }
    g->body_len += len;
    if (g->pause_once) {
        g->pause_once = 0;
        g->paused_flag = 1;
        return -1; /* request a pause (chunk still consumed) */
    }
    return 0;
}

/* Write a small fixed 200 OK (empty body) via the handle, then finish. Used by
 * the oversize-after-done case to prove a gateway response written after the
 * body is complete still flushes to the client even though trailing garbage
 * arrived. */
static void
write_small_200_and_finish(struct fake_gw *g)
{
    char head[128];
    int o = 0, n;
    n = mq_http1_write_status(head + o, sizeof(head) - o, 200, "OK");
    o += n;
    n = mq_http1_write_header(head + o, sizeof(head) - o, "Connection", "close");
    o += n;
    n = mq_http1_write_header(head + o, sizeof(head) - o, "Content-Length", "0");
    o += n;
    head[o++] = '\r';
    head[o++] = '\n';
    mq_fetch_conn_write(g->handle, head, (size_t)o);
    mq_fetch_conn_finish(g->handle);
}

/* Feed as much of a large response body as the output queue accepts, stopping
 * when mq_fetch_conn_write returns 0 (high watermark). When all bytes are
 * accepted, finish. Drives the high-watermark/drain test. */
static void
big_pump(struct fake_gw *g)
{
    static const uint8_t chunk[8192] = {'A'};
    while (g->big_sent < g->big_total) {
        size_t want = g->big_total - g->big_sent;
        if (want > sizeof(chunk)) want = sizeof(chunk);
        int rc = mq_fetch_conn_write(g->handle, chunk, want);
        if (rc < 0) return; /* handle dead */
        g->big_sent += want;
        if (rc == 0) {
            g->saw_zero_return = 1;
            return; /* high watermark: wait for drain_cb */
        }
    }
    mq_fetch_conn_finish(g->handle);
}

static void
big_drain_cb(void *user)
{
    struct fake_gw *g = (struct fake_gw *)user;
    g->drain_fired = 1;
    big_pump(g);
}

static void
fake_on_body_done(void *req_ctx)
{
    struct fake_gw *g = (struct fake_gw *)req_ctx;
    g->on_body_done_called++;
    if (g->write_small_200_on_done) {
        write_small_200_and_finish(g);
        return;
    }
    if (g->write_big_on_done) {
        /* Write a head with a large Content-Length, then stream the body,
         * exercising the high watermark and drain callback. */
        char head[128];
        int o = 0, n;
        n = mq_http1_write_status(head + o, sizeof(head) - o, 200, "OK");
        o += n;
        n = mq_http1_write_header(head + o, sizeof(head) - o, "Connection", "close");
        o += n;
        char cl[32];
        snprintf(cl, sizeof(cl), "%zu", g->big_total);
        n = mq_http1_write_header(head + o, sizeof(head) - o, "Content-Length", cl);
        o += n;
        head[o++] = '\r';
        head[o++] = '\n';
        mq_fetch_conn_write(g->handle, head, (size_t)o);
        mq_fetch_conn_set_drain_cb(g->handle, big_drain_cb, g);
        big_pump(g);
        return;
    }
    if (g->write_echo_reply) {
        char head[128];
        int o = 0, n;
        n = mq_http1_write_status(head + o, sizeof(head) - o, 200, "OK");
        o += n;
        n = mq_http1_write_header(head + o, sizeof(head) - o, "Connection", "close");
        o += n;
        char cl[32];
        snprintf(cl, sizeof(cl), "%zu", g->body_len);
        n = mq_http1_write_header(head + o, sizeof(head) - o, "Content-Length", cl);
        o += n;
        head[o++] = '\r';
        head[o++] = '\n';
        mq_fetch_conn_write(g->handle, head, (size_t)o);
        if (g->body_len > 0) mq_fetch_conn_write(g->handle, g->body, g->body_len);
        mq_fetch_conn_finish(g->handle);
    }
}

static void
fake_on_aborted(void *req_ctx)
{
    struct fake_gw *g = (struct fake_gw *)req_ctx;
    g->on_aborted_called++;
}

static mq_fetch_cbs_t
fake_cbs(void)
{
    mq_fetch_cbs_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.on_request = fake_on_request;
    cbs.on_body = fake_on_body;
    cbs.on_body_done = fake_on_body_done;
    cbs.on_aborted = fake_on_aborted;
    return cbs;
}

/* Substring search over a byte range (avoids the GNU-only memmem). */
static int
contains(const uint8_t *hay, size_t hlen, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || hlen < nl) return 0;
    for (size_t i = 0; i + nl <= hlen; i++) {
        if (memcmp(hay + i, needle, nl) == 0) return 1;
    }
    return 0;
}

/* ── loopback test plumbing (mirrors test_socks5_listener.c) ────────────── */
static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int
dial(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void
send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, p + off, len - off, 0);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

/* Pump the base while reading up to `want` bytes from fd, up to budget_ms. */
static size_t
pump_read(struct event_base *base, int fd, uint8_t *out, size_t want, uint64_t budget_ms)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
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
    fcntl(fd, F_SETFL, fl);
    return got;
}

/* Pump until fd is at EOF (peer closed), or budget elapses. Returns 1 if EOF. */
static int
pump_until_eof(struct event_base *base, int fd, uint64_t budget_ms)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int eof = 0;
    uint64_t deadline = now_ms() + budget_ms;
    while (!eof && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        uint8_t b[64];
        ssize_t n = recv(fd, b, sizeof(b), 0);
        if (n == 0) {
            eof = 1;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            eof = 1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    return eof;
}

/* Pump the base a few times to let pending I/O / cbs settle. */
static void
pump_a_bit(struct event_base *base, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

/* Read the full reply (head + body) until EOF, into out. Returns total bytes. */
static size_t
pump_read_all(struct event_base *base, int fd, uint8_t *out, size_t cap,
              uint64_t budget_ms)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    size_t got = 0;
    int eof = 0;
    uint64_t deadline = now_ms() + budget_ms;
    while (!eof && got < cap && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        ssize_t n = recv(fd, out + got, cap - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n == 0) {
            eof = 1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    return got;
}

/* ── Scenario 1: echo roundtrip ─────────────────────────────────────────── */
static void
test_echo_roundtrip(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    g.write_echo_reply = 1;
    mq_fetch_cbs_t cbs = fake_cbs();

    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_fetch_listener_port(l);
    MQ_CHECK(port != 0);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_fetch_listener_free(l);
        return;
    }

    const char *body = "hello world";
    char reqbuf[256];
    int rn = snprintf(reqbuf, sizeof(reqbuf),
                      "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                      "Content-Length: %zu\r\n\r\n%s",
                      strlen(body), body);
    send_all(c, reqbuf, (size_t)rn);

    uint8_t reply[512] = {0};
    size_t got = pump_read_all(base, c, reply, sizeof(reply), 2000);
    MQ_CHECK(got > 0);

    /* Reply parses as 200 with the echoed body. */
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);
    MQ_CHECK_EQ_INT(g.on_request_called, 1);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 1);
    MQ_CHECK_EQ_INT(g.on_aborted_called, 0);
    MQ_CHECK_EQ_INT(g.body_len, strlen(body));
    MQ_CHECK_MEM(g.body, body, strlen(body));

    /* The reply tail must contain the echoed body. */
    MQ_CHECK(contains(reply, got, body));

    close(c);
    pump_a_bit(base, 100);
    mq_fetch_listener_free(l);
}

/* ── Scenario 2: 404 (wrong method/path), no cbs ────────────────────────── */
static void
test_404(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    const char *req = "GET /other HTTP/1.1\r\nHost: x\r\n\r\n";
    send_all(c, req, strlen(req));

    uint8_t reply[128] = {0};
    size_t got = pump_read(base, c, reply, 12, 1000);
    MQ_CHECK(got >= 12);
    MQ_CHECK_MEM(reply, "HTTP/1.1 404", 12);
    MQ_CHECK_EQ_INT(g.on_request_called, 0);
    MQ_CHECK(pump_until_eof(base, c, 1000));

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 3: 411 (chunked TE), no cbs ───────────────────────────────── */
static void
test_411(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                      "Transfer-Encoding: chunked\r\n\r\n";
    send_all(c, req, strlen(req));

    uint8_t reply[128] = {0};
    size_t got = pump_read(base, c, reply, 12, 1000);
    MQ_CHECK(got >= 12);
    MQ_CHECK_MEM(reply, "HTTP/1.1 411", 12);
    MQ_CHECK_EQ_INT(g.on_request_called, 0);
    MQ_CHECK(pump_until_eof(base, c, 1000));

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 4: 400 (malformed head) ───────────────────────────────────── */
static void
test_400(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    /* obs-fold continuation line is rejected as BAD by the parser. */
    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n \tfolded\r\n\r\n";
    send_all(c, req, strlen(req));

    uint8_t reply[128] = {0};
    size_t got = pump_read(base, c, reply, 12, 1000);
    MQ_CHECK(got >= 12);
    MQ_CHECK_MEM(reply, "HTTP/1.1 400", 12);
    MQ_CHECK_EQ_INT(g.on_request_called, 0);
    MQ_CHECK(pump_until_eof(base, c, 1000));

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 5: mid-body abort ─────────────────────────────────────────── */
static void
test_mid_body_abort(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    const char *head = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                       "Content-Length: 1000\r\n\r\n";
    send_all(c, head, strlen(head));
    /* Only 10 of the promised 1000 body bytes, then close. */
    send_all(c, "0123456789", 10);
    pump_a_bit(base, 100);
    close(c);

    /* Pump until the listener sees EOF and fires on_aborted. */
    uint64_t deadline = now_ms() + 1000;
    while (g.on_aborted_called == 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(g.on_request_called, 1);
    MQ_CHECK_EQ_INT(g.on_aborted_called, 1);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 0);
    MQ_CHECK_EQ_INT(g.body_len, 10);

    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 6: backpressure smoke ─────────────────────────────────────── */
static void
test_backpressure(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    g.pause_once = 1;       /* first on_body returns -1 -> pause */
    g.write_echo_reply = 1; /* on done, echo back + finish */
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    /* Send head, then body in two pieces so the first on_body triggers a pause
     * before all body is delivered. */
    const char *head = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                       "Content-Length: 20\r\n\r\n";
    send_all(c, head, strlen(head));
    send_all(c, "0123456789", 10);
    pump_a_bit(base, 100);

    /* The pause must have happened, and only the first chunk delivered so far. */
    MQ_CHECK_EQ_INT(g.paused_flag, 1);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 0);

    /* Send the rest; it stays buffered in the socket while paused. */
    send_all(c, "abcdefghij", 10);
    pump_a_bit(base, 100);
    /* Still paused: the remaining bytes must NOT have been delivered yet. */
    MQ_CHECK_EQ_INT(g.on_body_done_called, 0);

    /* Resume: full body must now flow and on_body_done fire. */
    mq_fetch_conn_resume_read(g.handle);

    uint8_t reply[512] = {0};
    size_t got = pump_read_all(base, c, reply, sizeof(reply), 2000);
    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 1);
    MQ_CHECK_EQ_INT(g.body_len, 20);
    MQ_CHECK_MEM(g.body, "0123456789abcdefghij", 20);

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 7: oversize body (trailing garbage after a complete body) ──────
 *
 * Trailing bytes past Content-Length are a peer protocol violation, but the
 * request body is FULLY received: on_body_done fires, the gateway writes its
 * response, and that response must still flush to the client. The listener must
 * NOT fire on_aborted (that contract is "peer died BEFORE CL") and must NOT yank
 * the conn from the read path — teardown is the gateway's finish()/abort(). */
static void
test_oversize_body(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    g.write_small_200_on_done = 1; /* gateway responds after the body completes */
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    /* CL=5 but send 5 + 7 trailing garbage bytes in one shot. */
    const char *head = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                       "Content-Length: 5\r\n\r\n";
    send_all(c, head, strlen(head));
    send_all(c, "HELLOgarbage", 12);

    /* The gateway's 200 (written from on_body_done) must reach the client. */
    uint8_t reply[256] = {0};
    size_t got = pump_read_all(base, c, reply, sizeof(reply), 2000);

    /* on_body saw exactly CL=5 bytes; on_body_done fired exactly once. The
     * trailing garbage must NOT fire on_aborted and must NOT discard the
     * gateway's response. */
    MQ_CHECK_EQ_INT(g.on_request_called, 1);
    MQ_CHECK_EQ_INT(g.body_len, 5);
    MQ_CHECK_MEM(g.body, "HELLO", 5);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 1); /* exactly CL delivered */
    MQ_CHECK_EQ_INT(g.on_aborted_called, 0);   /* NOT aborted: body was complete */
    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12); /* gateway response still flushed */

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ── Scenario 8: free listener with a live mid-body conn ─────────────────────
 *
 * mq_fetch_listener_free must tear down a connection that is still mid-body
 * (head parsed, on_request fired, body incomplete) without crashing or leaking
 * (verified under ASan). No on_aborted is required here — free is a hard
 * shutdown, not a peer EOF. */
static void
test_free_live_conn(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    const char *head = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                       "Content-Length: 1000\r\n\r\n";
    send_all(c, head, strlen(head));
    send_all(c, "0123456789", 10); /* partial body: conn stays mid-body */
    pump_a_bit(base, 100);

    /* The conn is alive and mid-body. */
    MQ_CHECK_EQ_INT(g.on_request_called, 1);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 0);

    /* Free with the conn still live: must not crash / leak. */
    mq_fetch_listener_free(l);

    close(c);
    pump_a_bit(base, 50);
}

/* ── Scenario 9: high watermark + drain ──────────────────────────────────────
 *
 * The gateway writes more than the high watermark, so mq_fetch_conn_write
 * returns 0 at least once; the drain callback then fires and the write
 * completes. */
static void
test_highwater_drain(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
    g.write_big_on_done = 1;
    /* Far larger than any plausible loopback socket buffer, so the output queue
     * is forced past the 256 KiB high watermark while the client is not being
     * read. The gateway stops feeding at the watermark (queue stays ~256 KiB,
     * well under the 4 MiB ceiling regardless of this total). */
    g.big_total = 8 * 1024 * 1024;
    mq_fetch_cbs_t cbs = fake_cbs();
    mq_fetch_listener_t *l = mq_fetch_listener_new(base, "127.0.0.1", 0, &cbs, &g);
    MQ_CHECK(l != NULL);
    uint16_t port = mq_fetch_listener_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);

    const char *head = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                       "Content-Length: 0\r\n\r\n";
    send_all(c, head, strlen(head));

    /* Drain the client slowly enough that the queue actually crosses the high
     * watermark first (pump a few times before reading everything). */
    pump_a_bit(base, 50);

    uint8_t *reply = malloc(g.big_total + 1024);
    MQ_CHECK(reply != NULL);
    size_t got = pump_read_all(base, c, reply, g.big_total + 1024, 4000);

    MQ_CHECK_EQ_INT(g.on_body_done_called, 1);
    MQ_CHECK_EQ_INT(g.saw_zero_return, 1); /* high watermark was hit */
    MQ_CHECK_EQ_INT(g.drain_fired, 1);     /* drain cb fired */
    MQ_CHECK_EQ_INT(g.big_sent, g.big_total);
    MQ_CHECK(got >= g.big_total); /* full body reached the client */
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);

    free(reply);
    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
}

/* ════════════════════════════════════════════════════════════════════════════
 * Gateway client (Task 3.2): fetch→H3 bridge cases.
 *
 * These stand up a REAL in-process H3 tunnel over loopback UDP:
 *   - a fake gateway SERVER: server transport (TLS) + runtime + mq_h3 with
 *     server hooks that recv the forwarded request and reply per scenario;
 *   - the CLIENT under test: client transport + runtime + mq_h3 (NULL hooks) +
 *     mq_gw_client + a real mq_fetch_listener wired to the gw_client's cbs.
 * A local "curl" socket POSTs /_mqproxy/fetch; we assert the response.
 * ════════════════════════════════════════════════════════════════════════════ */

#include <netinet/in.h>
#include <sys/socket.h>

/* Reserve an ephemeral loopback UDP port (bind :0, read it, close). */
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

/* ── fake gateway server (H3) ───────────────────────────────────────────────*/

#define SRV_MAX_HDRS 32
#define SRV_HDR_LEN  512

typedef struct {
    char name[SRV_HDR_LEN];
    char value[SRV_HDR_LEN];
} srv_hdr_t;

/* Per-request server state + scenario controls. */
typedef struct {
    mq_h3_req_t *req;
    int got_headers;
    int saw_fin;
    int closed;

    srv_hdr_t hdrs[SRV_MAX_HDRS];
    int n_hdrs;

    uint8_t body[256 * 1024];
    size_t body_len;

    int responded;

    /* response send state (driven by srv_respond + srv_on_req_write). */
    const uint8_t *snd; /* response body to send (points at s->body or g_dl_body) */
    size_t snd_total;   /* total response body length */
    size_t snd_off;     /* bytes accepted so far */
    int snd_fin_done;   /* the fin has been sent */

    /* scenario controls (set on the shared server before the request). */
    int scenario;      /* see SC_* below */
    int request_count; /* incremented on each on_new_req (for case 4 asserts) */
} gw_srv_t;

enum {
    SC_200_CL = 0,      /* 200 + content-length + body */
    SC_200_NOCL = 1,    /* 200 WITHOUT content-length (forces chunked downstream) */
    SC_ECHO_UPLOAD = 2, /* 200 + echo the received upload body back (CL) */
    SC_RESET_MID = 3,   /* headers + partial body then reset (mid-download trunc) */
    SC_HANG = 4,        /* receive everything but NEVER respond (request stays live) */
};

static gw_srv_t g_srv; /* one in-flight request at a time in these tests */

static const uint8_t *g_dl_body; /* download body for SC_200_CL / SC_200_NOCL */
static size_t g_dl_body_len;

static void
srv_capture_hdr(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    gw_srv_t *s = (gw_srv_t *)u;
    if (s->n_hdrs >= SRV_MAX_HDRS) return;
    srv_hdr_t *h = &s->hdrs[s->n_hdrs++];
    size_t cn = nl < SRV_HDR_LEN - 1 ? nl : SRV_HDR_LEN - 1;
    size_t cv = vl < SRV_HDR_LEN - 1 ? vl : SRV_HDR_LEN - 1;
    memcpy(h->name, n, cn);
    h->name[cn] = '\0';
    memcpy(h->value, v, cv);
    h->value[cv] = '\0';
}

static const char *
srv_find_hdr(const gw_srv_t *s, const char *name)
{
    for (int i = 0; i < s->n_hdrs; i++)
        if (strcmp(s->hdrs[i].name, name) == 0) return s->hdrs[i].value;
    return NULL;
}

/* Push as much of the pending response body as xquic accepts, riding fin on the
 * last byte; any EAGAIN remainder is retried from srv_on_req_write. Safe to call
 * repeatedly. */
static void
srv_body_pump(gw_srv_t *s)
{
    if (!s->req || s->snd_fin_done) return;
    while (s->snd_off < s->snd_total) {
        int last = 1; /* whole remainder is the tail */
        long acc = mq_h3_req_send_body(s->req, s->snd + s->snd_off,
                                       s->snd_total - s->snd_off, last);
        if (acc <= 0) return; /* EAGAIN: resume on the next on_write */
        s->snd_off += (size_t)acc;
        if (s->snd_off >= s->snd_total) {
            s->snd_fin_done = 1; /* fin rode the last byte */
            return;
        }
    }
    /* Zero-length body: send a bare fin. */
    if (s->snd_total == 0) {
        mq_h3_req_finish(s->req);
        s->snd_fin_done = 1;
    }
}

static void
srv_respond(gw_srv_t *s)
{
    if (s->responded || !s->req) return;

    if (s->scenario == SC_HANG) {
        /* Never respond: leave the request open so the bridge has a live in-flight
         * request at teardown. Do NOT mark responded (nothing was sent). */
        return;
    }

    s->responded = 1;

    if (s->scenario == SC_RESET_MID) {
        /* Headers (no CL) + a partial body chunk, then reset → the downstream
         * local socket must see a truncated (no clean terminator) close. */
        mq_h3_header_t h[] = {{":status", "200"}};
        mq_h3_req_send_headers(s->req, h, 1, 0);
        static const uint8_t part[64] = {'P'};
        mq_h3_req_send_body(s->req, part, sizeof(part), 0);
        mq_h3_req_reset(s->req);
        s->req = NULL;
        return;
    }

    if (s->scenario == SC_ECHO_UPLOAD) {
        char cl[32];
        snprintf(cl, sizeof(cl), "%zu", s->body_len);
        mq_h3_header_t h[] = {{":status", "200"}, {"content-length", cl}};
        mq_h3_req_send_headers(s->req, h, 2, 0);
        s->snd = s->body;
        s->snd_total = s->body_len;
        s->snd_off = 0;
        srv_body_pump(s);
        return;
    }

    /* SC_200_CL / SC_200_NOCL: download a fixed body. */
    if (s->scenario == SC_200_NOCL) {
        mq_h3_header_t h[] = {{":status", "200"}, {"x-mq-origin-protocol", "h2"}};
        mq_h3_req_send_headers(s->req, h, 2, 0);
    } else {
        char cl[32];
        snprintf(cl, sizeof(cl), "%zu", g_dl_body_len);
        mq_h3_header_t h[] = {{":status", "200"}, {"content-length", cl}};
        mq_h3_req_send_headers(s->req, h, 2, 0);
    }
    s->snd = g_dl_body;
    s->snd_total = g_dl_body_len;
    s->snd_off = 0;
    srv_body_pump(s);
}

static void
srv_on_req_read(mq_h3_req_t *r, int flag, void *user)
{
    gw_srv_t *s = (gw_srv_t *)user;
    if (flag & (XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_TRAILER)) {
        int fin = 0;
        int n = mq_h3_req_recv_headers(r, srv_capture_hdr, s, &fin);
        if (n >= 0) s->got_headers = 1;
        if (fin) s->saw_fin = 1;
    }
    for (;;) {
        int fin = 0;
        long n = mq_h3_req_recv_body(r, s->body + s->body_len,
                                     sizeof(s->body) - s->body_len, &fin);
        if (n > 0) s->body_len += (size_t)n;
        if (fin) s->saw_fin = 1;
        if (n <= 0) break;
    }
    /* Respond once the full request body (fin) has arrived. */
    if (s->saw_fin && !s->responded) srv_respond(s);
}

static void
srv_on_req_write(mq_h3_req_t *r, void *user)
{
    (void)r;
    gw_srv_t *s = (gw_srv_t *)user;
    if (!s->responded) return;
    srv_body_pump(s); /* resume any flow-control-blocked response body */
}

static void
srv_on_req_close(mq_h3_req_t *r, void *user)
{
    (void)r;
    gw_srv_t *s = (gw_srv_t *)user;
    s->closed = 1;
    s->req = NULL;
}

static void
srv_on_new_req(mq_h3_req_t *r, void *user)
{
    (void)user;
    g_srv.request_count++;
    g_srv.req = r;
    mq_h3_req_set_cbs(r, srv_on_req_read, srv_on_req_write, srv_on_req_close, &g_srv);
}

static void
srv_on_new_conn(mq_h3_conn_t *c, void *user)
{
    (void)c;
    (void)user;
}

/* ── gateway-client fixture ─────────────────────────────────────────────────*/

typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_h3_t *srv_h3;
    mq_h3_t *cli_h3;
    mq_gw_client_t *gw;
    mq_fetch_listener_t *listener;
    uint16_t lport;
} gw_fixture_t;

static int
gw_fixture_up(gw_fixture_t *f, const char *token)
{
    memset(f, 0, sizeof(*f));
    memset(&g_srv, 0, sizeof(g_srv));

    f->base = event_base_new();
    if (!f->base) return -1;

    uint16_t srv_port = reserve_udp_port();
    if (!srv_port) return -1;

    /* Server transport + runtime + h3 (server hooks). */
    f->srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    if (!f->srv_t) return -1;
    f->srv_rt = mq_runtime_new(f->srv_t, f->base);
    if (!f->srv_rt) return -1;

    /* Match the H3 fabric's mp settings so the negotiated conn settings line up. */
    xqc_conn_settings_t srv_settings;
    memset(&srv_settings, 0, sizeof(srv_settings));
    srv_settings.proto_version = XQC_VERSION_V1;
    srv_settings.pacing_on = 1;
    mq_conn_apply_mp_settings(&srv_settings, /*is_server=*/1, MQ_CC_BBR2);
    xqc_server_set_conn_settings(mq_transport_xqc(f->srv_t), &srv_settings);

    f->srv_h3 = mq_h3_init(f->srv_t, srv_on_new_conn, srv_on_new_req, NULL);
    if (!f->srv_h3) return -1;
    if (mq_runtime_open_udp_path(f->srv_rt, "127.0.0.1", srv_port) != 0) return -1;

    /* Client transport + runtime + h3 (pure client). */
    f->cli_t = mq_transport_new(0);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    if (!f->cli_rt) return -1;
    if (mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0) != 0) return -1;
    f->cli_h3 = mq_h3_init(f->cli_t, NULL, NULL, NULL);
    if (!f->cli_h3) return -1;

    f->gw = mq_gw_client_new(f->cli_t, f->cli_rt, f->cli_h3, "127.0.0.1", srv_port, token,
                             MQ_CC_BBR2);
    if (!f->gw) return -1;

    /* Real fetch listener wired to the gw client's cbs. */
    f->listener = mq_fetch_listener_new(f->base, "127.0.0.1", 0, mq_gw_client_fetch_cbs(),
                                        mq_gw_client_fetch_user(f->gw));
    if (!f->listener) return -1;
    f->lport = mq_fetch_listener_port(f->listener);
    if (!f->lport) return -1;

    /* Pump until the tunnel conn is established (gw connected eagerly). */
    uint64_t deadline = now_ms() + 5000;
    while (now_ms() < deadline) {
        event_base_loop(f->base, EVLOOP_NONBLOCK);
        /* No direct accessor; a short settle is enough on loopback. The first
         * fetch request itself drives further pumping. */
        if (now_ms() > deadline - 4700) break; /* ~300ms settle */
    }
    return 0;
}

/* tunnel-unavailable fixture: gw points at a CLOSED UDP port (no server). */
static int
gw_fixture_up_dead(gw_fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    memset(&g_srv, 0, sizeof(g_srv));
    f->base = event_base_new();
    if (!f->base) return -1;
    uint16_t dead = reserve_udp_port(); /* reserved then released → nothing listens */
    if (!dead) return -1;

    f->cli_t = mq_transport_new(0);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    if (!f->cli_rt) return -1;
    if (mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0) != 0) return -1;
    f->cli_h3 = mq_h3_init(f->cli_t, NULL, NULL, NULL);
    if (!f->cli_h3) return -1;
    f->gw = mq_gw_client_new(f->cli_t, f->cli_rt, f->cli_h3, "127.0.0.1", dead, "tok",
                             MQ_CC_BBR2);
    if (!f->gw) return -1;
    f->listener = mq_fetch_listener_new(f->base, "127.0.0.1", 0, mq_gw_client_fetch_cbs(),
                                        mq_gw_client_fetch_user(f->gw));
    if (!f->listener) return -1;
    f->lport = mq_fetch_listener_port(f->listener);
    if (!f->lport) return -1;
    return 0;
}

static void
gw_fixture_down(gw_fixture_t *f)
{
    /* SANCTIONED TEARDOWN ORDER (mq_gw_client.h): gw_client_free FIRST, while the
     * client H3 engine is STILL LIVE, so it can detach (set_cbs NULL) + reset any
     * in-flight request against a live engine and abort its local handle — no
     * UAF. THEN mq_h3_free (mq_h3.h contract: before transport_free), THEN
     * transport_free. The listener is freed after gw_client (gw_client aborts the
     * local handles; the listener then tears down its own conn state). The server
     * side has no gw_client, so its h3/transport free in the usual order. */
    if (f->gw) mq_gw_client_free(f->gw);
    if (f->cli_h3) mq_h3_free(f->cli_h3);
    if (f->srv_h3) mq_h3_free(f->srv_h3);
    if (f->cli_t) mq_transport_free(f->cli_t);
    if (f->srv_t) mq_transport_free(f->srv_t);
    if (f->cli_rt) mq_runtime_free(f->cli_rt);
    if (f->srv_rt) mq_runtime_free(f->srv_rt);
    if (f->listener) mq_fetch_listener_free(f->listener);
    if (f->base) event_base_free(f->base);
}

/* Parse a chunked HTTP/1.1 body from the response buffer into out. Returns the
 * de-chunked length, or (size_t)-1 on a framing error. `body_start` is the
 * offset of the first chunk-size line (after the head's \r\n\r\n). */
static size_t
dechunk(const uint8_t *p, size_t len, uint8_t *out, size_t out_cap)
{
    size_t i = 0, o = 0;
    for (;;) {
        /* parse hex chunk size up to \r\n */
        size_t sz = 0;
        int any = 0;
        while (i < len && p[i] != '\r') {
            char ch = (char)p[i];
            int d;
            if (ch >= '0' && ch <= '9')
                d = ch - '0';
            else if (ch >= 'a' && ch <= 'f')
                d = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F')
                d = ch - 'A' + 10;
            else
                return (size_t)-1;
            sz = sz * 16 + (size_t)d;
            any = 1;
            i++;
        }
        if (!any || i + 1 >= len || p[i] != '\r' || p[i + 1] != '\n') return (size_t)-1;
        i += 2;
        if (sz == 0) return o; /* terminator */
        if (i + sz + 2 > len || o + sz > out_cap) return (size_t)-1;
        memcpy(out + o, p + i, sz);
        o += sz;
        i += sz;
        if (p[i] != '\r' || p[i + 1] != '\n') return (size_t)-1;
        i += 2;
    }
}

/* Locate the response body start (offset after the head terminator). */
static size_t
head_end(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++)
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n')
            return i + 4;
    return (size_t)-1;
}

/* Pump while sending the POST request and reading the full response to EOF. */
static size_t
fetch_roundtrip(struct event_base *base, uint16_t lport, const char *reqbytes,
                size_t reqlen, uint8_t *out, size_t cap, uint64_t budget_ms)
{
    int c = dial(lport);
    MQ_CHECK(c >= 0);
    if (c < 0) return 0;
    send_all(c, reqbytes, reqlen);
    size_t got = pump_read_all(base, c, out, cap, budget_ms);
    close(c);
    pump_a_bit(base, 100);
    return got;
}

/* ── Case 1: GET via fetch API → 200 + CL passthrough + byte-exact body ──────*/
static void
test_gw_get_cl(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    static const uint8_t DL[] = "the-downloaded-file-contents-0123456789";
    g_dl_body = DL;
    g_dl_body_len = sizeof(DL) - 1;
    g_srv.scenario = SC_200_CL;

    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/file\r\n"
                      "Cookie: should-be-stripped\r\n"
                      "X-Custom-Hdr: keepme\r\n"
                      "Content-Length: 0\r\n\r\n";
    uint8_t reply[4096] = {0};
    size_t got =
        fetch_roundtrip(f.base, f.lport, req, strlen(req), reply, sizeof(reply), 6000);

    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);
    /* Server saw the forwarded request. */
    MQ_CHECK_EQ_INT(g_srv.request_count, 1);
    MQ_CHECK(g_srv.got_headers);
    const char *m = srv_find_hdr(&g_srv, ":method");
    const char *sc = srv_find_hdr(&g_srv, ":scheme");
    const char *au = srv_find_hdr(&g_srv, ":authority");
    const char *pa = srv_find_hdr(&g_srv, ":path");
    const char *xa = srv_find_hdr(&g_srv, "x-mq-auth");
    const char *ck = srv_find_hdr(&g_srv, "cookie");
    const char *cu = srv_find_hdr(&g_srv, "x-custom-hdr");
    MQ_CHECK(m && strcmp(m, "GET") == 0);
    MQ_CHECK(sc && strcmp(sc, "https") == 0);
    MQ_CHECK(au && strcmp(au, "example.test") == 0);
    MQ_CHECK(pa && strcmp(pa, "/file") == 0);
    MQ_CHECK(xa && strcmp(xa, "Bearer sekrit") == 0); /* forwarded verbatim */
    MQ_CHECK(ck == NULL);                             /* Cookie stripped */
    MQ_CHECK(cu && strcmp(cu, "keepme") == 0);        /* custom header kept */

    /* Local reply: CL passthrough + byte-exact body. The response header name is
     * carried verbatim from H3 (lowercase field names). */
    MQ_CHECK(contains(reply, got, "content-length: 39"));
    MQ_CHECK(contains(reply, got, (const char *)DL));

    gw_fixture_down(&f);
}

/* ── Case 2: response WITHOUT content-length → chunked downstream ────────────*/
static void
test_gw_chunked(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    static const uint8_t DL[] =
        "no-content-length-here-so-this-must-be-chunked-downstream!!";
    g_dl_body = DL;
    g_dl_body_len = sizeof(DL) - 1;
    g_srv.scenario = SC_200_NOCL;

    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/stream\r\n"
                      "Content-Length: 0\r\n\r\n";
    uint8_t reply[4096] = {0};
    size_t got =
        fetch_roundtrip(f.base, f.lport, req, strlen(req), reply, sizeof(reply), 6000);

    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);
    MQ_CHECK(contains(reply, got, "Transfer-Encoding: chunked"));
    /* x-mq-* diagnostic header forwarded downstream. */
    MQ_CHECK(contains(reply, got, "x-mq-origin-protocol"));

    size_t hs = head_end(reply, got);
    MQ_CHECK(hs != (size_t)-1);
    uint8_t debody[4096];
    size_t dl = dechunk(reply + hs, got - hs, debody, sizeof(debody));
    MQ_CHECK_EQ_INT((int)dl, (int)(sizeof(DL) - 1));
    MQ_CHECK_MEM(debody, DL, sizeof(DL) - 1);

    gw_fixture_down(&f);
}

/* ── Case 3: upload (POST with CL body ≥ 64 KiB) echoed back ─────────────────*/
static void
test_gw_upload(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    g_srv.scenario = SC_ECHO_UPLOAD;

    const size_t N = 96 * 1024;
    uint8_t *body = malloc(N);
    MQ_CHECK(body != NULL);
    for (size_t i = 0; i < N; i++)
        body[i] = (uint8_t)((i * 131 + 7) & 0xff);

    char head[256];
    int hn = snprintf(head, sizeof(head),
                      "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/upload\r\n"
                      "X-Mq-Method: POST\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      N);
    uint8_t *reqbuf = malloc((size_t)hn + N);
    MQ_CHECK(reqbuf != NULL);
    memcpy(reqbuf, head, (size_t)hn);
    memcpy(reqbuf + hn, body, N);

    int c = dial(f.lport);
    MQ_CHECK(c >= 0);
    /* Send the whole request (head + body); the local listener streams the body
     * and our gw client applies backpressure as needed. */
    send_all(c, reqbuf, (size_t)hn + N);

    uint8_t *reply = malloc(N + 4096);
    MQ_CHECK(reply != NULL);
    size_t got = pump_read_all(f.base, c, reply, N + 4096, 15000);

    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 200", 12);
    MQ_CHECK_EQ_INT(g_srv.request_count, 1);
    const char *m = srv_find_hdr(&g_srv, ":method");
    MQ_CHECK(m && strcmp(m, "POST") == 0);
    /* The known request Content-Length must be re-emitted over the tunnel
     * (design §7.1 "再計算"): the gw client strips the client's original CL and
     * sends its own validated value, so the server frames the upload by CL. */
    {
        const char *cl = srv_find_hdr(&g_srv, "content-length");
        char want[32];
        snprintf(want, sizeof(want), "%zu", N);
        MQ_CHECK(cl && strcmp(cl, want) == 0);
    }
    MQ_CHECK(g_srv.saw_fin); /* upload finished cleanly */

    /* The echoed body must reach the local socket byte-exact. */
    size_t hs = head_end(reply, got);
    MQ_CHECK(hs != (size_t)-1);
    MQ_CHECK_EQ_INT((int)(got - hs), (int)N);
    if (got - hs == N) MQ_CHECK(memcmp(reply + hs, body, N) == 0);

    close(c);
    pump_a_bit(f.base, 100);
    free(body);
    free(reqbuf);
    free(reply);
    gw_fixture_down(&f);
}

/* ── Case 4: 400 family (client-owned) — server never sees a request ─────────*/
static void
test_gw_400_family(void)
{
    /* 4a: missing X-Mq-Auth. */
    {
        gw_fixture_t f;
        if (gw_fixture_up(&f, "sekrit") != 0) {
            gw_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                          "X-Mq-Target: https://example.test/x\r\n"
                          "Content-Length: 0\r\n\r\n";
        uint8_t reply[1024] = {0};
        size_t got = fetch_roundtrip(f.base, f.lport, req, strlen(req), reply,
                                     sizeof(reply), 4000);
        MQ_CHECK(got > 0);
        MQ_CHECK_MEM(reply, "HTTP/1.1 400", 12);
        MQ_CHECK(contains(reply, got, "X-Mq-Error: missing-auth"));
        MQ_CHECK_EQ_INT(g_srv.request_count, 0); /* server never saw it */
        gw_fixture_down(&f);
    }
    /* 4b: bad target (no scheme). */
    {
        gw_fixture_t f;
        if (gw_fixture_up(&f, "sekrit") != 0) {
            gw_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                          "X-Mq-Auth: Bearer sekrit\r\n"
                          "X-Mq-Target: not-a-valid-url\r\n"
                          "Content-Length: 0\r\n\r\n";
        uint8_t reply[1024] = {0};
        size_t got = fetch_roundtrip(f.base, f.lport, req, strlen(req), reply,
                                     sizeof(reply), 4000);
        MQ_CHECK(got > 0);
        MQ_CHECK_MEM(reply, "HTTP/1.1 400", 12);
        MQ_CHECK(contains(reply, got, "X-Mq-Error: bad-target"));
        MQ_CHECK_EQ_INT(g_srv.request_count, 0);
        gw_fixture_down(&f);
    }
    /* 4c: duplicate X-Mq-Target → 400. */
    {
        gw_fixture_t f;
        if (gw_fixture_up(&f, "sekrit") != 0) {
            gw_fixture_down(&f);
            MQ_CHECK(0);
            return;
        }
        const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                          "X-Mq-Auth: Bearer sekrit\r\n"
                          "X-Mq-Target: https://example.test/a\r\n"
                          "X-Mq-Target: https://example.test/b\r\n"
                          "Content-Length: 0\r\n\r\n";
        uint8_t reply[1024] = {0};
        size_t got = fetch_roundtrip(f.base, f.lport, req, strlen(req), reply,
                                     sizeof(reply), 4000);
        MQ_CHECK(got > 0);
        MQ_CHECK_MEM(reply, "HTTP/1.1 400", 12);
        MQ_CHECK(contains(reply, got, "X-Mq-Error: duplicate-control-header"));
        MQ_CHECK_EQ_INT(g_srv.request_count, 0);
        gw_fixture_down(&f);
    }
}

/* ── Case 5: tunnel-unavailable → 502 + X-Mq-Error: tunnel-unavailable ───────*/
static void
test_gw_tunnel_unavailable(void)
{
    gw_fixture_t f;
    if (gw_fixture_up_dead(&f) != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                      "X-Mq-Auth: Bearer tok\r\n"
                      "X-Mq-Target: https://example.test/x\r\n"
                      "Content-Length: 0\r\n\r\n";
    uint8_t reply[1024] = {0};
    size_t got =
        fetch_roundtrip(f.base, f.lport, req, strlen(req), reply, sizeof(reply), 3000);
    MQ_CHECK(got > 0);
    MQ_CHECK_MEM(reply, "HTTP/1.1 502", 12);
    MQ_CHECK(contains(reply, got, "X-Mq-Error: tunnel-unavailable"));
    gw_fixture_down(&f);
}

/* ── Case 6: mid-download reset → local socket sees a truncated close ────────*/
static void
test_gw_mid_download_reset(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    g_srv.scenario = SC_RESET_MID;

    const char *req = "POST /_mqproxy/fetch HTTP/1.1\r\nHost: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/trunc\r\n"
                      "Content-Length: 0\r\n\r\n";
    uint8_t reply[4096] = {0};
    size_t got =
        fetch_roundtrip(f.base, f.lport, req, strlen(req), reply, sizeof(reply), 6000);

    /* The upstream was reset mid-response. Two valid outcomes depending on
     * whether the 200 headers raced ahead of the RESET_STREAM:
     *   (a) headers arrived first → local sees "HTTP/1.1 200" but the chunked
     *       body is TRUNCATED: no clean "0\r\n\r\n" terminator (abort, not a
     *       fake clean finish);
     *   (b) the reset won the race (no headers delivered) → the bridge
     *       synthesizes "HTTP/1.1 502" + X-Mq-Error: upstream-reset.
     * In NEITHER case may the local client see a clean, complete download. */
    MQ_CHECK(got > 0);
    int is_200 = (got >= 12 && memcmp(reply, "HTTP/1.1 200", 12) == 0);
    int is_502 = (got >= 12 && memcmp(reply, "HTTP/1.1 502", 12) == 0);
    MQ_CHECK(is_200 || is_502);
    if (is_200) {
        /* Truncated: no clean chunked terminator. */
        MQ_CHECK(!contains(reply, got, "\r\n0\r\n\r\n"));
    } else if (is_502) {
        MQ_CHECK(contains(reply, got, "X-Mq-Error: upstream-reset"));
    }
    /* The request was forwarded (server saw it). */
    MQ_CHECK_EQ_INT(g_srv.request_count, 1);

    gw_fixture_down(&f);
}

/* ── Case 7: teardown with a request mid-flight (sanctioned order) ───────────
 *
 * A POST upload is STARTED but never completed (only part of the promised CL
 * body is sent) and the server NEVER responds (SC_HANG). At teardown the bridge
 * therefore holds a live in-flight mq_gw_req_t: the H3 request is open (tunnel
 * side live), the local handle is live, no response has begun. We then tear down
 * in the sanctioned order (gw_client_free FIRST, while the H3 engine is still
 * live). gw_client_free must detach the H3 callbacks + reset the request against
 * the LIVE engine and abort the local handle, with NO use-after-free and NO leak
 * (verified under ASan / LSan). */
static void
test_gw_teardown_midflight(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }
    g_srv.scenario = SC_HANG; /* server receives but never responds */

    /* Promise a large body but send only a fraction of it: the upload is started
     * (request open, headers + partial body forwarded) but never finished, so the
     * bridge keeps a live in-flight request. */
    const size_t CL = 256 * 1024;
    char head[256];
    int hn = snprintf(head, sizeof(head),
                      "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/hang\r\n"
                      "X-Mq-Method: POST\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      CL);

    int c = dial(f.lport);
    MQ_CHECK(c >= 0);
    send_all(c, head, (size_t)hn);
    /* Only a small slice of the promised body — upload stays mid-flight. */
    uint8_t chunk[4096];
    memset(chunk, 'U', sizeof(chunk));
    send_all(c, chunk, sizeof(chunk));

    /* Pump enough to drive the H3 request open + forward headers/partial body to
     * the (hanging) server. The request is now live on the bridge. */
    pump_a_bit(f.base, 400);

    /* The server saw exactly one request and never responded. */
    MQ_CHECK_EQ_INT(g_srv.request_count, 1);
    MQ_CHECK_EQ_INT(g_srv.responded, 0);

    /* Tear down with the request still mid-flight, in the sanctioned order
     * (gw_fixture_down frees gw_client FIRST while the H3 engine is live). Must
     * be ASan-clean and leak-free. */
    close(c);
    pump_a_bit(f.base, 50);
    gw_fixture_down(&f);
}

static void
run_all(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    test_echo_roundtrip(base);
    test_404(base);
    test_411(base);
    test_400(base);
    test_mid_body_abort(base);
    test_backpressure(base);
    test_oversize_body(base);
    test_free_live_conn(base);
    test_highwater_drain(base);

    event_base_free(base);

    /* Gateway-client (Task 3.2) cases — each owns its own base + transports. */
    test_gw_get_cl();
    test_gw_chunked();
    test_gw_upload();
    test_gw_400_family();
    test_gw_tunnel_unavailable();
    test_gw_mid_download_reset();
    test_gw_teardown_midflight();
}

MQ_TEST_MAIN(run_all())
