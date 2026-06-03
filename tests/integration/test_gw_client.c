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
    int write_echo_reply; /* on done, write 200 + accumulated body, finish */
    int reject;           /* on_request returns -1 (handler-owned reply) */
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

static void
fake_on_body_done(void *req_ctx)
{
    struct fake_gw *g = (struct fake_gw *)req_ctx;
    g->on_body_done_called++;
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

/* ── Scenario 7: oversize body ──────────────────────────────────────────── */
static void
test_oversize_body(struct event_base *base)
{
    struct fake_gw g;
    memset(&g, 0, sizeof(g));
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

    pump_a_bit(base, 200);

    /* on_body saw exactly CL=5 bytes; the conn was aborted (oversize). The
     * listener fires on_aborted on the oversize path. */
    MQ_CHECK_EQ_INT(g.on_request_called, 1);
    MQ_CHECK_EQ_INT(g.body_len, 5);
    MQ_CHECK_MEM(g.body, "HELLO", 5);
    MQ_CHECK_EQ_INT(g.on_body_done_called, 1); /* exactly CL delivered first */
    MQ_CHECK_EQ_INT(g.on_aborted_called, 1);   /* then the overflow aborts */
    MQ_CHECK(pump_until_eof(base, c, 1000));

    close(c);
    pump_a_bit(base, 50);
    mq_fetch_listener_free(l);
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

    event_base_free(base);
}

MQ_TEST_MAIN(run_all())
