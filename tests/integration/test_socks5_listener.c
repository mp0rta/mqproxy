// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_socks5_listener.c — Task 14 integration test for the ingress listeners.
 *
 * Drives the SOCKS5 (and a smoke-test of the HTTP CONNECT) accept loop with a
 * MOCK tcp_open to isolate the listener from the real proxy client. The mock
 * records the call (host/port/atype), fires cb(ok=1), and sets up an in-process
 * echo on local_fd so the test can assert bytes relay end-to-end. Because the
 * mock owns local_fd from the call onward (matching mq_client ownership), it
 * closes local_fd when the client side disconnects.
 *
 * Scenarios:
 *   1. Happy path: greeting (05 01 00) -> method reply (05 00); CONNECT to a
 *      domain host:port -> assert the mock saw the right target, the success
 *      reply (05 00 00 01 ...) arrives, and an echoed byte round-trips.
 *   2. UNSUPPORTED command (BIND): assert a reject reply (REP != 0) and the fd
 *      is closed by the listener (read returns EOF).
 *   3. Malformed greeting (bad version): assert the fd is closed (EOF), no
 *      tcp_open call.
 *   4. HTTP CONNECT smoke: a CONNECT line -> assert the mock saw the target and
 *      a 200 arrives.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "ingress/mq_listener.h"

/* ── Mock tcp_open ──────────────────────────────────────────────────────────
 * Records the most recent call, fires cb(ok=1), and keeps local_fd to act as
 * an echo origin: anything the app writes after the success reply is echoed
 * back. The mock owns local_fd (like the real client) and closes it on EOF.
 */
struct mock_open {
    struct event_base *base;
    int called;
    uint8_t host[256];
    size_t host_len;
    mq_addr_type_t atype;
    uint16_t port;
    uint8_t prebuf[512]; /* bytes coalesced with the request head */
    size_t prebuf_len;
    /* echo plumbing */
    int local_fd;
    struct event *echo_ev;
    int forced_ok; /* 1 => ok, 0 => fail with forced_err */
    mq_tcp_err_t forced_err;
};

static void
mock_echo_cb(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    struct mock_open *m = (struct mock_open *)user;
    uint8_t buf[256];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = send(fd, buf + off, (size_t)(n - off), 0);
            if (w <= 0) break;
            off += w;
        }
        return;
    }
    /* EOF or error: mock (owner of local_fd) closes it. */
    if (m->echo_ev) {
        event_free(m->echo_ev);
        m->echo_ev = NULL;
    }
    close(fd);
    m->local_fd = -1;
}

static void
mock_tcp_open(void *core, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
              uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
              void *user, mq_tcp_open_cb cb)
{
    struct mock_open *m = (struct mock_open *)core;
    m->called++;
    m->host_len = host_len < sizeof(m->host) ? host_len : sizeof(m->host);
    memcpy(m->host, host, m->host_len);
    m->atype = atype;
    m->port = port;
    m->local_fd = local_fd;
    m->prebuf_len = prebuf_len < sizeof(m->prebuf) ? prebuf_len : sizeof(m->prebuf);
    if (m->prebuf_len > 0 && prebuf) memcpy(m->prebuf, prebuf, m->prebuf_len);

    if (!m->forced_ok) {
        /* Fail path: fire cb(0) so the listener writes its error reply on
         * local_fd; the mock (owner) then closes local_fd after the cb. */
        if (cb) cb(0, m->forced_err, user);
        close(local_fd);
        m->local_fd = -1;
        return;
    }

    /* Success: fire cb(1) so the listener writes the success reply, then set up
     * an echo on local_fd. */
    if (cb) cb(1, MQ_TCP_OK, user);
    if (m->local_fd >= 0) {
        m->echo_ev =
            event_new(m->base, m->local_fd, EV_READ | EV_PERSIST, mock_echo_cb, m);
        event_add(m->echo_ev, NULL);
    }
}

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Connect a blocking-ish client socket to 127.0.0.1:port; returns fd or -1. */
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

/* Pump the event base while trying to read `want` bytes from fd, up to budget.
 * Returns total bytes read (may be < want on timeout). The client fd is
 * blocking, so we make it non-blocking for the pump and poll it. */
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
            break; /* EOF */
        }
    }
    fcntl(fd, F_SETFL, fl);
    return got;
}

/* Returns 1 if fd is at EOF (peer closed) within budget, else 0. */
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

static void
send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) break;
        off += (size_t)n;
    }
}

/* ── Scenario 1: SOCKS5 happy path ──────────────────────────────────────── */
static void
test_socks5_happy(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);
    MQ_CHECK(port != 0);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    /* Greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth). */
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    send_all(c, greeting, sizeof(greeting));

    uint8_t mreply[2] = {0};
    size_t got = pump_read(base, c, mreply, 2, 1000);
    MQ_CHECK_EQ_INT(got, 2);
    MQ_CHECK_EQ_INT(mreply[0], 0x05);
    MQ_CHECK_EQ_INT(mreply[1], 0x00);

    /* CONNECT to "example.com":443 (domain). */
    const char host[] = "example.com";
    uint8_t req[4 + 1 + 11 + 2];
    size_t i = 0;
    req[i++] = 0x05; /* VER */
    req[i++] = 0x01; /* CMD CONNECT */
    req[i++] = 0x00; /* RSV */
    req[i++] = 0x03; /* ATYP DOMAIN */
    req[i++] = (uint8_t)(sizeof(host) - 1);
    memcpy(req + i, host, sizeof(host) - 1);
    i += sizeof(host) - 1;
    req[i++] = (uint8_t)(443 >> 8);
    req[i++] = (uint8_t)(443 & 0xff);
    send_all(c, req, i);

    uint8_t creply[10] = {0};
    got = pump_read(base, c, creply, 10, 1000);
    MQ_CHECK_EQ_INT(got, 10);
    MQ_CHECK_EQ_INT(creply[0], 0x05);
    MQ_CHECK_EQ_INT(creply[1], 0x00); /* REP success */
    MQ_CHECK_EQ_INT(creply[3], 0x01); /* ATYP IPv4 bind */

    /* Mock saw the right target. */
    MQ_CHECK_EQ_INT(m.called, 1);
    MQ_CHECK_EQ_INT(m.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(m.port, 443);
    MQ_CHECK_EQ_INT(m.host_len, sizeof(host) - 1);
    MQ_CHECK_MEM(m.host, host, sizeof(host) - 1);

    /* End-to-end echo through local_fd. */
    uint8_t payload[] = "ping";
    send_all(c, payload, sizeof(payload) - 1);
    uint8_t echo[4] = {0};
    got = pump_read(base, c, echo, 4, 1000);
    MQ_CHECK_EQ_INT(got, 4);
    MQ_CHECK_MEM(echo, payload, 4);

    close(c);
    /* Pump so the mock's echo sees EOF and closes local_fd (no leak). */
    uint64_t deadline = now_ms() + 500;
    while (m.local_fd >= 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(m.local_fd, -1);

    mq_listener_free(l);
}

/* ── Scenario 2: SOCKS5 UNSUPPORTED command (BIND) ──────────────────────── */
static void
test_socks5_unsupported(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    uint8_t greeting[] = {0x05, 0x01, 0x00};
    send_all(c, greeting, sizeof(greeting));
    uint8_t mreply[2] = {0};
    MQ_CHECK_EQ_INT(pump_read(base, c, mreply, 2, 1000), 2);

    /* CONNECT request but CMD = BIND (0x02) => UNSUPPORTED. */
    uint8_t req[] = {0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50};
    send_all(c, req, sizeof(req));

    uint8_t creply[10] = {0};
    size_t got = pump_read(base, c, creply, 10, 1000);
    MQ_CHECK_EQ_INT(got, 10);
    MQ_CHECK_EQ_INT(creply[0], 0x05);
    MQ_CHECK_EQ_INT(creply[1], 0x07); /* REP 0x07: command not supported (BIND) */

    /* No tcp_open call, and the listener closes the accepted fd. */
    MQ_CHECK_EQ_INT(m.called, 0);
    MQ_CHECK(pump_until_eof(base, c, 1000));

    close(c);
    mq_listener_free(l);
}

/* ── Scenario 3: malformed greeting (bad version) ───────────────────────── */
static void
test_socks5_malformed(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    /* Bad version 0x04 => ERROR, fd closed, no reply guaranteed. */
    uint8_t bad[] = {0x04, 0x01, 0x00};
    send_all(c, bad, sizeof(bad));

    MQ_CHECK(pump_until_eof(base, c, 1000));
    MQ_CHECK_EQ_INT(m.called, 0);

    close(c);
    mq_listener_free(l);
}

/* ── Scenario 4: HTTP CONNECT smoke ─────────────────────────────────────── */
static void
test_http_connect_smoke(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l =
        mq_http_connect_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    const char *line =
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    send_all(c, (const uint8_t *)line, strlen(line));

    /* Read the 200 status line (just the start "HTTP/1.1 200"). */
    uint8_t buf[64] = {0};
    size_t got = pump_read(base, c, buf, 12, 1000);
    MQ_CHECK(got >= 12);
    MQ_CHECK_MEM(buf, "HTTP/1.1 200", 12);

    MQ_CHECK_EQ_INT(m.called, 1);
    MQ_CHECK_EQ_INT(m.atype, MQ_ADDR_DOMAIN);
    MQ_CHECK_EQ_INT(m.port, 443);
    MQ_CHECK_EQ_INT(m.host_len, strlen("example.com"));
    MQ_CHECK_MEM(m.host, "example.com", strlen("example.com"));

    close(c);
    uint64_t deadline = now_ms() + 500;
    while (m.local_fd >= 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(m.local_fd, -1);

    mq_listener_free(l);
}

/* ── Scenario 5: SOCKS5 request coalesced with early payload ─────────────────
 * The CONNECT request and the app's first upload bytes arrive in ONE send, so
 * the listener reads them in a single recv. The trailing bytes must be handed to
 * open_fn as the prebuffer (not dropped). */
static void
test_socks5_pipelined_prebuf(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    uint8_t greeting[] = {0x05, 0x01, 0x00};
    send_all(c, greeting, sizeof(greeting));
    uint8_t mreply[2] = {0};
    MQ_CHECK_EQ_INT(pump_read(base, c, mreply, 2, 1000), 2);

    /* CONNECT to example.com:443 (domain) immediately followed by "ping", in one
     * send so the listener reads request+payload together. */
    const char host[] = "example.com";
    const uint8_t early[] = "ping";
    uint8_t req[4 + 1 + 11 + 2 + 4];
    size_t i = 0;
    req[i++] = 0x05;
    req[i++] = 0x01;
    req[i++] = 0x00;
    req[i++] = 0x03;
    req[i++] = (uint8_t)(sizeof(host) - 1);
    memcpy(req + i, host, sizeof(host) - 1);
    i += sizeof(host) - 1;
    req[i++] = (uint8_t)(443 >> 8);
    req[i++] = (uint8_t)(443 & 0xff);
    memcpy(req + i, early, sizeof(early) - 1);
    i += sizeof(early) - 1;
    send_all(c, req, i);

    /* Drain the success reply so the pump runs the drive. */
    uint8_t creply[10] = {0};
    MQ_CHECK_EQ_INT(pump_read(base, c, creply, 10, 1000), 10);

    MQ_CHECK_EQ_INT(m.called, 1);
    MQ_CHECK_EQ_INT(m.prebuf_len, sizeof(early) - 1);
    MQ_CHECK_MEM(m.prebuf, early, sizeof(early) - 1);

    close(c);
    uint64_t deadline = now_ms() + 500;
    while (m.local_fd >= 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    mq_listener_free(l);
}

/* ── Scenario 6: HTTP CONNECT head coalesced with early payload ──────────── */
static void
test_http_pipelined_prebuf(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l =
        mq_http_connect_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t port = mq_listener_local_port(l);

    int c = dial(port);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    const char head[] =
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    const uint8_t early[] = "ping";
    uint8_t buf[256];
    size_t hn = strlen(head);
    memcpy(buf, head, hn);
    memcpy(buf + hn, early, sizeof(early) - 1);
    send_all(c, buf, hn + sizeof(early) - 1);

    uint8_t status[12] = {0};
    MQ_CHECK(pump_read(base, c, status, 12, 1000) >= 12);
    MQ_CHECK_MEM(status, "HTTP/1.1 200", 12);

    MQ_CHECK_EQ_INT(m.called, 1);
    MQ_CHECK_EQ_INT(m.prebuf_len, sizeof(early) - 1);
    MQ_CHECK_MEM(m.prebuf, early, sizeof(early) - 1);

    close(c);
    uint64_t deadline = now_ms() + 500;
    while (m.local_fd >= 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    mq_listener_free(l);
}

static void
run_all(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    test_socks5_happy(base);
    test_socks5_unsupported(base);
    test_socks5_malformed(base);
    test_http_connect_smoke(base);
    test_socks5_pipelined_prebuf(base);
    test_http_pipelined_prebuf(base);

    event_base_free(base);
}

MQ_TEST_MAIN(run_all())
