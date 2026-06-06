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
 *
 * UDP ASSOCIATE scenarios (stub UDP relay core) cover establish/free, TCP-close
 * teardown, mixed shutdown, no-close-after-err, availability sweep, REP 0x07
 * refusals, and the dst_alloc reclaim sweep after destination churn (the last
 * pins the codex-found mq_udp_assoc.c dst_alloc dead-entry reclaim fix).
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
#include "ingress/mq_socks5.h"
#include "ingress/mq_udp_assoc.h"

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

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              NULL, NULL, NULL, NULL);
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

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              NULL, NULL, NULL, NULL);
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

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              NULL, NULL, NULL, NULL);
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

    mq_listener_t *l = mq_http_connect_listener_new(base, "127.0.0.1", 0, mock_tcp_open,
                                                    &m, NULL, NULL, NULL, NULL);
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

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              NULL, NULL, NULL, NULL);
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

    mq_listener_t *l = mq_http_connect_listener_new(base, "127.0.0.1", 0, mock_tcp_open,
                                                    &m, NULL, NULL, NULL, NULL);
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

/* ── Stub UDP relay core (the mq_udp_open_fn boundary) ───────────────────────
 *
 * Models the client-role relay table for ASSOCIATE tests. open() hands back a
 * heap session and records the DST; send() optionally round-trips the payload
 * back via on_rx (so the test can read it on the UDP socket); close() and on_err
 * counters let us assert lifecycle. Forcing knobs:
 *   - force_open_null: open() returns NULL (transient failure / unavailable)
 *   - force_err_on_send: the FIRST send triggers an on_err(err) instead of rx
 *
 * The stub honors the boundary contract: after on_err for a session it never
 * touches that handle again, and after close() it fires no callbacks. Test (d)
 * is realized here: the stub records close_fn calls and, post-close, does not
 * deliver on_rx/on_err — exactly the suppression the real core guarantees.
 */
struct stub_sess {
    struct stub_udp *core;
    mq_udp_rx_fn on_rx;
    mq_udp_err_fn on_err;
    void *user;
    mq_addr_type_t atype;
    uint8_t host[MQ_MAX_HOST];
    size_t host_len;
    uint16_t port;
    int closed;  /* close_fn called */
    int errored; /* on_err fired (handle invalid after) */
    int alive;   /* slot in use */
};

struct stub_udp {
    int open_calls;
    int close_calls;
    int send_calls;
    int post_death_sends; /* sends on a closed/errored handle — contract violation */
    int force_open_null;
    int force_err_on_send;
    mq_udp_err_t forced_err;
    int echo; /* 1 => send() round-trips payload via on_rx */
    struct stub_sess sessions[16];
};

static void *
stub_open(void *core, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
          uint16_t port, mq_udp_rx_fn on_rx, mq_udp_err_fn on_err, void *user)
{
    struct stub_udp *s = (struct stub_udp *)core;
    s->open_calls++;
    if (s->force_open_null) return NULL;
    for (size_t i = 0; i < 16; i++) {
        if (!s->sessions[i].alive) {
            struct stub_sess *ss = &s->sessions[i];
            memset(ss, 0, sizeof(*ss));
            ss->core = s;
            ss->on_rx = on_rx;
            ss->on_err = on_err;
            ss->user = user;
            ss->atype = atype;
            ss->host_len = host_len < sizeof(ss->host) ? host_len : sizeof(ss->host);
            if (ss->host_len) memcpy(ss->host, host, ss->host_len);
            ss->port = port;
            ss->alive = 1;
            return ss;
        }
    }
    return NULL;
}

static void
stub_send(void *session, const uint8_t *payload, size_t len)
{
    struct stub_sess *ss = (struct stub_sess *)session;
    struct stub_udp *s = ss->core;
    s->send_calls++;
    /* Contract: assoc must never send on a dead/closed handle. Record any
     * violation so tests can assert post_death_sends == 0 at teardown. */
    if (ss->closed || ss->errored) {
        s->post_death_sends++;
        return;
    }
    if (s->force_err_on_send) {
        ss->errored = 1;
        /* Per the boundary contract the handle is invalid after on_err: free the
         * slot so the stub can admit a fresh open() for the next destination.
         * (errored stays set so post_death_sends still catches any stray send.) */
        ss->alive = 0;
        if (ss->on_err) ss->on_err(ss, s->forced_err, ss->user);
        return;
    }
    if (s->echo && ss->on_rx) {
        ss->on_rx(payload, len, ss->user); /* round-trip back to the client */
    }
}

static void
stub_close(void *session)
{
    struct stub_sess *ss = (struct stub_sess *)session;
    struct stub_udp *s = ss->core;
    s->close_calls++;
    ss->closed = 1;
    ss->alive = 0;
}

/* Dial a UDP socket bound to an ephemeral 127.0.0.1 port. */
static int
udp_dial(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Complete the SOCKS5 greeting + ASSOCIATE request on a TCP control socket and
 * read the 10-byte reply. Returns the reply REP code and fills *udp_port (host
 * order) from BND.PORT on success. If reply_out is non-NULL, the full 10-byte
 * reply is copied there. */
static int
socks5_associate(struct event_base *base, int c, uint16_t *udp_port_out, uint8_t *rep_out,
                 uint8_t reply_out[10])
{
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    send_all(c, greeting, sizeof(greeting));
    uint8_t mreply[2] = {0};
    if (pump_read(base, c, mreply, 2, 1000) != 2) return -1;

    /* ASSOCIATE with DST 0.0.0.0:0 (client does not know its src yet). */
    uint8_t req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send_all(c, req, sizeof(req));

    uint8_t reply[10] = {0};
    if (pump_read(base, c, reply, 10, 1000) != 10) return -1;
    if (rep_out) *rep_out = reply[1];
    if (udp_port_out) *udp_port_out = (uint16_t)((reply[8] << 8) | reply[9]);
    if (reply_out) memcpy(reply_out, reply, 10);
    return 0;
}

/* Build a SOCKS5 UDP encapsulation header + payload into out; returns total len. */
static size_t
build_udp_dgram(uint8_t *out, size_t cap, uint32_t dst_ip_be, uint16_t dst_port,
                const uint8_t *payload, size_t plen)
{
    mq_socks5_req_t dst;
    memset(&dst, 0, sizeof(dst));
    dst.atype = MQ_ADDR_IPV4;
    dst.host_len = 4;
    memcpy(dst.host, &dst_ip_be, 4);
    dst.port = dst_port;
    int hlen = mq_socks5_build_udp_hdr(out, cap, &dst);
    if (hlen < 0) return 0;
    if ((size_t)hlen + plen > cap) return 0;
    memcpy(out + hlen, payload, plen);
    return (size_t)hlen + plen;
}

/* ── ASSOCIATE Scenario A: establish, free listener while TCP open ───────────
 * (a) ASSOCIATE established → TCP kept open → listener free → no fd/session/
 *     event leak (ASan). */
static void
test_assoc_establish_free(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));
    s.echo = 1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);

    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }

    uint16_t uport = 0;
    uint8_t rep = 0xff;
    uint8_t areply[10] = {0};
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, areply), 0);
    MQ_CHECK_EQ_INT(rep, 0x00); /* REP success */
    MQ_CHECK(uport != 0);
    /* BND.ADDR must be IPv4 127.0.0.1 (listener bound to 127.0.0.1). */
    MQ_CHECK_EQ_INT(areply[3], 0x01); /* ATYP = IPv4 */
    MQ_CHECK_EQ_INT(areply[4], 127);  /* BND.ADDR[0] */
    MQ_CHECK_EQ_INT(areply[5], 0);    /* BND.ADDR[1] */
    MQ_CHECK_EQ_INT(areply[6], 0);    /* BND.ADDR[2] */
    MQ_CHECK_EQ_INT(areply[7], 1);    /* BND.ADDR[3] */

    /* Round-trip a UDP datagram: client → UDP socket → stub echo → back. */
    int u = udp_dial();
    MQ_CHECK(u >= 0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(uport);

    uint8_t dgram[64];
    uint8_t payload[] = "udp-ping";
    uint32_t dst_ip = htonl(0x08080808); /* 8.8.8.8 */
    size_t dlen =
        build_udp_dgram(dgram, sizeof(dgram), dst_ip, 53, payload, sizeof(payload) - 1);
    MQ_CHECK(dlen > 0);
    sendto(u, dgram, dlen, 0, (struct sockaddr *)&dst, sizeof(dst));

    /* Pump and read the echoed datagram back on the same UDP socket. */
    uint8_t rxb[64] = {0};
    int fl = fcntl(u, F_GETFL, 0);
    fcntl(u, F_SETFL, fl | O_NONBLOCK);
    ssize_t rn = -1;
    uint64_t deadline = now_ms() + 1000;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
        rn = recv(u, rxb, sizeof(rxb), 0);
        if (rn > 0) break;
    }
    MQ_CHECK(rn > 0);
    MQ_CHECK_EQ_INT(s.open_calls, 1);
    MQ_CHECK_EQ_INT(s.send_calls, 1);
    /* The echoed datagram has the encap header (DST as src) + payload. */
    mq_socks5_udp_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    int hr = mq_socks5_parse_udp_hdr(rxb, (size_t)rn, &hdr);
    MQ_CHECK(hr > 0);
    if (hr > 0) {
        MQ_CHECK_EQ_INT(hdr.dst.port, 53);
        MQ_CHECK_EQ_INT((size_t)rn - hdr.hdr_len, sizeof(payload) - 1);
        MQ_CHECK_MEM(rxb + hdr.hdr_len, payload, sizeof(payload) - 1);
    }

    close(u);
    /* Free the listener with the TCP control connection STILL open: the assoc
     * shell (UDP fd / TCP fd / events) and the live stub session must all be
     * reaped (close_fn called for the live session). */
    mq_listener_free(l);
    MQ_CHECK_EQ_INT(s.close_calls, 1); /* the live session was closed at reap */
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
    close(c);
}

/* ── ASSOCIATE Scenario B: TCP close tears the assoc down ────────────────── */
static void
test_assoc_tcp_close_teardown(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));
    s.echo = 1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);

    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x00);

    /* Establish a live session via one datagram. */
    int u = udp_dial();
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(uport);
    uint8_t dgram[64];
    uint8_t payload[] = "x";
    size_t dlen = build_udp_dgram(dgram, sizeof(dgram), htonl(0x01020304), 99, payload,
                                  sizeof(payload) - 1);
    sendto(u, dgram, dlen, 0, (struct sockaddr *)&dst, sizeof(dst));
    uint64_t deadline = now_ms() + 500;
    while (s.open_calls == 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(s.open_calls, 1);
    close(u);

    /* Close the TCP control connection → assoc tears down → close_fn called. */
    close(c);
    deadline = now_ms() + 1000;
    while (s.close_calls == 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(s.close_calls, 1);

    mq_listener_free(l);
    /* No double-close: the assoc already self-removed at TCP-EOF teardown. */
    MQ_CHECK_EQ_INT(s.close_calls, 1);
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
}

/* ── ASSOCIATE Scenario C: mixed shutdown (in-flight CONNECT + live ASSOCIATE)
 * The graph-A ordering (transport→runtime→client→listener) is exercised by the
 * real-core e2e tests; here, with stub cores, we assert the listener-side
 * structural half: an accepted-but-not-yet-handed-off CONNECT parse state AND a
 * live UDP assoc co-exist, then mq_listener_free reaps BOTH without UAF/leak
 * (ASan). The CONNECT conn is left mid-greeting so it is still a listener-owned
 * conn_state at free time. */
static void
test_assoc_mixed_shutdown(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));
    s.echo = 1;
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);

    /* (1) A live ASSOCIATE with one open session. */
    int ca = dial(tport);
    MQ_CHECK(ca >= 0);
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, ca, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x00);
    int u = udp_dial();
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(uport);
    uint8_t dgram[64];
    uint8_t payload[] = "m";
    size_t dlen = build_udp_dgram(dgram, sizeof(dgram), htonl(0x09090909), 1, payload,
                                  sizeof(payload) - 1);
    sendto(u, dgram, dlen, 0, (struct sockaddr *)&dst, sizeof(dst));
    uint64_t deadline = now_ms() + 500;
    while (s.open_calls == 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(s.open_calls, 1);
    close(u);

    /* (2) A second connection mid-greeting (accepted, parse state owned by the
     * listener, NOT yet handed off). */
    int cp = dial(tport);
    MQ_CHECK(cp >= 0);
    uint8_t partial[] = {0x05}; /* incomplete greeting */
    send_all(cp, partial, sizeof(partial));
    deadline = now_ms() + 200;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }

    /* Free with both alive: assoc reaped (close_fn on the live session) + the
     * pending CONNECT conn_state reaped (its fd closed by the listener). */
    mq_listener_free(l);
    MQ_CHECK_EQ_INT(s.close_calls, 1);
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
    close(ca);
    close(cp);
}

/* ── ASSOCIATE Scenario D: post-teardown callback suppression ────────────────
 * Interpretation (see context): the stub IS the core, so this asserts the
 * assoc-side half of the boundary contract — at teardown the assoc calls
 * close_fn exactly once per live session, and after a session's on_err it never
 * calls close_fn on that (now invalid) handle. We drive force_err_on_send so the
 * single session dies via on_err, then tear down: close_fn must NOT be called for
 * the dead session (else it would be a UAF in the real core). */
static void
test_assoc_no_close_after_err(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));
    s.force_err_on_send = 1;
    s.forced_err = MQ_UDP_DNS_FAILED;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);
    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x00);

    int u = udp_dial();
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(uport);
    uint8_t dgram[64];
    uint8_t payload[] = "q";
    size_t dlen = build_udp_dgram(dgram, sizeof(dgram), htonl(0x05060708), 7, payload,
                                  sizeof(payload) - 1);
    sendto(u, dgram, dlen, 0, (struct sockaddr *)&dst, sizeof(dst));
    uint64_t deadline = now_ms() + 500;
    while (s.open_calls == 0 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK_EQ_INT(s.open_calls, 1);
    MQ_CHECK_EQ_INT(s.send_calls, 1); /* the send triggered on_err */
    close(u);

    /* Tear down via listener free: the (dead) session must NOT be closed. */
    mq_listener_free(l);
    MQ_CHECK_EQ_INT(s.close_calls, 0); /* dead handle never closed (no UAF) */
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
    close(c);
}

/* ── ASSOCIATE Scenario E: availability sweep ────────────────────────────────
 * tri-state -1 optimistically admits ASSOCIATE (no UDP sent); a stub then sets
 * availability 0 → the assoc's TCP control connection is closed (UDP-unused
 * assoc must not survive). */
static void
test_assoc_availability_sweep(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);
    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    /* -1 default → optimistic admit. */
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x00);
    MQ_CHECK_EQ_INT(s.open_calls, 0); /* no UDP sent yet */

    /* Server turns out not to support UDP → set availability 0 → sweep closes
     * the control connection of the (UDP-unused) assoc. */
    mq_listener_set_udp_availability(l, 0);

    /* The client side sees EOF on the TCP control connection. */
    MQ_CHECK(pump_until_eof(base, c, 1000));
    MQ_CHECK_EQ_INT(s.close_calls, 0); /* no session was ever opened */
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);

    mq_listener_free(l);
    close(c);
}

/* ── ASSOCIATE Scenario: REP 0x07 when no UDP boundary ───────────────────────
 * A SOCKS5 listener with a NULL udp_open quad refuses ASSOCIATE unconditionally. */
static void
test_assoc_refused_no_udp(struct event_base *base)
{
    struct mock_open m;
    memset(&m, 0, sizeof(m));
    m.base = base;
    m.forced_ok = 1;
    m.local_fd = -1;

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, &m,
                                              NULL, NULL, NULL, NULL);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);
    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x07); /* command not supported */
    MQ_CHECK(pump_until_eof(base, c, 1000));
    mq_listener_free(l);
    close(c);
}

/* ── ASSOCIATE Scenario: availability 0 refuses up front (REP 0x07) ──────── */
static void
test_assoc_refused_unavail(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    mq_listener_set_udp_availability(l, 0); /* server has no UDP */
    uint16_t tport = mq_listener_local_port(l);
    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x07);
    MQ_CHECK_EQ_INT(s.open_calls, 0);
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
    mq_listener_free(l);
    close(c);
}

/* ── ASSOCIATE Scenario: dst-entry reclaim after destination churn ───────────
 * Pins the dst_alloc reclaim sweep (mq_udp_assoc.c dst_alloc): when no free DST
 * slot exists, dst_alloc must reclaim a dead entry that is immediately
 * reclaimable (dead && failed_at == 0, i.e. closed via MQ_UDP_CLOSED which is
 * never negative-cached) instead of returning NULL and dropping the datagram.
 *
 * Drive MQ_UDP_ASSOC_MAX_DST (64) DISTINCT destinations through one established
 * assoc; for each, the stub fires on_err(MQ_UDP_CLOSED) on the first send so the
 * entry becomes dead with failed_at == 0 (immediately reclaimable). Then drive a
 * 65th distinct destination and assert open_fn was invoked for it — proving the
 * sweep reclaimed a dead slot rather than returning NULL. Without the sweep, the
 * 65th open never happens (open_calls stays at 64). */
static void
test_assoc_dst_reclaim_churn(struct event_base *base)
{
    struct stub_udp s;
    memset(&s, 0, sizeof(s));
    s.force_err_on_send = 1;
    s.forced_err = MQ_UDP_CLOSED; /* failed_at stays 0 → immediately reclaimable */

    mq_listener_t *l = mq_socks5_listener_new(base, "127.0.0.1", 0, mock_tcp_open, NULL,
                                              stub_open, stub_send, stub_close, &s);
    MQ_CHECK(l != NULL);
    if (!l) return;
    uint16_t tport = mq_listener_local_port(l);

    int c = dial(tport);
    MQ_CHECK(c >= 0);
    if (c < 0) {
        mq_listener_free(l);
        return;
    }
    uint16_t uport = 0;
    uint8_t rep = 0xff;
    MQ_CHECK_EQ_INT(socks5_associate(base, c, &uport, &rep, NULL), 0);
    MQ_CHECK_EQ_INT(rep, 0x00);
    MQ_CHECK(uport != 0);

    int u = udp_dial();
    MQ_CHECK(u >= 0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(uport);

    /* Fill all 64 DST slots: each distinct destination opens a session, the first
     * send fires on_err(MQ_UDP_CLOSED) → the entry is marked dead (failed_at==0).
     * Vary BOTH the DST.ADDR and DST.PORT so every encap header is distinct. */
    const int MAXDST = 64; /* == MQ_UDP_ASSOC_MAX_DST */
    uint8_t payload[] = "x";
    for (int i = 0; i < MAXDST; i++) {
        uint8_t dgram[64];
        uint32_t dip = htonl(0x0A000000u + (uint32_t)i); /* 10.0.0.i (distinct addr) */
        uint16_t dport = (uint16_t)(1000 + i);           /* distinct port too */
        size_t dlen = build_udp_dgram(dgram, sizeof(dgram), dip, dport, payload,
                                      sizeof(payload) - 1);
        MQ_CHECK(dlen > 0);
        sendto(u, dgram, dlen, 0, (struct sockaddr *)&dst, sizeof(dst));
        /* Pump until this destination's open + on_err have been processed. */
        int want = i + 1;
        uint64_t deadline = now_ms() + 500;
        while (s.open_calls < want && now_ms() < deadline) {
            event_base_loop(base, EVLOOP_NONBLOCK);
        }
        MQ_CHECK_EQ_INT(s.open_calls, want);
    }
    /* All 64 DST entries are now dead-and-immediately-reclaimable. */
    MQ_CHECK_EQ_INT(s.open_calls, MAXDST);

    /* 65th DISTINCT destination: with no free slot, dst_alloc must reclaim a dead
     * entry → open_fn is invoked again (open_calls advances to 65). */
    uint8_t dgram65[64];
    uint32_t dip65 = htonl(0x0A000000u + (uint32_t)MAXDST); /* 10.0.0.64 */
    uint16_t dport65 = (uint16_t)(1000 + MAXDST);
    size_t dlen65 = build_udp_dgram(dgram65, sizeof(dgram65), dip65, dport65, payload,
                                    sizeof(payload) - 1);
    MQ_CHECK(dlen65 > 0);
    sendto(u, dgram65, dlen65, 0, (struct sockaddr *)&dst, sizeof(dst));
    uint64_t deadline = now_ms() + 1000;
    while (s.open_calls < MAXDST + 1 && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    /* The load-bearing assertion: the 65th destination opened a session, proving
     * dst_alloc reclaimed a dead slot instead of returning NULL/dropping. */
    MQ_CHECK_EQ_INT(s.open_calls, MAXDST + 1);

    close(u);
    mq_listener_free(l);
    MQ_CHECK_EQ_INT(s.post_death_sends, 0);
    close(c);
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

    /* UDP ASSOCIATE edge (Task 6.3). */
    test_assoc_establish_free(base);     /* (a) */
    test_assoc_tcp_close_teardown(base); /* (b) */
    test_assoc_mixed_shutdown(base);     /* (c) */
    test_assoc_no_close_after_err(base); /* (d) */
    test_assoc_availability_sweep(base); /* (e) */
    test_assoc_refused_no_udp(base);     /* REP 0x07 when no UDP boundary */
    test_assoc_refused_unavail(base);    /* REP 0x07 when availability == 0 */
    test_assoc_dst_reclaim_churn(base);  /* dst_alloc reclaim sweep (codex gap) */

    event_base_free(base);
}

MQ_TEST_MAIN(run_all())
