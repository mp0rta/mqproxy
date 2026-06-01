/* test_e2e_single_path.c — Task 16: the 1-A end-to-end milestone.
 *
 * Drives the FULL ingress→origin path with REAL client sockets over a SINGLE
 * path and asserts byte-exact transfer + error mapping. Unlike
 * test_client_server.c (which calls mq_client_tcp_open directly), this test
 * exercises the real LISTENERS: a real SOCKS5 handshake and a real HTTP CONNECT
 * request come in on a TCP socket, traverse
 *
 *     listener (SOCKS5 / HTTP CONNECT)
 *         → mq_client (tcp_open → CONNECT_TCP_REQUEST over MPQUIC)
 *             → mq_server (auth + dial origin + relay)
 *                 → in-process origin
 *
 * and the reply + relayed bytes come all the way back to the client socket.
 *
 * Everything runs in ONE process on ONE libevent base (server engine + client
 * engine + in-process origins + the two listeners). The client sockets are made
 * non-blocking and polled by the same bounded pump loop that drives the event
 * base — single-threaded, deterministic, ASan-clean (no threads to join).
 *
 * Cases (design §8 / §9.1):
 *   1. SOCKS5 download e2e: origin streams N=200000 deterministic bytes then
 *      closes; a real SOCKS5 client reads ALL N bytes (count + checksum) and a
 *      clean EOF — byte-exact through the whole stack incl. the SOCKS5 reply.
 *   2. SOCKS5 echo e2e: SOCKS5 CONNECT to an echo origin; a few KB echo back
 *      byte-exact.
 *   3. HTTP CONNECT echo e2e: same as (2) through the HTTP CONNECT listener.
 *   4. Error mapping: SOCKS5 CONNECT to a closed port → REP 0x05 (refused);
 *      HTTP CONNECT to a closed port → HTTP/1.1 502.
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

/* ── full-stack fixture: server + client engines + the two listeners ─────────
 * One libevent base. The client engine + mq_client wrap a single MPQUIC conn to
 * the server; both listeners hand accepted fds to mq_client_tcp_open via the
 * mq_tcp_open_fn boundary. */
typedef struct {
    struct event_base *base;
    mq_engine_t *srv;
    mq_engine_t *cli;
    mq_path_t *srv_path;
    mq_path_t *cli_path;
    mq_server_t *server;
    mq_client_t *client;
    mq_listener_t *socks5;
    mq_listener_t *http;
} fixture_t;

static int
fixture_up(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

    /* Server engine + server (auth token "secret"). */
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

    /* Client engine + client. */
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

    /* Listeners wired to the real client core via the tcp_open boundary. */
    void *core = mq_client_tcp_open_core(f->client);
    f->socks5 =
        mq_socks5_listener_new(f->base, "127.0.0.1", 0, mq_client_tcp_open_fn(), core);
    MQ_CHECK(f->socks5 != NULL);
    if (!f->socks5) return -1;
    f->http = mq_http_connect_listener_new(f->base, "127.0.0.1", 0,
                                           mq_client_tcp_open_fn(), core);
    MQ_CHECK(f->http != NULL);
    if (!f->http) return -1;
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Listeners first (they own no live relay fds once handed to the core, but
     * close any still-pending accepted fds). Then paths, engines, and finally
     * the client/server objects (whose state callbacks the engines may fire on
     * free). */
    if (f->socks5) mq_listener_free(f->socks5);
    if (f->http) mq_listener_free(f->http);
    if (f->cli_path) mq_path_close(f->cli_path);
    if (f->srv_path) mq_path_close(f->srv_path);
    if (f->cli) mq_engine_free(f->cli);
    if (f->srv) mq_engine_free(f->srv);
    if (f->client) mq_client_free(f->client);
    if (f->server) mq_server_free(f->server);
    if (f->base) event_base_free(f->base);
}

/* ── client-socket helpers (non-blocking, pumped by the same base) ──────────── */

/* Dial 127.0.0.1:port, return a non-blocking fd or -1. The connect is
 * non-blocking; on loopback it usually completes immediately, but we treat
 * EINPROGRESS as success (the pump drives it). */
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

/* Send all of buf on a non-blocking fd while pumping the base for writability. */
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

/* Read exactly `want` bytes into out, pumping the base. Returns bytes read
 * (< want on timeout / EOF). */
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
            break; /* EOF */
        }
    }
    return got;
}

/* SOCKS5 greeting + method reply. Returns 0 on success. */
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

/* Send a SOCKS5 CONNECT request to IPv4 127.0.0.1:port. */
static int
socks5_connect_v4(struct event_base *base, int fd, uint16_t port)
{
    uint8_t req[10];
    size_t i = 0;
    req[i++] = 0x05; /* VER */
    req[i++] = 0x01; /* CMD CONNECT */
    req[i++] = 0x00; /* RSV */
    req[i++] = 0x01; /* ATYP IPv4 */
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(req + i, &v4, 4);
    i += 4;
    req[i++] = (uint8_t)(port >> 8);
    req[i++] = (uint8_t)(port & 0xff);
    return send_all_nb(base, fd, req, i, 1000);
}

/* Obtain a port with nothing listening: bind+listen an ephemeral port, capture
 * it, then close it. */
static uint16_t
dead_port(void)
{
    int tmp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    bind(tmp, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(tmp, (struct sockaddr *)&sa, &sl);
    uint16_t p = ntohs(sa.sin_port);
    close(tmp);
    return p;
}

/* ── in-process echo origin ─────────────────────────────────────────────────
 * Accepts one connection and echoes every byte. */
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

/* ── in-process bulk origin: streams N deterministic bytes, then closes ─────── */
typedef struct {
    struct event_base *base;
    int listen_fd;
    int conn_fd;
    struct event *listen_ev;
    struct event *write_ev;
    size_t total;
    size_t sent;
    int finished;
} bulk_origin_t;

static void
bulk_write_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    bulk_origin_t *o = (bulk_origin_t *)arg;
    unsigned char chunk[8192];
    while (o->sent < o->total) {
        size_t want = o->total - o->sent;
        if (want > sizeof(chunk)) want = sizeof(chunk);
        for (size_t i = 0; i < want; i++)
            chunk[i] = (unsigned char)((o->sent + i) & 0xff);
        ssize_t w = send(fd, chunk, want, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                event_add(o->write_ev, NULL);
                return;
            }
            break;
        }
        if (w == 0) break;
        o->sent += (size_t)w;
    }
    shutdown(fd, SHUT_WR);
    if (o->write_ev) {
        event_free(o->write_ev);
        o->write_ev = NULL;
    }
    close(fd);
    o->conn_fd = -1;
    o->finished = 1;
}

static void
bulk_accept_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    bulk_origin_t *o = (bulk_origin_t *)arg;
    int c = accept(fd, NULL, NULL);
    if (c < 0) return;
    set_nonblock(c);
    o->conn_fd = c;
    o->write_ev = event_new(o->base, c, EV_WRITE, bulk_write_cb, o);
    bulk_write_cb(c, EV_WRITE, o);
}

static int
bulk_origin_up(bulk_origin_t *o, struct event_base *base, size_t total,
               uint16_t *out_port)
{
    memset(o, 0, sizeof(*o));
    o->base = base;
    o->conn_fd = -1;
    o->total = total;
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
    o->listen_ev = event_new(base, o->listen_fd, EV_READ | EV_PERSIST, bulk_accept_cb, o);
    event_add(o->listen_ev, NULL);
    return 0;
}

static void
bulk_origin_down(bulk_origin_t *o)
{
    if (o->write_ev) event_free(o->write_ev);
    if (o->listen_ev) event_free(o->listen_ev);
    if (o->conn_fd >= 0) close(o->conn_fd);
    if (o->listen_fd >= 0) close(o->listen_fd);
}

/* ── Case 1: SOCKS5 download e2e (byte-exact, clean EOF) ─────────────────── */
static void
test_socks5_download(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    const size_t N = 200000;
    bulk_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(bulk_origin_up(&origin, f.base, N, &origin_port), 0);

    int c = dial_nb(mq_listener_local_port(f.socks5));
    MQ_CHECK(c >= 0);
    if (c < 0) {
        bulk_origin_down(&origin);
        fixture_down(&f);
        return;
    }

    MQ_CHECK_EQ_INT(socks5_greet(f.base, c), 0);
    MQ_CHECK_EQ_INT(socks5_connect_v4(f.base, c, origin_port), 0);

    /* SOCKS5 CONNECT reply: 05 00 00 01 <4-byte bind addr> <2-byte port>. */
    uint8_t reply[10] = {0};
    MQ_CHECK_EQ_INT((int)recv_exact(f.base, c, reply, 10, 8000), 10);
    MQ_CHECK_EQ_INT(reply[0], 0x05);
    MQ_CHECK_EQ_INT(reply[1], 0x00); /* success */
    MQ_CHECK_EQ_INT(reply[2], 0x00);
    MQ_CHECK_EQ_INT(reply[3], 0x01);

    /* Drain the download until clean EOF, counting bytes + checksum. */
    size_t got = 0;
    uint32_t sum = 0;
    int eof = 0;
    uint64_t deadline = now_ms() + 12000;
    while (!eof && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        unsigned char buf[16384];
        for (;;) {
            ssize_t n = recv(c, buf, sizeof(buf), 0);
            if (n > 0) {
                for (ssize_t i = 0; i < n; i++)
                    sum += buf[i];
                got += (size_t)n;
            } else if (n == 0) {
                eof = 1;
                break;
            } else {
                break; /* EAGAIN */
            }
        }
    }

    uint32_t expect = 0;
    for (size_t i = 0; i < N; i++)
        expect += (unsigned char)(i & 0xff);

    MQ_CHECK(eof);                                      /* clean EOF, no hang */
    MQ_CHECK_EQ_INT((long long)got, (long long)N);      /* ALL bytes, no trunc */
    MQ_CHECK_EQ_INT((long long)sum, (long long)expect); /* checksum matches */

    close(c);
    bulk_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case 2: SOCKS5 echo e2e (byte-exact round-trip) ────────────────────── */
static void
test_socks5_echo(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

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

    /* Send a few KB and assert byte-exact echo. */
    const size_t M = 4096;
    uint8_t *payload = malloc(M);
    MQ_CHECK(payload != NULL);
    for (size_t i = 0; i < M; i++)
        payload[i] = (uint8_t)((i * 31 + 7) & 0xff);
    MQ_CHECK_EQ_INT(send_all_nb(f.base, c, payload, M, 4000), 0);

    uint8_t *back = malloc(M);
    MQ_CHECK(back != NULL);
    size_t got = recv_exact(f.base, c, back, M, 8000);
    MQ_CHECK_EQ_INT((long long)got, (long long)M);
    MQ_CHECK(memcmp(payload, back, M) == 0);

    free(payload);
    free(back);
    close(c);
    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case 3: HTTP CONNECT echo e2e (byte-exact round-trip) ──────────────── */
static void
test_http_echo(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    int c = dial_nb(mq_listener_local_port(f.http));
    MQ_CHECK(c >= 0);
    if (c < 0) {
        echo_origin_down(&origin);
        fixture_down(&f);
        return;
    }

    char line[128];
    int ln = snprintf(line, sizeof(line),
                      "CONNECT 127.0.0.1:%u HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n",
                      (unsigned)origin_port, (unsigned)origin_port);
    MQ_CHECK_EQ_INT(send_all_nb(f.base, c, (const uint8_t *)line, (size_t)ln, 2000), 0);

    /* Expect a "HTTP/1.1 200" status line. */
    uint8_t status[12] = {0};
    MQ_CHECK_EQ_INT((int)recv_exact(f.base, c, status, 12, 8000), 12);
    MQ_CHECK_MEM(status, "HTTP/1.1 200", 12);

    /* Consume the rest of the response headers up to the blank line so the
     * subsequent reads see only relayed application bytes. The HTTP CONNECT
     * reply is a fixed short status line ending in \r\n\r\n; read until we have
     * consumed it. */
    uint8_t hdr[256];
    size_t hlen = 0;
    uint64_t deadline = now_ms() + 4000;
    int done = 0;
    while (!done && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        while (hlen < sizeof(hdr)) {
            ssize_t n = recv(c, hdr + hlen, 1, 0);
            if (n == 1) {
                hlen++;
                if (hlen >= 4 && memcmp(hdr + hlen - 4, "\r\n\r\n", 4) == 0) {
                    done = 1;
                    break;
                }
            } else {
                break;
            }
        }
    }
    MQ_CHECK(done);

    /* Echo a few KB byte-exact. */
    const size_t M = 4096;
    uint8_t *payload = malloc(M);
    MQ_CHECK(payload != NULL);
    for (size_t i = 0; i < M; i++)
        payload[i] = (uint8_t)((i * 17 + 3) & 0xff);
    MQ_CHECK_EQ_INT(send_all_nb(f.base, c, payload, M, 4000), 0);

    uint8_t *recvd = malloc(M);
    MQ_CHECK(recvd != NULL);
    size_t got = recv_exact(f.base, c, recvd, M, 8000);
    MQ_CHECK_EQ_INT((long long)got, (long long)M);
    MQ_CHECK(memcmp(payload, recvd, M) == 0);

    free(payload);
    free(recvd);
    close(c);
    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case 4a: SOCKS5 error mapping → REP 0x05 (connection refused) ───────── */
static void
test_socks5_refused(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    uint16_t dp = dead_port();

    int c = dial_nb(mq_listener_local_port(f.socks5));
    MQ_CHECK(c >= 0);
    if (c < 0) {
        fixture_down(&f);
        return;
    }

    MQ_CHECK_EQ_INT(socks5_greet(f.base, c), 0);
    MQ_CHECK_EQ_INT(socks5_connect_v4(f.base, c, dp), 0);

    uint8_t reply[10] = {0};
    MQ_CHECK_EQ_INT((int)recv_exact(f.base, c, reply, 10, 8000), 10);
    MQ_CHECK_EQ_INT(reply[0], 0x05);
    MQ_CHECK_EQ_INT(reply[1], 0x05); /* connection refused */

    close(c);
    fixture_down(&f);
}

/* ── Case 4b: HTTP CONNECT error mapping → HTTP/1.1 502 ──────────────────── */
static void
test_http_refused(void)
{
    fixture_t f;
    if (fixture_up(&f) != 0) {
        fixture_down(&f);
        return;
    }

    uint16_t dp = dead_port();

    int c = dial_nb(mq_listener_local_port(f.http));
    MQ_CHECK(c >= 0);
    if (c < 0) {
        fixture_down(&f);
        return;
    }

    char line[128];
    int ln = snprintf(line, sizeof(line),
                      "CONNECT 127.0.0.1:%u HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n",
                      (unsigned)dp, (unsigned)dp);
    MQ_CHECK_EQ_INT(send_all_nb(f.base, c, (const uint8_t *)line, (size_t)ln, 2000), 0);

    uint8_t status[12] = {0};
    MQ_CHECK_EQ_INT((int)recv_exact(f.base, c, status, 12, 8000), 12);
    MQ_CHECK_MEM(status, "HTTP/1.1 502", 12);

    close(c);
    fixture_down(&f);
}

static void
test_e2e_single_path(void)
{
    test_socks5_download();
    test_socks5_echo();
    test_http_echo();
    test_socks5_refused();
    test_http_refused();
}

MQ_TEST_MAIN(test_e2e_single_path())
