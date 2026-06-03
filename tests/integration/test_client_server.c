// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_client_server.c — Task 11 integration test: control-stream AUTH.
 *
 * Two engines (server with cert/key + client) share one libevent base on
 * loopback. The client opens the control stream (first client-initiated bidi
 * stream) and sends AUTH_REQUEST; the server replies AUTH_RESPONSE on the same
 * stream.
 *
 * This task tests ONLY the auth FAILURE path + control-stream identification:
 *   Case A — wrong token: on_auth fires ok==0 / MQ_AUTH_FAILED and the client
 *            connection subsequently closes.
 *   Case B — matching token: on_auth fires ok==1, and the server ran auth on
 *            exactly the first stream (auth-attempt counter == 1) even though
 *            the client opens a second (data) stream afterward.
 *
 * Happy-path data exchange is covered by Tasks 12/13.
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

#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"
#include "wire/mq_wire.h"

#define TEST_ALPN "mqproxy-tcp/1"

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

/* Reserve an ephemeral loopback UDP port: bind a temp socket to :0, read the
 * assigned port, then close it so a runtime can bind that fixed port. The
 * runtime no longer exposes the bound port of an ephemeral (:0) bind, so the
 * test pins a concrete port for the server up front. */
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

/* ── auth-callback bookkeeping ──────────────────────────────────────────── */
static int g_auth_fired;
static int g_auth_ok;
static mq_auth_err_t g_auth_err;

static void
on_auth(int ok, mq_auth_err_t err, void *user)
{
    (void)user;
    g_auth_fired = 1;
    g_auth_ok = ok;
    g_auth_err = err;
}

static int g_client_closed;
static void
on_client_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    (void)user;
    if (st == MQ_CONN_CLOSED) {
        g_client_closed = 1;
    }
}

/* Stand up a server+client on a shared base, run the handshake + auth, and
 * report the auth outcome. Returns the mq_server (so the caller can read the
 * auth-attempt counter) via out_server; client conn via out_conn. */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
} fixture_t;

static int
fixture_up(fixture_t *f, const char *client_token)
{
    memset(f, 0, sizeof(*f));
    f->base = event_base_new();
    MQ_CHECK(f->base != NULL);
    if (!f->base) return -1;

    uint16_t port = reserve_udp_port();
    MQ_CHECK(port != 0);
    if (!port) return -1;

    /* Server: transport (TLS) + runtime borrowing the shared base. */
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

    /* Client: transport + runtime borrowing the SAME shared base. */
    f->cli_t = mq_transport_new(0);
    MQ_CHECK(f->cli_t != NULL);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    MQ_CHECK(f->cli_rt != NULL);
    if (!f->cli_rt) return -1;

    MQ_CHECK_EQ_INT(mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0), 0);

    f->client =
        mq_client_new(f->cli_t, f->cli_rt, "127.0.0.1", port, "client-1", client_token);
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;
    mq_client_set_on_auth(f->client, on_auth, NULL);

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    mq_client_set_on_state(f->client, on_client_state, NULL);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Per side: free the transport FIRST (engine destroy fires conn_close_notify
     * -> the client/server state callbacks, whose `user` is the mq_client /
     * mq_server, and may also fire the runtime send_udp on a final close), so the
     * runtime + client + server must outlive the transport. Then the runtimes
     * (which BORROWED the shared base, so they do NOT free it), then the proxy
     * objects. The test owns the shared base and frees it last. */
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

/* ── Case A: wrong token → auth FAILED + conn closes ────────────────────── */
static void
test_auth_wrong_token(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_OK;
    g_client_closed = 0;

    fixture_t f;
    if (fixture_up(&f, "wrong") != 0) {
        fixture_down(&f);
        return;
    }

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_fired);
    MQ_CHECK_EQ_INT(g_auth_ok, 0);
    MQ_CHECK_EQ_INT((int)g_auth_err, (int)MQ_AUTH_FAILED);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 0);

    /* Server closes the connection after rejecting; client should observe it. */
    pump_until(f.base, &g_client_closed, 2000);
    MQ_CHECK(g_client_closed);

    fixture_down(&f);
}

/* ── Case B: matching token → auth OK + auth ran on exactly one stream ──── */
static void
test_auth_matching_token(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_FAILED;
    g_client_closed = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_fired);
    MQ_CHECK_EQ_INT(g_auth_ok, 1);
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 1);

    /* Open a SECOND (non-control) stream afterward; the server must NOT run
     * auth on it. Give the loop time to deliver it. */
    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);
    if (conn) {
        mq_stream_t *s2 = mq_conn_open_stream(conn);
        MQ_CHECK(s2 != NULL);
        if (s2) {
            static const unsigned char data[] = "data";
            (void)mq_stream_send(s2, data, sizeof(data), 0);
        }
    }
    pump_until(f.base, NULL, 800);

    MQ_CHECK_EQ_INT(mq_server_auth_attempts(f.server), 1);

    fixture_down(&f);
}

/* ── in-process echo TCP origin ─────────────────────────────────────────── */
/* A libevent-driven listening socket on 127.0.0.1:ephemeral that accepts one
 * connection and echoes back every byte it receives. Returns the listening fd
 * and reports the bound port. */
typedef struct {
    struct event_base *base;
    int listen_fd;
    int conn_fd;
    struct event *listen_ev;
    struct event *conn_ev;
} echo_origin_t;

static void
echo_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

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
    /* Echo back (best effort; test payloads are tiny). */
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
    echo_set_nonblock(c);
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
    echo_set_nonblock(o->listen_fd);
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

/* ── in-process bulk origin (sends N bytes, then closes; never reads) ───── */
/* On accept, this origin streams a deterministic N-byte payload to the client
 * (writing as flow control allows via an on-demand EV_WRITE) and then closes
 * its socket. It is the "download to completion" peer for Case G. Byte i has
 * value (i & 0xff); the client recomputes the same rolling checksum. */
typedef struct {
    struct event_base *base;
    int listen_fd;
    int conn_fd;
    struct event *listen_ev;
    struct event *write_ev;
    size_t total; /* N bytes to send */
    size_t sent;  /* bytes sent so far */
    uint32_t sum; /* rolling checksum of bytes sent (for cross-check) */
    int finished; /* all N bytes sent + socket closed */
} bulk_origin_t;

static void
bulk_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void
bulk_write_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    bulk_origin_t *o = (bulk_origin_t *)arg;
    unsigned char chunk[8192];
    while (o->sent < o->total) {
        size_t want = o->total - o->sent;
        if (want > sizeof(chunk)) want = sizeof(chunk);
        for (size_t i = 0; i < want; i++) {
            chunk[i] = (unsigned char)((o->sent + i) & 0xff);
        }
        ssize_t w = send(fd, chunk, want, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                event_add(o->write_ev, NULL); /* resume on writable edge */
                return;
            }
            break; /* hard error: stop */
        }
        if (w == 0) break;
        for (ssize_t i = 0; i < w; i++)
            o->sum += chunk[i];
        o->sent += (size_t)w;
    }
    /* All bytes flushed (or errored): half-close the write side so the proxy
     * sees EOF and propagates a clean FIN, then drop the fd. */
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
    bulk_set_nonblock(c);
    o->conn_fd = c;
    o->write_ev = event_new(o->base, c, EV_WRITE, bulk_write_cb, o);
    bulk_write_cb(c, EV_WRITE, o); /* prime the pump immediately */
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
    bulk_set_nonblock(o->listen_fd);
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

/* ── data-stream client helper (test-only; mq_client tcp_open is Task 13) ── */
/* Build a CONNECT_TCP_REQUEST to 127.0.0.1:port and capture stream rx. */
typedef struct {
    unsigned char rx[8192];
    size_t rxlen;
    int resp_seen;
    mq_connect_tcp_resp_t resp;
    size_t resp_consumed; /* bytes of rx the CONNECT_TCP_RESPONSE occupied */
    int payload_seen;     /* the echoed payload arrived after the response */

    /* Bulk-download bookkeeping (Case G). The post-response payload may exceed
     * the small rx[] above, so we count it out-of-band with a rolling checksum
     * rather than buffering it all. */
    int track_bulk;       /* enable bulk counting on the post-response stream */
    size_t payload_bytes; /* count of post-CONNECT_TCP_RESPONSE payload bytes */
    uint32_t payload_sum; /* rolling additive checksum of payload bytes */
    int fin_seen;         /* the QUIC stream delivered a clean FIN */
    int err_seen;         /* mq_stream_recv returned a hard error (RESET) */
} datastream_t;

/* Fold post-response bytes that are currently sitting in rx[] into the bulk
 * counters, then drop them so rx[] never overflows on a long download. Only the
 * response prefix is preserved in rx[]. */
static void
ds_drain_bulk(datastream_t *d)
{
    if (!d->track_bulk || !d->resp_seen) return;
    if (d->rxlen <= d->resp_consumed) return;
    size_t avail = d->rxlen - d->resp_consumed;
    for (size_t i = 0; i < avail; i++) {
        d->payload_sum += d->rx[d->resp_consumed + i];
    }
    d->payload_bytes += avail;
    d->rxlen = d->resp_consumed; /* keep only the response prefix */
}

static void
ds_readable(mq_stream_t *s, void *user)
{
    datastream_t *d = (datastream_t *)user;
    for (;;) {
        if (d->rxlen >= sizeof(d->rx)) {
            /* rx[] full: in bulk mode, fold+drop to make room and keep reading. */
            if (d->track_bulk && d->resp_seen) {
                ds_drain_bulk(d);
                if (d->rxlen >= sizeof(d->rx)) break; /* still full: give up */
            } else {
                break;
            }
        }
        int fin = 0;
        long n = mq_stream_recv(s, d->rx + d->rxlen, sizeof(d->rx) - d->rxlen, &fin);
        if (n < 0) {
            d->err_seen = 1;
            break;
        }
        if (n > 0) d->rxlen += (size_t)n;
        if (fin) d->fin_seen = 1;
        if (n == 0 && !fin) break; /* EAGAIN: nothing more right now */
        if (!d->resp_seen) {
            int c = mq_decode_connect_tcp_resp(d->rx, d->rxlen, &d->resp);
            if (c > 0) {
                d->resp_seen = 1;
                d->resp_consumed = (size_t)c;
            }
        }
        ds_drain_bulk(d);
        if (fin) break;
    }
    if (d->resp_seen && d->rxlen >= d->resp_consumed + 4) {
        if (memcmp(d->rx + d->resp_consumed, "ping", 4) == 0) d->payload_seen = 1;
    }
}

/* Open a data stream, send CONNECT_TCP_REQUEST(IPv4 127.0.0.1:port). */
static mq_stream_t *
open_tcp_data_stream(mq_conn_t *conn, uint16_t port, datastream_t *d)
{
    mq_stream_t *s = mq_conn_open_stream(conn);
    if (!s) return NULL;
    mq_stream_set_cbs(s, ds_readable, NULL, NULL, d);

    mq_connect_tcp_req_t req;
    memset(&req, 0, sizeof(req));
    req.flags = 0;
    req.address_type = MQ_ADDR_IPV4;
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(req.host, &v4, 4);
    req.host_len = 4;
    req.port = port;

    uint8_t buf[512];
    int n = mq_encode_connect_tcp_req(buf, sizeof(buf), &req);
    if (n < 0) return NULL;
    (void)mq_stream_send(s, buf, (size_t)n, 0);
    return s;
}

/* ── Case C: authed data stream → dial echo origin → OK + payload echoes ── */
static void
test_data_stream_echo(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_FAILED;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = open_tcp_data_stream(conn, origin_port, &d);
    MQ_CHECK(s != NULL);

    /* Wait for CONNECT_TCP_RESPONSE(OK). */
    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_OK);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_TCP_OK);

    /* Now send "ping" on the data stream and expect it echoed back. */
    if (s) (void)mq_stream_send(s, (const unsigned char *)"ping", 4, 0);
    pump_until(f.base, &d.payload_seen, 4000);
    MQ_CHECK(d.payload_seen);

    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case D: CONNECT_TCP to a closed port → ERROR(CONN_REFUSED) ─────────── */
static void
test_data_stream_refused(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    /* Bind+listen then close to obtain a port that is reliably not listening. */
    int tmp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    bind(tmp, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(tmp, (struct sockaddr *)&sa, &sl);
    uint16_t dead_port = ntohs(sa.sin_port);
    close(tmp);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = open_tcp_data_stream(conn, dead_port, &d);
    MQ_CHECK(s != NULL);

    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_ERROR);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_TCP_CONN_REFUSED);

    fixture_down(&f);
}

/* ── Case E: data stream BEFORE auth completes → reset, no dial ─────────── */
/* Driven by a RAW client conn (no mq_client / no AUTH_REQUEST), so the server's
 * `authed` flag is deterministically 0 when the data stream arrives.
 *
 * The server claims the FIRST client-initiated bidi stream as the control
 * stream (Task 11) and waits for AUTH_REQUEST bytes there. We open that control
 * stream but never send a valid AUTH_REQUEST, so auth never succeeds. Then we
 * open a SECOND (data) stream carrying a CONNECT_TCP_REQUEST. xquic surfaces the
 * streams to the server in stream-id order, so by the time the data stream is
 * seen, `authed` is still 0 → the server MUST reset it without dialing. */
typedef struct {
    uint16_t origin_port;
    datastream_t *d;
    int opened;
} preauth_ctx_t;

static void
preauth_on_state(mq_conn_t *conn, mq_conn_state_t st, void *user)
{
    preauth_ctx_t *p = (preauth_ctx_t *)user;
    if (st != MQ_CONN_ESTABLISHED || p->opened) return;
    p->opened = 1;

    /* Stream #1: claimed as the control stream by the server. Send nothing
     * (and definitely no valid AUTH_REQUEST) so the server stays unauthed. */
    mq_stream_t *ctrl = mq_conn_open_stream(conn);
    MQ_CHECK(ctrl != NULL);
    if (ctrl) {
        static const unsigned char nudge[] = {0x00};
        (void)mq_stream_send(ctrl, nudge, sizeof(nudge), 0);
    }

    /* Stream #2: a data stream with a CONNECT_TCP_REQUEST while unauthed. */
    (void)open_tcp_data_stream(conn, p->origin_port, p->d);
}

static void
test_data_stream_preauth_reset(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    uint16_t srv_port = reserve_udp_port();
    MQ_CHECK(srv_port != 0);

    /* Server: transport (TLS) + runtime borrowing the shared base. */
    mq_transport_t *srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv_t != NULL);
    mq_runtime_t *srv_rt = srv_t ? mq_runtime_new(srv_t, base) : NULL;
    MQ_CHECK(srv_rt != NULL);
    mq_server_t *server =
        (srv_t && srv_rt) ? mq_server_new(srv_t, srv_rt, "secret") : NULL;
    MQ_CHECK(server != NULL);

    int srv_bound = srv_rt ? mq_runtime_open_udp_path(srv_rt, "127.0.0.1", srv_port) : -1;
    MQ_CHECK_EQ_INT(srv_bound, 0);

    echo_origin_t origin;
    uint16_t origin_port = 0;
    if (base) MQ_CHECK_EQ_INT(echo_origin_up(&origin, base, &origin_port), 0);

    /* Client: RAW transport conn (no mq_client / no AUTH_REQUEST). */
    mq_transport_t *cli_t = mq_transport_new(0);
    MQ_CHECK(cli_t != NULL);
    mq_runtime_t *cli_rt = cli_t ? mq_runtime_new(cli_t, base) : NULL;
    MQ_CHECK(cli_rt != NULL);
    if (cli_t)
        MQ_CHECK_EQ_INT(mq_conn_register_alpn(cli_t, TEST_ALPN, NULL, NULL, NULL), 0);
    int cli_bound = cli_rt ? mq_runtime_open_udp_path(cli_rt, "127.0.0.1", 0) : -1;
    MQ_CHECK_EQ_INT(cli_bound, 0);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    preauth_ctx_t pctx = {.origin_port = origin_port, .d = &d, .opened = 0};

    mq_conn_t *conn = NULL;
    if (cli_t && cli_bound == 0) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(srv_port);
        xqc_conn_settings_t settings;
        memset(&settings, 0, sizeof(settings));
        settings.proto_version = XQC_VERSION_V1;
        settings.pacing_on = 1;
        settings.max_pkt_out_size = 1200;
        conn = mq_conn_connect(cli_t, (struct sockaddr *)&sa, sizeof(sa), TEST_ALPN,
                               &settings, NULL);
        MQ_CHECK(conn != NULL);
        if (conn) mq_conn_set_on_state(conn, preauth_on_state, &pctx);
    }

    /* Let the handshake + both streams settle. */
    pump_until(base, NULL, 2500);

    /* The server must NOT have dialed the origin (no accepted connection) and
     * must NOT have returned a CONNECT_TCP_RESPONSE(OK) for the premature
     * stream. (It is reset; the client may or may not observe a response.) */
    MQ_CHECK_EQ_INT(origin.conn_fd, -1);
    MQ_CHECK(!(d.resp_seen && d.resp.status == MQ_STATUS_OK));

    echo_origin_down(&origin);
    /* Per side: transport first, then runtime (borrowed base, not freed here),
     * then the server. The test frees the shared base last. */
    if (cli_t) mq_transport_free(cli_t);
    if (srv_t) mq_transport_free(srv_t);
    if (cli_rt) mq_runtime_free(cli_rt);
    if (srv_rt) mq_runtime_free(srv_rt);
    if (server) mq_server_free(server);
    if (base) event_base_free(base);
}

/* ── Case F: connection drop mid-transfer reaps relays (ASan/LSan) ──────── */
static void
test_data_stream_teardown(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = open_tcp_data_stream(conn, origin_port, &d);
    MQ_CHECK(s != NULL);

    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_OK);

    /* Force the MPQUIC connection closed mid-transfer. The server must reap the
     * active relay (close stream + fd once, free relay) with no leak/UAF. */
    mq_conn_close(conn);
    pump_until(f.base, NULL, 1500);

    echo_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case G: download to completion → ALL N bytes + clean FIN, no RESET ─── */
/* The origin streams N bytes (N spans several packets / flow-control quanta)
 * then closes. The client reads the data stream until the QUIC stream FIN and
 * must observe EXACTLY N payload bytes with a matching checksum AND a clean FIN
 * (never a reset/error). Against the pre-fix server this FAILS: completion reap
 * runs with graceful==0 → RESET_STREAM, truncating un-acked STREAM data, so the
 * client sees far fewer than N bytes and never a FIN. */
static void
test_data_stream_download_completion(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    const size_t N = 200000; /* > one MTU / flow-control quantum: multi-packet */
    bulk_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(bulk_origin_up(&origin, f.base, N, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    d.track_bulk = 1;
    mq_stream_t *s = open_tcp_data_stream(conn, origin_port, &d);
    MQ_CHECK(s != NULL);

    /* Drive until the client sees the QUIC stream FIN (or the budget expires).
     * A RESET would surface as err_seen / a missing FIN, not a clean fin_seen. */
    pump_until(f.base, &d.fin_seen, 8000);

    /* Compute the expected checksum the origin would have produced for N bytes. */
    uint32_t expect_sum = 0;
    for (size_t i = 0; i < N; i++)
        expect_sum += (unsigned char)(i & 0xff);

    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_OK);
    MQ_CHECK(d.fin_seen);           /* clean FIN, not a reset */
    MQ_CHECK_EQ_INT(d.err_seen, 0); /* no hard error / RESET */
    MQ_CHECK_EQ_INT((long long)d.payload_bytes, (long long)N); /* ALL bytes */
    MQ_CHECK_EQ_INT((long long)d.payload_sum, (long long)expect_sum);

    bulk_origin_down(&origin);
    fixture_down(&f);
}

/* ── Case H: origin half-closes while client lingers → no busy-spin ─────── */
/* The origin sends a tiny reply then closes (recv→0 at the proxy). The client
 * keeps its side open briefly. Against the pre-fix server, the EOF'd origin fd's
 * level-triggered EV_READ re-fires forever (one event_base_loop iteration never
 * returns), so the bounded pump budget below is blown / the test hangs. After
 * the fix, the dead fd's read event is event_del'd on EOF and a FIN is
 * propagated, so the client gets the reply + a clean FIN well within budget. */
static void
test_data_stream_halfclose_nospin(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    const size_t N = 64; /* tiny reply */
    bulk_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(bulk_origin_up(&origin, f.base, N, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    d.track_bulk = 1;
    mq_stream_t *s = open_tcp_data_stream(conn, origin_port, &d);
    MQ_CHECK(s != NULL);

    uint64_t start = now_ms();
    /* Bounded budget: a busy-spin would make a single loop iteration never
     * return, so wall-clock would blow far past this. */
    pump_until(f.base, &d.fin_seen, 5000);
    uint64_t elapsed = now_ms() - start;

    MQ_CHECK(d.resp_seen);
    MQ_CHECK(d.fin_seen);
    MQ_CHECK_EQ_INT(d.err_seen, 0);
    MQ_CHECK_EQ_INT((long long)d.payload_bytes, (long long)N);
    /* Completed well within the budget (no spin): generous ceiling. */
    MQ_CHECK(elapsed < 5000);

    bulk_origin_down(&origin);
    fixture_down(&f);
}

/* ── Task 13: real mq_client_tcp_open end-to-end ────────────────────────────
 *
 * These exercise the CLIENT data path (mq_client_tcp_open), not the test-only
 * raw-stream helper above. A socketpair() stands in for the local app socket:
 * one end (local_fd) is handed to the client as the relay's B side; the test
 * drives/reads the OTHER end (app_fd) as the application would. */

/* tcp_open callback bookkeeping. */
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

/* Build an IPv4 host buffer for 127.0.0.1 into host[4]. */
static void
v4_loopback(uint8_t host[4])
{
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(host, &v4, 4);
}

/* Case I — client tcp_open echo: app→local_fd→client→stream→server→origin→back. */
static void
test_client_open_echo(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_FAILED;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    echo_set_nonblock(sp[0]);
    echo_set_nonblock(sp[1]);
    int app_fd = sp[0];
    int local_fd = sp[1]; /* handed to the client */

    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       origin_port, local_fd, NULL, 0, &res, on_tcp_open);

    pump_until(f.base, &res.fired, 4000);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 1);
    MQ_CHECK_EQ_INT((int)res.err, (int)MQ_TCP_OK);

    /* Write "ping" into the app end; expect it echoed back through the path. */
    MQ_CHECK_EQ_INT((int)write(app_fd, "ping", 4), 4);

    char rx[16];
    size_t got = 0;
    uint64_t deadline = now_ms() + 4000;
    while (got < 4 && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        ssize_t n = recv(app_fd, rx + got, sizeof(rx) - got, 0);
        if (n > 0) got += (size_t)n;
    }
    MQ_CHECK_EQ_INT((int)got, 4);
    MQ_CHECK(memcmp(rx, "ping", 4) == 0);

    close(app_fd);
    echo_origin_down(&origin);
    fixture_down(&f);
}

/* Case J — client-side download completion: ALL N bytes + clean EOF on local_fd,
 * no truncation. Proves the client relay propagates the server's stream FIN to a
 * shutdown/close of the local fd. */
static void
test_client_open_download(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    const size_t N = 200000;
    bulk_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(bulk_origin_up(&origin, f.base, N, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    echo_set_nonblock(sp[0]);
    echo_set_nonblock(sp[1]);
    int app_fd = sp[0];
    int local_fd = sp[1];

    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       origin_port, local_fd, NULL, 0, &res, on_tcp_open);

    pump_until(f.base, &res.fired, 4000);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 1);

    /* Drain the app end until clean EOF (recv == 0), counting bytes + checksum. */
    size_t got = 0;
    uint32_t sum = 0;
    int eof = 0;
    uint64_t deadline = now_ms() + 8000;
    while (!eof && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        unsigned char buf[8192];
        for (;;) {
            ssize_t n = recv(app_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                for (ssize_t i = 0; i < n; i++)
                    sum += buf[i];
                got += (size_t)n;
            } else if (n == 0) {
                eof = 1; /* clean EOF: the FIN propagated to a local-fd close */
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

    close(app_fd);
    bulk_origin_down(&origin);
    fixture_down(&f);
}

/* Case K — pre-auth queue: call tcp_open BEFORE auth, drains after auth + echoes. */
static void
test_client_open_preauth_queue(void)
{
    g_auth_fired = g_auth_ok = 0;
    g_auth_err = MQ_AUTH_FAILED;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    /* Do NOT pump for auth yet — issue tcp_open while unauthed. */
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 0);

    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    echo_set_nonblock(sp[0]);
    echo_set_nonblock(sp[1]);
    int app_fd = sp[0];
    int local_fd = sp[1];

    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       origin_port, local_fd, NULL, 0, &res, on_tcp_open);

    /* It must NOT have completed yet (queued, awaiting auth). */
    MQ_CHECK_EQ_INT(res.fired, 0);

    /* Now let auth + the drained open complete. */
    pump_until(f.base, &res.fired, 6000);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 1);

    MQ_CHECK_EQ_INT((int)write(app_fd, "ping", 4), 4);
    char rx[16];
    size_t got = 0;
    uint64_t deadline = now_ms() + 4000;
    while (got < 4 && now_ms() < deadline) {
        event_base_loop(f.base, EVLOOP_NONBLOCK);
        ssize_t n = recv(app_fd, rx + got, sizeof(rx) - got, 0);
        if (n > 0) got += (size_t)n;
    }
    MQ_CHECK_EQ_INT((int)got, 4);
    MQ_CHECK(memcmp(rx, "ping", 4) == 0);

    close(app_fd);
    echo_origin_down(&origin);
    fixture_down(&f);
}

/* Case L — refused propagation: tcp_open to a closed port → cb ok=0 / REFUSED. */
static void
test_client_open_refused(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    int tmp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    bind(tmp, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(tmp, (struct sockaddr *)&sa, &sl);
    uint16_t dead_port = ntohs(sa.sin_port);
    close(tmp);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    int sp[2];
    MQ_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    echo_set_nonblock(sp[0]);
    echo_set_nonblock(sp[1]);
    int app_fd = sp[0];
    int local_fd = sp[1];

    open_result_t res;
    memset(&res, 0, sizeof(res));
    uint8_t host[4];
    v4_loopback(host);
    mq_client_tcp_open(mq_client_tcp_open_core(f.client), host, 4, MQ_ADDR_IPV4,
                       dead_port, local_fd, NULL, 0, &res, on_tcp_open);

    pump_until(f.base, &res.fired, 4000);
    MQ_CHECK(res.fired);
    MQ_CHECK_EQ_INT(res.ok, 0);
    MQ_CHECK_EQ_INT((int)res.err, (int)MQ_TCP_CONN_REFUSED);

    close(app_fd);
    fixture_down(&f);
}

/* Case M — server-side coalesced request+payload: a client sends the
 * CONNECT_TCP_REQUEST and its first upload bytes in ONE stream write, so the
 * server pulls both into its header buffer in a single read. The trailing
 * payload must reach the origin (the server's flow prebuffer), not be dropped.
 * Asserts the echoed payload returns. */
static void
test_data_stream_coalesced_payload(void)
{
    g_auth_fired = g_auth_ok = 0;

    fixture_t f;
    if (fixture_up(&f, "secret") != 0) {
        fixture_down(&f);
        return;
    }

    echo_origin_t origin;
    uint16_t origin_port = 0;
    MQ_CHECK_EQ_INT(echo_origin_up(&origin, f.base, &origin_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    mq_conn_t *conn = mq_client_conn(f.client);
    MQ_CHECK(conn != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = mq_conn_open_stream(conn);
    MQ_CHECK(s != NULL);
    if (s) {
        mq_stream_set_cbs(s, ds_readable, NULL, NULL, &d);

        mq_connect_tcp_req_t req;
        memset(&req, 0, sizeof(req));
        req.flags = 0;
        req.address_type = MQ_ADDR_IPV4;
        uint32_t v4 = htonl(INADDR_LOOPBACK);
        memcpy(req.host, &v4, 4);
        req.host_len = 4;
        req.port = origin_port;

        /* Encode the request and append "ping" so they go out in one write — the
         * server reads request+payload in a single buffer fill. */
        uint8_t buf[512];
        int n = mq_encode_connect_tcp_req(buf, sizeof(buf), &req);
        MQ_CHECK(n > 0);
        if (n > 0 && (size_t)n + 4 <= sizeof(buf)) {
            memcpy(buf + n, "ping", 4);
            (void)mq_stream_send(s, buf, (size_t)n + 4, 0);
        }
    }

    pump_until(f.base, &d.payload_seen, 6000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_OK);
    MQ_CHECK(d.payload_seen); /* the coalesced "ping" reached the origin + echoed */

    echo_origin_down(&origin);
    fixture_down(&f);
}

static void
test_client_server(void)
{
    test_auth_wrong_token();
    test_auth_matching_token();
    test_data_stream_echo();
    test_data_stream_refused();
    test_data_stream_preauth_reset();
    test_data_stream_teardown();
    test_data_stream_download_completion();
    test_data_stream_halfclose_nospin();
    test_data_stream_coalesced_payload();
    test_client_open_echo();
    test_client_open_download();
    test_client_open_preauth_queue();
    test_client_open_refused();
}

MQ_TEST_MAIN(test_client_server())
