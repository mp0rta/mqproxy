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
#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "transport/mq_path.h"
#include "transport/mq_stream.h"
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
    mq_engine_t *srv;
    mq_engine_t *cli;
    mq_path_t *srv_path;
    mq_path_t *cli_path;
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

    /* Server */
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

    /* Client */
    f->cli = mq_engine_new(0, f->base);
    MQ_CHECK(f->cli != NULL);
    if (!f->cli) return -1;

    f->client = mq_client_new(f->cli, "127.0.0.1", port, "client-1", client_token);
    MQ_CHECK(f->client != NULL);
    if (!f->client) return -1;
    mq_client_set_on_auth(f->client, on_auth, NULL);

    f->cli_path = mq_path_open(f->cli, 0, "127.0.0.1", 0);
    MQ_CHECK(f->cli_path != NULL);
    if (!f->cli_path) return -1;

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    mq_client_set_on_state(f->client, on_client_state, NULL);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
    /* Tear down in dependency order: paths first, then engines. Freeing an
     * engine destroys its connections, firing conn_close_notify which invokes
     * the client/server state callbacks (whose `user` is the mq_client /
     * mq_server). So those must outlive the engine — free them LAST. */
    if (f->cli_path) mq_path_close(f->cli_path);
    if (f->srv_path) mq_path_close(f->srv_path);
    if (f->cli) mq_engine_free(f->cli);
    if (f->srv) mq_engine_free(f->srv);
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

/* ── data-stream client helper (test-only; mq_client tcp_open is Task 13) ── */
/* Build a CONNECT_TCP_REQUEST to 127.0.0.1:port and capture stream rx. */
typedef struct {
    unsigned char rx[8192];
    size_t rxlen;
    int resp_seen;
    mq_connect_tcp_resp_t resp;
    size_t resp_consumed; /* bytes of rx the CONNECT_TCP_RESPONSE occupied */
    int payload_seen;     /* the echoed payload arrived after the response */
} datastream_t;

static void
ds_readable(mq_stream_t *s, void *user)
{
    datastream_t *d = (datastream_t *)user;
    for (;;) {
        if (d->rxlen >= sizeof(d->rx)) break;
        int fin = 0;
        long n = mq_stream_recv(s, d->rx + d->rxlen, sizeof(d->rx) - d->rxlen, &fin);
        if (n <= 0) break;
        d->rxlen += (size_t)n;
    }
    if (!d->resp_seen) {
        int c = mq_decode_connect_tcp_resp(d->rx, d->rxlen, &d->resp);
        if (c > 0) {
            d->resp_seen = 1;
            d->resp_consumed = (size_t)c;
        }
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

    mq_engine_t *srv = mq_engine_new_server(base, TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv != NULL);
    mq_server_t *server = srv ? mq_server_new(srv, "secret") : NULL;
    MQ_CHECK(server != NULL);

    mq_path_t *srv_path = srv ? mq_path_open(srv, 0, "127.0.0.1", 0) : NULL;
    MQ_CHECK(srv_path != NULL);

    echo_origin_t origin;
    uint16_t origin_port = 0;
    if (base) MQ_CHECK_EQ_INT(echo_origin_up(&origin, base, &origin_port), 0);

    uint16_t srv_port = 0;
    if (srv_path) {
        struct sockaddr_storage sa;
        socklen_t sl = 0;
        MQ_CHECK_EQ_INT(mq_path_local_addr(srv_path, &sa, &sl), 0);
        srv_port = ntohs(((struct sockaddr_in *)&sa)->sin_port);
    }

    mq_engine_t *cli = mq_engine_new(0, base);
    MQ_CHECK(cli != NULL);
    if (cli) MQ_CHECK_EQ_INT(mq_conn_register_alpn(cli, TEST_ALPN, NULL, NULL, NULL), 0);
    mq_path_t *cli_path = cli ? mq_path_open(cli, 0, "127.0.0.1", 0) : NULL;
    MQ_CHECK(cli_path != NULL);

    datastream_t d;
    memset(&d, 0, sizeof(d));
    preauth_ctx_t pctx = {.origin_port = origin_port, .d = &d, .opened = 0};

    mq_conn_t *conn = NULL;
    if (cli && cli_path) {
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
        conn = mq_conn_connect(cli, (struct sockaddr *)&sa, sizeof(sa), TEST_ALPN,
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
    if (cli_path) mq_path_close(cli_path);
    if (srv_path) mq_path_close(srv_path);
    if (cli) mq_engine_free(cli);
    if (srv) mq_engine_free(srv);
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

static void
test_client_server(void)
{
    test_auth_wrong_token();
    test_auth_matching_token();
    test_data_stream_echo();
    test_data_stream_refused();
    test_data_stream_preauth_reset();
    test_data_stream_teardown();
}

MQ_TEST_MAIN(test_client_server())
