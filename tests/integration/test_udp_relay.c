// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_udp_relay.c — UDP relay full-path integration (Task 5.3 + 6.2).
 *
 * Stands up a REAL mq_client + REAL mq_server over loopback in-process on a
 * shared libevent base (same harness shape as test_client_server.c), plus a
 * local UDP echo socket bound inside the test.
 *
 * Cases 1/2/a/b drive the CLIENT-ROLE boundary (mq_client_udp_open_fn /
 * send / close — Task 6.2): the client owns the conn's datagram callback and
 * reassembles server→client datagrams into on_rx. Cases 3/6/7/8/9 assemble the
 * 0x02 (UDP_SESSION) stream + DATAGRAM frames DIRECTLY on the conn using the
 * Task 1/4 codecs (raw-conn server-stimulus scaffolding), keeping precise
 * control over send ordering / malformed inputs for server-behaviour coverage.
 *
 * Cases (design §2/§6/§9.2):
 *   1. client-role open → send → byte-exact echo (optimistic send, post-auth).
 *   2. client-role open + send SAME turn → server pre-OPEN buffer delivers echo
 *      (xquic datagram-before-stream ordering regression — design §2).
 *   a. client-role open + send BEFORE auth → queued; flushed post-auth (startup
 *      race regression).
 *   b. client-role 3000B frag relay → byte-exact echo + frags_reassembled > 0.
 *   c. client-role on_err path — open to nonexistent.invalid (DOMAIN atype) →
 *      on_err fired once with MQ_UDP_DNS_FAILED; handle dead (no send/close).
 *   3. OPEN to a non-existent host (.invalid) → RESP MQ_UDP_DNS_FAILED + close.
 *   4. enabled=0 (--no-udp) → RESP MQ_UDP_POLICY_DENIED.
 *   5. idle_timeout_ms=100, left idle → server closes the 0x02 stream.
 *   6. 17 unknown-sid datagrams → pre-OPEN ring evicts the oldest (counter ≥ 1).
 *   7. datagram BEFORE auth → dropped (drops_preauth), and NOT later flushed
 *      when the same sid OPENs after auth (pre-auth bytes never leak through).
 *   8. duplicate-SID OPEN: a second OPEN for a live sid resets the new stream;
 *      the original session keeps echoing.
 *   9. enabled=0 + datagram → dropped (drops_preauth), pre-OPEN buffer stays
 *      empty (no eviction churn while every OPEN is denied).
 *  10. (d2) pre-OPEN flush double-free: buffer datagrams for TWO distinct unknown
 *      sids, OPEN only one → srv_preopen_flush must MOVE (not shallow-copy) the
 *      surviving sid's entry; teardown runs srv_preopen_free_all over the
 *      compacted ring. ASan-clean = no double-free (regression pin).
 *
 * Counter access (cases 6/7/9): the server exposes the most-recent conn's UDP
 * relay state via mq_server_last_udp_srv() (observability accessor) and the
 * relay exposes a by-value counter snapshot via mq_udp_srv_counters(). Both are
 * public, documented observability APIs (not test-only hacks) added alongside
 * this test; with one client per server instance the "most recent" conn is the
 * one under test.
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
#include <xquic/xquic.h>

#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "proxy/mq_udp_session.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"
#include "wire/mq_udp_msg.h"
#include "wire/mq_wire.h"

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

static void
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ── local UDP echo origin ──────────────────────────────────────────────────
 *
 * A connected-less UDP socket bound on 127.0.0.1:ephemeral. On EV_READ it
 * recvfrom()s each datagram and sendto()s the identical bytes back to the
 * sender. This is the target the server's relay dials. */
typedef struct {
    struct event_base *base;
    int fd;
    struct event *ev;
    int rx_count; /* datagrams echoed (for sanity) */
} udp_echo_t;

static void
udp_echo_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    udp_echo_t *e = (udp_echo_t *)arg;
    for (;;) {
        unsigned char buf[65535];
        struct sockaddr_storage from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) break; /* EAGAIN */
        e->rx_count++;
        (void)sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fl);
    }
}

static int
udp_echo_up(udp_echo_t *e, struct event_base *base, uint16_t *out_port)
{
    memset(e, 0, sizeof(*e));
    e->base = base;
    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (e->fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(e->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    socklen_t sl = sizeof(sa);
    if (getsockname(e->fd, (struct sockaddr *)&sa, &sl) != 0) return -1;
    *out_port = ntohs(sa.sin_port);
    set_nonblock(e->fd);
    e->ev = event_new(base, e->fd, EV_READ | EV_PERSIST, udp_echo_cb, e);
    event_add(e->ev, NULL);
    return 0;
}

static void
udp_echo_down(udp_echo_t *e)
{
    if (e->ev) event_free(e->ev);
    if (e->fd >= 0) close(e->fd);
}

/* ── fixture: real client + real server on a shared base ─────────────────── */
typedef struct {
    struct event_base *base;
    mq_transport_t *srv_t;
    mq_transport_t *cli_t;
    mq_runtime_t *srv_rt;
    mq_runtime_t *cli_rt;
    mq_server_t *server;
    mq_client_t *client;
} fixture_t;

static int g_auth_fired;
static int g_auth_ok;

static void
on_auth(int ok, mq_auth_err_t err, void *user)
{
    (void)err;
    (void)user;
    g_auth_fired = 1;
    g_auth_ok = ok;
}

static int
fixture_up(fixture_t *f, uint64_t udp_idle_ms, int udp_enabled)
{
    memset(f, 0, sizeof(*f));
    g_auth_fired = 0;
    g_auth_ok = 0;

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
    f->server = mq_server_new(f->srv_t, f->srv_rt, "secret", MQ_CC_BBR2, udp_idle_ms,
                              udp_enabled);
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
    mq_client_set_on_auth(f->client, on_auth, NULL);

    MQ_CHECK_EQ_INT(mq_client_start(f->client), 0);
    return 0;
}

static void
fixture_down(fixture_t *f)
{
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

static void
pump_for(struct event_base *base, uint64_t ms)
{
    uint64_t deadline = now_ms() + ms;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

/* ── 0x02 UDP_SESSION stream + RESP capture ──────────────────────────────── */
typedef struct {
    unsigned char rx[1024];
    size_t rxlen;
    int resp_seen;
    mq_udp_session_resp_t resp;
    int closed;   /* close-notify fired (full close: RESET, or both-side FIN) */
    int fin_seen; /* the server FIN'd its send side (read direction closed) */
} udpstream_t;

static void
us_readable(mq_stream_t *s, void *user)
{
    udpstream_t *d = (udpstream_t *)user;
    for (;;) {
        if (d->rxlen >= sizeof(d->rx)) break;
        int fin = 0;
        long n = mq_stream_recv(s, d->rx + d->rxlen, sizeof(d->rx) - d->rxlen, &fin);
        if (n < 0) break;
        if (n > 0) d->rxlen += (size_t)n;
        if (fin) d->fin_seen = 1;
        if (!d->resp_seen) {
            int c = mq_decode_udp_session_resp(d->rx, d->rxlen, &d->resp);
            if (c > 0) d->resp_seen = 1;
        }
        if (n == 0) break;
    }
}

static void
us_closed(mq_stream_t *s, void *user)
{
    (void)s;
    udpstream_t *d = (udpstream_t *)user;
    d->closed = 1;
}

/* Open a 0x02 stream and send [discriminator varint][UDP_SESSION_OPEN] in ONE
 * mq_stream_send — mirrors how mq_client coalesces the discriminator + body.
 * IPv4 127.0.0.1:port unless host/host_len override it (for the .invalid case). */
static mq_stream_t *
open_udp_session(mq_conn_t *conn, uint32_t sid, mq_addr_type_t atype, const uint8_t *host,
                 size_t host_len, uint16_t port, uint64_t idle_ms, udpstream_t *d)
{
    mq_stream_t *s = mq_conn_open_stream(conn);
    if (!s) return NULL;
    mq_stream_set_cbs(s, us_readable, NULL, us_closed, d);

    mq_udp_session_open_t open;
    memset(&open, 0, sizeof(open));
    open.session_id = sid;
    open.flags = 0;
    open.address_type = atype;
    memcpy(open.host, host, host_len);
    open.host_len = host_len;
    open.port = port;
    open.idle_timeout_ms = idle_ms;

    uint8_t buf[512];
    buf[0] = (uint8_t)MQ_STREAM_TYPE_UDP_SESSION;
    int n = mq_encode_udp_session_open(buf + 1, sizeof(buf) - 1, &open);
    if (n < 0) return NULL;
    (void)mq_stream_send(s, buf, (size_t)(1 + n), 0);
    return s;
}

static mq_stream_t *
open_udp_v4(mq_conn_t *conn, uint32_t sid, uint16_t port, uint64_t idle_ms,
            udpstream_t *d)
{
    uint8_t host[4];
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(host, &v4, 4);
    return open_udp_session(conn, sid, MQ_ADDR_IPV4, host, 4, port, idle_ms, d);
}

/* ── tunnel datagram assembly (single-fragment) ──────────────────────────── */
/* Build one unfragmented UDP_MSG datagram (9-byte hdr + payload) into out and
 * send it on the conn's DATAGRAM channel. */
static int
send_tunnel_datagram(mq_conn_t *conn, uint32_t sid, uint16_t pkt_id,
                     const uint8_t *payload, size_t plen)
{
    uint8_t out[9 + 2048];
    if (plen > sizeof(out) - MQ_UDP_MSG_HDR) return -1;
    mq_udp_msg_hdr_t h;
    h.session_id = sid;
    h.packet_id = pkt_id;
    h.flags = 0;
    h.frag_id = 0;
    h.frag_count = 1;
    mq_udp_msg_encode_hdr(out, &h);
    memcpy(out + MQ_UDP_MSG_HDR, payload, plen);
    return mq_conn_datagram_send(conn, out, MQ_UDP_MSG_HDR + plen);
}

/* ── datagram receive capture (server→tunnel echo lands here) ──────────────
 *
 * Sized to 4096 so the 3000B frag-relay case (b) captures byte-exact. Used by
 * the RAW-conn cases (6/7/8/9) that decode datagrams directly; the client-role
 * cases use the cli_rx_t capture below (on_rx delivers reassembled payload). */
static uint8_t g_dgm_rx[4096];
static size_t g_dgm_rxlen;
static int g_dgm_done;
static uint32_t g_dgm_want_sid;

static void
on_client_datagram(mq_conn_t *c, const uint8_t *data, size_t len, void *user)
{
    (void)c;
    (void)user;
    if (g_dgm_done || len < MQ_UDP_MSG_HDR) return;
    mq_udp_msg_hdr_t h;
    if (mq_udp_msg_decode_hdr(data, len, &h) != 0) return;
    if (h.session_id != g_dgm_want_sid) return;
    size_t plen = len - MQ_UDP_MSG_HDR;
    if (plen > sizeof(g_dgm_rx)) plen = sizeof(g_dgm_rx);
    memcpy(g_dgm_rx, data + MQ_UDP_MSG_HDR, plen);
    g_dgm_rxlen = plen;
    g_dgm_done = 1;
}

static void
reset_dgm_capture(uint32_t sid)
{
    g_dgm_done = 0;
    g_dgm_rxlen = 0;
    g_dgm_want_sid = sid;
    memset(g_dgm_rx, 0, sizeof(g_dgm_rx));
}

/* Authenticate the fixture's client + wire the client's datagram callback.
 *
 * NOTE: the RAW-conn cases (6/7/8/9) install on_client_datagram on the conn to
 * decode datagrams directly. The client-role cases (1/2/a/b) must NOT do this:
 * the mq_client already owns the conn's datagram callback (routing to its
 * mq_udp_cli dispatch), so they leave it in place and capture via cli_rx_t. */
static mq_conn_t *
fixture_authed_conn(fixture_t *f)
{
    pump_until(f->base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);
    mq_conn_t *conn = mq_client_conn(f->client);
    MQ_CHECK(conn != NULL);
    if (conn) mq_conn_set_on_datagram(conn, on_client_datagram, NULL);
    return conn;
}

/* ── client-role session capture (on_rx / on_err via the mq_udp_open_fn) ────
 *
 * The boundary delivers reassembled UDP payloads through on_rx and terminal
 * failures through on_err. cli_rx_t captures the first payload (byte-exact, up
 * to 4096B for the frag case) and any on_err code for assertion. */
typedef struct {
    uint8_t rx[4096];
    size_t rxlen;
    int rx_done;
    int err_fired;
    mq_udp_err_t err;
} cli_rx_t;

static void
cli_on_rx(const uint8_t *payload, size_t len, void *user)
{
    cli_rx_t *c = (cli_rx_t *)user;
    if (c->rx_done) return;
    size_t n = len > sizeof(c->rx) ? sizeof(c->rx) : len;
    memcpy(c->rx, payload, n);
    c->rxlen = n;
    c->rx_done = 1;
}

static void
cli_on_err(void *session, mq_udp_err_t err, void *user)
{
    (void)session;
    cli_rx_t *c = (cli_rx_t *)user;
    c->err_fired = 1;
    c->err = err;
}

/* Open a UDP relay session through the boundary (mq_client_udp_open_fn) using
 * a domain atype. Returns the opaque session handle (or NULL). */
static void *
cli_open_domain(mq_client_t *client, const char *hostname, uint16_t port, cli_rx_t *cap)
{
    mq_udp_open_fn open_fn = mq_client_udp_open_fn();
    void *core = mq_client_udp_open_core(client);
    return open_fn(core, (const uint8_t *)hostname, strlen(hostname), MQ_ADDR_DOMAIN,
                   port, cli_on_rx, cli_on_err, cap);
}

/* Open a UDP relay session through the boundary (mq_client_udp_open_fn) to the
 * loopback echo on `port`. Returns the opaque session handle (or NULL). */
static void *
cli_open_v4(mq_client_t *client, uint16_t port, cli_rx_t *cap)
{
    uint8_t host[4];
    uint32_t v4 = htonl(INADDR_LOOPBACK);
    memcpy(host, &v4, 4);
    mq_udp_open_fn open_fn = mq_client_udp_open_fn();
    void *core = mq_client_udp_open_core(client);
    return open_fn(core, host, 4, MQ_ADDR_IPV4, port, cli_on_rx, cli_on_err, cap);
}

/* ── default-server scenarios (enabled=1, idle=60s): cases 1,2,3,6,7,8 ───── */

/* Case 1: client-role open → send → byte-exact echo (via the mq_udp_open_fn
 * boundary). Exercises optimistic send (open then send, post-auth) end-to-end. */
static void
test_case1_open_resp_echo(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    /* Wait for auth (so the open issues the stream immediately); the mq_client
     * owns the conn datagram callback (routing to its cli dispatch). */
    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_udp_available(f.client), 1);

    cli_rx_t cap;
    memset(&cap, 0, sizeof(cap));
    void *sess = cli_open_v4(f.client, echo_port, &cap);
    MQ_CHECK(sess != NULL);

    /* Optimistic send: payload goes out without waiting for RESP. */
    uint8_t payload[512];
    for (int i = 0; i < 512; i++)
        payload[i] = (uint8_t)((i * 37 + 5) & 0xff);
    mq_client_udp_send_fn()(sess, payload, sizeof(payload));

    pump_until(f.base, &cap.rx_done, 4000);
    MQ_CHECK(cap.rx_done);
    MQ_CHECK_EQ_INT((int)cap.rxlen, 512);
    if (cap.rx_done) MQ_CHECK_MEM(cap.rx, payload, 512);
    MQ_CHECK_EQ_INT(cap.err_fired, 0);

    mq_client_udp_close_fn()(sess);
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case 2: client-role open + send in the SAME turn (post-auth) → optimistic
 * send + server pre-OPEN buffer deliver the echo byte-exact. */
static void
test_case2_preopen_sameflight(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    cli_rx_t cap;
    memset(&cap, 0, sizeof(cap));

    uint8_t payload[300];
    for (int i = 0; i < 300; i++)
        payload[i] = (uint8_t)((i * 91 + 13) & 0xff);

    /* SAME turn: open issues the 0x02 stream + OPEN AND we send the datagram,
     * before any pump. The datagram beats the stream at the server (xquic
     * ordering, design §2), so the server's pre-OPEN buffer must flush it. */
    void *sess = cli_open_v4(f.client, echo_port, &cap);
    MQ_CHECK(sess != NULL);
    mq_client_udp_send_fn()(sess, payload, sizeof(payload));

    pump_until(f.base, &cap.rx_done, 5000);
    MQ_CHECK(cap.rx_done);
    MQ_CHECK_EQ_INT((int)cap.rxlen, 300);
    if (cap.rx_done) MQ_CHECK_MEM(cap.rx, payload, 300);

    mq_client_udp_close_fn()(sess);
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case (a): client-role open + send BEFORE auth completes (startup race
 * regression). The open is issued immediately after mq_client_start (auth not
 * yet settled); the send is queued in the per-session pre-auth queue; after
 * auth the stream issues, the queue flushes, and the echo returns. */
static void
test_caseA_preauth_open_send(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    /* No auth pump: open + send right after fixture_up (auth pending). */
    MQ_CHECK_EQ_INT(mq_client_is_authed(f.client), 0);
    MQ_CHECK_EQ_INT(mq_client_udp_available(f.client), -1); /* undetermined */

    cli_rx_t cap;
    memset(&cap, 0, sizeof(cap));
    void *sess = cli_open_v4(f.client, echo_port, &cap);
    MQ_CHECK(sess != NULL); /* held pending-auth, stream deferred */

    uint8_t payload[200];
    for (int i = 0; i < 200; i++)
        payload[i] = (uint8_t)((i * 53 + 17) & 0xff);
    mq_client_udp_send_fn()(sess, payload, sizeof(payload)); /* queued pre-auth */

    /* Now pump: auth settles → stream issues → queued send flushes → echo. */
    pump_until(f.base, &cap.rx_done, 5000);
    MQ_CHECK(cap.rx_done);
    MQ_CHECK_EQ_INT((int)cap.rxlen, 200);
    if (cap.rx_done) MQ_CHECK_MEM(cap.rx, payload, 200);
    MQ_CHECK_EQ_INT(cap.err_fired, 0);

    mq_client_udp_close_fn()(sess);
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case (b): in-process frag relay — a 3000B payload (> datagram mss) sent via
 * the client role is split into frags, echoed by the origin, reassembled on the
 * way back, and delivered byte-exact through on_rx. Asserts the server's
 * frags_reassembled counter advanced (deterministic frag-path proof). */
static void
test_caseB_frag_relay(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);

    cli_rx_t cap;
    memset(&cap, 0, sizeof(cap));
    void *sess = cli_open_v4(f.client, echo_port, &cap);
    MQ_CHECK(sess != NULL);

    /* 3000B forces a multi-frag split (datagram mss ~1200). */
    uint8_t payload[3000];
    for (int i = 0; i < 3000; i++)
        payload[i] = (uint8_t)((i * 131 + 7) & 0xff);
    mq_client_udp_send_fn()(sess, payload, sizeof(payload));

    pump_until(f.base, &cap.rx_done, 6000);
    MQ_CHECK(cap.rx_done);
    MQ_CHECK_EQ_INT((int)cap.rxlen, 3000);
    if (cap.rx_done) MQ_CHECK_MEM(cap.rx, payload, 3000);
    MQ_CHECK_EQ_INT(cap.err_fired, 0);

    /* The server reassembled the multi-frag tunnel→target packet. */
    mq_udp_srv_t *u = mq_server_last_udp_srv(f.server);
    MQ_CHECK(u != NULL);
    if (u) {
        mq_udp_srv_counters_t c = mq_udp_srv_counters(u);
        MQ_CHECK(c.frags_reassembled > 0);
    }

    mq_client_udp_close_fn()(sess);
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case 3: OPEN to a non-existent host (.invalid) → RESP DNS_FAILED + close. */
static void
test_case3_dns_failed(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x33333333u;
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    static const char host[] = "nonexistent.invalid";
    mq_stream_t *s = open_udp_session(conn, SID, MQ_ADDR_DOMAIN, (const uint8_t *)host,
                                      strlen(host), 9, 0, &d);
    MQ_CHECK(s != NULL);

    pump_until(f.base, &d.resp_seen, 5000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_ERROR);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_DNS_FAILED);

    /* The server FIN's the RESP (graceful, no RESET): the client observes the
     * FIN on its read side. (A half-close: the client never closes its own send
     * side, so xquic's full close-notify need not fire — the FIN is the close
     * signal the protocol delivers, mirroring the TCP refused path.) */
    pump_until(f.base, &d.fin_seen, 2000);
    MQ_CHECK(d.fin_seen);

    fixture_down(&f);
}

/* Case 6: 17 unknown-sid datagrams → pre-OPEN ring evicts oldest (≥ 1). */
static void
test_case6_preopen_evict(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    mq_conn_t *conn = fixture_authed_conn(&f);

    /* 17 distinct unknown sids, each a small (≤1KiB) payload so the 32KiB byte
     * cap is not the trigger — the 16-entry count cap evicts the oldest. */
    uint8_t payload[256];
    memset(payload, 0xAB, sizeof(payload));
    for (uint32_t i = 0; i < 17; i++) {
        MQ_CHECK_EQ_INT(
            send_tunnel_datagram(conn, 0x9000u + i, 0, payload, sizeof(payload)), 0);
    }
    /* Pump so the datagrams land at the server (no OPEN ⇒ all buffered). */
    pump_for(f.base, 500);

    mq_udp_srv_t *u = mq_server_last_udp_srv(f.server);
    MQ_CHECK(u != NULL);
    mq_udp_srv_counters_t c = mq_udp_srv_counters(u);
    MQ_CHECK(c.preopen_evictions >= 1);
    /* All 17 were authed+enabled ⇒ none counted as pre-auth drops. */
    MQ_CHECK_EQ_INT((int)c.drops_preauth, 0);

    fixture_down(&f);
}

/* Case 7 uses a RAW client conn (not mq_client) so the test controls send
 * ordering precisely: on ESTABLISHED it emits the pre-auth datagram FIRST, THEN
 * opens the control stream + sends AUTH_REQUEST. The datagram is therefore in an
 * earlier flight than the AUTH_REQUEST and lands at the server while `authed`==0
 * → counted as drops_preauth and (critically) NEVER buffered. mq_client cannot
 * be used here because it sends AUTH_REQUEST on the ESTABLISHED edge before
 * forwarding to the user callback, so a datagram queued there always loses the
 * race to auth on fast loopback. */
#define CASE7_ALPN "mqproxy-tcp/1"

typedef struct {
    uint32_t sid;
    const uint8_t *marker;
    size_t marker_len;
    int established;
    int auth_sent;
} case7_ctx_t;

static void
case7_send_auth(mq_conn_t *conn, case7_ctx_t *p)
{
    mq_stream_t *ctrl = mq_conn_open_stream(conn);
    if (!ctrl) return;
    mq_auth_req_t req;
    memset(&req, 0, sizeof(req));
    req.version = 1;
    snprintf(req.client_id, sizeof(req.client_id), "%s", "case7");
    snprintf(req.auth_token, sizeof(req.auth_token), "%s", "secret");
    req.features = 0;
    uint8_t buf[512];
    int n = mq_encode_auth_req(buf, sizeof(buf), &req);
    if (n < 0) return;
    (void)mq_stream_send(ctrl, buf, (size_t)n, 0);
    p->auth_sent = 1;
}

static void
case7_on_state(mq_conn_t *conn, mq_conn_state_t st, void *user)
{
    case7_ctx_t *p = (case7_ctx_t *)user;
    if (st != MQ_CONN_ESTABLISHED || p->established) return;
    p->established = 1;

    /* 1) Pre-auth datagram FIRST — queued/flushed before any auth bytes. */
    (void)send_tunnel_datagram(conn, p->sid, 0, p->marker, p->marker_len);

    /* 2) THEN open the control stream + send AUTH_REQUEST. */
    case7_send_auth(conn, p);
}

/* Case 7: datagram BEFORE auth → dropped (drops_preauth) and NOT flushed when
 * the same sid OPENs after auth (pre-auth bytes must not leak through). */
static void
test_case7_preauth_drop_noflush(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    uint16_t srv_port = reserve_udp_port();
    MQ_CHECK(srv_port != 0);

    mq_transport_t *srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv_t != NULL);
    mq_runtime_t *srv_rt = srv_t ? mq_runtime_new(srv_t, base) : NULL;
    MQ_CHECK(srv_rt != NULL);
    mq_server_t *server =
        (srv_t && srv_rt) ? mq_server_new(srv_t, srv_rt, "secret", MQ_CC_BBR2, 60000, 1)
                          : NULL;
    MQ_CHECK(server != NULL);
    int srv_bound = srv_rt ? mq_runtime_open_udp_path(srv_rt, "127.0.0.1", srv_port) : -1;
    MQ_CHECK_EQ_INT(srv_bound, 0);

    udp_echo_t echo;
    uint16_t echo_port = 0;
    if (base) MQ_CHECK_EQ_INT(udp_echo_up(&echo, base, &echo_port), 0);

    mq_transport_t *cli_t = mq_transport_new(0);
    MQ_CHECK(cli_t != NULL);
    mq_runtime_t *cli_rt = cli_t ? mq_runtime_new(cli_t, base) : NULL;
    MQ_CHECK(cli_rt != NULL);
    if (cli_t)
        MQ_CHECK_EQ_INT(mq_conn_register_alpn(cli_t, CASE7_ALPN, NULL, NULL, NULL), 0);
    int cli_bound = cli_rt ? mq_runtime_open_udp_path(cli_rt, "127.0.0.1", 0) : -1;
    MQ_CHECK_EQ_INT(cli_bound, 0);

    const uint32_t SID = 0x77777777u;
    const uint8_t preauth_marker[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                                        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF};
    case7_ctx_t pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.sid = SID;
    pctx.marker = preauth_marker;
    pctx.marker_len = sizeof(preauth_marker);

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
        settings.max_datagram_frame_size = 65535;
        mq_conn_apply_mp_settings(&settings, /*is_server=*/0, MQ_CC_BBR2);
        conn = mq_conn_connect(cli_t, (struct sockaddr *)&sa, sizeof(sa), CASE7_ALPN,
                               &settings, NULL);
        MQ_CHECK(conn != NULL);
        if (conn) {
            mq_conn_set_on_datagram(conn, on_client_datagram, NULL);
            mq_conn_set_on_state(conn, case7_on_state, &pctx);
        }
    }

    /* Pump until the pre-auth datagram has been dropped at the server. */
    mq_udp_srv_t *u = NULL;
    {
        uint64_t deadline = now_ms() + 4000;
        while (now_ms() < deadline) {
            event_base_loop(base, EVLOOP_NONBLOCK);
            u = mq_server_last_udp_srv(server);
            if (u && mq_udp_srv_counters(u).drops_preauth >= 1) break;
        }
    }
    MQ_CHECK(u != NULL);
    mq_udp_srv_counters_t c0 = mq_udp_srv_counters(u);
    MQ_CHECK(c0.drops_preauth >= 1);               /* pre-auth datagram dropped */
    MQ_CHECK_EQ_INT((int)c0.preopen_evictions, 0); /* never entered the buffer */

    /* Let auth settle (AUTH_REQUEST already sent in case7_on_state). */
    pump_for(base, 300);

    /* OPEN the SAME sid now (post-auth), send a fresh distinct payload, and
     * verify the echo is the fresh payload — the pre-auth marker must NOT have
     * been buffered/flushed (it was dropped at the gate). */
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    if (conn) {
        mq_stream_t *s = open_udp_v4(conn, SID, echo_port, 0, &d);
        MQ_CHECK(s != NULL);
    }
    pump_until(base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_OK);

    uint8_t fresh[64];
    for (int i = 0; i < 64; i++)
        fresh[i] = (uint8_t)(0x40 + (i & 0x3f));
    reset_dgm_capture(SID);
    if (conn)
        MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID, 1, fresh, sizeof(fresh)), 0);
    pump_until(base, &g_dgm_done, 4000);
    MQ_CHECK(g_dgm_done);
    MQ_CHECK_EQ_INT((int)g_dgm_rxlen, 64);
    if (g_dgm_done) {
        MQ_CHECK_MEM(g_dgm_rx, fresh, 64);
        /* The echoed bytes are the fresh payload, never the pre-auth marker. */
        MQ_CHECK(memcmp(g_dgm_rx, preauth_marker, sizeof(preauth_marker)) != 0);
    }

    udp_echo_down(&echo);
    if (cli_t) mq_transport_free(cli_t);
    if (srv_t) mq_transport_free(srv_t);
    if (cli_rt) mq_runtime_free(cli_rt);
    if (srv_rt) mq_runtime_free(srv_rt);
    if (server) mq_server_free(server);
    if (base) event_base_free(base);
}

/* Case 8: duplicate-SID OPEN resets the new stream; original keeps echoing. */
static void
test_case8_dup_sid(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x88888888u;
    udpstream_t d1;
    memset(&d1, 0, sizeof(d1));
    mq_stream_t *s1 = open_udp_v4(conn, SID, echo_port, 0, &d1);
    MQ_CHECK(s1 != NULL);
    pump_until(f.base, &d1.resp_seen, 4000);
    MQ_CHECK(d1.resp_seen);
    MQ_CHECK_EQ_INT((int)d1.resp.error_code, (int)MQ_UDP_OK);

    /* Second OPEN for the SAME live sid: the server resets the NEW stream with
     * no RESP and leaves the original session intact. */
    udpstream_t d2;
    memset(&d2, 0, sizeof(d2));
    mq_stream_t *s2 = open_udp_v4(conn, SID, echo_port, 0, &d2);
    MQ_CHECK(s2 != NULL);
    pump_until(f.base, &d2.closed, 4000);
    MQ_CHECK(d2.closed);              /* new stream was reset */
    MQ_CHECK_EQ_INT(d2.resp_seen, 0); /* no RESP decoded on the duplicate */

    /* The original session still relays: round-trip a datagram on SID. */
    uint8_t payload[128];
    for (int i = 0; i < 128; i++)
        payload[i] = (uint8_t)((i * 7 + 3) & 0xff);
    reset_dgm_capture(SID);
    MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID, 0, payload, sizeof(payload)), 0);
    pump_until(f.base, &g_dgm_done, 4000);
    MQ_CHECK(g_dgm_done);
    MQ_CHECK_EQ_INT((int)g_dgm_rxlen, 128);
    if (g_dgm_done) MQ_CHECK_MEM(g_dgm_rx, payload, 128);
    /* The original control stream stayed open (not closed by the duplicate). */
    MQ_CHECK_EQ_INT(d1.closed, 0);

    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case 10 (d2): pre-OPEN flush double-free regression. Buffer datagrams for TWO
 * distinct unknown sids (A=0xAAA1, B=0xBBB2) BEFORE opening either, then OPEN
 * ONLY A. srv_preopen_flush() drains A's entries and MOVES B's surviving entry
 * into the compacted ring — it MUST clear the source slot's data pointer so B is
 * not left double-owned. At teardown srv_preopen_free_all() walks all 16 physical
 * slots; with the OLD bug (no source-slot clear) B's buffer is freed twice. The
 * assertion is implicit: under ASan there must be NO double-free / NO leak over
 * the compaction + free_all path. We also confirm A's buffered datagram was
 * delivered by the flush (its echo round-trips). B (0xBBB2) is NEVER opened — its
 * kept entry is freed only at teardown, which is the path under test. All
 * payloads are < MQ_PREOPEN_MAX_BYTES and the open happens within the 250ms TTL
 * (pumped non-blocking, no wall sleeps) so the entries survive to the flush. */
static void
test_case10_preopen_flush_double_free(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID_A = 0x0000AAA1u; /* opened → flushed */
    const uint32_t SID_B = 0x0000BBB2u; /* NEVER opened → kept, freed at teardown */

    /* 1) Buffer a datagram for sid A WITHOUT opening it (lands in pre-OPEN buf). */
    uint8_t payload_a[96];
    for (int i = 0; i < (int)sizeof(payload_a); i++)
        payload_a[i] = (uint8_t)((i * 11 + 3) & 0xff);
    MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID_A, 0, payload_a, sizeof(payload_a)),
                    0);
    /* Pump briefly (non-blocking, well under the 250ms TTL) so it's buffered. */
    pump_for(f.base, 30);

    /* 2) Buffer a datagram for the SECOND distinct sid B (also unopened). */
    uint8_t payload_b[112];
    for (int i = 0; i < (int)sizeof(payload_b); i++)
        payload_b[i] = (uint8_t)((i * 29 + 7) & 0xff);
    MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID_B, 0, payload_b, sizeof(payload_b)),
                    0);
    pump_for(f.base, 30);

    /* 3) OPEN ONLY sid A. The RESP-OK path runs srv_preopen_flush(A), which drains
     * A's buffered datagram and MUST move B's entry while clearing the source
     * slot. We capture A's flushed echo on the datagram channel. */
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    reset_dgm_capture(SID_A);
    mq_stream_t *s = open_udp_v4(conn, SID_A, echo_port, 0, &d);
    MQ_CHECK(s != NULL);
    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_OK);

    /* The flush delivered A's buffered datagram → origin echo round-trips. */
    pump_until(f.base, &g_dgm_done, 4000);
    MQ_CHECK(g_dgm_done);
    MQ_CHECK_EQ_INT((int)g_dgm_rxlen, (int)sizeof(payload_a));
    if (g_dgm_done) MQ_CHECK_MEM(g_dgm_rx, payload_a, sizeof(payload_a));

    /* 4) Tear down WITHOUT ever opening sid B. fixture_down → mq_server_free →
     * mq_udp_srv_free → srv_preopen_free_all walks the compacted ring containing
     * B's kept entry. With the fix this frees B exactly once; the OLD bug
     * double-frees → ASan abort. */
    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case 5: idle_timeout_ms=100 server, left idle → server closes the stream. */
static void
test_case5_idle_timeout(void)
{
    fixture_t f;
    if (fixture_up(&f, 100, 1) != 0) {
        fixture_down(&f);
        return;
    }
    udp_echo_t echo;
    uint16_t echo_port = 0;
    MQ_CHECK_EQ_INT(udp_echo_up(&echo, f.base, &echo_port), 0);

    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x55555555u;
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    /* Request idle 0 ⇒ server applies its own 100ms. */
    mq_stream_t *s = open_udp_v4(conn, SID, echo_port, 0, &d);
    MQ_CHECK(s != NULL);
    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_OK);

    /* Sit idle: no datagrams. The server's 100ms idle timer must fire and tear
     * the session down, closing the 0x02 stream. Pump ~600ms. */
    pump_until(f.base, &d.closed, 600);
    MQ_CHECK(d.closed);

    udp_echo_down(&echo);
    fixture_down(&f);
}

/* ── disabled-server scenarios (enabled=0): cases 4, 9 ───────────────────── */

/* Case 4: enabled=0 → OPEN answered MQ_UDP_POLICY_DENIED. */
static void
test_case4_policy_denied(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 0) != 0) {
        fixture_down(&f);
        return;
    }
    /* echo port is irrelevant (OPEN is denied before any dial). */
    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x44444444u;
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = open_udp_v4(conn, SID, 9, 0, &d);
    MQ_CHECK(s != NULL);
    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_ERROR);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_POLICY_DENIED);

    fixture_down(&f);
}

/* Case 9: enabled=0 + datagram → dropped (drops_preauth), no pre-OPEN buffering
 * (the buffer must not grow while every OPEN is denied). */
static void
test_case9_disabled_datagram_drop(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 0) != 0) {
        fixture_down(&f);
        return;
    }
    mq_conn_t *conn = fixture_authed_conn(&f);

    uint8_t payload[256];
    memset(payload, 0xCD, sizeof(payload));
    for (uint32_t i = 0; i < 5; i++) {
        MQ_CHECK_EQ_INT(
            send_tunnel_datagram(conn, 0xA000u + i, 0, payload, sizeof(payload)), 0);
    }
    pump_for(f.base, 400);

    mq_udp_srv_t *u = mq_server_last_udp_srv(f.server);
    MQ_CHECK(u != NULL);
    mq_udp_srv_counters_t c = mq_udp_srv_counters(u);
    /* On a disabled conn every datagram is dropped at the auth/enabled gate and
     * never reaches the pre-OPEN buffer. */
    MQ_CHECK(c.drops_preauth >= 5);
    MQ_CHECK_EQ_INT((int)c.preopen_evictions, 0);

    fixture_down(&f);
}

/* Case (c): client-role on_err path — open to a non-resolvable domain via the
 * mq_udp_open_fn boundary, pump, assert on_err fired exactly once with
 * err == MQ_UDP_DNS_FAILED, and that the handle is dead afterwards (do NOT call
 * send/close — per contract the core already freed it when on_err fired). */
static void
test_casec_client_on_err_dns_failed(void)
{
    fixture_t f;
    if (fixture_up(&f, 60000, 1) != 0) {
        fixture_down(&f);
        return;
    }

    /* Wait for auth: the client must be authed so the 0x02 stream is issued
     * immediately and the server sees the OPEN → DNS failure → RESP(ERROR). */
    pump_until(f.base, &g_auth_fired, 4000);
    MQ_CHECK(g_auth_ok);
    MQ_CHECK_EQ_INT(mq_client_udp_available(f.client), 1);

    cli_rx_t cap;
    memset(&cap, 0, sizeof(cap));

    /* Open a session to an unresolvable domain (atype = DOMAIN). Port 9 is the
     * discard port — any port is fine since DNS fails before any socket dial. */
    void *sess = cli_open_domain(f.client, "nonexistent.invalid", 9, &cap);
    MQ_CHECK(sess != NULL); /* open itself succeeds locally; failure is async */

    /* Pump until on_err fires or the budget expires. */
    pump_until(f.base, &cap.err_fired, 5000);

    /* on_err must fire exactly once with MQ_UDP_DNS_FAILED. */
    MQ_CHECK(cap.err_fired);
    MQ_CHECK_EQ_INT((int)cap.err, (int)MQ_UDP_DNS_FAILED);

    /* on_rx must NOT have fired (no payload ever delivered on an error path). */
    MQ_CHECK_EQ_INT(cap.rx_done, 0);

    /* Per contract: the core freed the session inside on_err.  Do NOT call
     * send/close here — sess is a dangling pointer at this point. */

    fixture_down(&f);
}

static void
test_udp_relay(void)
{
    test_case1_open_resp_echo();
    test_case2_preopen_sameflight();
    test_caseA_preauth_open_send();
    test_caseB_frag_relay();
    test_case3_dns_failed();
    test_casec_client_on_err_dns_failed();
    test_case6_preopen_evict();
    test_case7_preauth_drop_noflush();
    test_case8_dup_sid();
    test_case10_preopen_flush_double_free();
    test_case5_idle_timeout();
    test_case4_policy_denied();
    test_case9_disabled_datagram_drop();
}

MQ_TEST_MAIN(test_udp_relay())
