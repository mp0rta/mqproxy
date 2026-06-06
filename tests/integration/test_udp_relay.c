// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_udp_relay.c — Task 5.3: server-side UDP relay full-path integration.
 *
 * Stands up a REAL mq_client + REAL mq_server over loopback in-process on a
 * shared libevent base (same harness shape as test_client_server.c), plus a
 * local UDP echo socket bound inside the test. The client side has no UDP
 * ingress yet, so the test assembles the 0x02 (UDP_SESSION) stream + DATAGRAM
 * frames DIRECTLY on the client's mq_conn using the Task 1/4 codecs — it does
 * not depend on any client-role UDP implementation (Chunk 6).
 *
 * Cases (design §2/§6/§9.2):
 *   1. OPEN → RESP OK → datagram round-trip byte-exact.
 *   2. OPEN + datagram in the SAME event-loop turn → delivered via the pre-OPEN
 *      buffer (xquic datagram-before-stream ordering regression — design §2).
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

/* ── datagram receive capture (server→tunnel echo lands here) ─────────────── */
static uint8_t g_dgm_rx[2048];
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

/* Authenticate the fixture's client + wire the client's datagram callback. */
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

/* ── default-server scenarios (enabled=1, idle=60s): cases 1,2,3,6,7,8 ───── */

/* Case 1: OPEN → RESP OK → datagram round-trip byte-exact. */
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

    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x11111111u;
    udpstream_t d;
    memset(&d, 0, sizeof(d));
    mq_stream_t *s = open_udp_v4(conn, SID, echo_port, 0, &d);
    MQ_CHECK(s != NULL);

    pump_until(f.base, &d.resp_seen, 4000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.status, (int)MQ_STATUS_OK);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_OK);

    /* Round-trip a patterned payload tunnel→target→tunnel. */
    uint8_t payload[512];
    for (int i = 0; i < 512; i++)
        payload[i] = (uint8_t)((i * 37 + 5) & 0xff);
    reset_dgm_capture(SID);
    MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID, 0, payload, sizeof(payload)), 0);

    pump_until(f.base, &g_dgm_done, 4000);
    MQ_CHECK(g_dgm_done);
    MQ_CHECK_EQ_INT((int)g_dgm_rxlen, 512);
    if (g_dgm_done) MQ_CHECK_MEM(g_dgm_rx, payload, 512);

    udp_echo_down(&echo);
    fixture_down(&f);
}

/* Case 2: OPEN + datagram in the SAME event-loop turn → pre-OPEN buffer path. */
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

    mq_conn_t *conn = fixture_authed_conn(&f);

    const uint32_t SID = 0x22222222u;
    udpstream_t d;
    memset(&d, 0, sizeof(d));

    uint8_t payload[300];
    for (int i = 0; i < 300; i++)
        payload[i] = (uint8_t)((i * 91 + 13) & 0xff);
    reset_dgm_capture(SID);

    /* SAME turn: open + OPEN-send AND the datagram, before any pump. The
     * datagram beats the stream at the server (xquic ordering, design §2), so
     * the relay must buffer it pre-OPEN and flush on session creation. */
    mq_stream_t *s = open_udp_v4(conn, SID, echo_port, 0, &d);
    MQ_CHECK(s != NULL);
    MQ_CHECK_EQ_INT(send_tunnel_datagram(conn, SID, 0, payload, sizeof(payload)), 0);

    /* The echo of the buffered datagram must come back byte-exact. */
    pump_until(f.base, &g_dgm_done, 5000);
    MQ_CHECK(d.resp_seen);
    MQ_CHECK_EQ_INT((int)d.resp.error_code, (int)MQ_UDP_OK);
    MQ_CHECK(g_dgm_done);
    MQ_CHECK_EQ_INT((int)g_dgm_rxlen, 300);
    if (g_dgm_done) MQ_CHECK_MEM(g_dgm_rx, payload, 300);

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

static void
test_udp_relay(void)
{
    test_case1_open_resp_echo();
    test_case2_preopen_sameflight();
    test_case3_dns_failed();
    test_case6_preopen_evict();
    test_case7_preauth_drop_noflush();
    test_case8_dup_sid();
    test_case5_idle_timeout();
    test_case4_policy_denied();
    test_case9_disabled_datagram_drop();
}

MQ_TEST_MAIN(test_udp_relay())
