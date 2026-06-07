// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_gw_reconnect.c — Task 5.2 (Phase 5b): in-process proof that the gateway
 * client reconnect path (Task 5.1) works END-TO-END.
 *
 * Same in-process H3-tunnel harness shape as the gateway-client cases in
 * test_gw_client.c: a fake gateway SERVER (server transport (TLS) + runtime +
 * mq_h3 with server hooks) and the CLIENT under test (client transport +
 * runtime + mq_h3 + mq_gw_client + a real mq_fetch_listener). A local "curl"
 * socket POSTs /_mqproxy/fetch; the gw_client bridges it onto an H3 request to
 * the server, which replies with a fixed download body.
 *
 * The DIFFERENCE from test_gw_client's fixture: here reconnect is ENABLED with a
 * SHORT max-backoff (1000ms — mq_gw_client floors it to 1000) so a deterministic
 * conn drop recovers fast.
 *
 * CONN-DROP MECHANISM: mq_gw_client exposes NO conn accessor and NO conn-close
 * path (auth is per-request; the conn is internal). So we drop the tunnel from
 * the SERVER side: srv_on_new_conn captures each accepted mq_h3_conn, and we call
 * mq_h3_conn_close() on it. That sends CONNECTION_CLOSE to the client, whose
 * gw_conn_state(established=0) fires → (reconnect on) arms the backoff timer →
 * the timer fires → gw_issue_connect re-dials the SAME still-up server fixture →
 * re-accept (a 2nd srv_on_new_conn). The same server port is re-dialed
 * (c->peer), and the server listener stays up across the drop, so recovery is
 * deterministic on loopback.
 *
 * RECONNECT-SUCCESS DETECTION: the gateway has NO connection-level auth event
 * (per-request auth), and conn_up is not observable from outside the gw_client.
 * We detect re-establishment two ways, both observable from the test's SERVER
 * side / the local socket:
 *   (a) the server's on_new_conn count goes to >= 2 (client re-dialed, server
 *       re-accepted) — proves the conn was re-established, not merely that the
 *       drop happened;
 *   (b) a NEW fetch issued after the drop COMPLETES end-to-end (status + body
 *       byte-exact). A fetch can only succeed on a live tunnel, so the end-to-end
 *       success IS the proof of backoff→re-establish→fresh-request-on-new-conn.
 *
 * Cases:
 *   1. Gateway reconnect end-to-end: baseline fetch → drop the tunnel from the
 *      server side → pump until re-established (server conn count >= 2) → a NEW
 *      fetch completes 200 + byte-exact body on the new conn. (Also validates the
 *      5.1 review concern: per-conn-close in-flight reaping didn't corrupt state.)
 *   2. Shutdown while reconnecting (ASan): drop the conn, and DURING the backoff
 *      window (before reconnect completes) call mq_gw_client_free → no crash, no
 *      late reconnect, leak/UAF-free under ASan.
 */
#include "mqtest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
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

/* Short reconnect max-backoff. mq_gw_client floors it to 1000ms (anti
 * busy-spin), so 1000 is the smallest deterministic value. */
#define RECONNECT_MAX_BACKOFF_MS 1000
/* Generous per-cycle budget: backoff (<=1s) + handshake on loopback. */
#define RECONNECT_BUDGET_MS 8000

/* ── time / port helpers (mirror test_gw_client.c) ──────────────────────────*/
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

static void
pump_a_bit(struct event_base *base, uint64_t budget_ms)
{
    uint64_t deadline = now_ms() + budget_ms;
    while (now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
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

/* ── fake gateway server (H3) — minimal: 200 + content-length + body ────────*/
#define SRV_MAX_HDRS 32
#define SRV_HDR_LEN  512

typedef struct {
    char name[SRV_HDR_LEN];
    char value[SRV_HDR_LEN];
} srv_hdr_t;

typedef struct {
    mq_h3_req_t *req;
    int got_headers;
    int saw_fin;

    srv_hdr_t hdrs[SRV_MAX_HDRS];
    int n_hdrs;

    uint8_t body[64 * 1024];
    size_t body_len;

    int responded;

    /* response send state. */
    const uint8_t *snd;
    size_t snd_total;
    size_t snd_off;
    int snd_fin_done;

    int request_count; /* on_new_req count */
} gw_srv_t;

static gw_srv_t g_srv;

/* Reconnect-success signals observable from the server side. */
static mq_h3_conn_t *g_srv_conn; /* most-recent accepted tunnel conn */
static int g_srv_conn_count;     /* on_new_conn count (>=2 ⇒ client re-dialed) */

static const uint8_t *g_dl_body;
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

static void
srv_body_pump(gw_srv_t *s)
{
    if (!s->req || s->snd_fin_done) return;
    while (s->snd_off < s->snd_total) {
        long acc = mq_h3_req_send_body(s->req, s->snd + s->snd_off,
                                       s->snd_total - s->snd_off, 1);
        if (acc <= 0) return;
        s->snd_off += (size_t)acc;
        if (s->snd_off >= s->snd_total) {
            s->snd_fin_done = 1;
            return;
        }
    }
    if (s->snd_total == 0) {
        mq_h3_req_finish(s->req);
        s->snd_fin_done = 1;
    }
}

static void
srv_respond(gw_srv_t *s)
{
    if (s->responded || !s->req) return;
    s->responded = 1;
    char cl[32];
    snprintf(cl, sizeof(cl), "%zu", g_dl_body_len);
    mq_h3_header_t h[] = {{":status", "200"}, {"content-length", cl}};
    mq_h3_req_send_headers(s->req, h, 2, 0);
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
    if (s->saw_fin && !s->responded) srv_respond(s);
}

static void
srv_on_req_write(mq_h3_req_t *r, void *user)
{
    (void)r;
    gw_srv_t *s = (gw_srv_t *)user;
    if (!s->responded) return;
    srv_body_pump(s);
}

static void
srv_on_req_close(mq_h3_req_t *r, void *user)
{
    (void)r;
    gw_srv_t *s = (gw_srv_t *)user;
    s->req = NULL;
}

/* Reset the per-request state for the NEXT request (a reconnect re-dials a fresh
 * conn; the next fetch is a fresh H3 request whose headers/body we re-capture). */
static void
srv_reset_req_state(gw_srv_t *s)
{
    s->req = NULL;
    s->got_headers = 0;
    s->saw_fin = 0;
    s->n_hdrs = 0;
    s->body_len = 0;
    s->responded = 0;
    s->snd = NULL;
    s->snd_total = 0;
    s->snd_off = 0;
    s->snd_fin_done = 0;
}

static void
srv_on_new_req(mq_h3_req_t *r, void *user)
{
    (void)user;
    srv_reset_req_state(&g_srv); /* fresh request: clear per-request capture */
    g_srv.request_count++;
    g_srv.req = r;
    mq_h3_req_set_cbs(r, srv_on_req_read, srv_on_req_write, srv_on_req_close, &g_srv);
}

static void
srv_on_new_conn(mq_h3_conn_t *c, void *user)
{
    (void)user;
    g_srv_conn = c; /* capture so the test can drop the tunnel from the server side */
    g_srv_conn_count++;
}

/* ── gateway-client fixture (RECONNECT ENABLED) ─────────────────────────────*/
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

/* Full fixture constructor: parameterizes reconnect_enabled + keepalive_idle_ms
 * so the terminal-path (reconnect off) and keepalive-setter (idle > 0) coverage
 * cases can stand up the matching client. gw_fixture_up wraps this with the
 * default (reconnect on, keepalive 0). */
static int
gw_fixture_up_ex(gw_fixture_t *f, const char *token, int reconnect_enabled,
                 uint64_t keepalive_idle_ms)
{
    memset(f, 0, sizeof(*f));
    memset(&g_srv, 0, sizeof(g_srv));
    g_srv_conn = NULL;
    g_srv_conn_count = 0;

    f->base = event_base_new();
    if (!f->base) return -1;

    uint16_t srv_port = reserve_udp_port();
    if (!srv_port) return -1;

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

    f->cli_t = mq_transport_new(0);
    if (!f->cli_t) return -1;
    f->cli_rt = mq_runtime_new(f->cli_t, f->base);
    if (!f->cli_rt) return -1;
    if (mq_runtime_open_udp_path(f->cli_rt, "127.0.0.1", 0) != 0) return -1;
    f->cli_h3 = mq_h3_init(f->cli_t, NULL, NULL, NULL);
    if (!f->cli_h3) return -1;

    /* RECONNECT ENABLED with a short max-backoff for fast recovery (the whole
     * point of this test; test_gw_client builds the same fixture with reconnect
     * DISABLED). */
    f->gw = mq_gw_client_new(f->cli_t, f->cli_rt, f->cli_h3, "127.0.0.1", srv_port, token,
                             MQ_CC_BBR2, keepalive_idle_ms, reconnect_enabled,
                             /*reconnect_max_backoff_ms=*/RECONNECT_MAX_BACKOFF_MS);
    if (!f->gw) return -1;

    f->listener = mq_fetch_listener_new(f->base, "127.0.0.1", 0, mq_gw_client_fetch_cbs(),
                                        mq_gw_client_fetch_user(f->gw));
    if (!f->listener) return -1;
    f->lport = mq_fetch_listener_port(f->listener);
    if (!f->lport) return -1;

    /* Settle: let the eager tunnel conn establish on loopback. */
    pump_a_bit(f->base, 300);
    return 0;
}

/* Default fixture: reconnect ENABLED, keepalive OFF (the original behavior). */
static int
gw_fixture_up(gw_fixture_t *f, const char *token)
{
    return gw_fixture_up_ex(f, token, /*reconnect_enabled=*/1, /*keepalive_idle_ms=*/0);
}

static void
gw_fixture_down(gw_fixture_t *f)
{
    /* SANCTIONED TEARDOWN ORDER (mq_gw_client.h): gw_client_free FIRST while the
     * client H3 engine is still live, THEN mq_h3_free, THEN transport_free.
     *
     * NB: this order is exactly what revert-proves the late-callback UAF guard in
     * mq_gw_client_free (the mq_h3_conn_set_state_cb(NULL) detach). Whenever a case
     * ends with a LIVE tunnel conn (e.g. case 1), freeing the gw_client here while
     * the conn is still alive orphans it; the subsequent mq_h3_free engine teardown
     * delivers a late conn-close into gw_conn_state. The detach makes that a no-op;
     * removing it makes this teardown ASan-abort (heap-use-after-free at the
     * gw_conn_state CLOSED branch reading the freed cli). So the gateway detach is
     * load-bearing and exercised by the existing cases — no dedicated case needed
     * (cf. test_client_reconnect case 9, which must INVERT its fixture order because
     * mq_client's fixture_down frees the transport before the client). */
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

/* Locate the response body start (offset after the head terminator). */
static size_t
head_end(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++)
        if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n')
            return i + 4;
    return (size_t)-1;
}

/* Issue one fetch through the gateway, reading the full reply to EOF. */
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

/* Run one GET fetch and assert 200 + byte-exact download body. Returns 0 on a
 * fully successful end-to-end fetch, -1 otherwise. */
static int
run_fetch_ok(gw_fixture_t *f, const char *path, const uint8_t *dl, size_t dl_len)
{
    g_dl_body = dl;
    g_dl_body_len = dl_len;

    char req[256];
    int rn = snprintf(req, sizeof(req),
                      "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test%s\r\n"
                      "Content-Length: 0\r\n\r\n",
                      path);
    MQ_CHECK(rn > 0 && (size_t)rn < sizeof(req));

    uint8_t reply[4096] = {0};
    size_t got =
        fetch_roundtrip(f->base, f->lport, req, (size_t)rn, reply, sizeof(reply), 6000);

    MQ_CHECK(got > 0);
    if (got < 12 || memcmp(reply, "HTTP/1.1 200", 12) != 0) return -1;

    size_t hs = head_end(reply, got);
    MQ_CHECK(hs != (size_t)-1);
    if (hs == (size_t)-1) return -1;
    if (got - hs != dl_len) {
        MQ_CHECK_EQ_INT((int)(got - hs), (int)dl_len);
        return -1;
    }
    if (memcmp(reply + hs, dl, dl_len) != 0) {
        MQ_CHECK(0);
        return -1;
    }
    MQ_CHECK(contains(reply, got, (const char *)dl));
    return 0;
}

/* Drop the tunnel conn from the SERVER side and pump until the client has
 * re-established (server accepted a NEW conn — on_new_conn count grew). Returns 1
 * on re-establishment, 0 on timeout. */
static int
drop_and_await_reconnect(gw_fixture_t *f, uint64_t budget_ms)
{
    int before = g_srv_conn_count;
    MQ_CHECK(g_srv_conn != NULL);
    if (!g_srv_conn) return 0;
    mq_h3_conn_close(g_srv_conn);
    g_srv_conn = NULL; /* freed after its close-notify; re-set on the next accept */

    uint64_t deadline = now_ms() + budget_ms;
    while (g_srv_conn_count <= before && now_ms() < deadline) {
        event_base_loop(f->base, EVLOOP_NONBLOCK);
    }
    return g_srv_conn_count > before;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 1: gateway reconnect end-to-end.
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case1_gw_reconnect(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    /* Baseline fetch over the eagerly-established tunnel. */
    static const uint8_t DL1[] = "baseline-download-body-0123456789";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/file1", DL1, sizeof(DL1) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv.request_count, 1);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1); /* one tunnel conn so far */

    /* Drop the tunnel from the server side; pump until the client re-establishes
     * (server accepts a 2nd conn). This exercises conn-loss → backoff →
     * re-establish, and the per-conn-close in-flight reaping (no live request at
     * the drop here, but the reconnect path must not corrupt conn state). */
    MQ_CHECK_EQ_INT(drop_and_await_reconnect(&f, RECONNECT_BUDGET_MS), 1);
    MQ_CHECK(g_srv_conn_count >= 2);

    /* A NEW fetch must complete end-to-end on the reconnected conn (status + body
     * byte-exact). This is the real assertion: a fetch can ONLY succeed on a live
     * re-established tunnel, so success proves backoff→re-establish→fresh request
     * on the new conn AND that the reaping/teardown left conn state intact. */
    static const uint8_t DL2[] = "post-reconnect-body-abcdefghijklmnop";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/file2", DL2, sizeof(DL2) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv.request_count, 2); /* server saw the 2nd fetch */

    /* Drop + recover once more, then a third fetch — proves repeated cycles work
     * (backoff counter reset on establish; not a one-shot). */
    MQ_CHECK_EQ_INT(drop_and_await_reconnect(&f, RECONNECT_BUDGET_MS), 1);
    MQ_CHECK(g_srv_conn_count >= 3);
    static const uint8_t DL3[] = "third-cycle-body-QRSTUVWXYZ";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/file3", DL3, sizeof(DL3) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv.request_count, 3);

    gw_fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 2: shutdown while reconnecting — mq_gw_client_free DURING the backoff
 *         window. No crash, no late reconnect, leak/UAF-free (ASan).
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case2_free_while_reconnecting(void)
{
    gw_fixture_t f;
    if (gw_fixture_up(&f, "sekrit") != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    /* Establish a baseline so there is a live tunnel conn to drop. */
    static const uint8_t DL[] = "before-shutdown-body";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/x", DL, sizeof(DL) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1);

    /* Drop the tunnel and pump JUST enough to register the close + arm the backoff
     * timer, WITHOUT pumping long enough to reconnect. The "1000ms" knob is the
     * MAX-backoff cap, not the first delay: the actual first-attempt delay is
     * mq_backoff_ms(250, cap, attempt=1)=500ms jittered to [250,500]ms, so the
     * real minimum before the timer can fire is ~250ms. We pump ~150ms — under
     * that ~250ms minimum — so gw_conn_state(closed) has fired and armed backoff
     * but the re-dial has NOT yet happened (margin ~100ms, robust on loopback;
     * ASan leak/UAF-freeness, not this timing, is the case's primary assertion). */
    MQ_CHECK(g_srv_conn != NULL);
    mq_h3_conn_close(g_srv_conn);
    g_srv_conn = NULL;
    int conn_count_at_drop = g_srv_conn_count;
    pump_a_bit(f.base, 150);
    /* Still in the backoff window: the client must NOT have re-established yet. */
    MQ_CHECK_EQ_INT(g_srv_conn_count, conn_count_at_drop); /* no reconnect yet */

    /* Free the gw_client mid-reconnect. mq_gw_client_free sets shutting_down first
     * and disarms/frees the backoff timer, so no reconnect fires after free. The
     * SANCTIONED TEARDOWN ORDER is honored (gw_client_free FIRST while h3 is live).
     * Free it here, then NULL it so gw_fixture_down does not double-free. */
    mq_gw_client_free(f.gw);
    f.gw = NULL;

    /* Pump well past the backoff window: NO reconnect must occur (server must NOT
     * accept a new conn) and no crash / UAF (caught by ASan). */
    pump_a_bit(f.base, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_srv_conn_count, conn_count_at_drop); /* no late reconnect */

    gw_fixture_down(&f); /* gw already freed; frees the rest cleanly */
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 3: terminal path — reconnect DISABLED. Drop the tunnel from the server
 *         side; the client must NOT reconnect (server on_new_conn stays at 1) and
 *         a subsequent fetch must FAIL (tunnel is terminal-dead). Exercises
 *         gw_conn_state's terminal else branch (reconnect off).
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case3_terminal_no_reconnect(void)
{
    gw_fixture_t f;
    if (gw_fixture_up_ex(&f, "sekrit", /*reconnect_enabled=*/0,
                         /*keepalive_idle_ms=*/0) != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    /* Baseline fetch over the eager tunnel. */
    static const uint8_t DL[] = "terminal-baseline-body";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/file1", DL, sizeof(DL) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1);

    /* Drop the tunnel from the server side. With reconnect DISABLED the client
     * takes gw_conn_state's terminal else branch: conn NULLed, NO backoff armed. */
    MQ_CHECK(g_srv_conn != NULL);
    mq_h3_conn_close(g_srv_conn);
    g_srv_conn = NULL;

    /* Pump well past any backoff window: the client must NOT re-establish. The
     * server must NOT accept a 2nd conn (terminal, not reconnecting). */
    pump_a_bit(f.base, RECONNECT_BUDGET_MS);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1); /* no reconnect — terminal */

    /* A subsequent fetch must FAIL: the tunnel is terminal-dead, so it cannot
     * complete with a 200. (Use a quiet round-trip, not run_fetch_ok, whose
     * MQ_CHECKs would count a failed fetch as a test failure.) The gateway maps a
     * dead tunnel to a non-2xx reply (e.g. 502/504) or a closed connection — in
     * all cases NOT "HTTP/1.1 200". */
    static const uint8_t DL2[] = "should-not-arrive";
    g_dl_body = DL2;
    g_dl_body_len = sizeof(DL2) - 1;
    char req[256];
    int rn = snprintf(req, sizeof(req),
                      "POST /_mqproxy/fetch HTTP/1.1\r\n"
                      "Host: x\r\n"
                      "X-Mq-Auth: Bearer sekrit\r\n"
                      "X-Mq-Target: https://example.test/file2\r\n"
                      "Content-Length: 0\r\n\r\n");
    MQ_CHECK(rn > 0 && (size_t)rn < sizeof(req));
    uint8_t reply[4096] = {0};
    size_t got =
        fetch_roundtrip(f.base, f.lport, req, (size_t)rn, reply, sizeof(reply), 6000);
    /* Must NOT be a 200 + download body. Either no reply, or a non-2xx status. */
    int is_200 = (got >= 12 && memcmp(reply, "HTTP/1.1 200", 12) == 0);
    MQ_CHECK_EQ_INT(is_200, 0);
    MQ_CHECK_EQ_INT(g_srv.request_count, 1); /* server never saw a 2nd request */
    /* Still no reconnect: the failed fetch must not have re-dialed the server. */
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1);

    gw_fixture_down(&f);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Case 4: keepalive non-zero wire-up. A gw client built with keepalive_idle_ms
 *         > 0 makes mq_h3_connect take the idle_time_out setter branch. Establish
 *         + fetch, idle ~1500ms (< the 4000ms idle) while pumping, then a second
 *         fetch still succeeds (conn held open across a sub-timeout idle). The
 *         primary goal is exercising the L545 idle_time_out setter in
 *         mq_h3_connect; the conn-survives assertion is the observable proof.
 * ════════════════════════════════════════════════════════════════════════ */
static void
test_case4_keepalive_wireup(void)
{
    gw_fixture_t f;
    if (gw_fixture_up_ex(&f, "sekrit", /*reconnect_enabled=*/1,
                         /*keepalive_idle_ms=*/4000) != 0) {
        gw_fixture_down(&f);
        MQ_CHECK(0);
        return;
    }

    /* Baseline fetch over the eager tunnel (keepalive idle = 4000ms). */
    static const uint8_t DL1[] = "keepalive-first-body-0123456789";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/k1", DL1, sizeof(DL1) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1);

    /* Idle ~1500ms (< 4000ms idle) with no fetch traffic, pumping the loop. The
     * conn must stay up (not idle-closed) and not reconnect. */
    pump_a_bit(f.base, 1500);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1); /* no drop+reconnect during the idle */

    /* A second fetch still succeeds on the same held-open conn. */
    static const uint8_t DL2[] = "keepalive-second-body-abcdefghij";
    MQ_CHECK_EQ_INT(run_fetch_ok(&f, "/k2", DL2, sizeof(DL2) - 1), 0);
    MQ_CHECK_EQ_INT(g_srv_conn_count, 1); /* same conn, no reconnect */
    MQ_CHECK_EQ_INT(g_srv.request_count, 2);

    gw_fixture_down(&f);
}

static void
run_all(void)
{
    /* A torn-down local socket write can raise SIGPIPE; ignore it. */
    signal(SIGPIPE, SIG_IGN);
    test_case1_gw_reconnect();
    test_case2_free_while_reconnecting();
    test_case3_terminal_no_reconnect();
    test_case4_keepalive_wireup();
}

MQ_TEST_MAIN(run_all())
