// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_datagram_fabric.c — Task 3.2: QUIC DATAGRAM API round-trip validation.
 *
 * Uses the same in-process loopback harness as test_conn_handshake.c
 * (shared libevent base, two mq_transport+mq_runtime pairs, real UDP sockets
 * on 127.0.0.1). Both sides negotiate max_datagram_frame_size=65535 so
 * datagrams are available after handshake.
 *
 * Cases verified:
 *   1. mq_conn_datagram_mss > 0 on both client and server after handshake.
 *   2. Byte-exact round-trip: client→server and server→client, each a
 *      1024-byte patterned payload. Data is copied in on_datagram (xquic owns
 *      the pointer only during the callback).
 *   3. mss+1 byte send returns -1 immediately (TOO_LARGE → drop).
 *   4. EAGAIN recovery: flood the client send queue (20 × 1024 B) without
 *      pumping, then pump to drain, then verify the connection is still usable
 *      via a server→client follow-on datagram.  If -1 is never hit (xquic's
 *      dgram queue appears unbounded with retx disabled), the test logs the
 *      finding and asserts the follow-on send+arrival anyway.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>
#include <xquic/xquic.h>

#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_transport.h"

#define TEST_ALPN "mqproxy-tcp/1"

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

/* Patterned payload size for cases 2 and 4. */
#define DGM_PAYLOAD_LEN 1024

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Reserve an ephemeral loopback UDP port (same trick as test_conn_handshake). */
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

/* ── shared test state ────────────────────────────────────────────────────── */

static int g_client_established;

/* Server-side conn handle (wired in on_server_conn so we can call send on it). */
static mq_conn_t *g_server_conn;

/* Case 2: bidirectional datagram receive buffers. */
static uint8_t g_srv_rx_buf[DGM_PAYLOAD_LEN];
static size_t g_srv_rx_len;
static int g_srv_rx_done; /* 1 once DGM_PAYLOAD_LEN bytes accumulated */

static uint8_t g_cli_rx_buf[DGM_PAYLOAD_LEN];
static size_t g_cli_rx_len;
static int g_cli_rx_done;

/* Case 4 follow-on receive.  g_cli_rx4_armed is set to 1 by the test body just
 * before the follow-on send; the callback only captures into the case4 buffer
 * when it is armed, avoiding false triggers from the earlier datagram flood. */
static uint8_t g_cli_rx4_buf[DGM_PAYLOAD_LEN];
static size_t g_cli_rx4_len;
static int g_cli_rx4_done;
static int g_cli_rx4_armed; /* set by test body before follow-on send */

/* ── datagram callbacks ───────────────────────────────────────────────────── */

/* Server receives a datagram from the client (case 2). */
static void
on_server_datagram(mq_conn_t *c, const uint8_t *data, size_t len, void *user)
{
    (void)c;
    (void)user;
    if (!g_srv_rx_done && len <= DGM_PAYLOAD_LEN) {
        /* Accumulate up to DGM_PAYLOAD_LEN bytes (a single datagram is always
         * <= mss, so this fires exactly once for the one send in case 2). */
        size_t copy = len;
        if (copy > DGM_PAYLOAD_LEN - g_srv_rx_len) copy = DGM_PAYLOAD_LEN - g_srv_rx_len;
        memcpy(g_srv_rx_buf + g_srv_rx_len, data, copy);
        g_srv_rx_len += copy;
        if (g_srv_rx_len >= DGM_PAYLOAD_LEN) g_srv_rx_done = 1;
    }
}

/* Client receives a datagram from the server (case 2 and case 4). */
static void
on_client_datagram(mq_conn_t *c, const uint8_t *data, size_t len, void *user)
{
    (void)c;
    (void)user;
    if (!g_cli_rx_done && len <= DGM_PAYLOAD_LEN) {
        size_t copy = len;
        if (copy > DGM_PAYLOAD_LEN - g_cli_rx_len) copy = DGM_PAYLOAD_LEN - g_cli_rx_len;
        memcpy(g_cli_rx_buf + g_cli_rx_len, data, copy);
        g_cli_rx_len += copy;
        if (g_cli_rx_len >= DGM_PAYLOAD_LEN) g_cli_rx_done = 1;
    } else if (g_cli_rx4_armed && !g_cli_rx4_done && len <= DGM_PAYLOAD_LEN) {
        /* Case 4 follow-on datagram: only captured when the test body has armed
         * us (g_cli_rx4_armed == 1), i.e. after the flood has been flushed. */
        size_t copy = len;
        if (copy > DGM_PAYLOAD_LEN - g_cli_rx4_len)
            copy = DGM_PAYLOAD_LEN - g_cli_rx4_len;
        memcpy(g_cli_rx4_buf + g_cli_rx4_len, data, copy);
        g_cli_rx4_len += copy;
        if (g_cli_rx4_len >= DGM_PAYLOAD_LEN) g_cli_rx4_done = 1;
    }
}

static void
on_client_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    (void)user;
    if (st == MQ_CONN_ESTABLISHED) g_client_established = 1;
}

/* Server accepted connection: save it and wire the datagram callback. */
static void
on_server_conn(mq_conn_t *c, void *user)
{
    (void)user;
    g_server_conn = c;
    mq_conn_set_on_datagram(c, on_server_datagram, NULL);
}

/* ── test body ────────────────────────────────────────────────────────────── */

static void
test_datagram_fabric(void)
{
    struct event_base *base = event_base_new();
    MQ_CHECK(base != NULL);
    if (!base) return;

    uint16_t srv_port = reserve_udp_port();
    MQ_CHECK(srv_port != 0);

    /* ── Server transport + runtime ── */
    mq_transport_t *srv_t = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(srv_t != NULL);
    mq_runtime_t *srv_rt = srv_t ? mq_runtime_new(srv_t, base) : NULL;
    MQ_CHECK(srv_rt != NULL);

    /* Register ALPN on the server; on_server_conn is called when a new conn is
     * accepted — we wire the datagram callback there. */
    int rc =
        srv_t ? mq_conn_register_alpn(srv_t, TEST_ALPN, on_server_conn, NULL, NULL) : -1;
    MQ_CHECK_EQ_INT(rc, 0);

    /* Server must advertise max_datagram_frame_size so xquic will accept and send
     * DATAGRAM frames on accepted conns. */
    {
        xqc_conn_settings_t srv_settings;
        memset(&srv_settings, 0, sizeof(srv_settings));
        srv_settings.proto_version = XQC_VERSION_V1;
        srv_settings.pacing_on = 1;
        srv_settings.max_pkt_out_size = 1200;
        srv_settings.max_datagram_frame_size = 65535;
        xqc_server_set_conn_settings(mq_transport_xqc(srv_t), &srv_settings);
    }

    int srv_bound = srv_rt ? mq_runtime_open_udp_path(srv_rt, "127.0.0.1", srv_port) : -1;
    MQ_CHECK_EQ_INT(srv_bound, 0);

    /* ── Client transport + runtime (SAME shared base) ── */
    mq_transport_t *cli_t = mq_transport_new(/*is_server=*/0);
    MQ_CHECK(cli_t != NULL);
    mq_runtime_t *cli_rt = cli_t ? mq_runtime_new(cli_t, base) : NULL;
    MQ_CHECK(cli_rt != NULL);

    rc = cli_t ? mq_conn_register_alpn(cli_t, TEST_ALPN, NULL, NULL, NULL) : -1;
    MQ_CHECK_EQ_INT(rc, 0);

    int cli_bound = cli_rt ? mq_runtime_open_udp_path(cli_rt, "127.0.0.1", 0) : -1;
    MQ_CHECK_EQ_INT(cli_bound, 0);

    if (!srv_t || !srv_rt || !cli_t || !cli_rt || srv_bound != 0 || cli_bound != 0) {
        goto cleanup;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port = htons(srv_port);

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;
    /* Enable QUIC DATAGRAM: both sides must set max_datagram_frame_size. */
    settings.max_datagram_frame_size = 65535;

    mq_conn_t *conn = mq_conn_connect(cli_t, (struct sockaddr *)&srv_addr,
                                      sizeof(srv_addr), TEST_ALPN, &settings, NULL);
    MQ_CHECK(conn != NULL);
    if (!conn) goto cleanup;

    mq_conn_set_on_state(conn, on_client_state, NULL);
    /* Wire the client's datagram receive callback before the handshake completes
     * (datagrams cannot arrive before ESTABLISHED, but pre-wiring is safe). */
    mq_conn_set_on_datagram(conn, on_client_datagram, NULL);

    /* ── Handshake ── */
    uint64_t deadline = now_ms() + 3000;
    while (!g_client_established && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
    MQ_CHECK(g_client_established);
    MQ_CHECK(g_server_conn != NULL);
    if (!g_client_established || !g_server_conn) goto cleanup;

    /* Give the handshake one more pump round so xquic finishes internalising the
     * peer's transport parameters (max_datagram_frame_size) before we query mss. */
    uint64_t settle = now_ms() + 200;
    while (now_ms() < settle)
        event_base_loop(base, EVLOOP_NONBLOCK);

    /* ── Case 1: mss > 0 on both sides ── */
    size_t cli_mss = mq_conn_datagram_mss(conn);
    size_t srv_mss = mq_conn_datagram_mss(g_server_conn);
    if (cli_mss == 0 || srv_mss == 0) {
        fprintf(stderr,
                "case1: mss==0 (cli_mss=%zu srv_mss=%zu) — "
                "peer transport params may not have propagated yet; "
                "pumping an extra 500 ms before asserting.\n",
                cli_mss, srv_mss);
        /* Re-sample after a short extra pump. */
        settle = now_ms() + 500;
        while (now_ms() < settle)
            event_base_loop(base, EVLOOP_NONBLOCK);
        cli_mss = mq_conn_datagram_mss(conn);
        srv_mss = mq_conn_datagram_mss(g_server_conn);
    }
    MQ_CHECK(cli_mss > 0);
    MQ_CHECK(srv_mss > 0);
    fprintf(stderr, "case1: cli_mss=%zu srv_mss=%zu\n", cli_mss, srv_mss);
    if (cli_mss == 0 || srv_mss == 0) goto cleanup;

    /* ── Case 2: byte-exact bidirectional datagram round-trip ── */

    /* Build patterned payloads. */
    uint8_t c2s_payload[DGM_PAYLOAD_LEN]; /* client → server */
    uint8_t s2c_payload[DGM_PAYLOAD_LEN]; /* server → client */
    for (int i = 0; i < DGM_PAYLOAD_LEN; i++) {
        c2s_payload[i] = (uint8_t)((i * 53 + 17) & 0xff);
        s2c_payload[i] = (uint8_t)((i * 97 + 31) & 0xff);
    }

    /* Send client→server and server→client (both before pumping, to keep the
     * test simple — datagrams are unordered, order of sends doesn't matter). */
    rc = mq_conn_datagram_send(conn, c2s_payload, DGM_PAYLOAD_LEN);
    MQ_CHECK_EQ_INT(rc, 0);
    rc = mq_conn_datagram_send(g_server_conn, s2c_payload, DGM_PAYLOAD_LEN);
    MQ_CHECK_EQ_INT(rc, 0);

    /* Pump until both sides have received, or 2s budget expires. */
    deadline = now_ms() + 2000;
    while ((!g_srv_rx_done || !g_cli_rx_done) && now_ms() < deadline) {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }

    MQ_CHECK(g_srv_rx_done);
    MQ_CHECK(g_cli_rx_done);

    if (g_srv_rx_done) {
        MQ_CHECK_EQ_INT((int)g_srv_rx_len, DGM_PAYLOAD_LEN);
        MQ_CHECK_MEM(g_srv_rx_buf, c2s_payload, DGM_PAYLOAD_LEN);
    }
    if (g_cli_rx_done) {
        MQ_CHECK_EQ_INT((int)g_cli_rx_len, DGM_PAYLOAD_LEN);
        MQ_CHECK_MEM(g_cli_rx_buf, s2c_payload, DGM_PAYLOAD_LEN);
    }
    fprintf(stderr, "case2: srv_rx=%zu cli_rx=%zu\n", g_srv_rx_len, g_cli_rx_len);

    /* ── Case 3: mss+1 send returns -1 immediately ── */
    {
        size_t oversized = cli_mss + 1;
        uint8_t *big = (uint8_t *)malloc(oversized);
        MQ_CHECK(big != NULL);
        if (big) {
            memset(big, 0xCC, oversized);
            int r3 = mq_conn_datagram_send(conn, big, oversized);
            MQ_CHECK_EQ_INT(r3, -1);
            free(big);
            fprintf(stderr, "case3: mss+1=%zu send returned %d (expect -1)\n", oversized,
                    r3);
        }
    }

    /* ── Case 4: EAGAIN recovery ──────────────────────────────────────────────
     *
     * Flood the CLIENT send queue without pumping the event loop, then pump to
     * drain, then verify the connection is still healthy via a server→client
     * send (received by on_client_datagram).
     *
     * Empirical finding: xquic's dgram send-queue appears effectively unbounded
     * with retx disabled on loopback; all sends consistently return 0 regardless
     * of flood size (no EAGAIN observed).  The flood size is capped at 20 × 1024 B
     * so the queue drains within the 2 s flush window.
     */
    {
        const int MAX_TIGHT = 20;
        uint8_t c4_payload[DGM_PAYLOAD_LEN];
        for (int i = 0; i < DGM_PAYLOAD_LEN; i++)
            c4_payload[i] = (uint8_t)((i * 73 + 41) & 0xff);

        int first_neg = -1; /* index where -1 first occurred, -1 = never */
        for (int i = 0; i < MAX_TIGHT; i++) {
            int r = mq_conn_datagram_send(conn, c4_payload, DGM_PAYLOAD_LEN);
            if (r == -1) {
                first_neg = i;
                break;
            }
        }
        fprintf(stderr,
                "case4: tight-loop send result: %s (first_neg=%d out of max %d)\n",
                first_neg == -1 ? "never hit -1 (queue absorbed all)" : "hit -1",
                first_neg, MAX_TIGHT);

        /* Pump briefly to let the flood flush through (≤200 ms settle).
         * We break early once the follow-on send path is clear; the real
         * health signal is the condition-based arrival wait below. */
        uint64_t flush_deadline = now_ms() + 200;
        while (now_ms() < flush_deadline)
            event_base_loop(base, EVLOOP_NONBLOCK);

        /* Follow-on: SERVER sends one datagram to the CLIENT.  This exercises
         * the server→client path and provides a clean signal at the client via
         * on_client_datagram.  Arm the case4 capture window BEFORE the send so
         * we don't capture any stray case-2 retries (case2 g_cli_rx_done is
         * already 1, so new server→client datagrams land in the armed branch). */
        uint8_t c4b_payload[DGM_PAYLOAD_LEN];
        for (int i = 0; i < DGM_PAYLOAD_LEN; i++)
            c4b_payload[i] = (uint8_t)((i * 113 + 7) & 0xff);

        g_cli_rx4_armed = 1;
        int r4 = mq_conn_datagram_send(g_server_conn, c4b_payload, DGM_PAYLOAD_LEN);
        MQ_CHECK_EQ_INT(r4, 0);

        /* Wait for arrival at the client (condition-based; exits early on success). */
        deadline = now_ms() + 5000;
        while (!g_cli_rx4_done && now_ms() < deadline)
            event_base_loop(base, EVLOOP_NONBLOCK);

        MQ_CHECK(g_cli_rx4_done);
        if (g_cli_rx4_done) {
            MQ_CHECK_EQ_INT((int)g_cli_rx4_len, DGM_PAYLOAD_LEN);
            MQ_CHECK_MEM(g_cli_rx4_buf, c4b_payload, DGM_PAYLOAD_LEN);
        }
        fprintf(stderr, "case4: follow-on server→client rc=%d arrived=%d\n", r4,
                g_cli_rx4_done);
    }

    /* Tear down the client conn, pump briefly for close frames to flush. */
    mq_conn_close(conn);
    uint64_t close_deadline = now_ms() + 500;
    while (now_ms() < close_deadline)
        event_base_loop(base, EVLOOP_NONBLOCK);

cleanup:
    if (cli_t) mq_transport_free(cli_t);
    if (srv_t) mq_transport_free(srv_t);
    if (cli_rt) mq_runtime_free(cli_rt);
    if (srv_rt) mq_runtime_free(srv_rt);
    event_base_free(base);
}

MQ_TEST_MAIN(test_datagram_fabric())
