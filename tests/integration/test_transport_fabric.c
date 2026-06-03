// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_transport_fabric.c — socket-free + libevent-free transport+stream
 * data-plane E2E (design §7, plan Chunk 8).
 *
 * Two mq_transport instances (client + server) are driven ENTIRELY in memory:
 * no real UDP sockets, no libevent dispatch, no mq_client / mq_server / mq_flow.
 * An in-memory "fabric" with two directional packet queues stands in for the
 * network — each transport's send_udp callback enqueues into the PEER's inbound
 * queue, and a single-threaded bounded driver loop ticks both transports and
 * drains each queue into the peer via mq_transport_on_udp_recv (design §7):
 *
 *     client mq_transport.send_udp ──┐
 *                                     ├─ in-memory fabric (per-path queues)
 *     server mq_transport.send_udp ──┘   peer's on_udp_recv ← driver drains
 *
 *     driver: while (i<MAX && !done) {
 *                 tick(client); tick(server);
 *                 drain client→server via on_udp_recv(server,…);
 *                 drain server→client via on_udp_recv(client,…);
 *             }
 *
 * Because there is no libevent timer, the driver MANUALLY ticks both sides each
 * iteration (the transport's on_timer callback is left unused — manual ticking
 * replaces the runtime's armed timer).
 *
 * WHAT THIS VERIFIES — a full MPQUIC handshake plus a bidirectional stream
 * exchange over the real mq_conn / mq_stream API, with no I/O:
 *   1. the client conn reaches MQ_CONN_ESTABLISHED;
 *   2. the server observes the peer-initiated stream (on_new_stream);
 *   3. the server reads the client's payload and ECHOES it back with FIN;
 *   4. the client reads the echo and the bytes match exactly (byte integrity)
 *      with a clean FIN on both directions.
 *
 * SCOPE NOTE: a fully socket-free auth + CONNECT_TCP + origin-relay test is NOT
 * achievable here — the proxy relay layer (mq_server / mq_flow) is libevent +
 * real-socket coupled until Phase F (design §7). That full criterion is covered
 * by the loopback E2E tests (test_e2e_single_path, test_client_server) which run
 * the real proxy layer. This test isolates the transport+stream data plane and
 * proves it correct deterministically, socket-free + libevent-free.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <xquic/xquic.h>

#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

#define TEST_ALPN "mqproxy-tcp/1"

/* Cap the driver loop so the test can NEVER hang. A working transport settles
 * the handshake + a one-shot stream echo in a handful of round trips; this is
 * comfortably above that. A regression must FAIL (cap reached), not hang. */
#define MAX_ITERS       4000
#define FABRIC_MAX_PKTS 256
#define FABRIC_MTU      2048

/* Wall-clock backstop (ms): even if the cap were mis-sized, the loop cannot run
 * longer than this. */
#define WALL_BUDGET_MS 5000

/* Synthetic loopback ports for the two logical endpoints. Real binds never
 * happen; these only have to give xquic two distinct, stable (local,peer)
 * 4-tuples so it keys the path consistently across packets. */
#define CLI_PORT 50001
#define SRV_PORT 50002

/* The payload whose round-trip byte integrity is the core assertion. */
static const unsigned char PAYLOAD[] = "the quick brown fox jumps over the lazy dog";
#define PAYLOAD_LEN (sizeof(PAYLOAD) - 1)

/* ── in-memory fabric ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t buf[FABRIC_MTU];
    size_t len;
    uint64_t path;
} fabric_pkt_t;

/* One directional queue (a bounded FIFO drained to empty each tick). */
typedef struct {
    fabric_pkt_t pkts[FABRIC_MAX_PKTS];
    size_t count;
    int overflow; /* set if a packet was dropped (queue full) */
} fabric_queue_t;

typedef struct {
    fabric_queue_t to_server; /* packets the client sent, awaiting the server */
    fabric_queue_t to_client; /* packets the server sent, awaiting the client */
} fabric_t;

/* Per-transport context: which queue this endpoint WRITES into when it sends,
 * plus the synthetic local addr xquic must see on the receiving side. */
typedef struct {
    fabric_queue_t *outbound; /* the PEER's inbound queue */
    const char *role;
} endpoint_t;

static void
fabric_enqueue(fabric_queue_t *q, uint64_t path, const uint8_t *pkt, size_t len)
{
    if (q->count >= FABRIC_MAX_PKTS || len > FABRIC_MTU) {
        q->overflow = 1;
        return;
    }
    fabric_pkt_t *p = &q->pkts[q->count++];
    memcpy(p->buf, pkt, len);
    p->len = len;
    p->path = path;
}

static void
make_addr(struct sockaddr_in *sa, uint16_t port)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa->sin_port = htons(port);
}

/* ── mq_transport callbacks (the fabric backend) ─────────────────────────── */

/* send_udp: copy the packet into the PEER's inbound queue and report the byte
 * count written (xquic's xqc_socket_write_pt contract; UDP is all-or-nothing).
 * The destination addr is implicit (each endpoint writes only into its peer's
 * queue), so it is not carried — the drain synthesises the (local,peer) tuple
 * from the receiving endpoint's identity. */
static int
fab_send_udp(uint64_t path, const uint8_t *pkt, size_t len, const struct sockaddr *peer,
             socklen_t peerlen, void *user)
{
    (void)peer;
    (void)peerlen;
    endpoint_t *ep = (endpoint_t *)user;
    fabric_enqueue(ep->outbound, path, pkt, len);
    return (int)len;
}

/* open_path_socket: no real socket. The primary path (path 0) is never routed
 * through here — xquic sends primary traffic via write_socket with no socket
 * lifecycle — so this only fires if a secondary path were added (not exercised
 * by this test). Installed for completeness; a no-op success. */
static int
fab_open_path_socket(uint64_t path, const char *local_ip, uint16_t port, void *user)
{
    (void)path;
    (void)local_ip;
    (void)port;
    (void)user;
    return 0;
}

static void
fab_close_path_socket(uint64_t path, void *user)
{
    (void)path;
    (void)user;
}

/* Drain every queued packet into `dst` via the real on_udp_recv input edge.
 * `dst` is the receiving endpoint, bound (logically) to dst_port; the source is
 * bound to src_port. xquic keys the path on the (local,peer) 4-tuple, so the
 * receiving side must always see local=dst_port, peer=src_port.
 *
 * Returns the number of packets on_udp_recv reported as accepted. The success
 * code from xqc_engine_packet_process is XQC_OK == 0, so a successfully consumed
 * packet returns 0 (>= 0); only a hard error is < 0. We count r >= 0. */
static int
fabric_drain(fabric_queue_t *q, mq_transport_t *dst, uint16_t dst_port, uint16_t src_port)
{
    struct sockaddr_in local, peer;
    make_addr(&local, dst_port);
    make_addr(&peer, src_port);

    int consumed = 0;
    for (size_t i = 0; i < q->count; i++) {
        fabric_pkt_t *p = &q->pkts[i];
        int r = mq_transport_on_udp_recv(dst, p->path, p->buf, p->len,
                                         (struct sockaddr *)&local, sizeof(local),
                                         (struct sockaddr *)&peer, sizeof(peer));
        if (r >= 0) consumed++;
    }
    q->count = 0;
    return consumed;
}

static uint64_t
now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* ── application state (the data-plane assertions) ───────────────────────── */

static int g_client_established;

/* Server side: the echo stream + the bytes seen so far. */
static mq_stream_t *g_server_stream;
static unsigned char g_server_rx[FABRIC_MTU];
static size_t g_server_rx_len;
static int g_server_saw_fin;
static int g_server_echoed;

/* Client side: the echo received back from the server. */
static unsigned char g_client_rx[FABRIC_MTU];
static size_t g_client_rx_len;
static int g_client_saw_fin;

static void
on_client_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    (void)user;
    if (st == MQ_CONN_ESTABLISHED) {
        g_client_established = 1;
    }
}

/* Client stream readable: drain the server's echo and note the FIN. */
static void
on_client_stream_readable(mq_stream_t *s, void *user)
{
    (void)user;
    for (;;) {
        int fin = 0;
        long n = mq_stream_recv(s, g_client_rx + g_client_rx_len,
                                sizeof(g_client_rx) - g_client_rx_len, &fin);
        if (n > 0) {
            g_client_rx_len += (size_t)n;
        }
        if (fin) {
            g_client_saw_fin = 1;
        }
        if (n <= 0) break;
    }
}

/* Server stream readable: drain the client's payload; once FIN is seen, echo
 * the accumulated bytes back with FIN. */
static void
on_server_stream_readable(mq_stream_t *s, void *user)
{
    (void)user;
    for (;;) {
        int fin = 0;
        long n = mq_stream_recv(s, g_server_rx + g_server_rx_len,
                                sizeof(g_server_rx) - g_server_rx_len, &fin);
        if (n > 0) {
            g_server_rx_len += (size_t)n;
        }
        if (fin) {
            g_server_saw_fin = 1;
        }
        if (n <= 0) break;
    }

    if (g_server_saw_fin && !g_server_echoed) {
        long sent = mq_stream_send(s, g_server_rx, g_server_rx_len, /*fin=*/1);
        if (sent >= 0) {
            g_server_echoed = 1;
        }
    }
}

/* Server side: accepted connections surface here. */
static void
on_server_conn(mq_conn_t *c, void *user)
{
    (void)c;
    (void)user;
}

/* Server side: peer-initiated stream surfaces here — wire its read callback so
 * we receive + echo the client's payload. */
static void
on_server_stream(mq_stream_t *s, void *user)
{
    (void)user;
    g_server_stream = s;
    mq_stream_set_cbs(s, on_server_stream_readable, /*on_writable=*/NULL,
                      /*on_close=*/NULL, NULL);
}

static void
test_transport_fabric(void)
{
    fabric_t fabric;
    memset(&fabric, 0, sizeof(fabric));

    /* Per-endpoint contexts: each transport sends into the PEER's queue. */
    endpoint_t client_ctx = {.outbound = &fabric.to_server, .role = "client"};
    endpoint_t server_ctx = {.outbound = &fabric.to_client, .role = "server"};

    mq_transport_callbacks_t cbs = {
        .send_udp = fab_send_udp,
        .open_path_socket = fab_open_path_socket,
        .close_path_socket = fab_close_path_socket,
    };

    /* Two transports over the shared fabric: client + server (with TLS material
     * so the server transport is handshake-capable). */
    mq_transport_t *client = mq_transport_new(/*is_server=*/0);
    MQ_CHECK(client != NULL);
    mq_transport_t *server = mq_transport_new_server(TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(server != NULL);
    if (!client || !server) {
        if (client) mq_transport_free(client);
        if (server) mq_transport_free(server);
        return;
    }
    mq_transport_set_callbacks(client, &cbs, &client_ctx);
    mq_transport_set_callbacks(server, &cbs, &server_ctx);

    MQ_CHECK(mq_transport_xqc(client) != NULL);
    MQ_CHECK(mq_transport_xqc(server) != NULL);

    /* Register the ALPN on both engines: server supplies new-conn / new-stream
     * hooks; the client is a pure initiator (NULL server hooks). */
    int rc =
        mq_conn_register_alpn(server, TEST_ALPN, on_server_conn, on_server_stream, NULL);
    MQ_CHECK_EQ_INT(rc, 0);
    rc = mq_conn_register_alpn(client, TEST_ALPN, NULL, NULL, NULL);
    MQ_CHECK_EQ_INT(rc, 0);

    /* The client connects to the server's synthetic loopback address. The
     * primary path (path 0) needs no open_path_socket — xquic emits its packets
     * via write_socket, which the fabric routes by endpoint identity. */
    struct sockaddr_in srv_addr;
    make_addr(&srv_addr, SRV_PORT);

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;

    mq_conn_t *conn = mq_conn_connect(client, (struct sockaddr *)&srv_addr,
                                      sizeof(srv_addr), TEST_ALPN, &settings, NULL);
    MQ_CHECK(conn != NULL);
    if (!conn) {
        mq_transport_free(client);
        mq_transport_free(server);
        return;
    }
    mq_conn_set_on_state(conn, on_client_state, NULL);

    /* ── Phase 1: drive the handshake to ESTABLISHED ─────────────────────── */
    uint64_t deadline = now_ms() + WALL_BUDGET_MS;
    int iters = 0;
    while (!g_client_established && iters < MAX_ITERS && now_ms() < deadline) {
        mq_transport_tick(client);
        mq_transport_tick(server);
        fabric_drain(&fabric.to_server, server, SRV_PORT, CLI_PORT);
        fabric_drain(&fabric.to_client, client, CLI_PORT, SRV_PORT);
        (void)mq_transport_next_timeout_ms(client);
        (void)mq_transport_next_timeout_ms(server);
        iters++;
    }
    MQ_CHECK(g_client_established);

    /* ── Phase 2: client opens a bidi stream, sends the payload with FIN ──── */
    mq_stream_t *cs = mq_conn_open_stream(conn);
    MQ_CHECK(cs != NULL);
    if (cs) {
        mq_stream_set_cbs(cs, on_client_stream_readable, /*on_writable=*/NULL,
                          /*on_close=*/NULL, NULL);
        long sent = mq_stream_send(cs, PAYLOAD, PAYLOAD_LEN, /*fin=*/1);
        MQ_CHECK_EQ_INT((int)sent, (int)PAYLOAD_LEN);
    }

    /* Drive until the round-trip echo lands (or the bounded caps fire). */
    int done = 0;
    while (!done && iters < MAX_ITERS && now_ms() < deadline) {
        mq_transport_tick(client);
        mq_transport_tick(server);
        fabric_drain(&fabric.to_server, server, SRV_PORT, CLI_PORT);
        fabric_drain(&fabric.to_client, client, CLI_PORT, SRV_PORT);
        (void)mq_transport_next_timeout_ms(client);
        (void)mq_transport_next_timeout_ms(server);
        iters++;
        done = (g_client_saw_fin && g_client_rx_len == PAYLOAD_LEN);
    }

    /* The fabric must not have silently dropped packets (would mask a failure
     * as a pass). */
    MQ_CHECK_EQ_INT(fabric.to_server.overflow, 0);
    MQ_CHECK_EQ_INT(fabric.to_client.overflow, 0);

    int established = g_client_established;
    int server_saw_stream = (g_server_stream != NULL) && g_server_saw_fin;
    int echo_matches = (g_client_rx_len == PAYLOAD_LEN) &&
                       (memcmp(g_client_rx, PAYLOAD, PAYLOAD_LEN) == 0);
    int clean_close = g_client_saw_fin && g_server_echoed;

    int success = established && server_saw_stream && echo_matches && clean_close;
    if (!success) {
        fprintf(stderr,
                "fabric E2E FAILED [%s/%s]: established=%d server_saw_stream=%d "
                "(stream=%p server_fin=%d) echo_matches=%d (rx_len=%zu want=%zu) "
                "clean_close=%d (client_fin=%d echoed=%d) iters=%d\n",
                client_ctx.role, server_ctx.role, established, server_saw_stream,
                (void *)g_server_stream, g_server_saw_fin, echo_matches, g_client_rx_len,
                (size_t)PAYLOAD_LEN, clean_close, g_client_saw_fin, g_server_echoed,
                iters);
    }
    MQ_CHECK(success);

    mq_conn_close(conn);

    /* Pump briefly so the local CONNECTION_CLOSE frame flushes to the peer
     * (bounded). xquic surfaces conn_close_notify only at engine teardown (after
     * its closing/drain timer), not within this in-memory pump, so the
     * MQ_CONN_CLOSED transition is not asserted here — the clean-close byte-level
     * criterion (client FIN seen + server echoed with FIN) is asserted above. */
    uint64_t close_deadline = now_ms() + 200;
    int close_iters = 0;
    while (close_iters < MAX_ITERS && now_ms() < close_deadline) {
        mq_transport_tick(client);
        mq_transport_tick(server);
        fabric_drain(&fabric.to_server, server, SRV_PORT, CLI_PORT);
        fabric_drain(&fabric.to_client, client, CLI_PORT, SRV_PORT);
        close_iters++;
    }

    mq_transport_free(client);
    mq_transport_free(server);
}

MQ_TEST_MAIN(test_transport_fabric())
