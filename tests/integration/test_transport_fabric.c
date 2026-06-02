// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* test_transport_fabric.c — Chunk 2: socket-free in-memory transport fabric
 * E2E (design §7). This is a deliberately RED test at this chunk.
 *
 * Two mq_transport instances (client + server) are driven ENTIRELY in memory:
 * no real UDP sockets, no libevent dispatch. An in-memory "fabric" with two
 * directional packet queues stands in for the network — each transport's
 * send_udp callback enqueues into the PEER's inbound queue, and a single-
 * threaded bounded driver loop ticks both transports and drains each queue
 * into the peer via mq_transport_on_udp_recv (design §7):
 *
 *     client mq_transport.send_udp ──┐
 *                                     ├─ in-memory fabric (per-path queues)
 *     server mq_transport.send_udp ──┘   peer's on_udp_recv ← driver drains
 *
 *     driver: while (i<MAX && !success) {
 *                 tick(client); tick(server);
 *                 drain client→server via on_udp_recv(server,…);
 *                 drain server→client via on_udp_recv(client,…);
 *             }
 *
 * ── WHY THIS FAILS NOW (RED), and what is STUBBED ──────────────────────────
 *
 * At Chunk 2 mq_transport is a thin SHELL over mq_engine (see
 * src/transport/mq_transport.c):
 *   - the send_udp / open_path_socket callbacks are STORED but never invoked
 *     (Chunk 3/6 invert mq_engine's direct socket I/O onto them);
 *   - mq_transport_on_udp_recv is a no-op that returns 0 (Chunk 5 wires it to
 *     xqc_engine_packet_process);
 *   - mq_transport_next_timeout_ms returns -1 (Chunk 4).
 * So no packet ever enters the fabric and nothing is ever delivered: the
 * `success` flag stays false and the final MQ_CHECK asserts cleanly (the
 * process exits non-zero WITHOUT hanging or crashing — the driver loop is
 * bounded at MAX_ITERS).
 *
 * SCOPE NOTE (per plan Chunk 2 REALISM clause): the proxy layer
 * (mq_client_new / mq_server_new / mq_conn_connect / mq_conn_register_alpn)
 * still takes mq_engine_t*, NOT mq_transport_t*, at this chunk, and
 * mq_transport.h does not expose the wrapped engine. The full AUTH +
 * CONNECT_TCP + bidirectional relay wiring on top of mq_transport therefore
 * cannot be expressed yet — it depends on the Chunk 7 proxy retarget. This
 * test establishes the harness SHAPE (fabric + two transports + bounded
 * driver loop over the real mq_transport API) and asserts the end-to-end
 * delivery invariant. Chunk 8 makes it GREEN and grows the assertions to the
 * full auth/CONNECT_TCP/relay byte-integrity criterion of design §7/§11 #2.
 */
#include "mqtest.h"

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <xquic/xquic.h>

#include "transport/mq_transport.h"

#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE "tests/certs/test.crt"
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE "tests/certs/test.key"
#endif

/* Cap the driver loop so the test can NEVER hang even though delivery is not
 * wired. With a working transport a handshake settles in a handful of round
 * trips; this is comfortably above that. */
#define MAX_ITERS       2000
#define FABRIC_MAX_PKTS 256
#define FABRIC_MTU      2048

/* ── in-memory fabric ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t buf[FABRIC_MTU];
    size_t len;
    uint64_t path;
    struct sockaddr_storage peer;
    socklen_t peerlen;
} fabric_pkt_t;

/* One directional queue (a simple ring is unnecessary; a bounded FIFO drained
 * to empty each tick suffices for the in-memory baseline). */
typedef struct {
    fabric_pkt_t pkts[FABRIC_MAX_PKTS];
    size_t count;
    int overflow; /* set if a packet was dropped (queue full) */
} fabric_queue_t;

typedef struct {
    fabric_queue_t to_server; /* packets the client sent, awaiting the server */
    fabric_queue_t to_client; /* packets the server sent, awaiting the client */
    int paths_opened;         /* count of open_path_socket calls (logical only) */
} fabric_t;

/* Per-transport context: which queue this endpoint WRITES into when it sends. */
typedef struct {
    fabric_t *fabric;
    fabric_queue_t *outbound; /* the PEER's inbound queue */
    const char *role;
} endpoint_t;

static void
fabric_enqueue(fabric_queue_t *q, uint64_t path, const uint8_t *pkt, size_t len,
               const struct sockaddr *peer, socklen_t peerlen)
{
    if (q->count >= FABRIC_MAX_PKTS || len > FABRIC_MTU) {
        q->overflow = 1;
        return;
    }
    fabric_pkt_t *p = &q->pkts[q->count++];
    memcpy(p->buf, pkt, len);
    p->len = len;
    p->path = path;
    p->peerlen = 0;
    if (peer && peerlen > 0 && peerlen <= (socklen_t)sizeof(p->peer)) {
        memcpy(&p->peer, peer, peerlen);
        p->peerlen = peerlen;
    }
}

/* ── mq_transport callbacks (the fabric backend) ─────────────────────────── */

/* send_udp: copy the packet into the PEER's inbound queue and report the byte
 * count written (xquic's xqc_socket_write_pt contract; UDP is all-or-nothing).
 * On the Chunk-2 shell this is NEVER invoked (mq_transport does not yet route
 * sends through the callback), which is precisely why delivery — and thus the
 * test — fails. */
static int
fab_send_udp(uint64_t path, const uint8_t *pkt, size_t len, const struct sockaddr *peer,
             socklen_t peerlen, void *user)
{
    endpoint_t *ep = (endpoint_t *)user;
    fabric_enqueue(ep->outbound, path, pkt, len, peer, peerlen);
    return (int)len;
}

/* open_path_socket: record the path as a logical channel; no real socket. */
static int
fab_open_path_socket(uint64_t path, const char *local_ip, uint16_t port, void *user)
{
    (void)path;
    (void)local_ip;
    (void)port;
    endpoint_t *ep = (endpoint_t *)user;
    ep->fabric->paths_opened++;
    return 0;
}

static void
fab_close_path_socket(uint64_t path, void *user)
{
    (void)path;
    (void)user;
}

/* Drain every queued packet into `dst` via the real on_udp_recv input edge.
 * Returns the number of packets that on_udp_recv reported as consumed (>0).
 * On the shell transport on_udp_recv is a no-op returning 0, so nothing is
 * ever counted as consumed. */
static int
fabric_drain(fabric_queue_t *q, mq_transport_t *dst)
{
    /* xqc_engine_packet_process needs a non-NULL local (bind) address — it keys
     * the path on the (local,peer) 4-tuple. The fabric has no real socket, so
     * synthesise a loopback local addr; it just has to be a valid sockaddr. */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons(0);

    int consumed = 0;
    for (size_t i = 0; i < q->count; i++) {
        fabric_pkt_t *p = &q->pkts[i];
        int r = mq_transport_on_udp_recv(dst, p->path, p->buf, p->len,
                                         (struct sockaddr *)&local, sizeof(local),
                                         (struct sockaddr *)&p->peer, p->peerlen);
        if (r > 0) consumed++;
    }
    q->count = 0;
    return consumed;
}

static void
test_transport_fabric(void)
{
    fabric_t fabric;
    memset(&fabric, 0, sizeof(fabric));

    /* Per-endpoint contexts: each transport sends into the PEER's queue. */
    endpoint_t client_ctx = {
        .fabric = &fabric, .outbound = &fabric.to_server, .role = "client"};
    endpoint_t server_ctx = {
        .fabric = &fabric, .outbound = &fabric.to_client, .role = "server"};

    mq_transport_callbacks_t cbs = {
        .send_udp = fab_send_udp,
        .open_path_socket = fab_open_path_socket,
        .close_path_socket = fab_close_path_socket,
    };

    /* Two transports over the shared fabric: client + server (with TLS material
     * so the server transport is handshake-capable once delivery is wired). */
    mq_transport_t *client = mq_transport_new(/*is_server=*/0, &cbs, &client_ctx);
    MQ_CHECK(client != NULL);
    mq_transport_t *server =
        mq_transport_new_server(&cbs, &server_ctx, TEST_CERT_FILE, TEST_KEY_FILE);
    MQ_CHECK(server != NULL);
    if (!client || !server) {
        if (client) mq_transport_free(client);
        if (server) mq_transport_free(server);
        return;
    }

    /* The xqc engines must be reachable through the public accessor (used by the
     * proxy layer in later chunks to drive conn/stream over the transport). */
    MQ_CHECK(mq_transport_xqc(client) != NULL);
    MQ_CHECK(mq_transport_xqc(server) != NULL);

    /* Bounded driver loop (design §7): tick both, then drain each direction
     * into the peer. `success` is the end-to-end delivery invariant — at least
     * one packet observed crossing the fabric AND consumed by the peer's input
     * edge. On the Chunk-2 shell, send_udp is never called (queues stay empty)
     * and on_udp_recv is a no-op (returns 0), so this never becomes true. The
     * loop is bounded, so the test always terminates (no hang). */
    int success = 0;
    int delivered = 0;
    for (int i = 0; i < MAX_ITERS && !success; i++) {
        mq_transport_tick(client);
        mq_transport_tick(server);
        delivered += fabric_drain(&fabric.to_server, server);
        delivered += fabric_drain(&fabric.to_client, client);
        /* next_timeout_ms is part of the real driver contract (runtime arms a
         * timer from it). Exercise it so the harness shape matches §7; the shell
         * returns -1 (no work scheduled). */
        (void)mq_transport_next_timeout_ms(client);
        (void)mq_transport_next_timeout_ms(server);
        if (delivered > 0) success = 1;
    }

    /* The fabric must not have silently dropped packets (would mask a failure as
     * a pass once delivery is wired). On the shell these stay empty/false. */
    MQ_CHECK_EQ_INT(fabric.to_server.overflow, 0);
    MQ_CHECK_EQ_INT(fabric.to_client.overflow, 0);

    /* THE RED ASSERTION. Chunk 8 wires the transport delivery path (and the
     * Chunk 7 proxy retarget supplies auth + CONNECT_TCP + relay on top); this
     * flips to true then. Today it is false — a CLEAN assert failure, not a
     * crash or hang. */
    MQ_CHECK(success);

    mq_transport_free(client);
    mq_transport_free(server);
}

MQ_TEST_MAIN(test_transport_fabric())
