// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_session.c — server-side UDP relay session table + OPEN handling.
 *
 * See mq_udp_session.h for the ownership / lifecycle contract. This file
 * implements Task 5.1: the session table, OPEN decode → resolve → dial → RESP,
 * the 0x02 stream lifecycle (stream-close ⇒ session teardown), the per-session
 * idle timer, and the three-way reap (stream close / idle expiry / conn close)
 * guarded so each session's fd / event / defrag are freed exactly once.
 *
 * The datagram relay (Task 5.2) is stubbed: mq_udp_srv_on_datagram drops, and
 * the UDP socket's EV_READ is armed with a no-op callback 5.2 replaces.
 */
#include "proxy/mq_udp_session.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_defrag.h"
#include "proxy/mq_framebuf.h"
#include "transport/mq_stream.h"
#include "util/mq_log.h"
#include "wire/mq_wire.h"

/* Per-session state. Lives in the parent's `sessions` array; `used` marks a slot
 * live. The 0x02 stream is the session's control handle: its close (or the conn
 * close, or an idle expiry) tears the session down. */
typedef struct {
    int used;
    uint32_t session_id;
    mq_stream_t *stream;     /* 0x02 control stream (NULL after close-notify) */
    int fd;                  /* connected UDP socket */
    struct event *rd_ev;     /* persistent EV_READ on fd (Task 5.2 callback) */
    struct event *idle_ev;   /* idle evtimer (re-armed on bidirectional activity) */
    mq_defrag_t *defrag;     /* lazy: allocated on first fragmented inbound packet */
    uint16_t next_packet_id; /* server→client packet_id counter (Task 5.2) */
    int reaped;              /* reap-once guard (Known risk 7) */
    int graceful;            /* an arm-failure RESP(ERROR) was sent with FIN:
                              * reap must NOT RESET (RESET drops the un-acked RESP) */
    mq_udp_srv_t *owner;     /* back-pointer for callbacks */
} mq_udp_sess_t;

struct mq_udp_srv {
    mq_conn_t *conn;
    struct event_base *base;
    uint64_t idle_timeout_ms; /* server-configured idle timeout */
    int enabled;              /* mirrors !--no-udp */
    mq_udp_sess_t sessions[MQ_UDP_SRV_MAX_SESSIONS];
    size_t live_count;
};

/* ── helpers ────────────────────────────────────────────────────────────── */

static mq_udp_sess_t *
srv_find_session(mq_udp_srv_t *u, uint32_t sid)
{
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (u->sessions[i].used && u->sessions[i].session_id == sid) {
            return &u->sessions[i];
        }
    }
    return NULL;
}

static mq_udp_sess_t *
srv_alloc_session(mq_udp_srv_t *u)
{
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (!u->sessions[i].used) {
            return &u->sessions[i];
        }
    }
    return NULL;
}

/* Send a UDP_SESSION_RESP on the OPEN stream. On the error path the codec maps
 * MQ_STATUS_ERROR ⇔ codes 1-4; OK ⇔ MQ_UDP_OK. message is empty.
 *
 * fin selects the close semantics, mirroring mq_server.c srv_send_tcp_resp:
 *   fin=0 — success: keep the stream open as the session control handle.
 *   fin=1 — error: close the send direction so the RESP is the stream's final
 *           frame. The caller MUST NOT mq_stream_close() afterwards: a RESET
 *           (xqc_stream_close → xqc_send_queue_drop_stream_frame_packets) would
 *           DROP the not-yet-flushed RESP (engine flush is deferred inside a read
 *           callback), so the client would see only RESET, never the error code.
 *           The FIN terminates the stream; the peer's close completes teardown. */
static void
srv_send_udp_resp(mq_stream_t *s, mq_status_t status, mq_udp_err_t err,
                  uint64_t idle_timeout_ms, int fin)
{
    mq_udp_session_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.error_code = err;
    resp.message[0] = '\0';
    resp.message_len = 0;
    resp.idle_timeout_ms = idle_timeout_ms;

    uint8_t buf[512];
    int n = mq_encode_udp_session_resp(buf, sizeof(buf), &resp);
    if (n < 0) {
        MQ_LOGE("mq_udp_srv: encode UDP_SESSION_RESP failed");
        return;
    }
    long sent = mq_stream_send(s, buf, (size_t)n, fin);
    if (sent < 0 || (size_t)sent != (size_t)n) {
        MQ_LOGW("mq_udp_srv: UDP_SESSION_RESP send short/failed (%ld of %d)", sent, n);
    }
}

/* Resolve the OPEN target into a connected-able sockaddr (SOCK_DGRAM). Mirrors
 * mq_server.c srv_resolve_target but tailored to UDP: it requests
 * hints.ai_socktype = SOCK_DGRAM and returns mq_udp_err_t. A minimal copy is
 * cleaner than exporting the TCP static (which returns mq_tcp_err_t and would
 * force an error-type translation + a new shared header dependency). */
static int
srv_resolve_udp_target(const mq_udp_session_open_t *open, struct sockaddr_storage *ss,
                       socklen_t *sslen, mq_udp_err_t *err)
{
    memset(ss, 0, sizeof(*ss));
    if (open->address_type == MQ_ADDR_IPV4) {
        if (open->host_len != 4) {
            *err = MQ_UDP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, open->host, 4);
        sin->sin_port = htons(open->port);
        *sslen = sizeof(*sin);
        return 0;
    }
    if (open->address_type == MQ_ADDR_IPV6) {
        if (open->host_len != 16) {
            *err = MQ_UDP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, open->host, 16);
        sin6->sin6_port = htons(open->port);
        *sslen = sizeof(*sin6);
        return 0;
    }
    /* DOMAIN: BLOCKING getaddrinfo (accepted debt, design §2). */
    char hostz[MQ_MAX_HOST + 1];
    if (open->host_len > MQ_MAX_HOST) {
        *err = MQ_UDP_DNS_FAILED;
        return -1;
    }
    memcpy(hostz, open->host, open->host_len);
    hostz[open->host_len] = '\0';
    char portz[8];
    snprintf(portz, sizeof(portz), "%u", (unsigned)open->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(hostz, portz, &hints, &res);
    if (gai != 0 || !res) {
        if (res) freeaddrinfo(res);
        *err = MQ_UDP_DNS_FAILED;
        return -1;
    }
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *sslen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* ── session teardown (reap-once, three callers) ───────────────────────────
 *
 * Known risk 7: stream-close (client-initiated), idle-timer expiry, and conn
 * close all free the same session. The `reaped` guard makes this idempotent;
 * fd / events / defrag are freed exactly once. The stream is RESET here ONLY
 * when it is still live AND the teardown did not originate from the stream's own
 * close-notify (which nulls sess->stream first) AND it is not a graceful
 * teardown (an error RESP was already FIN'd — a RESET would drop it), mirroring
 * mq_server's flow / srv_data_reap pattern. In every case the callbacks are
 * detached first so the eventual close-notify cannot touch the freed slot. */
static void
srv_reap_session(mq_udp_sess_t *sess)
{
    if (!sess || !sess->used || sess->reaped) {
        return;
    }
    sess->reaped = 1;

    if (sess->idle_ev) {
        event_free(sess->idle_ev);
        sess->idle_ev = NULL;
    }
    if (sess->rd_ev) {
        event_free(sess->rd_ev);
        sess->rd_ev = NULL;
    }
    if (sess->fd >= 0) {
        close(sess->fd);
        sess->fd = -1;
    }
    if (sess->defrag) {
        mq_defrag_free(sess->defrag);
        sess->defrag = NULL;
    }
    if (sess->stream) {
        /* Still live (teardown came from idle expiry or conn close, NOT the
         * stream's own close-notify). Drop our callbacks so the eventual
         * close-notify (from the FIN / peer close, or conn teardown) cannot fire
         * on the freed slot. On the graceful path an error RESP was already sent
         * with FIN — a RESET would drop it, so leave the close to the FIN / peer
         * (the transport frees the stream at conn teardown either way). */
        mq_stream_set_cbs(sess->stream, NULL, NULL, NULL, NULL);
        if (!sess->graceful) {
            mq_stream_close(sess->stream);
        }
        sess->stream = NULL;
    }

    mq_udp_srv_t *u = sess->owner;
    if (u && u->live_count > 0) {
        u->live_count--;
    }
    /* Clear the slot (used=0 frees it for reuse). */
    memset(sess, 0, sizeof(*sess));
    sess->fd = -1;
}

/* Idle timer expiry: tear the session down. */
static void
srv_idle_expired_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_udp_sess_t *sess = (mq_udp_sess_t *)arg;
    MQ_LOGI("mq_udp_srv: session %u idle-expired", sess->session_id);
    srv_reap_session(sess);
}

/* UDP socket readable: Task 5.2 implements target→tunnel. No-op stub for now
 * (the event is armed so 5.2 only swaps the callback). */
static void
srv_udp_readable_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
    /* Task 5.2: recv from target, split, datagram_send to tunnel, re-arm idle. */
}

/* The 0x02 stream's close-notify: the client closed/reset the session control
 * stream. Null our pointer (the transport frees the stream after this returns)
 * and reap the session. */
static void
srv_stream_closed_cb(mq_stream_t *s, void *user)
{
    (void)s;
    mq_udp_sess_t *sess = (mq_udp_sess_t *)user;
    sess->stream = NULL; /* transport frees it after this returns */
    srv_reap_session(sess);
}

/* The 0x02 stream readable after RESP: Task 5.2 may use the stream for control
 * traffic; for now just drain to avoid stalling it. */
static void
srv_stream_readable_cb(mq_stream_t *s, void *user)
{
    (void)user;
    uint8_t scratch[256];
    int fin = 0;
    while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
}

/* ── OPEN handling ─────────────────────────────────────────────────────────
 *
 * The 0x02 stream's readable callback during the OPEN phase: accumulate +
 * decode UDP_SESSION_OPEN (after the already-consumed 0x02 discriminator),
 * then resolve → dial → RESP. The pending-open state lives in a transient
 * heap struct hung off the stream's user pointer until the session is created
 * (or the stream errors). */
typedef struct {
    mq_udp_srv_t *u;
    mq_stream_t *stream;
    mq_framebuf_t rx;
    int settled; /* OPEN processed: ignore further reads */
} mq_udp_open_t;

static void
srv_open_free(mq_udp_open_t *op)
{
    free(op);
}

/* Pending-open stream close: the client gave up before OPEN completed. Free the
 * transient open state (no session was created yet). */
static void
srv_open_closed_cb(mq_stream_t *s, void *user)
{
    (void)s;
    mq_udp_open_t *op = (mq_udp_open_t *)user;
    srv_open_free(op);
}

/* Reject an OPEN before a session exists. Two shapes, mirroring the TCP path's
 * graceful-vs-RESET split (mq_server.c srv_data_fail / srv_data_reap):
 *
 *   send_resp != 0 (POLICY_DENIED / DNS_FAILED / SOCKET_FAILED / SESSION_LIMIT):
 *     send RESP(ERROR, err) with FIN, then detach callbacks and free the
 *     pending-open state. We do NOT mq_stream_close(): a RESET
 *     (xqc_send_queue_drop_stream_frame_packets) would drop the not-yet-flushed
 *     RESP — the engine flush is deferred inside this read callback — so the
 *     client would see only RESET, never the error code. The FIN terminates the
 *     send direction; the peer's close (or conn teardown) frees the stream.
 *     Because the callbacks are detached, the later close-notify cannot fire
 *     srv_open_closed_cb on the freed op (and the conn never frees op: it is a
 *     transient owned only here, freed exactly once below).
 *
 *   send_resp == 0 (duplicate-SID / malformed OPEN — no decodable session to
 *     RESP to): there is nothing to deliver, so RESET is correct and cheaper.
 *     Detach callbacks, mq_stream_close (RESET), free op. */
static void
srv_open_reject(mq_udp_open_t *op, int send_resp, mq_udp_err_t err)
{
    if (send_resp) {
        /* Graceful: FIN'd RESP, no RESET (would drop the un-acked RESP). */
        srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, err, 0, /*fin=*/1);
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
    } else {
        /* Silent reset: no RESP owed, RESET the stream. */
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
        mq_stream_close(op->stream);
    }
    srv_open_free(op);
}

/* Finalize a successful OPEN: create the session, send RESP(OK), hand the stream
 * over from the pending-open state to the session. */
static void
srv_open_success(mq_udp_open_t *op, const mq_udp_session_open_t *open,
                 struct sockaddr_storage *ss, socklen_t sslen, uint64_t eff_idle_ms)
{
    mq_udp_srv_t *u = op->u;

    int fd = socket(ss->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        MQ_LOGW("mq_udp_srv: socket: %s", strerror(errno));
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SOCKET_FAILED);
        return;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
        connect(fd, (struct sockaddr *)ss, sslen) != 0) {
        MQ_LOGW("mq_udp_srv: connect: %s", strerror(errno));
        close(fd);
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SOCKET_FAILED);
        return;
    }

    mq_udp_sess_t *sess = srv_alloc_session(u);
    if (!sess) {
        /* Lost the slot between the cap check and here (cannot happen single-
         * threaded, but fail closed). */
        close(fd);
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SESSION_LIMIT);
        return;
    }

    memset(sess, 0, sizeof(*sess));
    sess->used = 1;
    sess->session_id = open->session_id;
    sess->stream = op->stream;
    sess->fd = fd;
    sess->next_packet_id = 0;
    sess->owner = u;
    u->live_count++;

    /* Persistent EV_READ on the UDP socket (Task 5.2 callback). */
    sess->rd_ev = event_new(u->base, fd, EV_READ | EV_PERSIST, srv_udp_readable_cb, sess);
    if (!sess->rd_ev || event_add(sess->rd_ev, NULL) != 0) {
        MQ_LOGE("mq_udp_srv: EV_READ arm failed");
        /* Graceful: FIN'd error RESP so the client learns SOCKET_FAILED, then
         * reap WITHOUT a RESET (which would drop the un-acked RESP). The stream
         * still carries the pending-open callbacks (user = op, freed below);
         * detach them before reap so the later close-notify cannot fire
         * srv_open_closed_cb on the freed op. sess->graceful makes reap skip the
         * RESET; reap still closes fd + frees rd_ev + decrements live_count +
         * nulls the stream + resets the slot. */
        srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, MQ_UDP_SOCKET_FAILED, 0,
                          /*fin=*/1);
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
        sess->graceful = 1;
        srv_reap_session(sess);
        srv_open_free(op);
        return;
    }

    /* Re-point the stream callbacks at the live-session handlers. The session
     * now owns the stream; the pending-open state is freed. */
    mq_stream_set_cbs(op->stream, srv_stream_readable_cb, NULL, srv_stream_closed_cb,
                      sess);

    /* Arm the idle timer to the per-session effective (min) value. Task 5.2
     * re-arms it on every bidirectional activity. */
    {
        struct timeval tv;
        tv.tv_sec = (time_t)(eff_idle_ms / 1000);
        tv.tv_usec = (suseconds_t)((eff_idle_ms % 1000) * 1000);
        sess->idle_ev = evtimer_new(u->base, srv_idle_expired_cb, sess);
        if (!sess->idle_ev || evtimer_add(sess->idle_ev, &tv) != 0) {
            MQ_LOGE("mq_udp_srv: idle timer arm failed");
            /* Graceful: FIN'd error RESP so the client learns SOCKET_FAILED, then
             * reap WITHOUT a RESET (which would drop the un-acked RESP).
             * Callbacks were just re-pointed at the live-session handlers (user =
             * sess); detach them before reap so the later close-notify cannot
             * fire srv_stream_closed_cb with a reaped sess. sess->graceful makes
             * reap skip the RESET and just null the stream. */
            srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, MQ_UDP_SOCKET_FAILED, 0,
                              /*fin=*/1);
            mq_stream_set_cbs(sess->stream, NULL, NULL, NULL, NULL);
            sess->graceful = 1;
            srv_reap_session(sess);
            srv_open_free(op);
            return;
        }
    }

    srv_send_udp_resp(op->stream, MQ_STATUS_OK, MQ_UDP_OK, eff_idle_ms, /*fin=*/0);
    MQ_LOGI("mq_udp_srv: session %u OPEN ok (idle=%llums)", open->session_id,
            (unsigned long long)eff_idle_ms);

    srv_open_free(op);
}

static void
srv_open_readable_cb(mq_stream_t *s, void *user)
{
    mq_udp_open_t *op = (mq_udp_open_t *)user;
    if (op->settled) {
        /* Shouldn't fire (callbacks are re-pointed on success / freed on error),
         * but drain defensively. */
        uint8_t scratch[256];
        int fin = 0;
        while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
        return;
    }

    mq_framebuf_fill(s, &op->rx, NULL);

    mq_udp_session_open_t open;
    int consumed = mq_decode_udp_session_open(op->rx.buf, op->rx.len, &open);
    if (consumed < 0) {
        if (op->rx.len >= sizeof(op->rx.buf)) {
            MQ_LOGW("mq_udp_srv: UDP_SESSION_OPEN malformed/oversized, resetting");
            op->settled = 1;
            /* Malformed OPEN: silent reset (no decodable session to RESP to). */
            srv_open_reject(op, /*send_resp=*/0, MQ_UDP_OK);
        }
        return; /* need more bytes */
    }

    /* Invariant: the 0x02 control stream carries exactly ONE OPEN message.
     * After that single frame, this stream is a pure control handle — any
     * trailing or subsequent bytes are intentionally ignored.  UDP payload
     * rides DATAGRAM frames, not this stream; stream close signals session
     * close.  `consumed` therefore need not be acted upon. */
    (void)consumed;

    /* OPEN decoded — this stream is now settled regardless of outcome. */
    op->settled = 1;
    mq_udp_srv_t *u = op->u;

    /* Duplicate-SID detection (decode-direct, BEFORE socket creation): if the
     * session_id is already live, RESET the new stream with NO RESP and leave
     * the existing session entirely untouched. */
    if (srv_find_session(u, open.session_id) != NULL) {
        MQ_LOGW("mq_udp_srv: duplicate session_id %u, resetting new stream (no RESP)",
                open.session_id);
        srv_open_reject(op, /*send_resp=*/0, MQ_UDP_OK);
        return;
    }

    /* Policy gate: --no-udp ⇒ deny. */
    if (!u->enabled) {
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_POLICY_DENIED);
        return;
    }

    /* Session-table cap. */
    if (u->live_count >= MQ_UDP_SRV_MAX_SESSIONS) {
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SESSION_LIMIT);
        return;
    }

    /* Resolve (blocking getaddrinfo for DOMAIN). */
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    mq_udp_err_t rerr = MQ_UDP_DNS_FAILED;
    if (srv_resolve_udp_target(&open, &ss, &sslen, &rerr) != 0) {
        srv_open_reject(op, /*send_resp=*/1, rerr);
        return;
    }

    /* Effective idle timeout = min(client requested or server default if 0,
     * server setting). */
    uint64_t requested = open.idle_timeout_ms ? open.idle_timeout_ms : u->idle_timeout_ms;
    uint64_t eff = requested < u->idle_timeout_ms ? requested : u->idle_timeout_ms;

    srv_open_success(op, &open, &ss, sslen, eff);
}

/* ── public API ────────────────────────────────────────────────────────── */

mq_udp_srv_t *
mq_udp_srv_new(mq_conn_t *c, struct event_base *base, uint64_t idle_timeout_ms,
               int enabled)
{
    mq_udp_srv_t *u = calloc(1, sizeof(*u));
    if (!u) {
        return NULL;
    }
    u->conn = c;
    u->base = base;
    u->idle_timeout_ms = idle_timeout_ms;
    u->enabled = enabled;
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        u->sessions[i].fd = -1;
    }
    return u;
}

void
mq_udp_srv_free(mq_udp_srv_t *u)
{
    if (!u) {
        return;
    }
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (u->sessions[i].used) {
            srv_reap_session(&u->sessions[i]);
        }
    }
    free(u);
}

void
mq_udp_srv_attach_stream(mq_udp_srv_t *u, mq_stream_t *s, const uint8_t *carry,
                         size_t carry_len)
{
    mq_udp_open_t *op = calloc(1, sizeof(*op));
    if (!op) {
        MQ_LOGE("mq_udp_srv: OOM allocating pending-open state");
        mq_stream_close(s);
        return;
    }
    op->u = u;
    op->stream = s;
    op->settled = 0;

    /* Seed the OPEN framebuf with the carry-over bytes the server's stream-type
     * dispatch already pulled off the stream (the OPEN body that trailed the
     * 0x02 discriminator — client sends them in one send). Bounded by
     * MQ_FRAMEBUF_CAP; clamp defensively. */
    if (carry && carry_len > 0) {
        size_t n = carry_len > sizeof(op->rx.buf) ? sizeof(op->rx.buf) : carry_len;
        memcpy(op->rx.buf, carry, n);
        op->rx.len = n;
    }

    mq_stream_set_cbs(s, srv_open_readable_cb, NULL, srv_open_closed_cb, op);

    /* Try decoding immediately (carry-over may already hold the full OPEN);
     * else accumulate more from the stream on later readability. */
    srv_open_readable_cb(s, op);
}

void
mq_udp_srv_on_datagram(mq_udp_srv_t *u, const uint8_t *data, size_t len)
{
    (void)u;
    (void)data;
    (void)len;
    /* Task 5.2: demux by session_id, defrag, send to target, re-arm idle. */
}
