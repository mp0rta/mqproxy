// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_client.c — proxy client + control-stream AUTH handshake.
 *
 * Flow:
 *   mq_client_start -> mq_conn_connect (ALPN "mqproxy-tcp/1")
 *   on ESTABLISHED  -> open control stream, send AUTH_REQUEST (no FIN)
 *   on control stream readable -> accumulate bytes, retry mq_decode_auth_resp
 *                                 until it succeeds; report via on_auth.
 *
 * The control stream stays open after auth so Tasks 12/13 can reuse it.
 */
#include "proxy/mq_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_flow.h"
#include "proxy/mq_framebuf.h"
#include "proxy/mq_udp_session.h"
#include "transport/mq_stream.h"
#include "util/mq_backoff.h"
#include "util/mq_log.h"
#include "wire/mq_wire.h"

#define MQ_CLIENT_ALPN "mqproxy-tcp/1"

/* The buffered AUTH_RESPONSE / CONNECT_TCP_RESPONSE is bounded by
 * MQ_FRAMEBUF_CAP (512): both frames are tiny (status + error + small fields),
 * well under that. Exceeding the bound without a valid decode is malformed
 * (Phase 1: fail closed). */

/* Bound on pre-auth queued tcp_open requests. Beyond this we fail-fast new
 * opens (cb with CONN_REFUSED) rather than grow unboundedly. */
#define MQ_CLIENT_QUEUE_MAX 256

/* Extra (non-primary) local-bind IPs the CLI's --path args request. Each is
 * brought up as its own MPQUIC path once the conn is multipath-ready. */
#define MQ_CLIENT_MAX_PATHS 8
/* Max length of a stored bind IP literal (v4/v6). */
#define MQ_CLIENT_IP_MAX 64
/* Poll interval (ms) for the mp-ready deferral timer. */
#define MQ_CLIENT_MP_POLL_MS 50
/* Base delay (ms) for the reconnect exponential backoff. */
#define MQ_CLIENT_RECONNECT_BASE_MS 250

typedef struct mq_client_open_s mq_client_open_t;

/* A queued (pre-auth) tcp_open request. The host/port/atype/local_fd/cb/user are
 * captured verbatim and replayed once auth succeeds. */
struct mq_client_open_s {
    uint8_t host[MQ_MAX_HOST];
    size_t host_len;
    mq_addr_type_t atype;
    uint16_t port;
    int local_fd;
    /* App bytes the ingress read coalesced with the request head (owned copy,
     * freed on drain/fail); replayed into the flow's B-side prebuffer. */
    uint8_t *early;
    size_t early_len;
    void *user;
    mq_tcp_open_cb cb;
    mq_client_open_t *next;
};

/* An in-flight tcp_open: a data stream awaiting / relaying after the
 * CONNECT_TCP_RESPONSE. Two phases:
 *   1. Header: buffer stream bytes until CONNECT_TCP_RESPONSE decodes.
 *      On OK → fire cb(ok), start an mq_flow relay (stream ⇄ local_fd).
 *      On ERROR/malformed → fire cb(err), close stream + local_fd.
 *   2. Relaying: mq_flow drives the relay; on completion/teardown the flow
 *      closes the stream + local_fd and reaps this node. */
struct mq_client_data_s {
    struct mq_client_s *cli;
    mq_flow_t *flow;     /* relay node (owns stream + local_fd once relaying) */
    mq_stream_t *stream; /* header phase: the data stream (also held by flow) */
    int local_fd;        /* app socket; handed to the flow on relay start */
    int reaped;
    int resp_done; /* the response was decoded + cb fired */

    /* App bytes the ingress read coalesced with the request head (owned copy,
     * freed once injected into the flow's B-side prebuffer or on reap). */
    uint8_t *early;
    size_t early_len;

    void *user;
    mq_tcp_open_cb cb;

    mq_framebuf_t rx;

    struct mq_client_data_s *next;
};
typedef struct mq_client_data_s mq_client_data_t;

struct mq_client_s {
    mq_transport_t *transport;
    mq_runtime_t *rt;
    mq_cc_t cc; /* congestion control for this client's conn */
    char server_ip[64];
    uint16_t server_port;

    mq_auth_req_t req; /* prebuilt AUTH_REQUEST fields */

    mq_conn_t *conn;
    mq_stream_t *ctrl; /* control stream */

    mq_client_on_auth_fn on_auth;
    void *on_auth_user;
    mq_conn_on_state_fn on_state;
    void *on_state_user;

    /* AUTH_RESPONSE accumulation buffer. */
    mq_framebuf_t rx;

    int authed;
    int auth_reported; /* on_auth fired exactly once */
    int closed;        /* connection reached CLOSED: no new opens */

    /* AUTH_RESPONSE.features saved at auth time (for mq_client_udp_available). */
    uint64_t auth_features;

    /* Per-connection UDP relay session table (client role). Created in
     * mq_client_start; driven on auth/conn-close; freed in mq_client_free. */
    mq_udp_cli_t *udp;

    /* Pre-auth queue (FIFO) + count. */
    mq_client_open_t *queue_head;
    mq_client_open_t *queue_tail;
    size_t queue_len;

    /* Active in-flight / relaying data streams. */
    mq_client_data_t *data_head;

    /* Keepalive: if > 0, enables xquic PING keepalive with this idle timeout. */
    uint64_t keepalive_idle_ms;

    /* Deferred extra paths (Task 19, CLI --path). Stored at mq_client_add_paths;
     * added via mq_conn_add_path once the conn is multipath-ready. A recurring
     * libevent timer (pending_paths > 0) polls mp-ready and adds them. */
    char extra_paths[MQ_CLIENT_MAX_PATHS][MQ_CLIENT_IP_MAX];
    size_t n_extra_paths;   /* total registered */
    size_t added_paths;     /* how many have been brought up so far */
    struct event *mp_timer; /* armed while paths remain to add */

    /* Reconnect controller (Phase 5b). reconnect_ev is created ONCE in
     * mq_client_start (when enabled) and freed ONLY in mq_client_free; it is a
     * one-shot timer re-armed across reconnect cycles, so it must survive a stop.
     * shutting_down is set FIRST by mq_client_free so a late MQ_CONN_CLOSED takes
     * the terminal path (no reconnect-after-free). */
    int shutting_down;
    int reconnect_enabled;
    uint64_t reconnect_max_backoff_ms;
    struct event *reconnect_ev;
    unsigned reconnect_attempts;
};

/* Forward decl: the mp-ready deferral timer teardown is referenced from
 * client_on_state (CLOSED) but defined below near the other path-add helpers. */
static void client_mp_timer_stop(mq_client_t *c);
static void client_mp_timer_arm(mq_client_t *c);

/* Forward decls: the reconnect controller is referenced from client_on_state /
 * client_report_auth but its arm path needs client_issue_connect (defined below).
 * client_issue_connect itself is declared here so client_reconnect_cb can call it. */
static int client_issue_connect(mq_client_t *c);
static void client_reconnect_arm(mq_client_t *c);
static void client_reconnect_stop(mq_client_t *c);

/* Bridge mq_conn's datagram callback (mq_conn_t* + user) to the UDP relay
 * client role's dispatch (mq_udp_cli_t* first arg). user is the mq_client_t*. */
static void
client_on_datagram(mq_conn_t *conn, const uint8_t *data, size_t len, void *user)
{
    (void)conn;
    mq_client_t *c = (mq_client_t *)user;
    if (c && c->udp) {
        mq_udp_cli_on_datagram(c->udp, data, len);
    }
}

/* ── in-flight data-stream nodes ─────────────────────────────────────────── */

static void
client_data_unlink(mq_client_data_t *d)
{
    mq_client_t *c = d->cli;
    mq_client_data_t **pp = &c->data_head;
    while (*pp) {
        if (*pp == d) {
            *pp = d->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Reap a data node exactly once. In the relay phase the flow owns the stream +
 * local_fd and closes both; pre-relay we close them directly here. Idempotent. */
static void
client_data_reap(mq_client_data_t *d)
{
    if (!d || d->reaped) {
        return;
    }
    d->reaped = 1;

    if (d->flow) {
        mq_flow_t *fl = d->flow;
        d->flow = NULL;
        d->stream = NULL;
        d->local_fd = -1;
        mq_flow_reap(fl);
    } else {
        if (d->stream) {
            mq_stream_set_cbs(d->stream, NULL, NULL, NULL, NULL);
            mq_stream_close(d->stream);
            d->stream = NULL;
        }
        if (d->local_fd >= 0) {
            close(d->local_fd);
            d->local_fd = -1;
        }
    }
    free(d->early);
    d->early = NULL;
    d->early_len = 0;
    client_data_unlink(d);
    free(d);
}

/* Flow reap callback: the relay closed stream + local_fd. Drop our pointers and
 * reap the node. Guarded by d->reaped against the srv-style re-entry. */
static void
client_flow_on_reap(mq_flow_t *fl, void *user)
{
    (void)fl;
    mq_client_data_t *d = (mq_client_data_t *)user;
    d->flow = NULL;
    d->stream = NULL;
    d->local_fd = -1;
    client_data_reap(d);
}

/* Fire the open's cb exactly once. */
static void
client_data_report(mq_client_data_t *d, int ok, mq_tcp_err_t err)
{
    if (d->resp_done) {
        return;
    }
    d->resp_done = 1;
    if (d->cb) {
        d->cb(ok, err, d->user);
    }
}

/* Header phase: stream readable — buffer bytes, decode CONNECT_TCP_RESPONSE. */
static void
client_data_header_readable(mq_stream_t *s, void *user)
{
    mq_client_data_t *d = (mq_client_data_t *)user;

    int fin = 0;
    if (mq_framebuf_fill(s, &d->rx, &fin) < 0) {
        /* Hard error / RESET before a response: fail the open. */
        client_data_report(d, 0, MQ_TCP_CONN_REFUSED);
        client_data_reap(d);
        return;
    }

    mq_connect_tcp_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    int consumed = mq_decode_connect_tcp_resp(d->rx.buf, d->rx.len, &resp);
    if (consumed < 0) {
        if (d->rx.len >= sizeof(d->rx.buf) || fin) {
            /* Oversized or stream FIN'd without a valid response: malformed. */
            MQ_LOGW("mq_client: CONNECT_TCP_RESPONSE malformed/oversized");
            client_data_report(d, 0, MQ_TCP_CONN_REFUSED);
            client_data_reap(d);
        }
        return; /* otherwise need more bytes */
    }

    if (resp.status != MQ_STATUS_OK) {
        /* Error response: report the server's code, close stream + local_fd. */
        client_data_report(d, 0, resp.error_code);
        client_data_reap(d);
        return;
    }

    /* OK. Report success first (the ingress sends its app-side success reply),
     * then start the relay binding the stream ⇄ local_fd. */
    client_data_report(d, 1, MQ_TCP_OK);

    struct event_base *base = mq_runtime_base(d->cli->rt);
    d->flow = mq_flow_new(&d->flow, base, d->stream, d->local_fd, client_flow_on_reap, d);
    if (!d->flow) {
        MQ_LOGE("mq_client: flow alloc failed");
        client_data_reap(d);
        return;
    }
    /* The flow owns the stream + local_fd now. */
    d->local_fd = -1;

    /* CRITICAL: while buffering the response we may have pulled payload bytes
     * that trailed the CONNECT_TCP_RESPONSE in the same read into rx.buf. The
     * relay reads fresh from the stream, so hand these leftover bytes to the
     * flow's prebuffer or they would be silently dropped (truncating the
     * download by exactly the trailing amount). */
    size_t consumed_sz = (size_t)consumed;
    if (d->rx.len > consumed_sz) {
        if (mq_flow_prebuffer(d->flow, d->rx.buf + consumed_sz,
                              d->rx.len - consumed_sz) != 0) {
            MQ_LOGE("mq_client: prebuffer failed");
            client_data_reap(d);
            return;
        }
    }

    /* Symmetric uplink case: app bytes the ingress read coalesced with the
     * SOCKS5/HTTP CONNECT request. Hand them to the flow's B-side prebuffer so
     * they reach the origin ahead of fresh local_fd reads (else the first upload
     * bytes — e.g. a TLS ClientHello — are silently dropped). */
    if (d->early_len > 0) {
        if (mq_flow_prebuffer_b(d->flow, d->early, d->early_len) != 0) {
            MQ_LOGE("mq_client: B-side prebuffer failed");
            client_data_reap(d);
            return;
        }
        free(d->early);
        d->early = NULL;
        d->early_len = 0;
    }

    if (mq_flow_begin_relay(d->flow) != 0) {
        MQ_LOGE("mq_client: begin relay failed");
        client_data_reap(d);
    }
}

/* Header-phase stream close: the stream closed before a response decoded. */
static void
client_data_header_closed(mq_stream_t *s, void *user)
{
    (void)s;
    mq_client_data_t *d = (mq_client_data_t *)user;
    d->stream = NULL; /* the transport frees it after this returns */
    /* If no response was decoded yet, fail the open. */
    client_data_report(d, 0, MQ_TCP_CONN_REFUSED);
    client_data_reap(d);
}

/* Issue an authed tcp_open: open a data stream, send CONNECT_TCP_REQUEST, and
 * buffer the response. local_fd ownership transfers to the new node (closed on
 * any terminal outcome). On a synchronous failure the cb fires and local_fd is
 * closed here. early/early_len are app bytes that arrived coalesced with the
 * request head; they are copied and replayed into the flow's B-side prebuffer
 * once the relay starts (borrowed for the duration of this call). */
static void
client_issue_open(mq_client_t *c, const uint8_t *host, size_t host_len,
                  mq_addr_type_t atype, uint16_t port, int local_fd, const uint8_t *early,
                  size_t early_len, void *user, mq_tcp_open_cb cb)
{
    mq_stream_t *s = mq_conn_open_stream(c->conn);
    if (!s) {
        MQ_LOGE("mq_client: open data stream failed");
        if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
        if (local_fd >= 0) close(local_fd);
        return;
    }

    mq_client_data_t *d = calloc(1, sizeof(*d));
    if (!d) {
        MQ_LOGE("mq_client: OOM allocating data node");
        mq_stream_close(s);
        if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
        if (local_fd >= 0) close(local_fd);
        return;
    }
    d->cli = c;
    d->stream = s;
    d->local_fd = local_fd;
    d->user = user;
    d->cb = cb;
    if (early_len > 0 && early) {
        d->early = malloc(early_len);
        if (!d->early) {
            MQ_LOGE("mq_client: OOM copying coalesced bytes");
            mq_stream_close(s);
            free(d);
            if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
            if (local_fd >= 0) close(local_fd);
            return;
        }
        memcpy(d->early, early, early_len);
        d->early_len = early_len;
    }
    d->next = c->data_head;
    c->data_head = d;

    mq_stream_set_cbs(s, client_data_header_readable, NULL, client_data_header_closed, d);

    mq_connect_tcp_req_t req;
    memset(&req, 0, sizeof(req));
    req.flags = 0;
    req.address_type = atype;
    if (host_len > MQ_MAX_HOST) host_len = MQ_MAX_HOST;
    memcpy(req.host, host, host_len);
    req.host_len = host_len;
    req.port = port;

    uint8_t buf[512];
    /* Prepend the data-stream type discriminator (design §5.2).  Byte 0 is
     * MQ_STREAM_TYPE_CONNECT_TCP (0x01) encoded as a 1-byte varint; the
     * CONNECT_TCP_REQUEST frame follows immediately at offset 1.  Both are
     * sent in one mq_stream_send call so the server's header phase sees a
     * contiguous buffer and does not have to handle a split discriminator. */
    buf[0] = (uint8_t)MQ_STREAM_TYPE_CONNECT_TCP;
    int n = mq_encode_connect_tcp_req(buf + 1, sizeof(buf) - 1, &req);
    if (n < 0) {
        MQ_LOGE("mq_client: encode CONNECT_TCP_REQUEST failed");
        client_data_report(d, 0, MQ_TCP_CONN_REFUSED);
        client_data_reap(d);
        return;
    }
    /* No FIN: keep the stream open for the response + bidirectional relay. */
    (void)mq_stream_send(s, buf, (size_t)(1 + n), /*fin=*/0);

    /* Bytes may already be buffered; try decoding now. */
    client_data_header_readable(s, d);
}

/* Drain the pre-auth queue (auth succeeded). */
static void
client_drain_queue(mq_client_t *c)
{
    mq_client_open_t *q = c->queue_head;
    c->queue_head = c->queue_tail = NULL;
    c->queue_len = 0;
    while (q) {
        mq_client_open_t *next = q->next;
        client_issue_open(c, q->host, q->host_len, q->atype, q->port, q->local_fd,
                          q->early, q->early_len, q->user, q->cb);
        free(q->early);
        free(q);
        q = next;
    }
}

/* Fail + free the whole pre-auth queue (connection died before auth). */
static void
client_fail_queue(mq_client_t *c, mq_tcp_err_t err)
{
    mq_client_open_t *q = c->queue_head;
    c->queue_head = c->queue_tail = NULL;
    c->queue_len = 0;
    while (q) {
        mq_client_open_t *next = q->next;
        if (q->cb) q->cb(0, err, q->user);
        if (q->local_fd >= 0) close(q->local_fd);
        free(q->early);
        free(q);
        q = next;
    }
}

static void
client_report_auth(mq_client_t *c, int ok, mq_auth_err_t err)
{
    if (c->auth_reported) {
        return;
    }
    c->auth_reported = 1;
    c->authed = ok ? 1 : 0;
    if (c->on_auth) {
        c->on_auth(ok, err, c->on_auth_user);
    }
    /* Drain queued opens now that the auth outcome is known. On success they are
     * issued; on failure they are failed (cb + close local_fd). */
    if (ok) {
        /* Back to SERVING: reset the backoff counter + disarm the reconnect timer
         * so the next loss starts from base again. */
        c->reconnect_attempts = 0;
        client_reconnect_stop(c);
        client_drain_queue(c);
    } else {
        client_fail_queue(c, MQ_TCP_CONN_REFUSED);
    }

    /* Drive the UDP relay glue with the now-known auth + capability outcome:
     * issue pending sessions' streams (ok && available) or fail them closed
     * (auth failure / capability denied). mq_client_udp_available() consults the
     * saved features + datagram mss; here authed is already set above. */
    if (c->udp) {
        int avail = (mq_client_udp_available(c) == 1);
        mq_udp_cli_on_auth(c->udp, ok, avail);
    }
}

/* Control-stream readable: pull bytes, retry decode. */
static void
client_ctrl_readable(mq_stream_t *s, void *user)
{
    mq_client_t *c = (mq_client_t *)user;
    if (c->auth_reported) {
        /* Auth already settled; drain to keep the stream from stalling. */
        uint8_t scratch[256];
        int fin = 0;
        while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
        return;
    }

    mq_framebuf_fill(s, &c->rx, NULL);

    mq_auth_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    int consumed = mq_decode_auth_resp(c->rx.buf, c->rx.len, &resp);
    if (consumed >= 0) {
        int ok = (resp.status == MQ_STATUS_OK);
        /* Save the advertised features BEFORE reporting so mq_client_udp_available
         * (and the UDP glue inside client_report_auth) sees them. */
        c->auth_features = resp.features;
        client_report_auth(c, ok, resp.error_code);
        return;
    }

    /* decode failed: could be "need more" or malformed. Phase 1: once we have
     * accumulated past a sane bound without a valid frame, treat as malformed. */
    if (c->rx.len >= sizeof(c->rx.buf)) {
        MQ_LOGW("mq_client: AUTH_RESPONSE exceeded %d bytes, treating as malformed",
                MQ_FRAMEBUF_CAP);
        client_report_auth(c, 0, MQ_AUTH_FAILED);
    }
}

/* Connection state: on ESTABLISHED, open control stream + send AUTH_REQUEST. */
static void
client_on_state(mq_conn_t *conn, mq_conn_state_t st, void *user)
{
    mq_client_t *c = (mq_client_t *)user;

    if (st == MQ_CONN_ESTABLISHED) {
        c->ctrl = mq_conn_open_stream(conn);
        if (!c->ctrl) {
            MQ_LOGE("mq_client: failed to open control stream");
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }
        mq_stream_set_cbs(c->ctrl, client_ctrl_readable, NULL, NULL, c);

        uint8_t buf[512];
        int n = mq_encode_auth_req(buf, sizeof(buf), &c->req);
        if (n < 0) {
            MQ_LOGE("mq_client: encode AUTH_REQUEST failed");
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }
        /* No FIN: keep the control stream open for the response. */
        long sent = mq_stream_send(c->ctrl, buf, (size_t)n, /*fin=*/0);
        if (sent < 0 || (size_t)sent != (size_t)n) {
            MQ_LOGE("mq_client: send AUTH_REQUEST short/failed (%ld of %d)", sent, n);
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }

        /* Re-arm multipath for this (possibly reconnected) conn: reset added_paths
         * so the mp-timer re-adds every registered extra path on the new conn.
         * Harmless on the first start (added_paths is already 0 and arm is a no-op
         * when n_extra_paths == 0). */
        c->added_paths = 0;
        client_mp_timer_arm(c);
    } else if (st == MQ_CONN_CLOSED) {
        /* Reap every active data node: fail any in-flight open whose response
         * never arrived (cb with an error), then close stream + local_fd once.
         * In-flight flows do NOT survive a tunnel loss (irreducible — design
         * §Non-goal); only NEW opens resume after reconnect. Iterate defensively
         * against the self-unlink. This runs identically on both branches. */
        while (c->data_head) {
            mq_client_data_t *d = c->data_head;
            client_data_report(d, 0, MQ_TCP_CONN_REFUSED);
            client_data_reap(d);
        }

        /* Decide reconnect vs terminal from shutting_down + reconnect_enabled
         * ONLY (NOT auth_reported/authed — those are reset below on the reconnect
         * path). reconnect_ev != NULL also guards the timer existing. */
        int reconnect_now =
            (!c->shutting_down && c->reconnect_enabled && c->reconnect_ev != NULL);

        if (reconnect_now) {
            /* Carry the pre-auth/serving open queue across to the next attempt:
             * do NOT report auth failure and do NOT fail the queue. Instead reset
             * the per-conn one-shot latches + conn-bound buffers so the next auth
             * cycle runs fresh (design §Per-conn state reset). */
            c->auth_reported = 0;
            c->authed = 0;
            c->auth_features = 0;
            c->closed = 0;
            c->ctrl = NULL;
            c->rx.len = 0;

            /* UDP: fail live/pending sessions w/ MQ_UDP_CLOSED + null the conn,
             * then clear the latch/mss cache so the table is ready for a fresh
             * auth cycle. conn stays NULL through the backoff window;
             * client_issue_connect re-wires it (mq_udp_cli_set_conn) at the
             * re-issued connect. */
            if (c->udp) {
                mq_udp_cli_on_conn_close(c->udp);
                mq_udp_cli_reset(c->udp);
            }

            c->conn = NULL;
            /* No more paths can be added on the dead conn; the new ESTABLISHED
             * re-arms after resetting added_paths. */
            client_mp_timer_stop(c);

            /* Arm the backoff timer to re-establish the conn. */
            client_reconnect_arm(c);
        } else {
            /* Terminal (shutting_down or reconnect disabled): today's behavior. */
            c->conn = NULL;
            c->ctrl = NULL;
            c->closed = 1;
            /* The conn is gone: no more paths can be added. Disarm the deferral
             * timer so it does not dereference the freed conn. */
            client_mp_timer_stop(c);
            /* If the connection died before auth settled, report failure (this
             * also fails any pre-auth queued opens). If auth already succeeded,
             * the queue is empty, but fail it defensively in case opens were
             * queued in a race. */
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            client_fail_queue(c, MQ_TCP_CONN_REFUSED);

            /* Fail every live/pending UDP relay session with MQ_UDP_CLOSED (a
             * non-OPEN-failure close — the assoc must not negative-cache on it).
             * If the conn died before auth, client_report_auth above already
             * failed the pending UDP sessions with POLICY_DENIED (auth failure);
             * on_conn_close is then a no-op (cli already settled). */
            if (c->udp) {
                mq_udp_cli_on_conn_close(c->udp);
            }
        }
    }

forward:
    if (c->on_state) {
        c->on_state(conn, st, c->on_state_user);
    }
}

mq_client_t *
mq_client_new(mq_transport_t *t, mq_runtime_t *rt, const char *server_ip,
              uint16_t server_port, const char *client_id, const char *auth_token,
              mq_cc_t cc)
{
    if (!t || !rt || !server_ip || !client_id || !auth_token) {
        return NULL;
    }
    mq_client_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->transport = t;
    c->rt = rt;
    c->cc = cc;
    c->server_port = server_port;
    snprintf(c->server_ip, sizeof(c->server_ip), "%s", server_ip);

    c->req.version = 1;
    c->req.features = 0;
    snprintf(c->req.client_id, sizeof(c->req.client_id), "%s", client_id);
    /* auth_token is not NUL-guaranteed-meaningful but encoded as a string field;
     * use the NUL-terminated length. */
    snprintf(c->req.auth_token, sizeof(c->req.auth_token), "%s", auth_token);
    c->keepalive_idle_ms = 30000; /* default 30 s; 0 = disable */
    /* Reconnect on by default (design §Config); 30 s backoff cap. */
    c->reconnect_enabled = 1;
    c->reconnect_max_backoff_ms = 30000;
    return c;
}

void
mq_client_set_reconnect(mq_client_t *c, int enabled, uint64_t max_backoff_ms)
{
    if (!c) {
        return;
    }
    c->reconnect_enabled = enabled ? 1 : 0;
    if (max_backoff_ms < 1000) {
        max_backoff_ms = 1000;
    }
    c->reconnect_max_backoff_ms = max_backoff_ms;
}

void
mq_client_set_keepalive(mq_client_t *c, uint64_t idle_ms)
{
    if (!c) {
        return;
    }
    c->keepalive_idle_ms = idle_ms;
}

void
mq_client_set_on_auth(mq_client_t *c, mq_client_on_auth_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_auth = fn;
    c->on_auth_user = user;
}

void
mq_client_set_on_state(mq_client_t *c, mq_conn_on_state_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_state = fn;
    c->on_state_user = user;
}

/* Build sockaddr + conn settings, call mq_conn_connect, wire on_state, and
 * (if c->udp is already live from a previous start) re-wire the UDP table and
 * datagram callback onto the new conn.  On the first start c->udp is NULL, so
 * the re-wire block is skipped; mq_client_start creates the table afterwards.
 * Returns 0 on success, -1 on failure. */
static int
client_issue_connect(mq_client_t *c)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c->server_port);
    if (inet_pton(AF_INET, c->server_ip, &sa.sin_addr) != 1) {
        MQ_LOGE("mq_client: bad server ip '%s'", c->server_ip);
        return -1;
    }

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;
    /* Enable QUIC DATAGRAM (Phase 3 UDP relay carrier) on this mqproxy-tcp/1
     * conn. u16 field; max advertises the largest frame we accept (xquic caps
     * the effective payload to the path MTU regardless). */
    settings.max_datagram_frame_size = 65535;
    /* PING keepalive: send periodic PINGs to keep the idle connection alive and
     * detect peer loss.  Disabled when keepalive_idle_ms == 0. Only the post-
     * handshake idle timeout is set here; init_idle_time_out is left at the
     * xquic default (pre-handshake idle, intentional). */
    settings.ping_on = (c->keepalive_idle_ms > 0) ? 1 : 0;
    if (c->keepalive_idle_ms > 0) {
        settings.idle_time_out = c->keepalive_idle_ms;
    }
    /* Multipath + aggregate-BDP flow-control windows (see mq_conn.h). */
    mq_conn_apply_mp_settings(&settings, /*is_server=*/0, c->cc);

    c->conn = mq_conn_connect(c->transport, (struct sockaddr *)&sa, sizeof(sa),
                              MQ_CLIENT_ALPN, &settings, c);
    if (!c->conn) {
        MQ_LOGE("mq_client: connect failed");
        return -1;
    }
    mq_conn_set_on_state(c->conn, client_on_state, c);

    /* On reconnect (c->udp already exists), re-wire the UDP session table and
     * datagram callback onto the new conn.  On first start c->udp is NULL here
     * (mq_client_start creates it after this call), so the block is a no-op. */
    if (c->udp) {
        mq_udp_cli_set_conn(c->udp, c->conn);
        mq_conn_set_on_datagram(c->conn, client_on_datagram, c);
    }

    return 0;
}

/* ── Reconnect controller (Phase 5b) ─────────────────────────────────────────
 *
 * reconnect_ev is created ONCE in mq_client_start and freed ONLY in
 * mq_client_free; it is a one-shot timer re-armed across reconnect cycles, so
 * stop() must NOT free it (unlike the mp-timer). */

/* Disarm the backoff timer (idempotent). Does NOT free reconnect_ev — it must
 * survive for the next reconnect cycle (freed only in mq_client_free). */
static void
client_reconnect_stop(mq_client_t *c)
{
    if (c->reconnect_ev) {
        evtimer_del(c->reconnect_ev);
    }
}

/* Arm the one-shot backoff timer for the next reconnect attempt. Exponential
 * (base 250 ms, cap reconnect_max_backoff_ms) with full jitter + a floor:
 * the delay is randomised into [d/2, d] so the re-arm cannot land near zero and
 * spin. */
static void
client_reconnect_arm(mq_client_t *c)
{
    if (!c->reconnect_ev) {
        return;
    }
    c->reconnect_attempts++;
    uint64_t d = mq_backoff_ms(MQ_CLIENT_RECONNECT_BASE_MS, c->reconnect_max_backoff_ms,
                               c->reconnect_attempts);
    /* jitter into [d/2, d] (half-jitter with a d/2 floor to avoid near-zero re-spin). */
    uint64_t j = d / 2 + (uint64_t)(random() % (long)(d / 2 + 1));
    struct timeval tv = {.tv_sec = (time_t)(j / 1000),
                         .tv_usec = (suseconds_t)((j % 1000) * 1000)};
    evtimer_add(c->reconnect_ev, &tv);
}

/* Backoff timer fired: re-issue the connect. If the connect itself fails
 * (mq_conn_connect returned NULL), re-arm with the next backoff rather than
 * going terminal — an always-on device must self-heal across long outages. */
static void
client_reconnect_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_client_t *c = (mq_client_t *)arg;
    if (client_issue_connect(c) != 0) {
        client_reconnect_arm(c);
    }
}

int
mq_client_start(mq_client_t *c)
{
    if (!c) {
        return -1;
    }

    /* Register the client ALPN (no server-side hooks). Idempotency: registering
     * twice on one engine is not supported, so this assumes one client per
     * engine, which matches the proxy's usage. */
    if (mq_conn_register_alpn(c->transport, MQ_CLIENT_ALPN, NULL, NULL, NULL) != 0) {
        MQ_LOGE("mq_client: register_alpn failed");
        return -1;
    }

    /* Create the reconnect backoff timer ONCE (when enabled). It is one-shot,
     * armed only from the CLOSED handler, disarmed on reaching SERVING + on
     * shutdown, and freed only in mq_client_free. */
    if (c->reconnect_enabled) {
        c->reconnect_ev = evtimer_new(mq_runtime_base(c->rt), client_reconnect_cb, c);
        if (!c->reconnect_ev) {
            MQ_LOGW("mq_client: reconnect timer alloc failed (reconnect disabled)");
        }
    }

    if (client_issue_connect(c) != 0) {
        return -1;
    }

    /* Per-connection UDP relay session table (client role) + datagram dispatch.
     * Created here so opens may be queued pre-auth; freed in mq_client_free.
     * Non-fatal on OOM: the client still serves TCP, and UDP opens fail with a
     * NULL handle (mq_udp_cli_open on a NULL core returns NULL). */
    c->udp = mq_udp_cli_new(c->conn, mq_runtime_base(c->rt));
    if (c->udp) {
        mq_conn_set_on_datagram(c->conn, client_on_datagram, c);
    } else {
        MQ_LOGW("mq_client: UDP relay session table alloc failed (TCP-only)");
    }
    return 0;
}

int
mq_client_is_authed(const mq_client_t *c)
{
    return c ? c->authed : 0;
}

mq_conn_t *
mq_client_conn(const mq_client_t *c)
{
    return c ? c->conn : NULL;
}

/* ── Multipath: bring up deferred extra paths once mp-ready (Task 19) ───────── */

/* Disarm + free the mp-ready deferral timer (idempotent). */
static void
client_mp_timer_stop(mq_client_t *c)
{
    if (c->mp_timer) {
        event_free(c->mp_timer);
        c->mp_timer = NULL;
    }
}

/* Recurring timer: once the conn is multipath-ready, add every still-pending
 * extra path (each on an ephemeral local UDP port), then disarm. Disarms early
 * if the connection went away. */
static void
client_mp_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_client_t *c = (mq_client_t *)arg;

    if (c->closed || !c->conn) {
        client_mp_timer_stop(c);
        return;
    }
    if (!mq_conn_mp_ready(c->conn)) {
        return; /* not ready yet; the persistent timer will fire again */
    }

    while (c->added_paths < c->n_extra_paths) {
        const char *ip = c->extra_paths[c->added_paths];
        int pid = mq_conn_add_path(c->conn, ip, /*local_port=0 -> ephemeral*/ 0);
        /* mq_conn_add_path returns the new path_id (>= 0) on success, or the
         * documented failure sentinel -1. Treat any non-negative id as success
         * so a path_id of 0 is not mis-logged as a failure. */
        if (pid >= 0) {
            MQ_LOGI("mq_client: extra path up: bind %s -> path_id %d", ip, pid);
        } else {
            MQ_LOGW("mq_client: failed to add extra path bind %s (path_id rc=%d)", ip,
                    pid);
        }
        c->added_paths++; /* advance regardless: do not spin on a bad bind */
    }
    /* All pending paths processed — disarm. */
    client_mp_timer_stop(c);
}

/* Arm the recurring mp-ready timer if there is pending work and it is not yet
 * armed. Safe to call repeatedly. */
static void
client_mp_timer_arm(mq_client_t *c)
{
    if (c->mp_timer || c->added_paths >= c->n_extra_paths) {
        return;
    }
    struct event_base *base = mq_runtime_base(c->rt);
    if (!base) {
        return;
    }
    c->mp_timer = event_new(base, -1, EV_PERSIST, client_mp_timer_cb, c);
    if (!c->mp_timer) {
        MQ_LOGE("mq_client: failed to create mp-ready timer");
        return;
    }
    struct timeval tv = {.tv_sec = 0, .tv_usec = MQ_CLIENT_MP_POLL_MS * 1000};
    event_add(c->mp_timer, &tv);
}

int
mq_client_add_paths(mq_client_t *c, const char *const *ips, size_t n)
{
    if (!c || (n > 0 && !ips)) {
        return -1;
    }
    size_t accepted = 0;
    for (size_t i = 0; i < n; i++) {
        if (!ips[i]) {
            continue;
        }
        if (c->n_extra_paths >= MQ_CLIENT_MAX_PATHS) {
            MQ_LOGW("mq_client: extra-path capacity %d reached; ignoring %s",
                    MQ_CLIENT_MAX_PATHS, ips[i]);
            break;
        }
        snprintf(c->extra_paths[c->n_extra_paths], MQ_CLIENT_IP_MAX, "%s", ips[i]);
        c->n_extra_paths++;
        accepted++;
    }
    /* Arm the deferral timer if the runtime base is available (after
     * mq_client_new it is). Harmless if there is no pending work. */
    client_mp_timer_arm(c);
    return (int)accepted;
}

/* Enqueue a pre-auth tcp_open. Returns 0 on success, -1 if the queue is full. */
static int
client_enqueue_open(mq_client_t *c, const uint8_t *host, size_t host_len,
                    mq_addr_type_t atype, uint16_t port, int local_fd,
                    const uint8_t *early, size_t early_len, void *user, mq_tcp_open_cb cb)
{
    if (c->queue_len >= MQ_CLIENT_QUEUE_MAX) {
        return -1;
    }
    mq_client_open_t *q = calloc(1, sizeof(*q));
    if (!q) {
        return -1;
    }
    if (early_len > 0 && early) {
        q->early = malloc(early_len);
        if (!q->early) {
            free(q);
            return -1;
        }
        memcpy(q->early, early, early_len);
        q->early_len = early_len;
    }
    if (host_len > MQ_MAX_HOST) host_len = MQ_MAX_HOST;
    memcpy(q->host, host, host_len);
    q->host_len = host_len;
    q->atype = atype;
    q->port = port;
    q->local_fd = local_fd;
    q->user = user;
    q->cb = cb;
    q->next = NULL;
    if (c->queue_tail) {
        c->queue_tail->next = q;
    } else {
        c->queue_head = q;
    }
    c->queue_tail = q;
    c->queue_len++;
    return 0;
}

void
mq_client_tcp_open(void *core, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                   uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
                   void *user, mq_tcp_open_cb cb)
{
    mq_client_t *c = (mq_client_t *)core;
    if (!c || !host) {
        if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
        if (local_fd >= 0) close(local_fd);
        return;
    }
    /* Admission (Phase 5b reconnect-aware ordering):
     *   closed (terminal)         → fail fast.
     *   not authed                → enqueue (pre-auth OR reconnect window: conn
     *                               may be NULL; client_enqueue_open does not
     *                               dereference c->conn — it only queues). The
     *                               queue drains on the next auth OK (carried
     *                               across a reconnect loss).
     *   authed but no conn (race) → fail fast (narrow authed-mid-teardown guard;
     *                               do not simplify away).
     *   authed + conn             → issue immediately. */
    if (c->closed) {
        if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
        if (local_fd >= 0) close(local_fd);
    } else if (!c->authed) {
        if (client_enqueue_open(c, host, host_len, atype, port, local_fd, prebuf,
                                prebuf_len, user, cb) != 0) {
            MQ_LOGW("mq_client: tcp_open queue full, rejecting");
            if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
            if (local_fd >= 0) close(local_fd);
        }
    } else if (!c->conn) {
        if (cb) cb(0, MQ_TCP_CONN_REFUSED, user);
        if (local_fd >= 0) close(local_fd);
    } else {
        client_issue_open(c, host, host_len, atype, port, local_fd, prebuf, prebuf_len,
                          user, cb);
    }
}

mq_tcp_open_fn
mq_client_tcp_open_fn(void)
{
    return mq_client_tcp_open;
}

void *
mq_client_tcp_open_core(mq_client_t *c)
{
    return c;
}

/* ── UDP relay boundary getters + capability ─────────────────────────────── */

mq_udp_open_fn
mq_client_udp_open_fn(void)
{
    return mq_udp_cli_open;
}

mq_udp_send_fn
mq_client_udp_send_fn(void)
{
    return mq_udp_cli_send;
}

mq_udp_close_fn
mq_client_udp_close_fn(void)
{
    return mq_udp_cli_close;
}

void *
mq_client_udp_open_core(mq_client_t *c)
{
    /* The mq_udp_open_fn `core` is the mq_udp_cli_t* (the concrete relay table),
     * not the mq_client_t* — open/send/close operate directly on the cli role.
     * Returns NULL before mq_client_start (no conn / no table yet). */
    return c ? c->udp : NULL;
}

int
mq_client_udp_available(const mq_client_t *c)
{
    if (!c) {
        return 0;
    }
    if (!c->authed) {
        /* Pre-auth (or auth not yet settled): undetermined — admit optimistically.
         * Once CLOSED without auth, authed stays 0 and we report unavailable via
         * the auth-failure path; callers gate new opens on mq_client_conn() too. */
        if (c->auth_reported) {
            return 0; /* auth settled as failure */
        }
        return -1;
    }
    /* Authed: capability = server advertised MQ_FEAT_UDP_RELAY AND the conn's
     * datagram channel is usable (mss > 0). */
    if (!(c->auth_features & MQ_FEAT_UDP_RELAY)) {
        return 0;
    }
    if (!c->conn || mq_conn_datagram_mss(c->conn) == 0) {
        return 0;
    }
    return 1;
}

void
mq_client_free(mq_client_t *c)
{
    if (!c) {
        return;
    }
    /* (1) Mark teardown FIRST so a late MQ_CONN_CLOSED takes the terminal path
     * (no reconnect-after-free). (2) Disarm the backoff timer, then (3) free it.
     * (4) Detach the conn state callback so a late CLOSED (the engine frees the
     * conn after us, in some teardown orders) cannot re-enter client_on_state and
     * dereference the freed c. Only then run the existing teardown. */
    c->shutting_down = 1;
    client_reconnect_stop(c);
    if (c->reconnect_ev) {
        event_free(c->reconnect_ev);
        c->reconnect_ev = NULL;
    }
    if (c->conn) {
        mq_conn_set_on_state(c->conn, NULL, NULL);
    }
    /* Disarm the mp-ready deferral timer (no-op if already stopped). */
    client_mp_timer_stop(c);
    /* Free any still-queued opens (no cb: the owner is tearing down). The active
     * data nodes are reaped via the conn CLOSED path before the engine frees the
     * conn; by the time mq_client_free runs they should be gone. Fail defensively
     * in case free is called without a prior CLOSED. */
    client_fail_queue(c, MQ_TCP_CONN_REFUSED);
    while (c->data_head) {
        client_data_report(c->data_head, 0, MQ_TCP_CONN_REFUSED);
        client_data_reap(c->data_head);
    }
    /* Free the UDP relay session table (reaps any remaining sessions WITHOUT
     * firing on_err — the owner is tearing down, not a remote failure). */
    mq_udp_cli_free(c->udp);
    c->udp = NULL;
    free(c);
}
