// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_h3.h — wrapper exposing xquic's built-in HTTP/3 stack at the sans-io
 * transport core boundary (design §6.3 / §14 / §24).
 *
 * mq_h3 is the H3 counterpart of mq_conn + mq_stream: where those wrap raw
 * MPQUIC conns/streams for the "mqproxy-tcp/1" ALPN, mq_h3 wraps xquic's H3
 * conns/requests for the "h3"/"h3-29" ALPN. xquic owns the H3 framing, QPACK,
 * and control streams; mq_h3 only adds an owner-facing wrapper, a connection
 * recovery table, multipath plumbing (shared with mq_conn), and the send/recv
 * normalisation the proxy expects.
 *
 * USER_DATA SCHEME (CRITICAL — see the ABSOLUTE RULES below):
 *   - transport user_data  = the mq_transport_t*  (so write_socket_ex recovers
 *                            the transport by casting the conn's user_data).
 *   - h3 conn user_data     = ALSO the mq_transport_t*. xquic's internal H3
 *                            ALPN sets the H3 conn's user_data = the transport
 *                            user_data; our h3 conn callbacks therefore receive
 *                            the TRANSPORT pointer as h3c_user_data, NOT our
 *                            wrapper. We recover the mq_h3_conn wrapper from a
 *                            small fixed table keyed by xqc_h3_conn_t*.
 *   - h3 request user_data  = the mq_h3_req_t* (an independent, per-stream slot,
 *                            safe to own). Set at create on the client side and
 *                            via xqc_h3_request_set_user_data on the server side.
 *
 * ABSOLUTE RULES (violating the first two corrupts the send path):
 *   1. NEVER call xqc_h3_conn_set_user_data — it overwrites the conn's
 *      transport user_data slot (xqc_h3_conn.c sets transport_user_data), and
 *      mq_transport_write_socket_ex casts that slot to mq_transport_t*. The
 *      transport user_data must stay = mq_transport_t* forever. The client
 *      passes the transport as xqc_h3_connect's user_data; the server's
 *      transport user_data is already bound by mq_transport_server_accept.
 *   2. NEVER call xqc_engine_set_priv_ctx — that slot belongs to the
 *      "mqproxy-tcp/1" ALPN registration owned by mq_conn.
 *
 * LIFETIME / ORDERING:
 *   - The caller MUST free the mq_h3 (mq_h3_free) BEFORE mq_transport_free,
 *     because mq_h3_free destroys the H3 ctx (xqc_h3_ctx_destroy), which
 *     unregisters the H3 ALPNs and frees the H3 ctx via the still-live engine;
 *     mq_transport_free then destroys the engine.
 *   - One mq_h3 per transport (xqc_h3_ctx_init re-registers the H3 ALPN, so it
 *     is not idempotent); mq_h3_init guards against a double init.
 */
#ifndef MQ_TRANSPORT_MQ_H3_H
#define MQ_TRANSPORT_MQ_H3_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>

#include "transport/mq_conn.h" /* mq_cc_t */
#include "transport/mq_transport.h"

typedef struct mq_h3_s mq_h3_t;
typedef struct mq_h3_conn_s mq_h3_conn_t;
typedef struct mq_h3_req_s mq_h3_req_t;

/* Server-side hooks. on_conn fires when xquic accepts a peer H3 connection;
 * on_req fires when a peer opens an H3 request on an accepted connection. Both
 * may be NULL on a pure client. The yielded wrapper is freshly created; the
 * owner attaches its own context via mq_h3_req_set_cbs (requests) and may stash
 * state through the wrapper. */
typedef void (*mq_h3_on_new_conn_fn)(mq_h3_conn_t *c, void *user);
typedef void (*mq_h3_on_new_req_fn)(mq_h3_req_t *r, void *user);

/* Initialise the H3 stack on `t`'s engine and register the H3 ALPN callbacks.
 * on_conn / on_req / user are the server-side surfacing hooks (NULL on a pure
 * client). Returns a new mq_h3, or NULL on failure or if `t` already has an
 * mq_h3 (one per transport — xqc_h3_ctx_init is not idempotent). The returned
 * mq_h3 MUST be freed (mq_h3_free) before mq_transport_free. */
mq_h3_t *mq_h3_init(mq_transport_t *t, mq_h3_on_new_conn_fn on_conn,
                    mq_h3_on_new_req_fn on_req, void *user);

/* Destroy the H3 ctx and free the mq_h3. MUST run before mq_transport_free
 * (the H3 ctx is destroyed via the still-live engine). Any conn wrappers still
 * in the recovery table are freed by their h3_conn_close_notify during the
 * engine teardown in mq_transport_free, NOT here. */
void mq_h3_free(mq_h3_t *h);

/* ── Connection ─────────────────────────────────────────────────────────── */

/* Connection lifecycle reported to the owner. established!=0 once the H3
 * handshake finished; established==0 once the connection closed (the
 * mq_h3_conn is freed immediately after this callback returns). */
typedef void (*mq_h3_conn_state_fn)(mq_h3_conn_t *c, int established, void *user);

/* Client: initiate an H3 connection to `peer` with congestion control `cc`.
 * `st` / `user` receive lifecycle transitions (may be NULL). Returns a new
 * mq_h3_conn (callbacks fire later) or NULL on failure. */
mq_h3_conn_t *mq_h3_connect(mq_h3_t *h, const struct sockaddr *peer, socklen_t peerlen,
                            mq_cc_t cc, mq_h3_conn_state_fn st, void *user);

/* 1 once xquic fired ready_to_create_path_notify for this conn (cids exchanged)
 * — i.e. mq_h3_conn_add_path can now succeed. 0 before that (or on NULL).
 * Client conns only. */
int mq_h3_conn_mp_ready(const mq_h3_conn_t *c);

/* Re-point (or DETACH, with st==NULL) this conn's lifecycle callback. The owner
 * MUST call this with st==NULL before it frees the `user` it passed to
 * mq_h3_connect, if the owner can be freed while the conn is still alive: the
 * conn outlives mq_h3_connect's caller and its close transition fires during
 * mq_h3_free / engine teardown, so a dangling `user` would be a use-after-free.
 * Safe on NULL. */
void mq_h3_conn_set_state_cb(mq_h3_conn_t *c, mq_h3_conn_state_fn st, void *user);

/* Create a NEW MPQUIC path bound to local_ip:port (port 0 == ephemeral), open
 * its UDP socket via the transport, and mark it available. MUST be called after
 * mq_h3_conn_mp_ready(c) == 1. Returns the new path_id (>0) or -1 on failure.
 * Client conns only. Mirrors mq_conn_add_path. */
int mq_h3_conn_add_path(mq_h3_conn_t *c, const char *local_ip, uint16_t port);

/* Snapshot + log per-path byte counters (spec §23.1) for this conn. Delegates
 * to mq_conn_dump_stats_cid (shared core). Smoke-safe on any conn. */
void mq_h3_conn_dump_stats(mq_h3_conn_t *c);

/* Send CONNECTION_CLOSE. The mq_h3_conn is freed later via h3_conn_close_notify
 * (peer close / idle / error all flow there too — freeing is centralised). */
void mq_h3_conn_close(mq_h3_conn_t *c);

/* ── Request ────────────────────────────────────────────────────────────── */

/* Request callbacks. on_read fires when headers/body/trailer/fin are ready
 * (`flag` is the xqc_request_notify_flag_t bitmask: READ_HEADER=1, READ_BODY=2,
 * READ_TRAILER=4, READ_EMPTY_FIN=8). on_write fires when a previously-blocked
 * send can resume. on_close fires once, just before the mq_h3_req is freed (the
 * owner must drop its pointer afterwards). Any may be NULL. */
typedef void (*mq_h3_req_on_read_fn)(mq_h3_req_t *r, int flag, void *user);
typedef void (*mq_h3_req_on_write_fn)(mq_h3_req_t *r, void *user);
typedef void (*mq_h3_req_on_close_fn)(mq_h3_req_t *r, void *user);

/* Register the request's owner callbacks (any may be NULL). */
void mq_h3_req_set_cbs(mq_h3_req_t *r, mq_h3_req_on_read_fn on_read,
                       mq_h3_req_on_write_fn on_write, mq_h3_req_on_close_fn on_close,
                       void *user);

/* Client: open a new H3 request on `c`. Returns a new mq_h3_req or NULL. */
mq_h3_req_t *mq_h3_req_open(mq_h3_conn_t *c);

/* A single request/response header. name/value are NUL-terminated C strings
 * (the send path measures them with strlen and frames them as iovecs). */
typedef struct {
    const char *name, *value;
} mq_h3_header_t;

/* Send `n` headers; fin!=0 finishes the request after this write (no body).
 * Returns bytes accepted (>0), 0 if flow-control blocked (was -XQC_EAGAIN —
 * retry after on_write), or -1 on a hard error. Normalised like mq_stream_send.
 * Header values are NUL-terminated C strings. */
long mq_h3_req_send_headers(mq_h3_req_t *r, const mq_h3_header_t *hs, size_t n, int fin);

/* Send up to len body bytes; fin!=0 finishes the request after this write.
 * Returns bytes accepted (>0), 0 if blocked (retry after on_write), -1 on
 * error. Normalised like mq_stream_send. */
long mq_h3_req_send_body(mq_h3_req_t *r, const uint8_t *p, size_t len, int fin);

/* Send a bare fin (a STREAM frame carrying only fin) when there is nothing left
 * to send. Returns bytes accepted (>0)/0 finished, 0 if blocked, -1 on error. */
long mq_h3_req_finish(mq_h3_req_t *r);

/* Receive the request/response headers, invoking `each` once per header with
 * borrowed name/value pointers (valid only during the call — copy out if
 * needed). *fin (if non-NULL) is set to 1 if the headers carry fin (no body).
 * Returns the number of headers delivered (>=0), or -1 on error. xquic owns the
 * returned header memory; it is consumed entirely within this call.
 *
 * CALL GATING: xqc_h3_request_recv_headers returns NULL (mapped to -1 here)
 * both on hard error AND when no header section is pending. Callers MUST gate
 * calls on the READ_HEADER (flag & 1) or READ_TRAILER (flag & 4) bit from the
 * on_read notify to avoid spurious -1 returns.
 *
 * TRAILERS: one call drains exactly one header section. If the request carries
 * trailers, a second call is required after the READ_TRAILER notify fires —
 * headers come first, trailers come second. */
int mq_h3_req_recv_headers(mq_h3_req_t *r,
                           void (*each)(const char *n, size_t nl, const char *v,
                                        size_t vl, void *u),
                           void *u, int *fin);

/* Receive up to cap body bytes into buf. *fin (if non-NULL) is set to 1 if the
 * peer finished the request. Returns bytes read (>=0), or -1 on error. 0 with
 * *fin==0 means no body available right now (was -XQC_EAGAIN). */
long mq_h3_req_recv_body(mq_h3_req_t *r, uint8_t *buf, size_t cap, int *fin);

/* Close the request. xqc_h3_request_close sends RESET_STREAM only if the
 * request has not already completed; on a finished request it is a graceful
 * close. The mq_h3_req is freed later via h3_request_close_notify. */
void mq_h3_req_reset(mq_h3_req_t *r);

#endif /* MQ_TRANSPORT_MQ_H3_H */
