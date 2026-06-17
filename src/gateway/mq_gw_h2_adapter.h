// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_gw_h2_adapter.h — HTTP/2 (nghttp2) server adapter over the neutral
 * mq_gw_client intake boundary (Phase 7 MITM, Slice 3).
 *
 * The MITM data path terminates TLS (ALPN=h2) and feeds the resulting plaintext
 * H2 frames into this adapter. The adapter runs an nghttp2 SERVER session: it
 * decodes the browser's HTTP/2 requests, drives them onto the shared gateway
 * tunnel via the submit vtable, and frames the responses back out as H2.
 *
 * SKELETON SCOPE (Task 5): nghttp2 server session creation + §5.2 resource
 * limits (SETTINGS) + the recv / want_write plumbing to the byte transport. No
 * request demux, header policy, response path or body handling yet — those are
 * Tasks 6/7/8.
 *
 * ── TEST SEAM (submit vtable) ───────────────────────────────────────────────
 * mq_gw_client_t is opaque and mq_gw_client_req_begin opens a request on a LIVE
 * H3 tunnel (sockets), so the adapter cannot be unit-tested against the concrete
 * client. The adapter therefore drives a small SUBMISSION vtable: production
 * binds it to thin wrappers over mq_gw_client_* (mq_gw_h2_submit_ops_gwc, built
 * in Task 11); tests bind it to a capturing stub (no tunnel). This mirrors the
 * sink direction of mq_gw_intake.h.
 */
#ifndef MQ_GATEWAY_MQ_GW_H2_ADAPTER_H
#define MQ_GATEWAY_MQ_GW_H2_ADAPTER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> /* ssize_t */

#include "gateway/mq_gw_intake.h" /* mq_gw_req_head_t, mq_gw_sink_ops_t, mq_gw_xreq_t, mq_gw_reject_reason_t */
#include "transport/mq_h3.h" /* mq_h3_header_t */

typedef struct mq_gw_h2_adapter mq_gw_h2_adapter_t;

/* Submission boundary the adapter drives — production = thin wrappers over
 * mq_gw_client_*; tests = capturing stub (no tunnel). Mirrors mq_gw_intake.h's
 * sink direction.
 *
 * Only prevalidate/req_begin/auth_token truly need the gwc (carried as `u`); the
 * four mq_gw_xreq_t*-keyed ops ride the same seam so the stub can observe
 * upload/drain/abort without --wrap. */
typedef struct {
    mq_gw_reject_reason_t (*prevalidate)(void *u, const mq_h3_header_t *h, size_t n,
                                         int *status);
    mq_gw_xreq_t *(*req_begin)(void *u, const mq_gw_req_head_t *head,
                               const mq_gw_sink_ops_t *sink, void *sink_user,
                               int *err_status, mq_gw_reject_reason_t *reason);
    int (*req_body)(mq_gw_xreq_t *r, const uint8_t *p,
                    size_t len); /* 0=accepted, -1=pause */
    void (*req_body_done)(mq_gw_xreq_t *r);
    void (*req_drained)(mq_gw_xreq_t *r); /* DOWNLOAD resume — clears read_deferred */
    void (*req_aborted)(
        mq_gw_xreq_t *r); /* adapter→core "local gone"; NO sink callback */
    const char *(*auth_token)(void *u); /* raw token; adapter prepends "Bearer " */
} mq_gw_submit_ops_t;

/* Create an H2 server adapter.
 *
 *   submit / submit_user : the submission vtable + its user (BORROWED — the
 *       vtable and user must outlive the adapter). Production passes a wrapper
 *       holding the gwc; tests pass a capturing stub.
 *   send_cb / io         : plaintext writer. The adapter calls send_cb to emit
 *       the H2 bytes it wants written to the (TLS) transport. Returns bytes
 *       accepted (>=0) or <0 on a hard error. `io` is the writer's user pointer.
 *
 * Submits the §5.2 SETTINGS frame immediately so the handshake completes on the
 * first want_write drain. Returns NULL on bad args / OOM. */
mq_gw_h2_adapter_t *
mq_gw_h2_adapter_new(const mq_gw_submit_ops_t *submit, void *submit_user,
                     ssize_t (*send_cb)(void *io, const uint8_t *p, size_t n), void *io);

/* Feed `n` plaintext bytes from the TLS layer into the session. Returns 0 on
 * success, -1 on a fatal protocol/parse error (the caller should tear down). */
int mq_gw_h2_adapter_recv(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t n);

/* Drain any pending outbound frames through send_cb. Returns 0 on success, -1 on
 * a fatal error. (Named want_write to mirror the nghttp2 wants_write notion: the
 * caller invokes it whenever the session may have data to write.) */
int mq_gw_h2_adapter_want_write(mq_gw_h2_adapter_t *a);

/* Register a WRITABLE-NOTIFY callback (optional). The adapter fires it whenever a
 * RESPONSE-side event enqueues new outbound frames OUTSIDE the caller's recv /
 * want_write turn — i.e. from a sink op (resp_head/resp_body/resp_finish/
 * resp_abort) or an error-response render. These run on the async core→adapter
 * path (e.g. a tunnel response arriving on a DIFFERENT event than the local-fd
 * read), so without this notify nothing would drive the bytes to the transport
 * until the next inbound event — a deadlock the peer never breaks (it is waiting
 * for the response). The callback MUST be deferred-safe: it should only SCHEDULE
 * a later want_write (e.g. arm a one-shot writable event), NEVER call want_write
 * re-entrantly (the sink op may be nested inside the core's download pump, and a
 * re-entrant want_write would recurse through req_drained). `user` is opaque.
 * NULL cb clears it. Unset by default (the unit-test seam leaves it NULL and
 * pulls want_write itself, so the adapter stays transport-agnostic). */
void mq_gw_h2_adapter_set_writable_cb(mq_gw_h2_adapter_t *a, void (*cb)(void *user),
                                      void *user);

/* Free the adapter and its nghttp2 session. Does NOT free submit/submit_user/io
 * (all borrowed). Safe on NULL. */
void mq_gw_h2_adapter_free(mq_gw_h2_adapter_t *a);

/* ── production submit vtable bound to a gwc (Task 11) ───────────────────────
 *
 * The adapter drives the submit vtable, not mq_gw_client_* directly. Production
 * binds it via this pair: the STATIC vtable (mq_gw_h2_submit_ops_gwc) whose ops
 * thin-wrap mq_gw_client_*, plus a per-conn WRAPPER (mq_gw_h2_submit_gwc_t) that
 * carries the shared mq_gw_client_t* as the vtable's `submit_user`. */
typedef struct mq_gw_h2_submit_gwc mq_gw_h2_submit_gwc_t;
struct mq_gw_client_s; /* fwd — the wrapper borrows it */

/* The static production vtable (thin wrappers over mq_gw_client_*). The `u`
 * argument each op receives is the wrapper below. */
const mq_gw_submit_ops_t *mq_gw_h2_submit_ops_gwc(void);

/* Allocate a wrapper carrying the SHARED gwc (BORROWED — not freed by
 * mq_gw_h2_submit_gwc_free). The orchestrator passes the wrapper as `submit_user`
 * to mq_gw_h2_adapter_new and owns its lifetime (one wrapper per MITM conn; freed
 * in the conn's teardown AFTER the adapter is freed). Returns NULL on NULL gwc /
 * OOM. */
mq_gw_h2_submit_gwc_t *mq_gw_h2_submit_gwc_new(struct mq_gw_client_s *gwc);

/* Free a wrapper. Does NOT free the borrowed gwc. Safe on NULL. */
void mq_gw_h2_submit_gwc_free(mq_gw_h2_submit_gwc_t *w);

#endif /* MQ_GATEWAY_MQ_GW_H2_ADAPTER_H */
