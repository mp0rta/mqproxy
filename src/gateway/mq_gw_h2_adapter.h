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

/* Free the adapter and its nghttp2 session. Does NOT free submit/submit_user/io
 * (all borrowed). Safe on NULL. */
void mq_gw_h2_adapter_free(mq_gw_h2_adapter_t *a);

/* Production vtable bound to a gwc. Returns a static vtable whose `u` is a
 * wrapper holding an mq_gw_client_t*. DEFINED in Task 11 (its first live use) —
 * declared here for the header to be complete, but NOT implemented in this task
 * because it needs mq_gw_client_token() (added in Task 6). */
const mq_gw_submit_ops_t *mq_gw_h2_submit_ops_gwc(void);

#endif /* MQ_GATEWAY_MQ_GW_H2_ADAPTER_H */
