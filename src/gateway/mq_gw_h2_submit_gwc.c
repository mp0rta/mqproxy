// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_gw_h2_submit_gwc.c — PRODUCTION binding of the H2 adapter's submit vtable
 * (mq_gw_submit_ops_t) to a live mq_gw_client_t (Phase 7 MITM, Slice 3 Task 11).
 *
 * The mq_gw_h2_adapter is protocol-agnostic: it drives the submit vtable, not
 * mq_gw_client_* directly, so its unit test can bind a capturing stub with NO
 * tunnel. This file is the PRODUCTION binding — thin wrappers over mq_gw_client_*.
 *
 * It lives in a SEPARATE TU from mq_gw_h2_adapter.c ON PURPOSE: it references
 * mq_gw_client_* (which pulls in the xquic transport), whereas the adapter TU is
 * pure nghttp2. Splitting them keeps test_gw_h2_adapter xquic-free (the static
 * archive only drags this object into a link that actually references the gwc
 * wrapper — i.e. the MITM orchestrator + the live CLI, never the adapter test).
 *
 * Only prevalidate / req_begin / auth_token need the gwc (carried as the wrapper
 * `u`); the four mq_gw_xreq_t*-keyed ops (req_body / req_body_done / req_drained /
 * req_aborted) ignore `u` and forward to the per-request functions directly.
 *
 * LIFETIME: the wrapper instance is allocated + owned by the MITM orchestrator
 * (mq_mitm_conn) — one wrapper per MITM connection (freed in the conn's teardown,
 * AFTER the adapter is freed). The gwc it points at is SHARED (borrowed); the
 * wrapper merely carries the pointer so the static vtable's ops can recover it.
 * The vtable itself is a single static const shared by all conns. */
#include "gateway/mq_gw_h2_adapter.h"

#include <stdlib.h>

#include "gateway/mq_gw_client.h"

struct mq_gw_h2_submit_gwc {
    mq_gw_client_t *gwc; /* BORROWED — shared across all MITM conns */
};

static mq_gw_reject_reason_t
gwc_prevalidate(void *u, const mq_h3_header_t *h, size_t n, int *status)
{
    struct mq_gw_h2_submit_gwc *w = (struct mq_gw_h2_submit_gwc *)u;
    return mq_gw_client_prevalidate(w->gwc, h, n, status);
}

static mq_gw_xreq_t *
gwc_req_begin(void *u, const mq_gw_req_head_t *head, const mq_gw_sink_ops_t *sink,
              void *sink_user, int *err_status, mq_gw_reject_reason_t *reason)
{
    struct mq_gw_h2_submit_gwc *w = (struct mq_gw_h2_submit_gwc *)u;
    return mq_gw_client_req_begin(w->gwc, head, sink, sink_user, err_status, reason);
}

static int
gwc_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    return mq_gw_client_req_body(r, p, len);
}

static void
gwc_req_body_done(mq_gw_xreq_t *r)
{
    mq_gw_client_req_body_done(r);
}

static void
gwc_req_drained(mq_gw_xreq_t *r)
{
    mq_gw_client_req_drained(r);
}

static void
gwc_req_aborted(mq_gw_xreq_t *r)
{
    mq_gw_client_req_aborted(r);
}

static const char *
gwc_auth_token(void *u)
{
    struct mq_gw_h2_submit_gwc *w = (struct mq_gw_h2_submit_gwc *)u;
    return mq_gw_client_token(w->gwc); /* raw token; adapter prepends "Bearer " */
}

static const mq_gw_submit_ops_t g_gwc_ops = {
    .prevalidate = gwc_prevalidate,
    .req_begin = gwc_req_begin,
    .req_body = gwc_req_body,
    .req_body_done = gwc_req_body_done,
    .req_drained = gwc_req_drained,
    .req_aborted = gwc_req_aborted,
    .auth_token = gwc_auth_token,
};

const mq_gw_submit_ops_t *
mq_gw_h2_submit_ops_gwc(void)
{
    return &g_gwc_ops;
}

mq_gw_h2_submit_gwc_t *
mq_gw_h2_submit_gwc_new(struct mq_gw_client_s *gwc)
{
    if (!gwc) return NULL;
    mq_gw_h2_submit_gwc_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->gwc = gwc;
    return w;
}

void
mq_gw_h2_submit_gwc_free(mq_gw_h2_submit_gwc_t *w)
{
    free(w); /* does NOT free the borrowed gwc */
}
