// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#ifndef MQ_GW_INTAKE_H
#define MQ_GW_INTAKE_H

#include <stddef.h>
#include <stdint.h>
#include "transport/mq_h3.h" /* mq_h3_header_t */

/* How the response body will be framed for the adapter. */
typedef enum {
    MQ_GW_BODY_CONTENT_LENGTH = 0, /* relay as-is; length known */
    MQ_GW_BODY_STREAM = 1, /* unknown length (H1 renders chunked; H3 needs nothing) */
} mq_gw_body_mode_t;

/* Parsed, adapter-validated request head handed to the core. */
typedef struct {
    const char *method, *scheme, *authority, *path; /* non-NULL, non-empty */
    const mq_h3_header_t *headers;
    size_t n_headers;       /* regular headers, envelope-stripped */
    int64_t content_length; /* -1 unknown (stream); >=0 known */
} mq_gw_req_head_t;

/* Core -> adapter callbacks (replaces direct mq_fetch_conn_* calls). */
typedef struct {
    int (*resp_head)(void *u, int status, const mq_h3_header_t *hs, size_t n,
                     mq_gw_body_mode_t body_mode);
    int (*resp_body)(void *u, const uint8_t *p,
                     size_t len); /* >0 accept, 0 highwater, -1 dead */
    void (*resp_finish)(void *u);
    void (*resp_abort)(void *u);  /* mid-stream failure — never a fake clean finish */
    void (*resume_read)(void *u); /* upload backpressure released */
} mq_gw_sink_ops_t;

/* Opaque per-request core handle (was mq_gw_req_t). */
typedef struct mq_gw_xreq_s mq_gw_xreq_t;

/* Reject reason — maps 1:1 to the existing X-Mq-Error strings (which tests/e2e assert
 * byte-for-byte). The CORE returns this enum; the ADAPTER maps it to (status, X-Mq-Error
 * text) so rendered errors stay identical. Values mirror gw_reject_write call sites in
 * mq_gw_client.c (verified): */
typedef enum {
    MQ_GW_OK = 0,
    MQ_GW_REJ_DUP_CONTROL,  /* 400 "duplicate-control-header" */
    MQ_GW_REJ_MISSING_AUTH, /* 400 "missing-auth" */
    MQ_GW_REJ_BAD_AUTH,     /* 400 "bad-auth-format" */
    MQ_GW_REJ_BAD_TARGET,   /* 400 "bad-target"      (adapter-detected, fetch envelope) */
    MQ_GW_REJ_BAD_METHOD,   /* 400 "bad-method"      (adapter-detected, fetch envelope) */
    MQ_GW_REJ_BAD_ORIGIN_PROTO, /* 400 "bad-origin-protocol" */
    MQ_GW_REJ_BAD_CACHE_TTL,    /* 400 "bad-cache-ttl" */
    MQ_GW_REJ_HEADER_TOO_LONG,  /* 400 "header-too-long" */
    MQ_GW_REJ_TUNNEL_UNAVAIL,   /* 502 "tunnel-unavailable" */
    MQ_GW_REJ_INTERNAL,         /* 502 "internal-error" */
} mq_gw_reject_reason_t;

/* Map a reject reason → its X-Mq-Error string (byte-identical across adapters;
 * tests/e2e assert these verbatim). Returns a borrowed, NUL-terminated literal
 * (never NULL — an unknown reason maps to "internal-error"). Shared by every
 * gateway adapter (H1 fetch + H2 MITM) so the rendered error strings cannot
 * drift between protocols. Implemented in mq_gw_headers.c (a leaf gateway TU, kept
 * dependency-light so the nghttp2-only adapter test links it without dragging in
 * xquic). */
const char *mq_gw_reject_xmq(mq_gw_reject_reason_t reason);

#endif /* MQ_GW_INTAKE_H */
