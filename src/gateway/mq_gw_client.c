// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_client.c — client-side fetch→H3 bridge. See mq_gw_client.h.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PER-REQUEST OWNERSHIP (mq_gw_req_t)
 * ─────────────────────────────────────────────────────────────────────────────
 * This is the protocol-agnostic NEUTRAL CORE: it knows nothing about HTTP/1.1 or
 * the fetch listener. The local protocol lives entirely behind the sink boundary
 * (mq_gw_sink_ops_t), implemented today by mq_gw_fetch_adapter.c. Each request
 * owns one mq_gw_req_t referenced from two independent sides that can each die
 * first or race:
 *
 *   LOCAL side  (the sink: sink + sink_user): set on accept (mq_gw_client_req_
 *     begin); cleared when we terminate the response (sink->resp_finish/resp_abort)
 *     OR when the adapter tells us the local peer died (mq_gw_client_req_aborted).
 *     After any of those the sink is DEAD — we null sink/sink_user and never touch
 *     it again. The sink_user the adapter threads back to us stays valid until then.
 *
 *   TUNNEL side (the mq_h3_req): set on accept (mq_h3_req_open); cleared in the
 *     H3 on_close callback (the wrapper is freed right after). After on_close we
 *     null it and never touch it again.
 *
 * The mq_gw_req_t is freed when BOTH sides are detached. We track this with two
 * flags (local_dead, h3_dead) and free in gw_req_maybe_free() once both are set.
 * Every termination path routes through exactly one of:
 *
 *   - local terminates first: we mq_h3_req_reset (if h3 still live) → h3 on_close
 *     fires later → both dead → free. We set local_dead immediately and clear the
 *     sink so no further sink op runs.
 *   - tunnel terminates first (h3 on_close): we drive sink->resp_finish/resp_abort
 *     (if local still live) → that detaches local → both dead → free. on_close
 *     sets h3_dead and nulls the req pointer.
 *   - both race: idempotent flags; maybe_free runs only when both set, so the
 *     struct is freed exactly once regardless of order.
 *
 * mq_h3 guarantees on_close fires exactly once, and the adapter guarantees no
 * sink op is delivered after we detach (resp_finish/resp_abort/req_aborted are
 * each terminal). So each side flips its flag exactly once.
 *
 * One subtlety: when we drive a terminal sink op from inside an H3 callback, it
 * does NOT synchronously re-enter the core (the adapter is terminal). So no
 * reentrancy hazard there. Conversely, when the LOCAL side dies we learn it
 * either via mq_gw_client_req_aborted (explicit) or via a sink op returning -1 —
 * we treat a -1 from any sink write/resume as "local dead" and reset the tunnel.
 *
 * SINK INVARIANT (Task 4): `!local_dead` ⟹ `sink != NULL && sink_user != NULL`.
 * The sink is set once at req_begin (mq_gw_client_req_begin) and cleared in
 * lockstep with local_dead at every local-side termination site. Code that has
 * already established `!local_dead` (e.g. download_pump, which returns early if
 * local_dead) may call sink ops WITHOUT a redundant NULL guard.
 */
#include "gateway/mq_gw_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>

#include "gateway/mq_gw_headers.h"
#include "util/mq_backoff.h"
#include "util/mq_log.h"

/* Bound on the internal upload spill buffer (junction #1): bytes the local peer
 * delivered that H3 could not immediately accept. When non-empty we pause the
 * listener; we flush from on_write and resume_read once drained. */
#define MQ_GW_UPLOAD_SPILL_MAX (256 * 1024)

/* recv_body scratch size for the download path (junction #2). */
#define MQ_GW_DOWNLOAD_CHUNK 16384

/* Max number of forwarded request headers (request line pseudo-headers +
 * x-mq-auth + x-mq-class + ordinary headers). MQ_HTTP1_MAX_HEADERS bounds the
 * incoming set; add a margin for the pseudo-headers we synthesize. */
#define MQ_GW_MAX_SEND_HDRS (MQ_HTTP1_MAX_HEADERS + 8)

/* Per-forwarded-header arena slot caps (name / value). A slot holds cap-1 bytes
 * + NUL, so a name >= NAME_CAP or value >= VAL_CAP would be truncated. These bound
 * BOTH the gw_on_request reject check (fail closed before opening the H3 request)
 * AND the forwarding arena declarations — keep them in lockstep here so the two
 * sites can never drift. */
#define MQ_GW_HDR_NAME_CAP 128
#define MQ_GW_HDR_VAL_CAP  1024

/* Poll interval (ms) for the mp-ready deferral timer (mirrors mq_client). */
#define MQ_GW_MP_POLL_MS 50
#define MQ_GW_MAX_PATHS  8
#define MQ_GW_IP_MAX     64

/* Base delay (ms) for the reconnect exponential backoff (mirrors mq_client). */
#define MQ_GW_RECONNECT_BASE_MS 250

/* ── per-request state ──────────────────────────────────────────────────────*/

/* This is the definition of the opaque mq_gw_xreq_t (typedef'd in
 * mq_gw_intake.h as `struct mq_gw_xreq_s`). The neutral core owns only the
 * tunnel state and the sink boundary; all protocol-specific fields (H1 handle,
 * resp_chunked, etc.) live in the adapter (mq_gw_fetch_adapter.c). */
struct mq_gw_xreq_s {
    mq_gw_client_t *cli;

    /* ── neutral intake (sink) side ── */
    const mq_gw_sink_ops_t *sink; /* adapter callbacks (NULL == intake detached) */
    void *sink_user;              /* adapter per-request cookie */

    /* local (sink) side liveness flag */
    int local_dead;

    /* tunnel (H3) side */
    mq_h3_req_t *req; /* NULL once on_close fired (dead) */
    int h3_dead;

    /* ── upload (junction #1) ── */
    int upload_fin_sent; /* the request's fin has been sent on the H3 side */
    int upload_done;     /* on_body_done fired (listener will deliver no more) */
    int paused;          /* we returned -1 to pause the listener read */
    uint8_t *spill;      /* heap spill buffer (allocated lazily) */
    size_t spill_len;    /* valid bytes in spill */
    size_t spill_off;    /* bytes already flushed from spill */

    /* ── download (junction #2) ── */
    int resp_started;  /* we called sink->resp_head (response started) */
    int read_deferred; /* adapter output highwater; stop recv_body until drain */
    int resp_status;   /* parsed :status (for diagnostics) */

    struct mq_gw_xreq_s *next; /* intrusive list of live requests on the client */
};

/* In-file alias so the internal code can spell the struct `mq_gw_req_t`. */
typedef struct mq_gw_xreq_s mq_gw_req_t;

/* ── client state ───────────────────────────────────────────────────────────*/

struct mq_gw_client_s {
    mq_transport_t *t; /* borrowed */
    mq_runtime_t *rt;  /* borrowed */
    mq_h3_t *h3;       /* borrowed */
    mq_cc_t cc;

    char token[256];

    struct sockaddr_in peer;
    socklen_t peerlen;

    mq_h3_conn_t *conn; /* the gateway tunnel conn (borrowed; freed by mq_h3) */
    int conn_up;        /* 1 between established and closed */

    mq_gw_req_t *reqs; /* intrusive list of live per-request states */

    /* mp-poll timer (mirrors mq_client) */
    char extra_paths[MQ_GW_MAX_PATHS][MQ_GW_IP_MAX];
    size_t n_extra_paths;
    size_t added_paths;
    struct event *mp_timer;

    /* Keepalive: > 0 enables xquic PING keepalive with this idle timeout. Passed
     * to every mq_h3_connect (initial + reconnect). */
    uint64_t keepalive_idle_ms;

    /* Reconnect controller (Phase 5b, mirrors mq_client). reconnect_ev is created
     * ONCE in mq_gw_client_new (when enabled) and freed ONLY in mq_gw_client_free;
     * it is a one-shot timer re-armed across reconnect cycles, so a stop must NOT
     * free it. shutting_down is set FIRST by mq_gw_client_free so a late conn close
     * takes the terminal path (no reconnect-after-free). The gateway has NO
     * connection-level auth latch (auth is per-request via x-mq-auth), so the
     * reconnect-success hook is `established` (conn_up=1), not an auth-OK event. */
    int shutting_down;
    int reconnect_enabled;
    uint64_t reconnect_max_backoff_ms;
    struct event *reconnect_ev;
    unsigned reconnect_attempts;
};

/* ── forward decls ──────────────────────────────────────────────────────────*/
static void gw_req_unlink(mq_gw_client_t *c, mq_gw_req_t *r);
static void gw_req_maybe_free(mq_gw_req_t *r);
static void gw_local_dead(mq_gw_req_t *r);
static void gw_local_finish(mq_gw_req_t *r);
static void gw_local_abort(mq_gw_req_t *r);
static void h3_on_read(mq_h3_req_t *hr, int flag, void *user);
static void h3_on_write(mq_h3_req_t *hr, void *user);
static void h3_on_close(mq_h3_req_t *hr, void *user);
static void upload_pump(mq_gw_req_t *r);
static void download_pump(mq_gw_req_t *r);
static void gw_local_error_req(mq_gw_req_t *r, int code, const char *xmq);
/* Reconnect controller + the re-issuable connect body (defined below). */
static int gw_issue_connect(mq_gw_client_t *c);
static void gw_reconnect_arm(mq_gw_client_t *c);
static void gw_reconnect_stop(mq_gw_client_t *c);
static void gw_mp_timer_arm(mq_gw_client_t *c);
static void gw_mp_timer_stop(mq_gw_client_t *c);

/* ── small helpers ──────────────────────────────────────────────────────────*/

/* Case-insensitive equality for a slice vs a NUL-terminated lowercase literal. */
static int
slice_ieq(const char *s, size_t sl, const char *lit)
{
    size_t ll = strlen(lit);
    if (sl != ll) return 0;
    for (size_t i = 0; i < sl; i++) {
        char a = s[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (a != lit[i]) return 0;
    }
    return 1;
}

/* ── neutral header-list helpers (mq_h3_header_t, NUL-terminated) ────────────*/

/* Find header `name` (case-insensitive) in a neutral list; NULL if absent.
 * *out_vl receives strlen(value). */
static const char *
nfind_hdr(const mq_h3_header_t *hs, size_t n, const char *name, size_t *out_vl)
{
    for (size_t i = 0; i < n; i++) {
        if (slice_ieq(hs[i].name, strlen(hs[i].name), name)) {
            if (out_vl) *out_vl = strlen(hs[i].value);
            return hs[i].value;
        }
    }
    return NULL;
}

/* Returns 1 if the neutral list carries the same X-Mq-* name twice or more
 * (case-insensitive). Mirrors mq_gw_has_dup_xmq for the neutral representation. */
static int
nhas_dup_xmq(const mq_h3_header_t *hs, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        size_t il = strlen(hs[i].name);
        if (!slice_ieq(hs[i].name, il < 5 ? il : 5, "x-mq-")) continue;
        for (size_t j = i + 1; j < n; j++) {
            /* Both names come from the wire with arbitrary case; slice_ieq only
             * folds its first arg, so compare both sides case-insensitively here
             * (matches the original mq_gw_has_dup_xmq which lc()'d both). */
            size_t jl = strlen(hs[j].name);
            if (jl != il) continue;
            size_t k = 0;
            for (; k < il; k++) {
                char a = hs[i].name[k], b = hs[j].name[k];
                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                if (a != b) break;
            }
            if (k == il) return 1;
        }
    }
    return 0;
}

/* ── per-request lifecycle ──────────────────────────────────────────────────*/

static void
gw_req_unlink(mq_gw_client_t *c, mq_gw_req_t *r)
{
    mq_gw_req_t **pp = &c->reqs;
    while (*pp) {
        if (*pp == r) {
            *pp = r->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Free the per-request state once BOTH sides are detached. Idempotent guard via
 * the two flags. */
static void
gw_req_maybe_free(mq_gw_req_t *r)
{
    if (!r->local_dead || !r->h3_dead) return;
    gw_req_unlink(r->cli, r);
    free(r->spill);
    free(r);
}

/* The LOCAL side terminated (adapter output dead: resp_body returned -1, or
 * local peer died mid-upload). Detach the sink and, if the tunnel is still
 * live, reset it so its on_close eventually frees the struct. Does NOT call
 * any sink op — the adapter already knows the local side is dead. */
static void
gw_local_dead(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    r->local_dead = 1;
    r->sink = NULL;
    r->sink_user = NULL;
    if (!r->h3_dead && r->req) {
        /* Mid-stream local death: reset the H3 request (truncated). on_close
         * fires later and finishes the teardown. */
        mq_h3_req_reset(r->req);
    }
    gw_req_maybe_free(r);
}

/* Finish the local side cleanly (response fully relayed). Calls the sink's
 * resp_finish, then marks local done and frees if both sides are dead. */
static void
gw_local_finish(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    const mq_gw_sink_ops_t *sink = r->sink;
    void *su = r->sink_user;
    r->local_dead = 1;
    r->sink = NULL;
    r->sink_user = NULL;
    if (sink) sink->resp_finish(su);
    gw_req_maybe_free(r);
}

/* Abort the local side (mid-stream truncation visible to the local peer).
 * Calls the sink's resp_abort, then marks local done and frees if both dead. */
static void
gw_local_abort(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    const mq_gw_sink_ops_t *sink = r->sink;
    void *su = r->sink_user;
    r->local_dead = 1;
    r->sink = NULL;
    r->sink_user = NULL;
    if (sink) sink->resp_abort(su);
    gw_req_maybe_free(r);
}

/* ── neutral intake: prevalidate + req_begin (core) ─────────────────────────*/

/* Phase 1: header-only checks that run BEFORE the adapter parses the fetch
 * envelope's target/method — duplicate X-Mq-* control headers, then X-Mq-Auth
 * presence + "Bearer <non-empty>" format. Returns MQ_GW_OK or the reject reason
 * (+ *status). No tunnel touch. */
mq_gw_reject_reason_t
mq_gw_client_prevalidate(mq_gw_client_t *c, const mq_h3_header_t *headers, size_t n,
                         int *status)
{
    (void)c;
    /* 1. duplicate X-Mq-* control headers → 400. */
    if (nhas_dup_xmq(headers, n)) {
        if (status) *status = 400;
        return MQ_GW_REJ_DUP_CONTROL;
    }
    /* 2. X-Mq-Auth present + "Bearer <non-empty>" format check (client-side). */
    size_t auth_vl = 0;
    const char *auth = nfind_hdr(headers, n, "x-mq-auth", &auth_vl);
    if (!auth) {
        if (status) *status = 400;
        return MQ_GW_REJ_MISSING_AUTH;
    }
    {
        const char *pfx = "Bearer ";
        size_t pl = strlen(pfx);
        if (auth_vl <= pl || strncmp(auth, pfx, pl) != 0) {
            if (status) *status = 400;
            return MQ_GW_REJ_BAD_AUTH;
        }
    }
    return MQ_GW_OK;
}

/* Phase 2: begin a request (head already split + prevalidated). The core does,
 * IN ORDER: X-Mq-Origin-Protocol(400), X-Mq-Cache(400), header-size(400), tunnel
 * liveness(502); then opens the H3 request, forwards pseudo + x-mq-* + ordinary
 * headers, and streams the body via the sink. On reject sets *err_status +
 * *reason and returns NULL (the adapter renders the error). */
mq_gw_xreq_t *
mq_gw_client_req_begin(mq_gw_client_t *c, const mq_gw_req_head_t *head,
                       const mq_gw_sink_ops_t *sink, void *sink_user, int *err_status,
                       mq_gw_reject_reason_t *reason)
{
    const mq_h3_header_t *H = head->headers;
    size_t HN = head->n_headers;

    /* 4a. X-Mq-Origin-Protocol if present: validate via the shared parser. A present,
     * non-empty, UNRECOGNIZED token is a caller bug → 400. Absent / empty → DEFAULT
     * (no preference; not re-emitted below). */
    size_t xop_vl = 0;
    const char *xop = nfind_hdr(H, HN, "x-mq-origin-protocol", &xop_vl);
    mq_http_ver_t xop_ver = MQ_HTTP_VER_DEFAULT;
    if (xop && xop_vl > 0) {
        xop_ver = mq_gw_parse_http_ver(xop, xop_vl);
        if (xop_ver == MQ_HTTP_VER_DEFAULT) {
            *err_status = 400;
            *reason = MQ_GW_REJ_BAD_ORIGIN_PROTO;
            return NULL;
        }
    }

    /* 4a'. X-Mq-Cache if present: validate via the shared parser. A present, non-empty,
     * unparseable TTL is a caller bug → 400. Absent / empty → no caching. */
    size_t xmc_vl = 0;
    const char *xmc = nfind_hdr(H, HN, "x-mq-cache", &xmc_vl);
    unsigned xmc_ttl = 0;
    if (xmc && xmc_vl > 0) {
        xmc_ttl = mq_gw_parse_cache_ttl(xmc, xmc_vl);
        if (xmc_ttl == 0) {
            *err_status = 400;
            *reason = MQ_GW_REJ_BAD_CACHE_TTL;
            return NULL;
        }
    }

    /* 4b. Reject (BEFORE opening the H3 request) any header that would not fit the
     * forwarding arena, instead of silently clamping it. A clamped X-Mq-Auth can't
     * authenticate anyway, and a clamped forwarded value is a corruption / smuggling
     * surface; fail closed with 400 header-too-long. */
    int forward_cookie = 0;
    {
        const char *fc = nfind_hdr(H, HN, "x-mq-forward-cookie", NULL);
        if (fc) forward_cookie = slice_ieq(fc, strlen(fc), "true");
    }
    size_t auth_vl = 0;
    const char *auth = nfind_hdr(H, HN, "x-mq-auth", &auth_vl);
    size_t xae_vl = 0;
    const char *xae = nfind_hdr(H, HN, "x-mq-accept-encoding", &xae_vl);
    int inject_ae = (xae && xae_vl > 0); /* present AND non-empty (empty => no-op) */
    {
        if (auth_vl >= MQ_GW_HDR_VAL_CAP) {
            *err_status = 400;
            *reason = MQ_GW_REJ_HEADER_TOO_LONG;
            return NULL;
        }
        size_t xcl_vl = 0;
        const char *xcl = nfind_hdr(H, HN, "x-mq-class", &xcl_vl);
        if (xcl && xcl_vl >= MQ_GW_HDR_VAL_CAP) {
            *err_status = 400;
            *reason = MQ_GW_REJ_HEADER_TOO_LONG;
            return NULL;
        }
        if (inject_ae && xae_vl >= MQ_GW_HDR_VAL_CAP) {
            *err_status = 400;
            *reason = MQ_GW_REJ_HEADER_TOO_LONG;
            return NULL;
        }
        for (size_t i = 0; i < HN; i++) {
            const char *n = H[i].name;
            size_t nl = strlen(n);
            if (mq_gw_strip_client(n, nl, forward_cookie)) continue;
            if (nl >= MQ_GW_HDR_NAME_CAP || strlen(H[i].value) >= MQ_GW_HDR_VAL_CAP) {
                *err_status = 400;
                *reason = MQ_GW_REJ_HEADER_TOO_LONG;
                return NULL;
            }
        }
    }

    /* 5. tunnel must be up. */
    if (!c->conn_up || !c->conn) {
        *err_status = 502;
        *reason = MQ_GW_REJ_TUNNEL_UNAVAIL;
        return NULL;
    }

    /* Accept: open the H3 request. */
    mq_h3_req_t *hr = mq_h3_req_open(c->conn);
    if (!hr) {
        *err_status = 502;
        *reason = MQ_GW_REJ_TUNNEL_UNAVAIL;
        return NULL;
    }

    mq_gw_req_t *r = calloc(1, sizeof(*r));
    if (!r) {
        mq_h3_req_reset(hr);
        *err_status = 502;
        *reason = MQ_GW_REJ_INTERNAL;
        return NULL;
    }
    r->cli = c;
    r->sink = sink;
    r->sink_user = sink_user;
    r->req = hr;
    r->resp_status = 0;

    /* fin = no body. CL==-1 (absent) OR CL<=0 → no body. */
    int no_body = (head->content_length <= 0);

    /* Build the forwarded header list. NUL-terminated C strings are required by
     * mq_h3_req_send_headers, so copy each (name,value) into a per-request arena.
     * The arena lives only for the duration of this call (send_headers copies the
     * iovecs synchronously). */
    mq_h3_header_t hs[MQ_GW_MAX_SEND_HDRS];
    static const size_t NS = MQ_GW_HDR_NAME_CAP, VS = MQ_GW_HDR_VAL_CAP;
    char *namebuf = malloc(MQ_GW_MAX_SEND_HDRS * NS);
    char *valbuf = malloc(MQ_GW_MAX_SEND_HDRS * VS);
    if (!namebuf || !valbuf) {
        free(namebuf);
        free(valbuf);
        mq_h3_req_reset(hr);
        r->req = NULL;
        r->h3_dead = 1;
        free(r);
        *err_status = 502;
        *reason = MQ_GW_REJ_INTERNAL;
        return NULL;
    }
    size_t nh = 0;

    /* :method / :scheme / :authority / :path (pseudo-headers first). */
    hs[nh].name = ":method";
    hs[nh].value = head->method;
    nh++;
    hs[nh].name = ":scheme";
    hs[nh].value = head->scheme;
    nh++;
    hs[nh].name = ":authority";
    hs[nh].value = head->authority;
    nh++;
    hs[nh].name = ":path";
    hs[nh].value = head->path;
    nh++;

    /* x-mq-auth: forward the ORIGINAL header value (server verifies). */
    {
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        size_t vl = auth_vl < VS - 1 ? auth_vl : VS - 1;
        memcpy(nb, "x-mq-auth", 10);
        memcpy(vb, auth, vl);
        vb[vl] = '\0';
        hs[nh].name = nb;
        hs[nh].value = vb;
        nh++;
    }

    /* x-mq-class if present. */
    {
        size_t cl_vl = 0;
        const char *cls = nfind_hdr(H, HN, "x-mq-class", &cl_vl);
        if (cls && nh < MQ_GW_MAX_SEND_HDRS) {
            char *nb = namebuf + nh * NS;
            char *vb = valbuf + nh * VS;
            size_t vl = cl_vl < VS - 1 ? cl_vl : VS - 1;
            memcpy(nb, "x-mq-class", 11);
            memcpy(vb, cls, vl);
            vb[vl] = '\0';
            hs[nh].name = nb;
            hs[nh].value = vb;
            nh++;
        }
    }

    /* x-mq-origin-protocol: re-emit the RAW validated token only when a recognized
     * choice was parsed (DEFAULT = no preference, not conveyed). */
    if (xop_ver != MQ_HTTP_VER_DEFAULT && nh < MQ_GW_MAX_SEND_HDRS) {
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        size_t vl = xop_vl < VS - 1 ? xop_vl : VS - 1;
        memcpy(nb, "x-mq-origin-protocol", 21);
        memcpy(vb, xop, vl);
        vb[vl] = '\0';
        hs[nh].name = nb;
        hs[nh].value = vb;
        nh++;
    }

    /* x-mq-cache: re-emit the RAW validated TTL token only when a valid opt-in TTL
     * was parsed (absent / empty = no caching, not conveyed). */
    if (xmc_ttl != 0 && nh < MQ_GW_MAX_SEND_HDRS) {
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        size_t vl = xmc_vl < VS - 1 ? xmc_vl : VS - 1;
        memcpy(nb, "x-mq-cache", 11);
        memcpy(vb, xmc, vl);
        vb[vl] = '\0';
        hs[nh].name = nb;
        hs[nh].value = vb;
        nh++;
    }

    /* accept-encoding: emit when X-Mq-Accept-Encoding opt-in is present. */
    if (inject_ae && nh < MQ_GW_MAX_SEND_HDRS) {
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        size_t vl = xae_vl < VS - 1 ? xae_vl : VS - 1;
        memcpy(nb, "accept-encoding", 16);
        memcpy(vb, xae, vl);
        vb[vl] = '\0';
        hs[nh].name = nb;
        hs[nh].value = vb;
        nh++;
    }

    /* content-length: re-emit the recomputed value over the tunnel when the
     * request has a known body length (CL > 0). The ORIGINAL Content-Length header
     * is stripped (mq_gw_strip_client) and we emit our own validated value so the
     * value the server sees is the one this client committed to streaming. CL == 0
     * means fin-on-headers / no body (no_body above), so no content-length is
     * needed in that case. */
    if (head->content_length > 0 && nh < MQ_GW_MAX_SEND_HDRS) {
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        memcpy(nb, "content-length", 15);
        int vn = snprintf(vb, VS, "%lld", (long long)head->content_length);
        if (vn > 0 && (size_t)vn < VS) {
            hs[nh].name = nb;
            hs[nh].value = vb;
            nh++;
        }
    }

    /* Remaining request headers, EXCEPT those stripped client-side (hop-by-hop,
     * X-Mq-*, Host, Content-Length, Cookie). Lowercase the name (H3 requires
     * lowercase field names). */
    for (size_t i = 0; i < HN && nh < MQ_GW_MAX_SEND_HDRS; i++) {
        const char *n = H[i].name;
        size_t nl = strlen(n);
        if (mq_gw_strip_client(n, nl, forward_cookie)) continue;
        if (inject_ae && slice_ieq(n, nl, "accept-encoding")) continue;
        char *nb = namebuf + nh * NS;
        char *vb = valbuf + nh * VS;
        size_t cnl = nl < NS - 1 ? nl : NS - 1;
        for (size_t j = 0; j < cnl; j++) {
            char ch = n[j];
            if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
            nb[j] = ch;
        }
        nb[cnl] = '\0';
        size_t hvl = strlen(H[i].value);
        size_t vl = hvl < VS - 1 ? hvl : VS - 1;
        memcpy(vb, H[i].value, vl);
        vb[vl] = '\0';
        hs[nh].name = nb;
        hs[nh].value = vb;
        nh++;
    }

    /* Wire up H3 callbacks before sending so on_close cannot be lost. */
    mq_h3_req_set_cbs(hr, h3_on_read, h3_on_write, h3_on_close, r);

    long sh = mq_h3_req_send_headers(hr, hs, nh, no_body ? 1 : 0);
    free(namebuf);
    free(valbuf);

    if (sh < 0) {
        /* Hard send error: reset H3, synthesize 502. Detach the callbacks FIRST or
         * the deferred on_close would run on freed memory. r is not yet linked. */
        mq_h3_req_set_cbs(hr, NULL, NULL, NULL, NULL);
        mq_h3_req_reset(hr);
        r->req = NULL;
        r->h3_dead = 1;
        free(r);
        *err_status = 502;
        *reason = MQ_GW_REJ_TUNNEL_UNAVAIL;
        return NULL;
    }
    if (sh == 0) {
        /* EAGAIN on the header send (0 == NOTHING accepted). Essentially
         * unreachable; we fail closed with 502 rather than carry retry complexity. */
        MQ_LOGW("mq_gw_client: header send EAGAIN (flow-control); failing closed");
        mq_h3_req_set_cbs(hr, NULL, NULL, NULL, NULL);
        mq_h3_req_reset(hr);
        r->req = NULL;
        r->h3_dead = 1;
        free(r);
        *err_status = 502;
        *reason = MQ_GW_REJ_TUNNEL_UNAVAIL;
        return NULL;
    }

    if (no_body) r->upload_fin_sent = 1;

    /* Link the live request. */
    r->next = c->reqs;
    c->reqs = r;
    return r;
}


/* ── upload (junction #1) ───────────────────────────────────────────────────*/

/* Try to push as much of the spill buffer into H3 as it will take. When the
 * spill drains AND the upload is done, send the fin. Returns nothing; updates
 * paused/resume bookkeeping. */
static void
upload_pump(mq_gw_req_t *r)
{
    if (r->h3_dead || !r->req) return;

    /* Flush spill first. fin rides the LAST spill byte iff the local side has
     * signalled body-done (no more chunks will arrive) and this segment is the
     * tail. */
    while (r->spill && r->spill_off < r->spill_len) {
        size_t avail = r->spill_len - r->spill_off;
        int last = (r->upload_done && !r->upload_fin_sent);
        long acc =
            mq_h3_req_send_body(r->req, r->spill + r->spill_off, avail, last ? 1 : 0);
        if (acc < 0) {
            /* H3 hard error: reset; on_close handles the rest. */
            mq_h3_req_reset(r->req);
            return;
        }
        if (acc == 0) break; /* still blocked; wait for next on_write */
        r->spill_off += (size_t)acc;
        if (last && (size_t)acc == avail)
            r->upload_fin_sent = 1; /* fin went out with the last byte */
    }

    /* Spill drained? Reset the buffer + (maybe) resume the adapter input. */
    if (r->spill && r->spill_off >= r->spill_len) {
        r->spill_len = 0;
        r->spill_off = 0;
        if (r->paused && !r->local_dead && r->sink) {
            r->paused = 0;
            r->sink->resume_read(r->sink_user);
        }
    }

    /* All body delivered (on_body_done) and spill empty but fin not yet sent
     * (e.g. the spill was already empty when body-done fired, or the fin could
     * not ride a body byte) → send a bare fin. xqc_h3_request_finish on a
     * 0-length tail does not consume flow control, so EAGAIN here is effectively
     * unreachable; treat a non-negative return as success. */
    if (r->upload_done && !r->upload_fin_sent &&
        (!r->spill || r->spill_off >= r->spill_len)) {
        long fr = mq_h3_req_finish(r->req);
        if (fr < 0) {
            mq_h3_req_reset(r->req);
            return;
        }
        r->upload_fin_sent = 1;
    }
}

/* Neutral upload intake: feed `len` body bytes toward the tunnel. Returns 0 to
 * keep reading, -1 to pause (the bytes ARE consumed — the adapter must not
 * re-deliver them). Body of the former gw_on_body. */
int
mq_gw_client_req_body(mq_gw_xreq_t *r, const uint8_t *p, size_t len)
{
    if (r->local_dead) return 0;
    if (r->h3_dead || !r->req) {
        /* Tunnel gone but listener still feeding: drop bytes, ask for pause to
         * stop further delivery; the eventual local teardown handles cleanup. */
        return -1;
    }

    /* Append the new chunk after any spill that is still pending. The listener
     * contract: a -1 return means "pause AFTER consuming this chunk" — so we
     * MUST buffer the chunk if H3 cannot take all of it. */
    size_t off = 0;

    /* If nothing is buffered, try to send directly first (fast path). */
    if (!r->spill || r->spill_off >= r->spill_len) {
        long acc = mq_h3_req_send_body(r->req, p, len, 0);
        if (acc < 0) {
            mq_h3_req_reset(r->req);
            return -1;
        }
        off = (size_t)(acc > 0 ? acc : 0);
        if (off >= len) return 0; /* fully accepted; no pause needed */
    }

    /* Buffer the remainder [p+off, p+len). Compact any drained spill first. */
    if (r->spill && r->spill_off > 0) {
        memmove(r->spill, r->spill + r->spill_off, r->spill_len - r->spill_off);
        r->spill_len -= r->spill_off;
        r->spill_off = 0;
    }
    size_t need = len - off;
    size_t newlen = r->spill_len + need;
    if (newlen > MQ_GW_UPLOAD_SPILL_MAX) {
        /* Over the bound: still consume (contract) but the buffer is full. We
         * grow up to the bound and keep what fits; anything beyond is a hard
         * backpressure failure → reset the request rather than lose bytes
         * silently. In practice the listener pauses on our -1 before we reach
         * here, so this is a defensive ceiling. */
        MQ_LOGW("mq_gw_client: upload spill ceiling hit (%zu); resetting request",
                newlen);
        mq_h3_req_reset(r->req);
        return -1;
    }
    if (!r->spill) {
        r->spill = malloc(MQ_GW_UPLOAD_SPILL_MAX);
        if (!r->spill) {
            mq_h3_req_reset(r->req);
            return -1;
        }
        r->spill_len = 0;
        r->spill_off = 0;
    }
    memcpy(r->spill + r->spill_len, p + off, need);
    r->spill_len += need;

    /* Buffer non-empty → pause the listener (consume-on-deliver honored). */
    r->paused = 1;
    return -1;
}

/* Neutral upload intake: the adapter will deliver no more body bytes. Body of
 * the former gw_on_body_done. */
void
mq_gw_client_req_body_done(mq_gw_xreq_t *r)
{
    r->upload_done = 1;
    if (r->local_dead || r->h3_dead || !r->req) return;
    /* Flush any spill and send the fin if everything is out. */
    upload_pump(r);
}

/* Neutral intake: the adapter's input side died mid-request (truncated). Reset
 * the H3 request (never finish) and detach the sink side. The adapter is
 * already tearing down — do NOT call any sink op (the adapter handles its own
 * cleanup). */
void
mq_gw_client_req_aborted(mq_gw_xreq_t *r)
{
    r->sink = NULL;
    r->sink_user = NULL;
    if (r->local_dead) {
        gw_req_maybe_free(r);
        return;
    }
    r->local_dead = 1;
    if (!r->h3_dead && r->req) mq_h3_req_reset(r->req);
    gw_req_maybe_free(r);
}

/* Neutral intake: the adapter's output drained below its low watermark — resume
 * relaying the response body (replaces the listener drain_cb notification). */
void
mq_gw_client_req_drained(mq_gw_xreq_t *r)
{
    if (r->local_dead) return;
    if (r->read_deferred) {
        r->read_deferred = 0;
        download_pump(r);
    }
}

/* ── download (junction #2): H3 response → adapter SINK ─────────────────────
 *
 * The core extracts the H3 response head into a NEUTRAL (status, header-list,
 * body_mode) tuple and drives the adapter sink (resp_head/resp_body/resp_finish/
 * resp_abort). The in-file H1 sink (below) renders today's exact HTTP/1.1 bytes
 * (status line, Connection: close, chunked framing) so observable output is
 * byte-identical; a future H2/H3 adapter renders natively. */

/* Per-response header caps. The HARD limit on the response head is the H1 sink's
 * 8192-byte render buffer (h1_resp_head); MQ_GW_RESP_MAX_HDRS / _ARENA are sized
 * so that buffer fills FIRST. This reproduces the pre-refactor behavior, which had
 * per-field caps + an 8192 render buffer and NO header-COUNT cap — an origin
 * sending many small headers (e.g. 100+ Set-Cookie) must relay, not 502. */
#define MQ_GW_RESP_NAME_CAP 128
#define MQ_GW_RESP_VAL_CAP  2048
#define MQ_GW_RESP_MAX_HDRS 2048
#define MQ_GW_RESP_ARENA    16384

/* Header-capture context for recv_headers (download). Collects the response
 * headers into a NEUTRAL mq_h3_header_t list (pointers into a shared NUL-
 * terminated arena) instead of serializing HTTP/1.1 inline — the sink renders.
 * Slots/arena are sized generously so the sink's 8192-byte buffer is the binding
 * limit (not a count cap), matching the original byte-bounded behavior. */
typedef struct {
    mq_gw_req_t *r;
    int status;
    int has_cl; /* response carried a content-length */
    mq_h3_header_t hs[MQ_GW_RESP_MAX_HDRS];
    size_t nh;
    char arena[MQ_GW_RESP_ARENA]; /* name\0 value\0 ... for all collected headers */
    size_t arena_off;
    int ok; /* head fit + well-formed */
} dl_hdr_ctx_t;

static void
dl_each_header(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    dl_hdr_ctx_t *ctx = (dl_hdr_ctx_t *)u;
    if (!ctx->ok) return;

    /* :status pseudo-header → status line. An H3 :status is EXACTLY three ASCII
     * digits (RFC 9114/9113 response semantics). A hostile peer that sends e.g.
     * ":status: 99999999999" must not be accumulated into a signed int (overflow
     * is UB → UBSan abort); reject anything that is not 3 digits as an
     * upstream-protocol failure (ctx->ok=0 → caller synthesizes 502). */
    if (nl == 7 && memcmp(n, ":status", 7) == 0) {
        if (vl != 3 || v[0] < '0' || v[0] > '9' || v[1] < '0' || v[1] > '9' ||
            v[2] < '0' || v[2] > '9') {
            ctx->ok = 0;
            return;
        }
        int code = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
        if (code < 100 || code > 599) code = 502;
        ctx->status = code;
        return;
    }

    /* Other pseudo-headers (none expected on a response) → drop. */
    if (nl > 0 && n[0] == ':') return;

    /* Strip hop-by-hop. KEEP x-mq-* diagnostic headers (design: X-Mq-Origin-
     * Protocol etc. SHOULD reach the local client). */
    if (mq_gw_strip_hop(n, nl)) return;

    /* content-length → passthrough (and remember we have one). */
    if (slice_ieq(n, nl, "content-length")) ctx->has_cl = 1;

    /* Build NUL-terminated name/value (bounded). An origin response header NAME or
     * VALUE that would not fit must FAIL the response (ctx->ok = 0 → caller takes
     * the failure path), not be silently truncated: a clipped value corrupts the
     * downstream response, and origin headers this large are pathological — failing
     * closed beats corrupting. */
    if (nl >= MQ_GW_RESP_NAME_CAP || vl >= MQ_GW_RESP_VAL_CAP) {
        ctx->ok = 0;
        return;
    }
    /* Fail closed if we run out of header slots or arena space. Both are sized so
     * the sink's 8192-byte render buffer fills first, so in practice the binding
     * limit is the byte buffer (matching pre-refactor behavior), not a count. */
    if (ctx->nh >= MQ_GW_RESP_MAX_HDRS) {
        ctx->ok = 0;
        return;
    }
    if (ctx->arena_off + nl + 1 + vl + 1 > sizeof(ctx->arena)) {
        ctx->ok = 0;
        return;
    }
    char *nb = ctx->arena + ctx->arena_off;
    memcpy(nb, n, nl);
    nb[nl] = '\0';
    ctx->arena_off += nl + 1;
    char *vb = ctx->arena + ctx->arena_off;
    memcpy(vb, v, vl);
    vb[vl] = '\0';
    ctx->arena_off += vl + 1;
    ctx->hs[ctx->nh].name = nb;
    ctx->hs[ctx->nh].value = vb;
    ctx->nh++;
}

/* Extract the H3 response head and drive the sink's resp_head. Returns 0 on
 * success (head delivered), -1 on a hard failure (caller aborts). */
static int
download_start_response(mq_gw_req_t *r)
{
    dl_hdr_ctx_t *ctx = malloc(sizeof(*ctx));
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->r = r;
    ctx->ok = 1;

    int fin = 0;
    int n = mq_h3_req_recv_headers(r->req, dl_each_header, ctx, &fin);
    if (n < 0 || !ctx->ok || ctx->status == 0) {
        /* recv error / malformed / no :status → malformed response. */
        free(ctx);
        return -1;
    }
    r->resp_status = ctx->status;

    /* No content-length → unknown length (the H1 sink frames the body chunked). */
    mq_gw_body_mode_t mode = ctx->has_cl ? MQ_GW_BODY_CONTENT_LENGTH : MQ_GW_BODY_STREAM;

    int hr = r->sink->resp_head(r->sink_user, ctx->status, ctx->hs, ctx->nh, mode);
    free(ctx);
    if (hr < 0) return -1;
    r->resp_started = 1;

    /* If headers carried fin (no body), finish immediately. Use gw_local_finish
     * (not a direct resp_finish call) so that r->local_dead + r->sink are cleared
     * atomically — gw_local_finish sets local_dead=1 BEFORE calling resp_finish,
     * ensuring h3_on_close (which fires LATER on the same event loop iteration)
     * sees local_dead and skips any further sink op. A direct resp_finish call
     * here would free the adapter's per-request state without clearing r->sink /
     * r->sink_user, causing h3_on_close to call resp_abort on freed memory. */
    if (fin) gw_local_finish(r);
    return 0;
}

/* Drain H3 body and feed it to the sink. Honors the sink highwater: resp_body
 * returning 0 sets read_deferred and stops; the drain notification re-kicks. */
static void
download_pump(mq_gw_req_t *r)
{
    if (r->local_dead || r->h3_dead || !r->req) return;
    if (r->read_deferred) return; /* waiting for sink drain */

    uint8_t buf[MQ_GW_DOWNLOAD_CHUNK];
    for (;;) {
        int fin = 0;
        long n = mq_h3_req_recv_body(r->req, buf, sizeof(buf), &fin);
        if (n < 0) {
            /* Hard recv error mid-download → abort (truncation must be visible). */
            gw_local_abort(r);
            return;
        }
        if (n > 0) {
            int wr = r->sink->resp_body(r->sink_user, buf, (size_t)n);
            if (wr < 0) {
                /* Sink/local output dead → tear down the request (resets H3). */
                gw_local_dead(r);
                return;
            }
            if (wr == 0) {
                r->read_deferred = 1;
                if (!fin) return;
            }
        }
        if (fin) {
            gw_local_finish(r);
            return;
        }
        if (n == 0) return; /* no more body available right now */
    }
}

/* ── H3 request callbacks ───────────────────────────────────────────────────*/

static void
h3_on_read(mq_h3_req_t *hr, int flag, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    if (r->local_dead) {
        /* Local gone: keep draining/discarding so the stream can finish, but do
         * not write anywhere. We already reset on local death, so just return. */
        return;
    }

    if (flag & (XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_TRAILER)) {
        if (!r->resp_started) {
            /* First (and for us only) header section → build local response. */
            if (download_start_response(r) != 0) {
                /* Malformed/short response head → abort if started else 502.
                 * NOTE: download_start_response only ever returns non-zero BEFORE
                 * it sets r->resp_started (every failure path returns earlier), so
                 * the resp_started branch is defensive-only / currently
                 * unreachable; it is kept to stay correct if that ordering ever
                 * changes (e.g. a post-head write failure path is added). */
                if (r->resp_started)
                    gw_local_abort(r);
                else
                    gw_local_error_req(r, 502, "upstream-protocol");
                return;
            }
        } else {
            /* Trailer section: drain + ignore (we already sent Connection:close
             * and either CL or chunked framing; trailers are not forwarded in the
             * MVP). recv to keep xquic's flow moving. */
            int tfin = 0;
            mq_h3_req_recv_headers(r->req, NULL, NULL, &tfin);
        }
    }

    if (r->local_dead) return;

    /* Drain any available body. */
    download_pump(r);
}

static void
h3_on_write(mq_h3_req_t *hr, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    if (r->h3_dead || !r->req) return;
    /* A previously-blocked send can resume: flush upload spill / fin. */
    upload_pump(r);
}

static void
h3_on_close(mq_h3_req_t *hr, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    r->h3_dead = 1;
    r->req = NULL; /* freed right after this returns */

    if (!r->local_dead) {
        /* Tunnel closed. If the response never started, synthesize 502 via the
         * sink; else the local side must see a truncation (abort, not a fake
         * clean finish). Detach the sink INLINE (do NOT call gw_local_* helpers
         * — they call gw_req_maybe_free, which would free r out from under the
         * final maybe_free below → use-after-free). */
        const mq_gw_sink_ops_t *sink = r->sink;
        void *su = r->sink_user;
        r->local_dead = 1;
        r->sink = NULL;
        r->sink_user = NULL;
        if (sink) {
            if (!r->resp_started) {
                /* Synthesize 502 with X-Mq-Error: upstream-reset. */
                mq_h3_header_t eh[2];
                eh[0].name = "X-Mq-Error";
                eh[0].value = "upstream-reset";
                eh[1].name = "Content-Length";
                eh[1].value = "0";
                int hr2 = sink->resp_head(su, 502, eh, 2, MQ_GW_BODY_CONTENT_LENGTH);
                if (hr2 >= 0)
                    sink->resp_finish(su);
                else
                    sink->resp_abort(su);
            } else {
                sink->resp_abort(su);
            }
        }
    }
    gw_req_maybe_free(r); /* both sides now dead → frees r exactly once */
}

/* Synthesize an error response via the sink on a request whose local side is
 * still live (used from the read path when the response head is malformed). */
static void
gw_local_error_req(mq_gw_req_t *r, int code, const char *xmq)
{
    if (r->local_dead || !r->sink) return;
    const mq_gw_sink_ops_t *sink = r->sink;
    void *su = r->sink_user;
    r->local_dead = 1;
    r->sink = NULL;
    r->sink_user = NULL;
    mq_h3_header_t eh[2];
    eh[0].name = "X-Mq-Error";
    eh[0].value = (char *)xmq;
    eh[1].name = "Content-Length";
    eh[1].value = "0";
    int hr = sink->resp_head(su, code, eh, 2, MQ_GW_BODY_CONTENT_LENGTH);
    if (hr >= 0)
        sink->resp_finish(su);
    else
        sink->resp_abort(su);
    if (!r->h3_dead && r->req) mq_h3_req_reset(r->req);
    gw_req_maybe_free(r);
}

/* ── conn state ─────────────────────────────────────────────────────────────*/

static void
gw_conn_state(mq_h3_conn_t *c, int established, void *user)
{
    (void)c;
    mq_gw_client_t *cli = (mq_gw_client_t *)user;
    if (established) {
        cli->conn_up = 1;
        MQ_LOGI("mq_gw_client: tunnel conn established");
        /* Back to SERVING: reset the backoff counter + disarm the reconnect timer
         * so the next loss starts from base again. The gateway has no auth latch,
         * so `established` IS the reconnect-success hook. */
        cli->reconnect_attempts = 0;
        gw_reconnect_stop(cli);
        /* Re-arm multipath for this (possibly reconnected) conn: reset added_paths
         * so the mp-timer re-adds every registered extra path on the new conn.
         * Harmless on the first establish (added_paths is 0; arm is a no-op when
         * n_extra_paths == 0). */
        cli->added_paths = 0;
        gw_mp_timer_arm(cli);
    } else {
        MQ_LOGI("mq_gw_client: tunnel conn closed");
        /* In-flight requests get their own per-request on_close from mq_h3, which
         * handles their local teardown. Nothing to do here for them. */

        /* Decide reconnect vs terminal from shutting_down + reconnect_enabled ONLY.
         * reconnect_ev != NULL also guards the timer existing. */
        int reconnect_now =
            (!cli->shutting_down && cli->reconnect_enabled && cli->reconnect_ev != NULL);

        if (reconnect_now) {
            /* Do NOT go terminal: tear down the dead conn's per-conn state and arm
             * the backoff timer to re-establish. conn stays NULL through the backoff
             * window; gw_issue_connect re-wires a fresh conn. */
            cli->conn_up = 0;
            cli->conn = NULL; /* the conn wrapper is freed after this returns */
            cli->added_paths = 0;
            gw_mp_timer_stop(cli);
            gw_reconnect_arm(cli);
        } else {
            /* Terminal (shutting_down or reconnect disabled): legacy behavior. */
            cli->conn_up = 0;
            cli->conn = NULL; /* the conn wrapper is freed after this returns */
        }
    }
}

/* ── mp-poll timer (mirrors mq_client) ──────────────────────────────────────*/

static void
gw_mp_timer_stop(mq_gw_client_t *c)
{
    if (c->mp_timer) {
        event_free(c->mp_timer);
        c->mp_timer = NULL;
    }
}

static void
gw_mp_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_gw_client_t *c = (mq_gw_client_t *)arg;
    if (!c->conn) {
        gw_mp_timer_stop(c);
        return;
    }
    if (!mq_h3_conn_mp_ready(c->conn)) return;
    while (c->added_paths < c->n_extra_paths) {
        const char *ip = c->extra_paths[c->added_paths];
        int pid = mq_h3_conn_add_path(c->conn, ip, 0);
        if (pid >= 0)
            MQ_LOGI("mq_gw_client: extra path up: bind %s -> path_id %d", ip, pid);
        else
            MQ_LOGW("mq_gw_client: failed to add extra path bind %s (rc=%d)", ip, pid);
        c->added_paths++;
    }
    gw_mp_timer_stop(c);
}

static void
gw_mp_timer_arm(mq_gw_client_t *c)
{
    if (c->mp_timer || c->added_paths >= c->n_extra_paths) return;
    struct event_base *base = mq_runtime_base(c->rt);
    if (!base) return;
    c->mp_timer = event_new(base, -1, EV_PERSIST, gw_mp_timer_cb, c);
    if (!c->mp_timer) return;
    struct timeval tv = {.tv_sec = 0, .tv_usec = MQ_GW_MP_POLL_MS * 1000};
    event_add(c->mp_timer, &tv);
}

/* ── public API ─────────────────────────────────────────────────────────────*/

/* Issue the (re-)connect: open a fresh H3 tunnel conn with keepalive and wire the
 * state callback. Re-invoked by the reconnect timer. Returns 0 on success, -1 on
 * failure (the caller re-arms backoff). */
static int
gw_issue_connect(mq_gw_client_t *c)
{
    c->conn = mq_h3_connect(c->h3, (struct sockaddr *)&c->peer, c->peerlen, c->cc,
                            c->keepalive_idle_ms, gw_conn_state, c);
    if (!c->conn) {
        MQ_LOGE("mq_gw_client: tunnel connect failed");
        return -1;
    }
    return 0;
}

/* ── Reconnect controller (Phase 5b, mirrors mq_client) ──────────────────────
 *
 * reconnect_ev is created ONCE in mq_gw_client_new and freed ONLY in
 * mq_gw_client_free; it is a one-shot timer re-armed across reconnect cycles, so
 * stop() must NOT free it (unlike the mp-timer). */

/* Disarm the backoff timer (idempotent). Does NOT free reconnect_ev. */
static void
gw_reconnect_stop(mq_gw_client_t *c)
{
    if (c->reconnect_ev) {
        evtimer_del(c->reconnect_ev);
    }
}

/* Arm the one-shot backoff timer for the next reconnect attempt. Exponential
 * (base 250 ms, cap reconnect_max_backoff_ms) with half-jitter into [d/2, d] so
 * the re-arm cannot land near zero and spin. */
static void
gw_reconnect_arm(mq_gw_client_t *c)
{
    if (!c->reconnect_ev) {
        return;
    }
    c->reconnect_attempts++;
    uint64_t d = mq_backoff_ms(MQ_GW_RECONNECT_BASE_MS, c->reconnect_max_backoff_ms,
                               c->reconnect_attempts);
    uint64_t j = d / 2 + (uint64_t)(random() % (long)(d / 2 + 1));
    struct timeval tv = {.tv_sec = (time_t)(j / 1000),
                         .tv_usec = (suseconds_t)((j % 1000) * 1000)};
    evtimer_add(c->reconnect_ev, &tv);
}

/* Backoff timer fired: re-issue the connect. On a synchronous connect failure
 * re-arm with the next backoff rather than going terminal — an always-on device
 * must self-heal across long outages. */
static void
gw_reconnect_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_gw_client_t *c = (mq_gw_client_t *)arg;
    if (gw_issue_connect(c) != 0) {
        gw_reconnect_arm(c);
    }
}

mq_gw_client_t *
mq_gw_client_new(mq_transport_t *t, mq_runtime_t *rt, mq_h3_t *h3, const char *server_ip,
                 uint16_t server_port, const char *token, mq_cc_t cc,
                 uint64_t keepalive_idle_ms, int reconnect_enabled,
                 uint64_t reconnect_max_backoff_ms)
{
    if (!t || !rt || !h3 || !server_ip || !token) return NULL;

    mq_gw_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->t = t;
    c->rt = rt;
    c->h3 = h3;
    c->cc = cc;
    snprintf(c->token, sizeof(c->token), "%s", token);

    c->keepalive_idle_ms = keepalive_idle_ms;
    c->reconnect_enabled = reconnect_enabled ? 1 : 0;
    if (reconnect_max_backoff_ms < 1000) {
        reconnect_max_backoff_ms = 1000;
    }
    c->reconnect_max_backoff_ms = reconnect_max_backoff_ms;

    memset(&c->peer, 0, sizeof(c->peer));
    c->peer.sin_family = AF_INET;
    c->peer.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &c->peer.sin_addr) != 1) {
        free(c);
        return NULL;
    }
    c->peerlen = sizeof(c->peer);

    /* Create the reconnect backoff timer ONCE (when enabled), BEFORE the eager
     * connect so the timer exists if the first connect's conn later closes. It is
     * one-shot, armed only from the close handler, disarmed on establish + on
     * shutdown, and freed only in mq_gw_client_free. */
    if (c->reconnect_enabled) {
        c->reconnect_ev = evtimer_new(mq_runtime_base(c->rt), gw_reconnect_cb, c);
        if (!c->reconnect_ev) {
            MQ_LOGW("mq_gw_client: reconnect timer alloc failed (reconnect disabled)");
        }
    }

    /* Eager connect (mirror mq_client), using keepalive. */
    if (gw_issue_connect(c) != 0) {
        if (c->reconnect_ev) {
            event_free(c->reconnect_ev);
            c->reconnect_ev = NULL;
        }
        free(c);
        return NULL;
    }
    return c;
}

const char *
mq_gw_client_token(const mq_gw_client_t *c)
{
    if (!c) return NULL;
    return c->token;
}

void
mq_gw_client_dump_stats(mq_gw_client_t *c)
{
    if (!c || !c->conn) return;
    mq_h3_conn_dump_stats(c->conn);
}

int
mq_gw_client_add_paths(mq_gw_client_t *c, const char *const *ips, size_t n)
{
    if (!c || (n > 0 && !ips)) return -1;
    size_t accepted = 0;
    for (size_t i = 0; i < n; i++) {
        if (!ips[i]) continue;
        if (c->n_extra_paths >= MQ_GW_MAX_PATHS) {
            MQ_LOGW("mq_gw_client: extra-path capacity %d reached; ignoring %s",
                    MQ_GW_MAX_PATHS, ips[i]);
            break;
        }
        snprintf(c->extra_paths[c->n_extra_paths], MQ_GW_IP_MAX, "%s", ips[i]);
        c->n_extra_paths++;
        accepted++;
    }
    gw_mp_timer_arm(c);
    return (int)accepted;
}

void
mq_gw_client_free(mq_gw_client_t *c)
{
    if (!c) return;
    /* Mark teardown FIRST so a late conn close takes the terminal path (no
     * reconnect-after-free). Then disarm + free the backoff timer. */
    c->shutting_down = 1;
    gw_reconnect_stop(c);
    if (c->reconnect_ev) {
        event_free(c->reconnect_ev);
        c->reconnect_ev = NULL;
    }
    gw_mp_timer_stop(c);

    /* DETACH the conn-state callback first. gw_client_free runs while the H3
     * engine is still live (sanctioned order), so the conn's close transition
     * still fires LATER, during mq_h3_free / engine teardown — by then `c` is
     * freed. Clearing on_state(user) here stops gw_conn_state from touching the
     * freed gw_client. (The conn itself is borrowed; mq_h3 frees it.) */
    if (c->conn) mq_h3_conn_set_state_cb(c->conn, NULL, NULL);

    /* Tear down in-flight requests. SANCTIONED TEARDOWN ORDER (see header):
     * gw_client_free runs FIRST, while the H3 engine is STILL LIVE — so touching
     * r->req here is valid. For each live request we:
     *   1. DETACH its H3 callbacks (set_cbs NULL) so the deferred on_close that
     *      mq_h3_req_reset schedules cannot re-enter h3_on_close on the
     *      mq_gw_req_t we are about to free (that would be a UAF + double free).
     *   2. RESET the H3 request (truncate the tunnel side cleanly).
     *   3. ABORT the local side via the sink (the local peer sees truncation).
     *   4. Free the per-request state ourselves (we own it; both sides detached).
     * Because we cleared the callbacks, the subsequent mq_h3_free engine teardown
     * fires no callback back into us — our wrappers and r are already gone. */
    mq_gw_req_t *r = c->reqs;
    while (r) {
        mq_gw_req_t *next = r->next;
        if (!r->h3_dead && r->req) {
            mq_h3_req_set_cbs(r->req, NULL, NULL, NULL, NULL);
            mq_h3_req_reset(r->req);
        }
        if (!r->local_dead && r->sink) {
            r->sink->resp_abort(r->sink_user);
        }
        free(r->spill);
        free(r);
        r = next;
    }
    c->reqs = NULL;
    free(c);
}
