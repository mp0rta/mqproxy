// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_client.c — client-side fetch→H3 bridge. See mq_gw_client.h.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PER-REQUEST OWNERSHIP (mq_gw_req_t)
 * ─────────────────────────────────────────────────────────────────────────────
 * Each accepted fetch request owns one mq_gw_req_t. It is referenced from two
 * independent sides that can each die first or race:
 *
 *   LOCAL side  (the mq_fetch_listener handle): set on accept; cleared when we
 *     call mq_fetch_conn_finish/abort, OR when the listener tells us the local
 *     peer died (on_aborted). After any of those the handle is DEAD — we null it
 *     and never touch it again. The req_ctx the listener threads back to us
 *     stays valid until then.
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
 *     fires later → both dead → free. We set local_dead immediately and drop the
 *     handle so no further handle op runs.
 *   - tunnel terminates first (h3 on_close): we finish/abort the local handle
 *     (if still live) → that detaches local → both dead → free. on_close sets
 *     h3_dead and nulls the req pointer.
 *   - both race: idempotent flags; maybe_free runs only when both set, so the
 *     struct is freed exactly once regardless of order.
 *
 * The listener guarantees no cbs fire after finish/abort; mq_h3 guarantees
 * on_close fires exactly once. So each side flips its flag exactly once.
 *
 * One subtlety: when we call mq_fetch_conn_finish/abort from inside an H3
 * callback, that does NOT synchronously re-enter our fetch cbs (the listener
 * detaches first). So no reentrancy hazard there. Conversely, when the LOCAL
 * side dies we learn it either via on_aborted (explicit) or via a handle op
 * returning -1 (the listener handle is dead) — we treat a -1 from any write/
 * resume as "local dead" and reset the tunnel.
 *
 * HANDLE INVARIANT: r->handle is set exactly once (at accept) and is nulled in
 * the SAME step that sets r->local_dead=1 (every such site does both). Therefore
 * `!r->local_dead` ⟹ `r->handle != NULL`. Code that has already established
 * `!r->local_dead` (e.g. download_pump, which returns early if local_dead) may
 * call mq_fetch_conn_* on r->handle WITHOUT a redundant NULL guard. The few
 * `if (r->handle)` guards that remain are at points reachable independent of
 * that early check and are kept for defence-in-depth.
 *
 * NEUTRAL-BOUNDARY NOTE (Task 3): the per-request state is the opaque
 * mq_gw_xreq_t handed to adapters. Today the H1 fetch path also carries `handle`
 * (the listener fd) + H1-rendering scratch, and the in-file H1 sink writes via
 * mq_fetch_conn_* on it. Once Task 4 rewires the listener through the neutral
 * boundary and removes `handle`, the invariant becomes the SINK's liveness:
 * `!intake_dead` ⟹ `sink_user != NULL` (the sink is set once at req_begin and
 * cleared in lockstep with local_dead). For Task 3 the sink and `handle` track
 * each other 1:1 (the H1 sink's user IS the handle), so both invariants hold.
 */
#include "gateway/mq_gw_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>

#include "gateway/mq_gw_headers.h"
#include "gateway/mq_http1.h"
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
 * mq_gw_intake.h as `struct mq_gw_xreq_s`). The legacy `mq_gw_req_t` alias is
 * kept (below) so the in-file H1 fetch path reads unchanged this task; both name
 * the same struct. The `handle` + H1-rendering fields (resp_chunked etc.) belong
 * to the in-file H1 sink and are removed in Task 4 once the listener is rewired
 * onto the neutral boundary. The neutral side drives the sink via sink/sink_user. */
struct mq_gw_xreq_s {
    mq_gw_client_t *cli;

    /* ── neutral intake (sink) side ── */
    const mq_gw_sink_ops_t *sink; /* adapter callbacks (NULL == intake detached) */
    void *sink_user;              /* adapter per-request cookie */

    /* local (listener) side — H1 sink scratch; removed in Task 4. */
    void *handle; /* the fetch handle; NULL once detached (dead) */
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
    int resp_started;  /* we wrote the response status line locally */
    int resp_chunked;  /* response is framed as Transfer-Encoding: chunked */
    int read_deferred; /* local write hit highwater; stop recv_body until drain */
    int resp_status;   /* parsed :status (for diagnostics) */

    struct mq_gw_xreq_s *next; /* intrusive list of live requests on the client */
};

/* Legacy in-file alias: the H1 fetch path still spells the per-request state
 * `mq_gw_req_t`. Same struct as the public opaque mq_gw_xreq_t. */
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
static void h3_on_read(mq_h3_req_t *hr, int flag, void *user);
static void h3_on_write(mq_h3_req_t *hr, void *user);
static void h3_on_close(mq_h3_req_t *hr, void *user);
static void local_drain_cb(void *user);
static void upload_pump(mq_gw_req_t *r);
static void download_pump(mq_gw_req_t *r);
static void gw_local_error_req(mq_gw_req_t *r, int code, const char *reason,
                               const char *xmq);
/* Reconnect controller + the re-issuable connect body (defined below). */
static int gw_issue_connect(mq_gw_client_t *c);
static void gw_reconnect_arm(mq_gw_client_t *c);
static void gw_reconnect_stop(mq_gw_client_t *c);
static void gw_mp_timer_arm(mq_gw_client_t *c);
static void gw_mp_timer_stop(mq_gw_client_t *c);
/* In-file H1 response sink (defined with the download path below). */
static const mq_gw_sink_ops_t g_h1_sink;

/* ── small helpers ──────────────────────────────────────────────────────────*/

/* Serialize a complete HTTP/1.1 error response (status + Connection: close +
 * Content-Length: 0 + X-Mq-Error: <reason>) into buf. Returns the byte length,
 * or 0 if it did not fit. */
static size_t
gw_build_error(char *buf, size_t cap, int code, const char *reason, const char *xmq_error)
{
    int o = 0, n;
    n = mq_http1_write_status(buf + o, cap - o, code, reason);
    if (n <= 0) return 0;
    o += n;
    n = mq_http1_write_header(buf + o, cap - o, "Connection", "close");
    if (n <= 0) return 0;
    o += n;
    n = mq_http1_write_header(buf + o, cap - o, "Content-Length", "0");
    if (n <= 0) return 0;
    o += n;
    n = mq_http1_write_header(buf + o, cap - o, "X-Mq-Error", xmq_error);
    if (n <= 0) return 0;
    o += n;
    if ((size_t)o + 2 > cap) return 0;
    buf[o++] = '\r';
    buf[o++] = '\n';
    return (size_t)o;
}

/* on_request REJECTION path: write the error response and return -1. The
 * listener's on_request==-1 contract flushes + closes the connection itself
 * (detached), so we MUST NOT call mq_fetch_conn_finish here (that would double
 * the teardown). Write only. */
static void
gw_reject_write(void *handle, int code, const char *reason, const char *xmq_error)
{
    char buf[512];
    size_t n = gw_build_error(buf, sizeof(buf), code, reason, xmq_error);
    if (n) mq_fetch_conn_write(handle, buf, n);
}

/* POST-ACCEPT error path (the request was accepted, the listener is in RESP
 * phase waiting for finish/abort): write the error response THEN finish. */
static void
gw_local_error(void *handle, int code, const char *reason, const char *xmq_error)
{
    char buf[512];
    size_t n = gw_build_error(buf, sizeof(buf), code, reason, xmq_error);
    if (n) mq_fetch_conn_write(handle, buf, n);
    mq_fetch_conn_finish(handle);
}

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

/* Find the value slice of header `name` (case-insensitive) in req; NULL if
 * absent. *out_vl receives the value length. */
static const char *
find_hdr(const mq_http1_req_t *req, const char *name, size_t *out_vl)
{
    for (size_t i = 0; i < req->nh; i++) {
        if (slice_ieq(req->h[i].n, req->h[i].nl, name)) {
            if (out_vl) *out_vl = req->h[i].vl;
            return req->h[i].v;
        }
    }
    return NULL;
}

/* ── neutral header-list helpers (mq_h3_header_t, NUL-terminated) ────────────*/

/* Find header `name` (case-insensitive) in a neutral list; NULL if absent.
 * *out_vl receives strlen(value). */
static const char *
nfind_hdr(const mq_h3_header_t *hs, size_t n, const char *name, size_t *out_vl)
{
    size_t nl = strlen(name);
    for (size_t i = 0; i < n; i++) {
        if (slice_ieq(hs[i].name, strlen(hs[i].name), name)) {
            (void)nl;
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

/* The LOCAL side terminated (finish/abort already issued, OR on_aborted, OR a
 * handle op returned -1). Detach the handle and, if the tunnel is still live,
 * reset it so its on_close eventually frees the struct. */
static void
gw_local_dead(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    r->local_dead = 1;
    r->handle = NULL; /* dead — never touch again */
    if (!r->h3_dead && r->req) {
        /* Mid-stream local death: reset the H3 request (truncated). on_close
         * fires later and finishes the teardown. */
        mq_h3_req_reset(r->req);
    }
    gw_req_maybe_free(r);
}

/* Finish the local side cleanly (response fully relayed). Detaches the handle. */
static void
gw_local_finish(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    void *h = r->handle;
    r->local_dead = 1;
    r->handle = NULL;
    if (h) mq_fetch_conn_finish(h);
    gw_req_maybe_free(r);
}

/* Abort the local side (mid-stream truncation visible to the local peer).
 * Detaches the handle. */
static void
gw_local_abort(mq_gw_req_t *r)
{
    if (r->local_dead) return;
    void *h = r->handle;
    r->local_dead = 1;
    r->handle = NULL;
    if (h) mq_fetch_conn_abort(h);
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

/* ── H1 fetch path: shim onto the neutral boundary ──────────────────────────
 *
 * The listener-facing fetch callbacks (mq_gw_client_fetch_cbs) build neutral
 * inputs from the mq_http1_req_t and drive the core API. The X-Mq-Target/Method
 * parse (the fetch envelope) stays HERE (it is fetch-specific), sequenced
 * BETWEEN prevalidate and req_begin so the observable reject ORDER is preserved:
 *   dup -> auth -> target -> method -> [req_begin: origin-proto/cache/size/tunnel]
 * The in-file H1 sink (g_h1_sink) renders the response; on a req_begin reject we
 * map the reason enum to the byte-identical (status, X-Mq-Error) error. */

static const char *
gw_reason_xmq(mq_gw_reject_reason_t reason)
{
    switch (reason) {
    case MQ_GW_REJ_DUP_CONTROL: return "duplicate-control-header";
    case MQ_GW_REJ_MISSING_AUTH: return "missing-auth";
    case MQ_GW_REJ_BAD_AUTH: return "bad-auth-format";
    case MQ_GW_REJ_BAD_TARGET: return "bad-target";
    case MQ_GW_REJ_BAD_METHOD: return "bad-method";
    case MQ_GW_REJ_BAD_ORIGIN_PROTO: return "bad-origin-protocol";
    case MQ_GW_REJ_BAD_CACHE_TTL: return "bad-cache-ttl";
    case MQ_GW_REJ_HEADER_TOO_LONG: return "header-too-long";
    case MQ_GW_REJ_TUNNEL_UNAVAIL: return "tunnel-unavailable";
    case MQ_GW_REJ_INTERNAL: return "internal-error";
    default: return "internal-error";
    }
}

/* H1 reason → status-line reason phrase (mirrors the original literals). */
static const char *
gw_status_phrase(int code)
{
    return code == 502 ? "Bad Gateway" : "Bad Request";
}

static int
gw_on_request(const mq_http1_req_t *req, void *handle, void *user, void **req_ctx)
{
    mq_gw_client_t *c = (mq_gw_client_t *)user;
    *req_ctx = NULL;

    /* Build a NEUTRAL, NUL-terminated, UNtruncated copy of the request headers so
     * the core's strlen-based size checks observe the true lengths (the same
     * semantics the original slice-based checks had). Allocated on the heap to
     * hold arbitrary header sizes; freed before we return. */
    size_t hn = req->nh;
    mq_h3_header_t *H = NULL;
    char *namearena = NULL, *valarena = NULL;
    /* Per-slot caps generous enough that any header the original would have
     * forwarded fits; oversized ones still get a correct strlen (>= cap) so the
     * core's header-too-long check fires identically. */
    if (hn > 0) {
        H = calloc(hn, sizeof(*H));
        /* +2 for NUL terminators; size each slot to the actual slice length. */
        size_t names_sz = 0, vals_sz = 0;
        for (size_t i = 0; i < hn; i++) {
            names_sz += req->h[i].nl + 1;
            vals_sz += req->h[i].vl + 1;
        }
        namearena = malloc(names_sz ? names_sz : 1);
        valarena = malloc(vals_sz ? vals_sz : 1);
        if (!H || !namearena || !valarena) {
            free(H);
            free(namearena);
            free(valarena);
            gw_reject_write(handle, 502, "Bad Gateway", "internal-error");
            return -1;
        }
        char *np = namearena, *vp = valarena;
        for (size_t i = 0; i < hn; i++) {
            memcpy(np, req->h[i].n, req->h[i].nl);
            np[req->h[i].nl] = '\0';
            H[i].name = np;
            np += req->h[i].nl + 1;
            memcpy(vp, req->h[i].v, req->h[i].vl);
            vp[req->h[i].vl] = '\0';
            H[i].value = vp;
            vp += req->h[i].vl + 1;
        }
    }

    int status = 0;

    /* Phase 1 (header-only): dup-control-header, X-Mq-Auth. */
    mq_gw_reject_reason_t pre = mq_gw_client_prevalidate(c, H, hn, &status);
    if (pre != MQ_GW_OK) {
        gw_reject_write(handle, status, gw_status_phrase(status), gw_reason_xmq(pre));
        free(H);
        free(namearena);
        free(valarena);
        return -1;
    }

    /* Fetch envelope (fetch-specific; stays in the shim): X-Mq-Target. */
    size_t tgt_vl = 0;
    const char *tgt = find_hdr(req, "x-mq-target", &tgt_vl);
    mq_gw_target_t target;
    if (!tgt || mq_gw_parse_target(tgt, tgt_vl, &target) != 0) {
        gw_reject_write(handle, 400, "Bad Request", "bad-target");
        free(H);
        free(namearena);
        free(valarena);
        return -1;
    }

    /* X-Mq-Method if present parses; default GET. */
    char method[16];
    size_t mth_vl = 0;
    const char *mth = find_hdr(req, "x-mq-method", &mth_vl);
    if (mth) {
        if (mq_gw_parse_method(mth, mth_vl, method) != 0) {
            gw_reject_write(handle, 400, "Bad Request", "bad-method");
            free(H);
            free(namearena);
            free(valarena);
            return -1;
        }
    } else {
        memcpy(method, "GET", 4);
    }

    /* Phase 2 (core): origin-proto / cache / header-size / tunnel + open+forward.
     * The H1 sink_user is the per-request state itself (g_h1_sink reuses r). */
    mq_gw_req_head_t head;
    head.method = method;
    head.scheme = target.scheme;
    head.authority = target.authority;
    head.path = target.path;
    head.headers = H;
    head.n_headers = hn;
    head.content_length = req->content_length;

    /* sink_user is set to the returned xreq once we have it; req_begin links the
     * request first, then we patch handle + sink_user (the H1 sink needs r->handle
     * and uses r as its user). Pass r as sink_user via a two-step: req_begin needs
     * sink_user up front, but for the H1 sink the user IS the (not-yet-created)
     * xreq. Resolve by passing a placeholder and fixing it on success — but the
     * sink is not invoked during req_begin (only on later response/upload), so
     * patching sink_user immediately after return is safe. */
    int err_status = 0;
    mq_gw_reject_reason_t reason = MQ_GW_OK;
    mq_gw_xreq_t *r =
        mq_gw_client_req_begin(c, &head, &g_h1_sink, NULL, &err_status, &reason);

    free(H);
    free(namearena);
    free(valarena);

    if (!r) {
        gw_reject_write(handle, err_status, gw_status_phrase(err_status),
                        gw_reason_xmq(reason));
        return -1;
    }

    /* Bind the H1 sink + listener handle to the request (sink_user == r). */
    r->handle = handle;
    r->sink_user = r;
    *req_ctx = r;
    return 0;
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
 * the H3 request (never finish) and detach the local/sink side. The adapter is
 * already tearing down — do NOT call any sink op. Body of the former
 * gw_on_aborted. */
void
mq_gw_client_req_aborted(mq_gw_xreq_t *r)
{
    r->handle = NULL; /* gw_local_dead would reset+null; do the reset path here */
    r->sink = NULL;
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

/* Per-response header arena caps (mirror the original inline nb[128]/vb[2048]). */
#define MQ_GW_RESP_NAME_CAP 128
#define MQ_GW_RESP_VAL_CAP  2048
#define MQ_GW_RESP_MAX_HDRS 96

/* Header-capture context for recv_headers (download). Collects the response
 * headers into a NEUTRAL mq_h3_header_t list (NUL-terminated arena) instead of
 * serializing HTTP/1.1 inline — the sink renders. */
typedef struct {
    mq_gw_req_t *r;
    int status;
    int has_cl; /* response carried a content-length */
    mq_h3_header_t hs[MQ_GW_RESP_MAX_HDRS];
    size_t nh;
    char names[MQ_GW_RESP_MAX_HDRS][MQ_GW_RESP_NAME_CAP];
    char vals[MQ_GW_RESP_MAX_HDRS][MQ_GW_RESP_VAL_CAP];
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
    if (ctx->nh >= MQ_GW_RESP_MAX_HDRS) {
        ctx->ok = 0;
        return;
    }
    char *nb = ctx->names[ctx->nh];
    char *vb = ctx->vals[ctx->nh];
    memcpy(nb, n, nl);
    nb[nl] = '\0';
    memcpy(vb, v, vl);
    vb[vl] = '\0';
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

    /* If headers carried fin (no body), finish immediately. */
    if (fin) r->sink->resp_finish(r->sink_user);
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
            r->sink->resp_abort(r->sink_user);
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
            r->sink->resp_finish(r->sink_user);
            return;
        }
        if (n == 0) return; /* no more body available right now */
    }
}

/* ── in-file H1 sink: renders today's exact HTTP/1.1 response bytes ──────────
 *
 * sink_user is the mq_gw_req_t itself (the H1 sink lives in this file and reuses
 * r->handle + r->resp_chunked). A future MITM adapter (Task 4) supplies its own
 * sink with its own user cookie. Output here is byte-identical to the previous
 * inline rendering (status line, Transfer-Encoding/Connection: close, chunked
 * framing, terminator). */

static int
h1_sink_resp_head(void *u, int status, const mq_h3_header_t *hs, size_t n,
                  mq_gw_body_mode_t body_mode)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    if (!r->handle) return -1;

    char head[8192];
    size_t head_len = 0;

    int sn = mq_http1_write_status(head, sizeof(head), status, "");
    if (sn <= 0) return -1;
    head_len += (size_t)sn;

    for (size_t i = 0; i < n; i++) {
        int n2 = mq_http1_write_header(head + head_len, sizeof(head) - head_len,
                                       hs[i].name, hs[i].value);
        if (n2 <= 0) return -1;
        head_len += (size_t)n2;
    }

    /* Unknown length → chunked framing for the body. */
    if (body_mode == MQ_GW_BODY_STREAM) {
        r->resp_chunked = 1;
        int n2 = mq_http1_write_header(head + head_len, sizeof(head) - head_len,
                                       "Transfer-Encoding", "chunked");
        if (n2 <= 0) return -1;
        head_len += (size_t)n2;
    }

    /* Connection: close (one request per local connection). */
    {
        int n2 = mq_http1_write_header(head + head_len, sizeof(head) - head_len,
                                       "Connection", "close");
        if (n2 <= 0) return -1;
        head_len += (size_t)n2;
    }

    /* Terminating blank line. */
    if (head_len + 2 > sizeof(head)) return -1;
    head[head_len++] = '\r';
    head[head_len++] = '\n';

    /* Register the drain cb so a highwater hit during the body relay re-kicks
     * the download read path. */
    mq_fetch_conn_set_drain_cb(r->handle, local_drain_cb, r);
    int wr = mq_fetch_conn_write(r->handle, head, head_len);
    if (wr < 0) return -1;
    return 1;
}

static int
h1_sink_resp_body(void *u, const uint8_t *p, size_t len)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    if (r->local_dead || !r->handle) return -1;

    if (r->resp_chunked) {
        /* Frame the chunk: "<hex>\r\n<data>\r\n". Worst-case framing overhead is
         * small; write head then body then CRLF separately to avoid a second
         * large copy. The chunk-size line's highwater (0) is NOT a defer trigger
         * (it always fits in practice); only the body / trailing CRLF zero is. */
        char hdr[32];
        int hn = snprintf(hdr, sizeof(hdr), "%lx\r\n", (unsigned long)len);
        if (hn <= 0) return -1;
        int wr = mq_fetch_conn_write(r->handle, hdr, (size_t)hn);
        if (wr < 0) return -1;
        wr = mq_fetch_conn_write(r->handle, p, len);
        if (wr < 0) return -1;
        int wr2 = mq_fetch_conn_write(r->handle, "\r\n", 2);
        if (wr2 < 0) return -1;
        if (wr == 0 || wr2 == 0) return 0; /* body or CRLF highwater → defer */
        return 1;
    }

    int wr = mq_fetch_conn_write(r->handle, p, len);
    if (wr < 0) return -1;
    return wr == 0 ? 0 : 1; /* highwater → defer */
}

static void
h1_sink_resp_finish(void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    /* Chunked response → write the terminating zero-length chunk before close. */
    if (r->resp_chunked && r->handle) {
        char term[8];
        size_t tn = mq_http1_chunk_frame(term, sizeof(term), NULL, 0);
        if (tn > 0) mq_fetch_conn_write(r->handle, term, tn);
    }
    gw_local_finish(r);
}

static void
h1_sink_resp_abort(void *u)
{
    gw_local_abort((mq_gw_req_t *)u);
}

static void
h1_sink_resume_read(void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    if (!r->local_dead && r->handle) mq_fetch_conn_resume_read(r->handle);
}

static const mq_gw_sink_ops_t g_h1_sink = {
    .resp_head = h1_sink_resp_head,
    .resp_body = h1_sink_resp_body,
    .resp_finish = h1_sink_resp_finish,
    .resp_abort = h1_sink_resp_abort,
    .resume_read = h1_sink_resume_read,
};

/* Local output drained below the low watermark (listener drain_cb) → notify the
 * core via the neutral drained boundary, which resumes the download read path. */
static void
local_drain_cb(void *user)
{
    mq_gw_client_req_drained((mq_gw_req_t *)user);
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
                    gw_local_error_req(r, 502, "Bad Gateway", "upstream-protocol");
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
        /* Tunnel closed. If the response never started, synthesize 502; else the
         * local side must see a truncation (abort, not a fake clean finish).
         * Detach the local handle INLINE (do NOT call the gw_local_* helpers —
         * they call gw_req_maybe_free, which would free r out from under the
         * final maybe_free below → use-after-free). */
        void *h = r->handle;
        r->local_dead = 1;
        r->handle = NULL;
        if (h) {
            if (!r->resp_started)
                gw_local_error(h, 502, "Bad Gateway", "upstream-reset");
            else
                mq_fetch_conn_abort(h);
        }
    }
    gw_req_maybe_free(r); /* both sides now dead → frees r exactly once */
}

/* Synthesize an error response on a request whose handle is still live (used
 * from the read path when the response head is malformed before we started). */
static void
gw_local_error_req(mq_gw_req_t *r, int code, const char *reason, const char *xmq)
{
    if (r->local_dead || !r->handle) return;
    void *h = r->handle;
    r->local_dead = 1;
    r->handle = NULL;
    gw_local_error(h, code, reason, xmq);
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

/* H1 listener body callbacks: thin shims onto the neutral intake boundary. The
 * listener's req_ctx IS the mq_gw_xreq_t (set in gw_on_request). */
static int
gw_on_body(void *req_ctx, const uint8_t *p, size_t len)
{
    return mq_gw_client_req_body((mq_gw_xreq_t *)req_ctx, p, len);
}

static void
gw_on_body_done(void *req_ctx)
{
    mq_gw_client_req_body_done((mq_gw_xreq_t *)req_ctx);
}

static void
gw_on_aborted(void *req_ctx)
{
    mq_gw_client_req_aborted((mq_gw_xreq_t *)req_ctx);
}

static const mq_fetch_cbs_t g_gw_cbs = {
    .on_request = gw_on_request,
    .on_body = gw_on_body,
    .on_body_done = gw_on_body_done,
    .on_aborted = gw_on_aborted,
};

const mq_fetch_cbs_t *
mq_gw_client_fetch_cbs(void)
{
    return &g_gw_cbs;
}

void *
mq_gw_client_fetch_user(mq_gw_client_t *c)
{
    return c;
}

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
     *   3. ABORT the local handle (the local peer sees a truncated response).
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
        if (!r->local_dead && r->handle) {
            mq_fetch_conn_abort(r->handle);
        }
        free(r->spill);
        free(r);
        r = next;
    }
    c->reqs = NULL;
    free(c);
}
