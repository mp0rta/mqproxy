// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_server.c — server-side H3→origin execution bridge. See mq_gw_server.h.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PER-REQUEST OWNERSHIP (mq_gw_req_t)  — dual-flag, exactly-once discipline
 * ─────────────────────────────────────────────────────────────────────────────
 * Each accepted H3 request owns one mq_gw_req_t, referenced from two independent
 * sides that can each die first or race (mirrors mq_gw_client's local/h3 split):
 *
 *   H3 side     (the mq_h3_req): set on on_new_req; cleared in h3_on_close (the
 *     wrapper is freed right after). After on_close we null r->req (h3_dead=1).
 *
 *   ORIGIN side (the mq_origin_req): set on mq_origin_start; cleared either when
 *     on_done fires (the origin completed/errored — the request is freed right
 *     after on_done returns) or when WE call mq_origin_abort. Either way we null
 *     r->oreq and set origin_dead=1.
 *
 * The mq_gw_req_t is freed by gw_req_maybe_free() once BOTH flags are set. Each
 * side flips its flag exactly once:
 *   - H3 closes first (client reset / conn died): h3_on_close → mq_origin_abort
 *     (origin side dies, NO on_done) → both dead → free. on_close is an mq_h3
 *     callback, NOT a curl callback, so mq_origin_abort is safe there (per the
 *     re-entrancy contract in mq_origin_curl.h).
 *   - origin terminates first (on_done): we finish/reset the H3 request → its
 *     on_close fires later → both dead → free. on_done sets origin_dead + nulls
 *     r->oreq. We MUST NOT touch r->oreq after on_done.
 *   - both race: idempotent flags; maybe_free runs only when both set.
 *
 * BODY auth/validation failures (403/400) and origin-start failures synthesize
 * an H3 response and finish/reset BEFORE the origin side ever exists. There we
 * set origin_dead=1 up front so the single remaining flag is the H3 side.
 *
 * Re-entrancy note: mq_origin's on_status/on_header/on_body/on_done callbacks
 * run from inside curl. We never call mq_origin_abort from on_done (forbidden),
 * and the download/upload pumping calls only mq_h3_req_* (transport side) and
 * mq_origin_resume_* (deferred, always safe) from those curl callbacks.
 */
#include "gateway/mq_gw_server.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <curl/curl.h>
#include <event2/event.h>

#include "gateway/mq_gw_cache.h"
#include "gateway/mq_gw_headers.h"
#include "gateway/mq_gw_metrics.h"
#include "gateway/mq_origin_curl.h"
#include "util/mq_ct.h"
#include "util/mq_log.h"

/* Bound on the H3→origin upload spill (junction #3): body bytes recv'd from the
 * H3 request that curl's pull_body has not yet drained. */
#define MQ_GWS_UPLOAD_SPILL_MAX (256 * 1024)

/* recv_body scratch size for draining the H3 request body. */
#define MQ_GWS_RECV_CHUNK 16384

/* Max forwarded origin request headers (the request's non-stripped headers).
 * xqc delivers a bounded header set; 64 is comfortable for the MVP. */
#define MQ_GWS_MAX_HDRS 64

/* Monotonic millisecond clock for the cache's freshness/LRU accounting (the
 * cache itself is clock-free — callers inject now_ms). Single caller, so a
 * file-static rather than a shared util header. */
static uint64_t gw_now_ms(void) __attribute__((unused));
static uint64_t
gw_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ── TLS outcome (origin_tls field) ─────────────────────────────────────────*/

typedef enum {
    MQ_TLS_NA = 0,       /* non-TLS origin (http://) or origin not reached */
    MQ_TLS_OK,           /* https + curl OK + cert verified */
    MQ_TLS_VERIFY_FAIL,  /* cert rejected by curl */
    MQ_TLS_CONNECT_FAIL, /* any other transport/handshake failure on https */
} mq_tls_result_t;

static const char *tls_token(mq_tls_result_t t) __attribute__((unused));
static const char *
tls_token(mq_tls_result_t t)
{
    switch (t) {
    case MQ_TLS_OK: return "ok";
    case MQ_TLS_VERIFY_FAIL: return "verify_fail";
    case MQ_TLS_CONNECT_FAIL: return "connect_fail";
    default: return "na";
    }
}

/* ── per-request state ──────────────────────────────────────────────────────*/

typedef struct mq_gw_req_s {
    mq_gw_server_t *srv;

    /* H3 (transport) side */
    mq_h3_req_t *req; /* NULL once on_close fired (h3_dead) */
    int h3_dead;

    /* ORIGIN (curl) side */
    mq_origin_req_t *oreq; /* NULL once on_done fired OR we aborted (origin_dead) */
    int origin_dead;

    /* request parse / forwarding */
    int has_body;    /* the H3 request arrived without fin (a body follows) */
    int h3_body_fin; /* the H3 request body reached fin (no more upload bytes) */

    /* ── upload (junction #3): H3 body → curl pull_body ── */
    uint8_t *spill;   /* heap spill buffer (lazily allocated) */
    size_t spill_len; /* valid bytes in spill */
    size_t spill_off; /* bytes already drained by pull_body */
    int pull_paused;  /* pull_body returned 0 (PAUSE); resume when spill refills */

    /* ── download (junction #4): origin response → H3 response ── */
    int resp_headers_sent; /* we sent the H3 response header section */
    int resp_status;       /* origin http_status (from on_status) */
    long resp_http_ver;    /* CURLINFO_HTTP_VERSION (set on first body/on_done) */

    /* ── cacheability (Phase 6) ── */
    unsigned cache_ttl_s;  /* request X-Mq-Cache opt-in TTL (0 = not opted in) */
    int has_authorization; /* request carried an Authorization header */
    int cc_uncacheable;    /* response Cache-Control: no-store/private/no-cache */
    long cc_max_age;       /* response max-age/s-maxage (smaller of the two); -1 absent */
    int has_set_cookie;    /* response carried a Set-Cookie header */
    int has_vary;          /* response carried a Vary header */

    /* ── cache HIT replay (Phase 6) — copy-on-hit: the source entry can be evicted
     * by a LATER request's insert across the send turns this request yields on, so
     * we deep-copy the entry's body into req-owned storage (cache_body) and stage
     * its header strings into the EXISTING inline r->hdrs[] arrays (they are bounded
     * by the same 128/1024 arena caps the entry passed through on store, so the copy
     * is lossless — no separate header backing buffer is needed). The body is
     * replayed in 16 KiB slices by download_flush's from_cache loop. */
    int from_cache;        /* this request is being served from the cache (no origin) */
    uint8_t *cache_body;   /* owned copy of the cached body (NULL = none/empty) */
    size_t cache_body_len; /* total cached body length */
    size_t cache_off;      /* replay cursor into cache_body */
    char cache_key[8 + 256 + 1024 + 8]; /* "GET <url>" (built in gw_dispatch when caching
                                         * may apply; reused for lookup + store) */
    int is_get;                         /* request method is GET (cache gate) */

    /* ── cache STORE (Phase 6) — accumulate a cacheable miss's body, capped at the
     * cache's max_obj_bytes; on a clean 200 done we insert. Overflow / non-cacheable
     * frees store_buf and clears `storing` (keep streaming to the client). */
    uint8_t *store_buf; /* growable body accumulator (NULL until first cacheable body) */
    size_t store_len;   /* bytes accumulated */
    size_t store_cap;   /* current capacity of store_buf */
    int storing;        /* 1 while accumulating a cacheable miss */

    enum { MQ_CACHE_BYPASS = 0, MQ_CACHE_HIT, MQ_CACHE_MISS } cache_state;

    int origin_is_tls;          /* origin scheme == https (set in gw_dispatch, Task 5) */
    mq_tls_result_t origin_tls; /* TLS verify outcome, set in origin_on_done */
    char content_encoding[24];  /* origin response Content-Encoding value; "" => none */
    int origin_reuse;      /* 0 fresh / not-yet-done; 1 when the origin conn was reused */
    int origin_connect_ms; /* origin TCP+TLS setup ms; 0 on reuse; -1 unknown */

    /* observability (mq.req); captured in gw_dispatch */
    char method[16];
    char authority[256];
    char path[512];

    int recv_paused;    /* on_body returned 0 (curl download paused); resume on drain */
    int origin_done_ok; /* on_done(OK) fired; send the response fin once pend drains */
    int finished;       /* we sent the response fin (clean completion) */

    /* Accumulated response headers (captured in on_header, flushed with status on
     * the first on_body or on_done). NUL-terminated name/value pairs. */
    struct {
        char name[128];
        char value[1024];
    } hdrs[MQ_GWS_MAX_HDRS];
    int n_hdrs;
    int hdrs_overflow; /* dropped a header (response header count > MQ_GWS_MAX_HDRS).
                        * Fail closed: checked in download_send_headers alongside
                        * hdr_oversized — synthesize 502 + x-mq-error: upstream-protocol
                        * before any response header reaches the H3 client. Post-body
                        * trailers may set this after resp_headers_sent, but that path is
                        * already gated by `if (!r->resp_headers_sent)` (same as
                        * hdr_oversized), so trailers cannot trigger a spurious 502. */
    int hdr_oversized; /* an ORIGIN response header NAME/VALUE did not fit its
                        * arena slot (>127 name / >1023 value). Fail closed:
                        * checked in download_send_headers before any response
                        * header reaches the H3 client (a silently clipped
                        * origin header would corrupt the downstream response). */

    /* Pending download body byte that curl handed us but H3 could not accept
     * (send returned 0). We hold ONE chunk and resume the curl download via
     * mq_origin_resume_body once H3's on_write drains it. */
    uint8_t pend[MQ_GWS_RECV_CHUNK];
    size_t pend_len;
    size_t pend_off;

    struct mq_gw_req_s *next; /* intrusive list of live requests */
} mq_gw_req_t;

/* ── server state ───────────────────────────────────────────────────────────*/

struct mq_gw_server_s {
    mq_transport_t *t; /* borrowed */
    mq_runtime_t *rt;  /* borrowed */
    mq_h3_t *h3;       /* owned-by-creation but freed by the caller (see header) */
    mq_origin_t *origin;

    char token[256];
    size_t token_len;

    unsigned requests; /* accepted H3 requests (observability) */

    /* Most-recently-accepted H3 tunnel conn (Phase 5c observability). Set
     * unconditionally in gw_on_new_conn, cleared (if still itself) in
     * gw_srv_conn_state on close, and detached in mq_gw_server_free. Mirrors the
     * TCP server's last_conn (mq_server.c). Per-instance: one client conn. */
    mq_h3_conn_t *last_conn;

    mq_gw_req_t *reqs; /* intrusive list of live per-request states */

    int request_metrics; /* emit mq.req per-request line (opt-in; default 0) */

    /* In-memory origin response cache (opt-in via --cache-max-bytes; NULL when
     * disabled = default). Owned: freed in mq_gw_server_free. */
    mq_gw_cache_t *cache;
};

/* ── forward decls ──────────────────────────────────────────────────────────*/
static void gw_req_unlink(mq_gw_server_t *s, mq_gw_req_t *r);
static void gw_req_maybe_free(mq_gw_req_t *r);
static void h3_on_read(mq_h3_req_t *hr, int flag, void *user);
static void h3_on_write(mq_h3_req_t *hr, void *user);
static void h3_on_close(mq_h3_req_t *hr, void *user);
static void download_flush(mq_gw_req_t *r);
static unsigned gw_response_cacheable(const mq_gw_req_t *r);

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

/* Sanitize an attacker-controlled string for log emission: cap at `maxlen`
 * chars and replace non-printable bytes (<0x20 or >=0x7f) with '?'. Writes a
 * NUL-terminated result into `out` (which must have capacity maxlen+1). */
static void
sanitize_for_log(char *out, size_t maxlen, const char *s, size_t slen)
{
    size_t n = slen < maxlen ? slen : maxlen;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[n] = '\0';
}

/* http_ver → wire protocol token for x-mq-origin-protocol. */
static const char *
http_ver_token(long ver)
{
    switch (ver) {
    case CURL_HTTP_VERSION_1_1: return "http/1.1";
    case CURL_HTTP_VERSION_2: return "h2";
    case CURL_HTTP_VERSION_3: return "h3";
    case CURL_HTTP_VERSION_1_0: return "http/1.0";
    default: return "http/1.1";
    }
}

/* ── per-request lifecycle ──────────────────────────────────────────────────*/

static void
gw_req_unlink(mq_gw_server_t *s, mq_gw_req_t *r)
{
    mq_gw_req_t **pp = &s->reqs;
    while (*pp) {
        if (*pp == r) {
            *pp = r->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

static void
gw_req_maybe_free(mq_gw_req_t *r)
{
    if (!r->origin_dead || !r->h3_dead) return;
    gw_req_unlink(r->srv, r);
    free(r->spill);
    free(r->cache_body); /* copy-on-hit body (NULL when not a HIT) */
    free(r->store_buf);  /* STORE accumulator (NULL unless a cacheable miss aborted) */
    free(r);
}

/* Synthesize and send an H3 error response (status + x-mq-error + content-length:
 * 0), then finish the request. Used for auth/validation failures and origin
 * errors that occur BEFORE any response header has been sent. This does NOT
 * touch the origin side: most callers (auth/validation rejects) run before the
 * origin ever exists and leave origin_dead==0 — h3_on_close flips origin_dead
 * unconditionally once oreq==NULL (no live origin without an oreq), so the H3
 * side finishing naturally → on_close → maybe_free reclaims the state. (The
 * origin-error caller, origin_on_done, has already set origin_dead itself.) */
static void
gw_send_error(mq_gw_req_t *r, const char *status, const char *xmq_error)
{
    if (r->h3_dead || !r->req) return;
    /* :status is always 3 digits in practice; 32 keeps gcc's -Wformat-truncation
     * (which sizes this by the longest caller literal at -O2) satisfied. */
    char st[32];
    snprintf(st, sizeof(st), "%s", status);
    mq_h3_header_t hs[] = {
        {":status", st},
        {"x-mq-error", xmq_error},
        {"content-length", "0"},
    };
    /* Record the synthetic status so error rows report a non-zero status in mq.req
     * (B2: gw_send_error was the only send path that never stored resp_status). */
    r->resp_status = (int)strtol(
        status, NULL,
        10); /* intentional: mq.req `status` = status sent to client; synthetic error
                replaces any earlier origin status (e.g. a 502 over an oversized-header
                200) — that is correct, not a clobber bug */
    long sh = mq_h3_req_send_headers(r->req, hs, 3, /*fin=*/1);
    if (sh < 0) {
        /* Hard send failure: reset; on_close finishes teardown. */
        mq_h3_req_reset(r->req);
        return;
    }
    /* sh==0 (header EAGAIN) is effectively unreachable for a small header block on
     * a fresh stream; if it ever happens, the request will be reset by teardown.
     * Mark resp_headers_sent so no later path re-sends. */
    r->resp_headers_sent = 1;
    r->finished = 1;
}

/* ── upload (junction #3): H3 request body → curl pull_body ──────────────────*/

/* Drain H3 request body into the spill buffer (bounded). Sets h3_body_fin when
 * the request finishes. Pauses recv implicitly by NOT reading further once the
 * spill is full (xquic re-notifies on the next READ_BODY once we drain). */
static void
upload_recv(mq_gw_req_t *r)
{
    if (r->h3_dead || !r->req) return;

    for (;;) {
        /* Compact drained bytes to make room. */
        if (r->spill && r->spill_off > 0) {
            memmove(r->spill, r->spill + r->spill_off, r->spill_len - r->spill_off);
            r->spill_len -= r->spill_off;
            r->spill_off = 0;
        }
        if (r->spill_len >= MQ_GWS_UPLOAD_SPILL_MAX) {
            /* Buffer full: stop reading. The next pull_body drain re-arms us
             * (xquic re-delivers READ_BODY as the stream window reopens). */
            break;
        }
        if (!r->spill) {
            r->spill = malloc(MQ_GWS_UPLOAD_SPILL_MAX);
            if (!r->spill) {
                /* OOM: reset the request (truncates the origin upload too). */
                mq_h3_req_reset(r->req);
                return;
            }
            r->spill_len = 0;
            r->spill_off = 0;
        }
        size_t room = MQ_GWS_UPLOAD_SPILL_MAX - r->spill_len;
        int fin = 0;
        long n = mq_h3_req_recv_body(r->req, r->spill + r->spill_len, room, &fin);
        if (n < 0) {
            mq_h3_req_reset(r->req);
            return;
        }
        if (n > 0) r->spill_len += (size_t)n;
        if (fin) {
            r->h3_body_fin = 1;
            break;
        }
        if (n == 0) break; /* no more body available right now */
    }

    /* Newly buffered bytes (or fin) → resume a paused curl upload. */
    if (r->pull_paused && !r->origin_dead && r->oreq &&
        (r->spill_off < r->spill_len || r->h3_body_fin)) {
        r->pull_paused = 0;
        mq_origin_resume_pull(r->oreq);
    }
}

/* curl pull_body: drain the spill into curl's buffer. 0 = PAUSE (spill empty,
 * H3 fin not yet seen), -1 = EOF (spill empty AND H3 fin seen). Runs inside a
 * curl callback — only mq_h3_req_recv_body (transport recv) is touched here. */
static long
origin_pull_body(uint8_t *buf, size_t cap, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;

    /* Top up the spill from the H3 side first (recv is safe from a curl cb). */
    upload_recv(r);

    size_t avail =
        (r->spill && r->spill_len > r->spill_off) ? r->spill_len - r->spill_off : 0;
    if (avail == 0) {
        if (r->h3_body_fin) return -1; /* EOF */
        r->pull_paused = 1;
        return 0; /* PAUSE: resumed from upload_recv when more arrives */
    }
    size_t take = avail < cap ? avail : cap;
    memcpy(buf, r->spill + r->spill_off, take);
    r->spill_off += take;
    return (long)take;
}

/* ── download (junction #4): origin response → H3 response ───────────────────*/

/* Build + send the H3 response header section from the accumulated origin
 * headers (status + headers minus hop-by-hop + x-mq-origin-protocol). Sent once,
 * lazily, on the first on_body or on on_done. Returns 0 on success, -1 on a hard
 * H3 send failure (caller resets). */
static int
download_send_headers(mq_gw_req_t *r)
{
    if (r->resp_headers_sent) return 0;
    if (r->h3_dead || !r->req) return -1;

    /* Fail closed on an oversized ORIGIN response header (recorded in on_header)
     * or a response header-count overflow (> MQ_GWS_MAX_HDRS, also recorded in
     * on_header). In both cases no header has reached the H3 client yet, so we
     * synthesize a clean 502 + x-mq-error: upstream-protocol instead of
     * forwarding a corrupted/truncated header set. gw_send_error sends the fin
     * and sets finished; the caller must NOT also reset (it guards the reset on
     * !r->finished). */
    if (r->hdr_oversized || r->hdrs_overflow) {
        gw_send_error(r, "502", "upstream-protocol");
        return -1;
    }

    mq_h3_header_t hs[MQ_GWS_MAX_HDRS + 2];
    size_t nh = 0;

    char st[16];
    int code = (r->resp_status >= 100 && r->resp_status <= 599) ? r->resp_status : 502;
    snprintf(st, sizeof(st), "%d", code);
    hs[nh].name = ":status";
    hs[nh].value = st;
    nh++;

    /* x-mq-origin-protocol is a diagnostic of the NEGOTIATED origin protocol. A
     * cache HIT contacted NO origin, so synthesizing one here would emit a FALSE
     * `http/1.1` (http_ver_token's NONE default) — the response-version bug fixed
     * in commit 5136c46. Omit it on the HIT path (design §7). */
    if (!r->from_cache) {
        hs[nh].name = "x-mq-origin-protocol";
        hs[nh].value = http_ver_token(r->resp_http_ver);
        nh++;
    }

    for (int i = 0; i < r->n_hdrs && nh < (size_t)(MQ_GWS_MAX_HDRS + 2); i++) {
        hs[nh].name = r->hdrs[i].name;
        hs[nh].value = r->hdrs[i].value;
        nh++;
    }

    long sh = mq_h3_req_send_headers(r->req, hs, nh, /*fin=*/0);
    if (sh < 0) return -1;
    /* sh==0 (header-block EAGAIN) is effectively unreachable for a response header
     * block on an established stream; treat non-negative as sent. */
    r->resp_headers_sent = 1;
    return 0;
}

/* Try to flush the pending download chunk into H3. Sets send_blocked if H3 could
 * not take it all (curl stays paused); clears + resumes curl when fully drained.
 * Sends the response fin when the origin is done AND nothing is pending. */
static void
download_flush(mq_gw_req_t *r)
{
    if (r->h3_dead || !r->req) return;
    if (!r->resp_headers_sent) return; /* headers must precede body */

    if (r->from_cache) {
        /* drive the whole in-memory body, yielding only on real H3 backpressure */
        while (r->cache_off < r->cache_body_len || r->pend_off < r->pend_len) {
            if (r->pend_off >= r->pend_len &&
                r->cache_off < r->cache_body_len) { /* refill from cache */
                size_t rem = r->cache_body_len - r->cache_off;
                size_t n =
                    rem < MQ_GWS_RECV_CHUNK
                        ? rem
                        : MQ_GWS_RECV_CHUNK; /* inline clamp (no MIN macro in tree) */
                memcpy(r->pend, r->cache_body + r->cache_off, n);
                r->cache_off += n;
                r->pend_len = n;
                r->pend_off = 0;
            }
            long acc = mq_h3_req_send_body(r->req, r->pend + r->pend_off,
                                           r->pend_len - r->pend_off, /*fin=*/0);
            if (acc < 0) {
                if (!r->finished) mq_h3_req_reset(r->req);
                return;
            } /* hard error → reset, as curl path */
            r->pend_off += (size_t)acc;
            if (r->pend_off < r->pend_len)
                return; /* H3 blocked → h3_on_write re-drives later */
        }
        if (mq_h3_req_send_body(r->req, NULL, 0, /*fin=*/1) < 0) {
            if (!r->finished) mq_h3_req_reset(r->req);
            return;
        }
        r->finished = 1; /* mirror the curl path's post-finish flag */
        return;          /* never fall through to the curl tail */
    }

    while (r->pend_off < r->pend_len) {
        long acc = mq_h3_req_send_body(r->req, r->pend + r->pend_off,
                                       r->pend_len - r->pend_off, /*fin=*/0);
        if (acc < 0) {
            mq_h3_req_reset(r->req);
            return;
        }
        if (acc == 0) return; /* still blocked; wait for the next on_write */
        r->pend_off += (size_t)acc;
    }
    /* Pending fully drained. */
    r->pend_len = 0;
    r->pend_off = 0;
    if (r->recv_paused) {
        r->recv_paused = 0;
        /* We had returned 0 to curl (a chunk raced an undrained pend). Resume the
         * paused download (deferred; safe from anywhere). */
        if (!r->origin_dead && r->oreq) mq_origin_resume_body(r->oreq);
    }
    /* The origin completed (on_done OK) but its tail chunk was still buffered when
     * on_done ran: now that pend is empty, send the deferred response fin. */
    if (r->origin_done_ok && !r->finished) {
        long fr = mq_h3_req_finish(r->req);
        if (fr < 0)
            mq_h3_req_reset(r->req);
        else
            r->finished = 1;
    }
}

/* Case-insensitive search for `needle` (lowercase literal) in the value slice
 * [v, v+vl). Returns a pointer to the match (within v) or NULL. Local + simple
 * (the value is short; this runs once per cache-control header). */
static const char *
ci_memmem(const char *v, size_t vl, const char *needle)
{
    size_t nl = strlen(needle);
    if (nl == 0 || nl > vl) return NULL;
    for (size_t i = 0; i + nl <= vl; i++) {
        size_t j = 0;
        for (; j < nl; j++) {
            char a = v[i + j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (a != needle[j]) break;
        }
        if (j == nl) return v + i;
    }
    return NULL;
}

/* Token-boundary test for a valueless Cache-Control directive (no-store /
 * private / no-cache). `ci_memmem` matches substrings, so a header value like
 * `x-private-data` or `no-cacheable` would falsely set cc_uncacheable. Require a
 * delimiter (start-of-value / ',' / SP / HTAB) immediately BEFORE the match and a
 * terminator (end / ',' / SP / HTAB / ';') immediately AFTER — these directives
 * carry no `=value`, so an `=` after the token is NOT a valid boundary. Scans all
 * occurrences (a later token may be a clean match even if an earlier one is a
 * substring). */
static int
cc_has_token(const char *v, size_t vl, const char *tok)
{
    size_t tl = strlen(tok);
    const char *end = v + vl;
    for (const char *p = v; (p = ci_memmem(p, (size_t)(end - p), tok)) != NULL; p += tl) {
        char before = (p > v) ? p[-1] : ','; /* synthesize a delimiter at start */
        const char *a = p + tl;
        char after = (a < end) ? *a : ','; /* synthesize a delimiter at end */
        int bok = (before == ',' || before == ' ' || before == '\t');
        int aok = (after == ',' || after == ' ' || after == '\t' || after == ';');
        if (bok && aok) return 1;
    }
    return 0;
}

/* Parse the delta-seconds at `p` (just past a `…age=`), within the slice ending
 * at `end`. Returns the non-negative value, or -1 if no leading digit. Stops at
 * the first non-digit (',' / ' ' / end). Caps at INT32_MAX (still "cacheable"). */
static long
cc_parse_delta(const char *p, const char *end)
{
    if (p >= end || *p < '0' || *p > '9') return -1;
    long n = 0;
    for (; p < end && *p >= '0' && *p <= '9'; p++) {
        n = n * 10 + (*p - '0');
        if (n > 2147483647L) return 2147483647L; /* clamp; still "cacheable, large" */
    }
    return n;
}

/* Fold one parsed delta into cc_max_age, keeping the SMALLER of any already-set
 * value and this one (the more conservative freshness bound). */
static void
cc_take_min_age(mq_gw_req_t *r, long d)
{
    if (d >= 0 && (r->cc_max_age < 0 || d < r->cc_max_age)) r->cc_max_age = d;
}

/* Scan a response Cache-Control value for the cacheability-relevant directives
 * and fold them into r: no-store/private/no-cache ⇒ cc_uncacheable; max-age= /
 * s-maxage= ⇒ cc_max_age (the smaller of the two when both are present). The
 * `s-maxage=` token contains `max-age=` at offset 2, so each `max-age=` match is
 * accepted only when it is NOT the tail of an `s-maxage=` (the prior char is not
 * the 's' of "s-max"); both deltas still fold into the min. */
static void
cc_scan(mq_gw_req_t *r, const char *v, size_t vl)
{
    if (cc_has_token(v, vl, "no-store") || cc_has_token(v, vl, "private") ||
        cc_has_token(v, vl, "no-cache"))
        r->cc_uncacheable = 1;
    const char *end = v + vl;
    /* All `s-maxage=` occurrences. */
    for (const char *p = v; (p = ci_memmem(p, (size_t)(end - p), "s-maxage=")) != NULL;) {
        cc_take_min_age(r, cc_parse_delta(p + 9, end));
        p += 9;
    }
    /* All `max-age=` occurrences that are NOT the tail of an `s-maxage=` (i.e. not
     * immediately preceded by an 's'/'S'). */
    for (const char *p = v; (p = ci_memmem(p, (size_t)(end - p), "max-age=")) != NULL;) {
        char prev = (p > v) ? p[-1] : '\0';
        if (prev != 's' && prev != 'S') cc_take_min_age(r, cc_parse_delta(p + 8, end));
        p += 8;
    }
}

/* curl on_status: stash the final status code. */
static void
origin_on_status(int http_status, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    r->resp_status = http_status;
}

/* curl on_header: accumulate non-hop-by-hop response headers (already trimmed by
 * mq_origin). Names are lowercased (H3 requires lowercase field names). */
static void
origin_on_header(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    /* Drop-class checks must run BEFORE the capacity check: a dropped header
     * must not count toward the capacity limit. */
    if (mq_gw_strip_hop(n, nl)) return;
    /* Drop any x-mq-origin-protocol the origin itself sent — we synthesize ours
     * from the negotiated http_ver, and a duplicate pseudo-ish diagnostic would
     * be confusing. */
    if (slice_ieq(n, nl, "x-mq-origin-protocol")) return;
    if (slice_ieq(n, nl, "content-encoding")) {
        size_t cap = sizeof(r->content_encoding) - 1;
        size_t cn = vl < cap ? vl : cap;
        memcpy(r->content_encoding, v, cn);
        r->content_encoding[cn] = '\0';
    }
    /* Cacheability capture (Phase 6; set but unread until the STORE/HIT task).
     * Captured BEFORE the arena-capacity check so a full header set still gates
     * cacheability correctly. These headers are ALSO forwarded normally below. */
    if (slice_ieq(n, nl, "set-cookie"))
        r->has_set_cookie = 1;
    else if (slice_ieq(n, nl, "vary"))
        r->has_vary = 1;
    else if (slice_ieq(n, nl, "cache-control"))
        cc_scan(r, v, vl);
    if (r->n_hdrs >= MQ_GWS_MAX_HDRS) {
        r->hdrs_overflow = 1;
        return;
    }

    /* An origin response header NAME or VALUE that would not fit its arena slot
     * must FAIL the response (download_send_headers turns this into a 502
     * upstream-protocol before any header reaches the H3 client), NOT be silently
     * clamped: a clipped value corrupts the downstream response, and origin
     * headers this large are pathological — failing closed beats corrupting.
     * Mirrors the client-side dl_each_header fail-closed posture. on_header is a
     * void curl callback, so we cannot signal here; record the condition and act
     * at the next safe point (download_send_headers). */
    if (nl >= sizeof(r->hdrs[0].name) || vl >= sizeof(r->hdrs[0].value)) {
        r->hdr_oversized = 1;
        return;
    }
    int i = r->n_hdrs++;
    size_t cnl = nl;
    for (size_t j = 0; j < cnl; j++) {
        char ch = n[j];
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
        r->hdrs[i].name[j] = ch;
    }
    r->hdrs[i].name[cnl] = '\0';
    memcpy(r->hdrs[i].value, v, vl);
    r->hdrs[i].value[vl] = '\0';
}

/* STORE accumulation: append `len` body bytes to r->store_buf while this miss is
 * being cached. Lazily starts storing on the first chunk if the response is
 * cacheable. Capped at the cache's per-object limit (max_obj_bytes) — on overflow
 * (or OOM) we free the buffer and stop storing, but KEEP streaming to the client
 * (a store failure never breaks the request). Called once per ACCEPTED chunk. */
static void
store_accumulate(mq_gw_req_t *r, const uint8_t *p, size_t len)
{
    mq_gw_server_t *s = r->srv;
    if (r->from_cache || !s->cache) return; /* HIT replay or cache disabled */

    /* Decide once, on the first accepted chunk, whether this response is cacheable.
     * All inputs are known by now (status from on_status, CC/cookie/vary from
     * on_header, both before the first on_body). */
    if (!r->storing && r->store_buf == NULL && r->store_len == 0) {
        if (gw_response_cacheable(r) == 0) return; /* not cacheable → never store */
        r->storing = 1;
    }
    if (!r->storing) return; /* a prior overflow disabled storing */
    if (len == 0) return;

    size_t cap_max = mq_gw_cache_max_obj_bytes(s->cache);
    if (r->store_len + len > cap_max) {
        /* Object exceeds the per-object cap (the insert would refuse it anyway) →
         * stop storing now and reclaim the buffer; keep streaming to the client. */
        free(r->store_buf);
        r->store_buf = NULL;
        r->store_len = 0;
        r->store_cap = 0;
        r->storing = 0;
        return;
    }
    if (r->store_len + len > r->store_cap) {
        size_t ncap = r->store_cap ? r->store_cap * 2 : MQ_GWS_RECV_CHUNK;
        while (ncap < r->store_len + len)
            ncap *= 2;
        if (ncap > cap_max) ncap = cap_max; /* never grow past the per-object cap */
        uint8_t *nb = realloc(r->store_buf, ncap);
        if (!nb) { /* OOM → stop storing, keep streaming */
            free(r->store_buf);
            r->store_buf = NULL;
            r->store_len = 0;
            r->store_cap = 0;
            r->storing = 0;
            return;
        }
        r->store_buf = nb;
        r->store_cap = ncap;
    }
    memcpy(r->store_buf + r->store_len, p, len);
    r->store_len += len;
}

/* curl on_body: send response headers (if not yet) then the body chunk over H3.
 * Returns the bytes accepted: len (accept all, copying any unsent remainder into
 * the pending buffer + pausing) or 0 (pause) on a hard H3 block. Runs inside a
 * curl callback — only mq_h3_req_* (transport send) is touched. */
static long
origin_on_body(const uint8_t *p, size_t len, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    if (r->h3_dead || !r->req) return 0; /* H3 gone: pause (teardown handles it) */

    /* Capture the negotiated protocol lazily (http_ver is reliable by first body).
     * It is also re-read on on_done; either is fine. */

    if (!r->resp_headers_sent) {
        if (download_send_headers(r) != 0) {
            /* download_send_headers may have already synthesized a clean error
             * response (oversized origin header → 502 + fin); only reset if it
             * did NOT finish cleanly. */
            if (!r->finished) mq_h3_req_reset(r->req);
            return 0;
        }
    }

    /* BACKPRESSURE MODEL (one chunk in flight at a time):
     *   - If `pend` already holds an undrained chunk, we cannot take more →
     *     return 0 to PAUSE curl. We are now recv-paused; download_flush() resumes
     *     curl (mq_origin_resume_body) once `pend` drains. curl re-delivers the
     *     SAME chunk it offered now after resume, so returning 0 loses nothing.
     *   - Otherwise try to send directly. xqc may partially accept; we copy the
     *     UNSENT remainder into `pend` and `return len` (accept the whole chunk
     *     from curl's view). The remainder is flushed by download_flush() from the
     *     H3 on_write notify. We do NOT pause curl in this case — curl proceeds to
     *     the next chunk, which the pend-full guard above pauses if it races the
     *     drain.
     * curl's WRITEFUNCTION buffer is CURL_MAX_WRITE_SIZE (16 KiB) == the pend
     * buffer size, so a full chunk's remainder always fits. */
    if (r->pend_off < r->pend_len) {
        r->recv_paused = 1;
        return 0; /* PAUSE: resumed from download_flush once pend drains */
    }

    /* Past the pend-full pause we are COMMITTED to accepting this whole chunk (both
     * remaining returns yield `len`), so accumulate it for the cache exactly once —
     * a paused-then-redelivered chunk never reaches here twice. */
    store_accumulate(r, p, len);

    long acc = mq_h3_req_send_body(r->req, p, len, /*fin=*/0);
    if (acc < 0) {
        mq_h3_req_reset(r->req);
        return 0;
    }
    size_t off = (size_t)(acc > 0 ? acc : 0);
    if (off >= len) return (long)len; /* fully accepted */

    size_t rem = len - off;
    if (rem > sizeof(r->pend)) {
        /* Defensive: a chunk larger than the pend buffer cannot be stashed and we
         * have already sent `off` bytes, so re-delivery would duplicate. Treat as a
         * hard error (unreachable with the 16 KiB == 16 KiB sizing above). */
        MQ_LOGW("mq_gw_server: download chunk %zu exceeds pend buffer; resetting", len);
        mq_h3_req_reset(r->req);
        return 0;
    }
    memcpy(r->pend, p + off, rem);
    r->pend_len = rem;
    r->pend_off = 0;
    return (long)len; /* accept all; the remainder is buffered for on_write */
}

/* STORE finalize: on a clean cacheable miss, deep-copy the accumulated body +
 * response headers into the cache. Builds a temporary mq_gw_cache_hdr_t[] view of
 * the inline r->hdrs[] (the cache deep-copies, so the temp array + store_buf are
 * freed right after). A cache insert failure NEVER affects the already-delivered
 * response. Frees store_buf unconditionally (it is consumed here). */
static void
store_finalize(mq_gw_req_t *r)
{
    mq_gw_server_t *s = r->srv;
    if (!r->storing || !s->cache) {
        /* Not storing (empty body / overflow-disabled / non-cacheable / disabled):
         * nothing to insert. store_buf is NULL in all these cases, but free defensively.
         */
        free(r->store_buf);
        r->store_buf = NULL;
        r->store_len = 0;
        r->store_cap = 0;
        r->storing = 0;
        return;
    }

    unsigned ttl_s = gw_response_cacheable(r); /* re-check + compute the effective ttl */
    if (ttl_s > 0 && r->cache_key[0] != '\0') {
        mq_gw_cache_hdr_t tmp[MQ_GWS_MAX_HDRS];
        size_t nh = 0;
        for (int i = 0; i < r->n_hdrs && nh < MQ_GWS_MAX_HDRS; i++) {
            tmp[nh].name = r->hdrs[i].name;
            tmp[nh].value = r->hdrs[i].value;
            nh++;
        }
        /* Insert is best-effort: a -1 (per-object cap / OOM) leaves the cache
         * unchanged and the response already delivered — never a request failure. */
        (void)mq_gw_cache_insert(s->cache, r->cache_key, 200, tmp, nh, r->store_buf,
                                 r->store_len, (uint64_t)ttl_s * 1000u, gw_now_ms());
    }
    free(r->store_buf);
    r->store_buf = NULL;
    r->store_len = 0;
    r->store_cap = 0;
    r->storing = 0;
}

/* curl on_done: terminal. result==CURLE_OK → finish; error → 502/mapped status
 * (if headers not yet sent) or RESET (if already sent). The origin side is freed
 * right after this returns — null r->oreq + set origin_dead FIRST. */
static void
origin_on_done(int curl_result, long http_ver, long ssl_verify, int origin_reuse,
               int origin_connect_ms, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    r->oreq = NULL; /* freed right after on_done returns */
    r->origin_dead = 1;
    r->resp_http_ver = http_ver;
    r->origin_reuse = origin_reuse;
    r->origin_connect_ms = origin_connect_ms;
    /* TLS outcome — only meaningful for an https origin. A plain http:// origin
     * (scheme_ok accepts both, mq_gw_server.c:751) has NO TLS result → MQ_TLS_NA,
     * even on success. ok = https + curl OK + verify passed; verify_fail = cert
     * rejected; connect_fail = any other transport failure on an https origin.
     * origin_is_tls is set in gw_dispatch (Task 5); defaults 0 until then. */
    if (!r->origin_is_tls)
        r->origin_tls = MQ_TLS_NA;
    else if (curl_result == 0 && ssl_verify == 0)
        r->origin_tls = MQ_TLS_OK;
    else if (ssl_verify != 0 || curl_result == CURLE_PEER_FAILED_VERIFICATION)
        r->origin_tls = MQ_TLS_VERIFY_FAIL;
    else
        r->origin_tls = MQ_TLS_CONNECT_FAIL;

    if (r->h3_dead || !r->req) {
        gw_req_maybe_free(r);
        return;
    }

    if (curl_result == 0) {
        /* Success. Send headers if we never got a body (no-body response). */
        if (!r->resp_headers_sent) {
            if (download_send_headers(r) != 0) {
                /* May have synthesized a clean error (oversized origin header →
                 * 502 + fin); only reset if it did NOT finish cleanly. */
                if (!r->finished) mq_h3_req_reset(r->req);
                gw_req_maybe_free(r);
                return;
            }
        }
        /* Mark the origin done so the fin is sent once any buffered tail drains. */
        r->origin_done_ok = 1;
        /* STORE the cacheable miss (best-effort; all body chunks have been
         * accumulated by now — on_done fires after the last on_body). Consumes +
         * frees store_buf. Done before the flush; insert never touches the H3 side. */
        store_finalize(r);
        /* Flush any pending body; download_flush sends the fin when pend empties
         * (immediately here if nothing is buffered). */
        download_flush(r);
        gw_req_maybe_free(r);
        return;
    }

    /* Error. */
    if (r->resp_headers_sent) {
        /* Headers already on the wire → truncation must be visible. RESET, never
         * a fake clean fin (absolute rule). */
        mq_h3_req_reset(r->req);
    } else {
        int code = mq_gw_status_from_curl(curl_result);
        char status[16];
        snprintf(status, sizeof(status), "%d", code);
        char xmq[32];
        snprintf(xmq, sizeof(xmq), "curl:%d", curl_result);
        gw_send_error(r, status, xmq);
    }
    gw_req_maybe_free(r);
}

/* ── request parse + origin start ───────────────────────────────────────────*/

/* Header-capture context: pseudo-headers + x-mq-auth/class + forwarded headers. */
typedef struct {
    mq_gw_req_t *r;

    /* pseudo-headers (NUL-terminated). */
    char method[16];
    char scheme[8];
    char authority[256];
    char path[1024];
    int has_method, has_scheme, has_authority, has_path;
    /* A pseudo-header value that did NOT fit its buffer was silently truncated by
     * copy_z. Silent truncation of :authority / :path changes the outbound target
     * (a redirection / SSRF surface); a clipped :method becomes a different verb.
     * Capture the overlong condition so gw_dispatch rejects rather than acts on a
     * truncated value. */
    int method_overlong, scheme_overlong, authority_overlong, path_overlong;

    /* auth + class */
    char auth[512];
    int has_auth;
    char cls[128];
    int has_class;

    mq_http_ver_t origin_http_version; /* from x-mq-origin-protocol; DEFAULT if absent */

    /* cache control (Phase 6). cache_ttl_s = parsed X-Mq-Cache opt-in TTL (0 =
     * absent/not opted in); has_authorization = request carried an Authorization
     * header (a cacheability gate — the response is per-credential). */
    unsigned cache_ttl_s;
    int has_authorization;

    /* forwarded origin headers (minus x-mq-* / hop-by-hop / pseudo). */
    mq_h3_header_t fwd[MQ_GWS_MAX_HDRS];
    char fwd_name[MQ_GWS_MAX_HDRS][128];
    char fwd_val[MQ_GWS_MAX_HDRS][1024];
    size_t n_fwd;

    /* content-length from the request headers (for INFILESIZE), -1 if absent. */
    int64_t content_length;
    int cl_seen; /* a content-length header was parsed (duplicate detection) */
    int bad_cl;  /* content-length was empty / non-digit / overflowed / duplicated
                  * → reject the whole request with 400 (mirrors mq_http1's strict
                  * parse; a silently-unset CL would mis-frame the upload). */

    int bad;        /* a header could not be stored (overflow) — diagnostic */
    int bad_header; /* a forwarded header name/value carried control bytes →
                     * reject the whole request with 400 (smuggling posture). */
} req_hdr_ctx_t;

static void
copy_z(char *dst, size_t dstcap, const char *s, size_t sl)
{
    size_t n = sl < dstcap - 1 ? sl : dstcap - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

static void
req_each_header(const char *n, size_t nl, const char *v, size_t vl, void *u)
{
    req_hdr_ctx_t *ctx = (req_hdr_ctx_t *)u;

    /* Pseudo-headers. */
    if (nl > 0 && n[0] == ':') {
        if (slice_ieq(n, nl, ":method")) {
            if (vl >= sizeof(ctx->method)) ctx->method_overlong = 1;
            copy_z(ctx->method, sizeof(ctx->method), v, vl);
            ctx->has_method = 1;
        } else if (slice_ieq(n, nl, ":scheme")) {
            if (vl >= sizeof(ctx->scheme)) ctx->scheme_overlong = 1;
            copy_z(ctx->scheme, sizeof(ctx->scheme), v, vl);
            ctx->has_scheme = 1;
        } else if (slice_ieq(n, nl, ":authority")) {
            if (vl >= sizeof(ctx->authority)) ctx->authority_overlong = 1;
            copy_z(ctx->authority, sizeof(ctx->authority), v, vl);
            ctx->has_authority = 1;
        } else if (slice_ieq(n, nl, ":path")) {
            if (vl >= sizeof(ctx->path)) ctx->path_overlong = 1;
            copy_z(ctx->path, sizeof(ctx->path), v, vl);
            ctx->has_path = 1;
        }
        /* other pseudo-headers: ignore */
        return;
    }

    if (slice_ieq(n, nl, "x-mq-auth")) {
        copy_z(ctx->auth, sizeof(ctx->auth), v, vl);
        ctx->has_auth = 1;
        return;
    }
    if (slice_ieq(n, nl, "x-mq-class")) {
        copy_z(ctx->cls, sizeof(ctx->cls), v, vl);
        ctx->has_class = 1;
        return;
    }
    if (slice_ieq(n, nl, "x-mq-origin-protocol")) {
        /* Reuse the shared parser. Client already validated; DEFAULT here = defensive
         * no-op. */
        ctx->origin_http_version = mq_gw_parse_http_ver(v, vl);
        return; /* control header — do NOT forward to origin */
    }
    if (slice_ieq(n, nl, "x-mq-cache")) {
        /* Cache opt-in TTL (the client validated + re-emitted this). 0 = invalid/
         * absent → not opted in. Control header — auto-stripped, not forwarded. */
        ctx->cache_ttl_s = mq_gw_parse_cache_ttl(v, vl);
        return;
    }
    if (slice_ieq(n, nl, "authorization")) {
        /* NOTE the credential for the cacheability gate (a per-credential
         * response must not be cached) but STILL forward it to the origin — do
         * NOT return here; fall through to the forward path below. */
        ctx->has_authorization = 1;
    }
    /* Remember content-length for the upload framing, but do NOT forward it to
     * the origin: CURLOPT_INFILESIZE_LARGE is the sole framing source, so
     * forwarding CL as a request header would create a divergence surface for
     * CL-based request-smuggling (defense mirrors mq_gw_strip_client's CL rule). */
    if (slice_ieq(n, nl, "content-length")) {
        /* A SECOND content-length (even identical) is a framing ambiguity → reject
         * (mirrors mq_http1: a duplicate CL is a request-smuggling surface). */
        if (ctx->cl_seen) {
            ctx->bad_cl = 1;
            return;
        }
        ctx->cl_seen = 1;
        /* Strict decimal into [0, INT64_MAX]; empty / non-digit / overflow → reject
         * rather than silently leaving content_length unset (which would fall back
         * to chunked and mis-frame a bodied request). Mirrors the INT64_MAX/10
         * overflow guard in mq_http1.c parse_content_length. */
        int64_t cl = 0;
        int ok = vl > 0;
        for (size_t i = 0; i < vl; i++) {
            if (v[i] < '0' || v[i] > '9') {
                ok = 0;
                break;
            }
            int d = v[i] - '0';
            if (cl > (int64_t)922337203685477580LL ||
                (cl == (int64_t)922337203685477580LL && d > 7)) {
                ok = 0;
                break;
            }
            cl = cl * 10 + d;
        }
        if (ok)
            ctx->content_length = cl;
        else
            ctx->bad_cl = 1;
        return; /* strip from forwarded set */
    }

    /* Strip server→origin (x-mq-*) and hop-by-hop. Forward the rest. */
    if (mq_gw_strip_server(n, nl) || mq_gw_strip_hop(n, nl)) return;
    /* Defense-in-depth: reject (whole request → 400) any forwarded header whose
     * NAME or VALUE carries control bytes. A name/value smuggling a CR/LF would
     * be a request-splitting surface once replayed to the origin. HTAB is
     * permitted in values only (mirrors D3 / mq_gw_parse_target strictness). */
    if (!mq_gw_hdr_name_ok(n, nl) || !mq_gw_hdr_value_ok(v, vl)) {
        ctx->bad_header = 1;
        return;
    }
    /* A forwarded NAME/VALUE that would not fit its arena slot must be REJECTED,
     * not silently truncated by copy_z: a clipped header changes what reaches the
     * origin (and a truncated value is a smuggling surface). Reuse the bad-header
     * 400 path. nl/vl are the FULL slice lengths; the slots hold cap-1 + NUL. */
    if (nl >= sizeof(ctx->fwd_name[0]) || vl >= sizeof(ctx->fwd_val[0])) {
        ctx->bad_header = 1;
        return;
    }
    if (ctx->n_fwd >= MQ_GWS_MAX_HDRS) {
        ctx->bad = 1;
        return;
    }
    size_t i = ctx->n_fwd++;
    copy_z(ctx->fwd_name[i], sizeof(ctx->fwd_name[i]), n, nl);
    copy_z(ctx->fwd_val[i], sizeof(ctx->fwd_val[i]), v, vl);
    ctx->fwd[i].name = ctx->fwd_name[i];
    ctx->fwd[i].value = ctx->fwd_val[i];
}

/* Validate a scheme is exactly "http" or "https" (lowercase). */
static int
scheme_ok(const char *s)
{
    return strcmp(s, "http") == 0 || strcmp(s, "https") == 0;
}

/* Build the cache key "GET <url>" into buf. GET-only (the caller gates on method).
 * Returns the written length (excl. NUL), or 0 on truncation/failure. */
static size_t
gw_cache_key(const char *url, char *buf, size_t cap)
{
    int n = snprintf(buf, cap, "GET %s", url);
    if (n <= 0 || (size_t)n >= cap) {
        if (cap > 0) buf[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

/* Cacheability predicate for the ORIGIN response that ran (the STORE gate, and the
 * ttl source). Returns the storable TTL in SECONDS (>0) iff every rule holds, else
 * 0 (not cacheable). Rules: GET, 200, opted in (cache_ttl_s>0), no Authorization,
 * no no-store/private/no-cache, no Set-Cookie, no Vary, and the effective ttl
 * (min of the request opt-in and any response max-age/s-maxage) is > 0 — so a
 * `max-age=0` response is NOT cacheable. */
static unsigned
gw_response_cacheable(const mq_gw_req_t *r)
{
    if (!r->is_get) return 0;
    if (r->resp_status != 200) return 0;
    if (r->cache_ttl_s == 0) return 0;
    if (r->has_authorization) return 0;
    if (r->cc_uncacheable) return 0;
    if (r->has_set_cookie) return 0;
    if (r->has_vary) return 0;
    unsigned ttl_s = r->cache_ttl_s;
    if (r->cc_max_age >= 0 && (unsigned long)r->cc_max_age < ttl_s)
        ttl_s = (unsigned)r->cc_max_age; /* the more conservative bound (incl. 0) */
    return ttl_s;                        /* 0 ⇒ not cacheable (e.g. max-age=0) */
}

/* COPY-ON-HIT + replay: serve `e` (a fresh borrowed cache entry) as this request's
 * response. The entry can be evicted by a LATER request's insert across the send
 * turns we yield on, so we DEEP-COPY the body into r->cache_body and stage the
 * header strings into the inline r->hdrs[] arrays BEFORE sending anything. Then we
 * send the headers and kick off the from_cache body replay (download_flush drives
 * the whole in-memory body, yielding only on real H3 backpressure; h3_on_write
 * re-drives).
 *
 * Returns 0 when the HIT was HANDLED (the response is in flight, OR the request is
 * already being torn down by a hard H3 send failure — either way the caller must
 * NOT start an origin). Returns -1 ONLY on a pre-send OOM (the body deep-copy
 * failed and NOTHING was sent), where the caller safely degrades to a normal
 * proxied response. On -1 all partial state is cleared. */
static int
gw_serve_from_cache(mq_gw_req_t *r, const mq_gw_cache_entry_t *e)
{
    if (r->h3_dead || !r->req) return -1;

    /* Deep-copy the body first (the only heap we own on the HIT path). Done BEFORE
     * any send so a -1 (OOM) leaves the H3 side untouched → safe to degrade. */
    uint8_t *body = NULL;
    if (e->body_len > 0) {
        body = malloc(e->body_len);
        if (!body) return -1; /* OOM → degrade; nothing sent yet */
        memcpy(body, e->body, e->body_len);
    }

    /* Stage the cached headers into the inline r->hdrs[] arrays. The entry's header
     * strings passed the SAME 128/1024 arena caps on store (origin_on_header), so
     * copy_z here is lossless; cap defensively at MQ_GWS_MAX_HDRS regardless. */
    r->n_hdrs = 0;
    for (size_t i = 0; i < e->n_hdrs && r->n_hdrs < MQ_GWS_MAX_HDRS; i++) {
        int j = r->n_hdrs++;
        copy_z(r->hdrs[j].name, sizeof(r->hdrs[j].name), e->hdrs[i].name,
               strlen(e->hdrs[i].name));
        copy_z(r->hdrs[j].value, sizeof(r->hdrs[j].value), e->hdrs[i].value,
               strlen(e->hdrs[i].value));
    }

    r->resp_status = e->status;
    r->cache_body = body; /* owned; freed at both teardown sites */
    r->cache_body_len = e->body_len;
    r->cache_off = 0;
    r->from_cache = 1;

    /* Send the response header section (the x-mq-origin-protocol diagnostic is
     * suppressed for from_cache in download_send_headers). From here on the request
     * is COMMITTED to the HIT path: even a hard H3 send failure tears the request
     * down (reset) rather than degrading — falling back to the origin after bytes
     * (or a reset) hit the wire is not possible. So we return 0 (handled) in all
     * post-send outcomes; the from_cache replay state + cache_body remain owned and
     * are freed at teardown. */
    if (download_send_headers(r) != 0) {
        /* Hard H3 send failure (sh<0) OR a synthesized clean error (oversized header
         * → 502 fin; not reachable for cached headers but handled defensively).
         * Mirror origin_on_body: reset only if the error path did NOT already finish
         * cleanly. Leave from_cache state intact (download_flush is a no-op once
         * r->req is gone / finished); teardown frees cache_body once. */
        if (!r->finished) mq_h3_req_reset(r->req);
        return 0;
    }
    /* Prime the body replay (the from_cache outer loop fills pend on first iter).
     * h3_on_write re-drives on H3 backpressure. */
    download_flush(r);
    return 0;
}

/* on_new_req has fired and headers are ready: parse, auth, validate, start the
 * origin request. Synthesizes 403/400/5xx on failure. */
static void
gw_dispatch(mq_gw_req_t *r)
{
    mq_gw_server_t *s = r->srv;

    req_hdr_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.r = r;
    ctx.content_length = -1;

    int fin = 0;
    int nh = mq_h3_req_recv_headers(r->req, req_each_header, &ctx, &fin);
    if (nh < 0) {
        /* No headers / hard error: synthesize 400. */
        gw_send_error(r, "400", "bad-request");
        return;
    }
    /* A forwarded header carried control bytes → reject (smuggling posture). */
    if (ctx.bad_header) {
        gw_send_error(r, "400", "bad-header");
        return;
    }
    /* The forwardable-header COUNT exceeded the per-request arena (ctx.bad set in
     * req_each_header). Forwarding now would replay a SILENTLY TRUNCATED header
     * set to the origin — fail closed with 400 rather than corrupt the request. */
    if (ctx.bad) {
        gw_send_error(r, "400", "bad-request");
        return;
    }
    /* content-length was empty / non-digit / overflowed / duplicated → reject
     * rather than mis-frame the upload (strict, mirrors mq_http1). */
    if (ctx.bad_cl) {
        gw_send_error(r, "400", "bad-request");
        return;
    }
    /* fin on the header section → no request body. */
    r->has_body = fin ? 0 : 1;
    if (fin) r->h3_body_fin = 1;

    /* AUTH: x-mq-auth must be "Bearer <token>" with constant-time token compare. */
    {
        const char *pfx = "Bearer ";
        size_t pl = strlen(pfx);
        size_t al = ctx.has_auth ? strlen(ctx.auth) : 0;
        int ok = ctx.has_auth && al > pl && memcmp(ctx.auth, pfx, pl) == 0;
        if (ok) {
            const char *tok = ctx.auth + pl;
            size_t tl = al - pl;
            ok = mq_ct_equal(tok, tl, s->token, s->token_len);
        }
        if (!ok) {
            gw_send_error(r, "403", "auth-failed");
            return;
        }
    }

    /* x-mq-class: accept + log only (design: forward+log).
     * Sanitize before logging: the value is attacker-controlled (log-injection). */
    if (ctx.has_class) {
        char cls_safe[65]; /* 64 visible chars + NUL */
        sanitize_for_log(cls_safe, 64, ctx.cls, strlen(ctx.cls));
        MQ_LOGI("mq_gw_server: x-mq-class='%s'", cls_safe);
    }

    /* Validate pseudo-headers. An overlong :method (silently clipped above) is a
     * verb-confusion surface; reject it with the same 400 as a missing/empty one. */
    if (!ctx.has_method || !ctx.has_scheme || !ctx.has_authority || !ctx.has_path ||
        ctx.method[0] == '\0' || ctx.authority[0] == '\0' || ctx.path[0] == '\0' ||
        ctx.path[0] != '/' || !scheme_ok(ctx.scheme) || ctx.method_overlong ||
        ctx.scheme_overlong) {
        gw_send_error(r, "400", "bad-request");
        return;
    }
    /* Validate + canonicalise :method with the SAME strictness as the client side
     * (mq_gw_parse_method: RFC 7230 token chars only, <=15, ASCII-uppercased).
     * curl does NOT sanitize CURLOPT_CUSTOMREQUEST, so an unvalidated method from
     * a direct H3 peer (e.g. "GE T" / "GET\r") is a request-line-injection surface.
     * Overwrite ctx.method in place with the canonical (uppercased) form. */
    {
        char canon[16];
        if (mq_gw_parse_method(ctx.method, strlen(ctx.method), canon) != 0) {
            gw_send_error(r, "400", "bad-request");
            return;
        }
        memcpy(ctx.method, canon, sizeof(ctx.method));
    }
    /* An overlong :authority / :path was silently truncated by copy_z — that
     * changes the outbound target (redirection / SSRF surface), so reject. */
    if (ctx.authority_overlong || ctx.path_overlong) {
        gw_send_error(r, "400", "bad-target");
        return;
    }
    /* Re-validate :authority / :path strictness on this side of the tunnel
     * (defense-in-depth, mirrors mq_gw_parse_target): reject SP, CR, LF, other
     * control bytes, and 0x7f before these are folded into an outbound URL. */
    if (!mq_gw_uri_field_ok(ctx.authority, strlen(ctx.authority)) ||
        !mq_gw_uri_field_ok(ctx.path, strlen(ctx.path))) {
        gw_send_error(r, "400", "bad-target");
        return;
    }

    /* Build the origin URL = scheme://authority + path. */
    char url[8 + 256 + 1024 + 4];
    int un = snprintf(url, sizeof(url), "%s://%s%s", ctx.scheme, ctx.authority, ctx.path);
    if (un <= 0 || (size_t)un >= sizeof(url)) {
        gw_send_error(r, "400", "bad-target");
        return;
    }

    /* Observability capture (best-effort; safe even if the request later aborts).
     * ctx.scheme is validated by scheme_ok() above and NUL-terminated by copy_z. */
    snprintf(r->method, sizeof(r->method), "%s", ctx.method);
    snprintf(r->authority, sizeof(r->authority), "%s", ctx.authority);
    snprintf(
        r->path, sizeof(r->path), "%.*s", (int)sizeof(r->path) - 1,
        ctx.path); /* r->path is 512 B, ctx.path is 1024 B: a 513–1023 B path is the
                      full value at the origin URL (built above) but is silently
                      truncated in this metrics-only copy. The %.*s precision bound
                      caps output to fit so -Werror=format-truncation can prove it. */
    r->origin_is_tls = (strcmp(ctx.scheme, "https") == 0); /* gates origin_tls (NEW-3) */

    /* Cacheability inputs from the request side (Phase 6; the response-side flags
     * are captured later in origin_on_header). */
    r->cache_ttl_s = ctx.cache_ttl_s;
    r->has_authorization = ctx.has_authorization;
    r->is_get = (strcmp(ctx.method, "GET") == 0);

    /* CACHE HIT path (Phase 6) — check the cache BEFORE starting the origin. A hit
     * serves the stored 200 from memory and contacts NO origin. Gated on: caching
     * enabled, opted in (X-Mq-Cache), GET, and no Authorization (a per-credential
     * response is never served from a shared cache). A cache failure NEVER breaks
     * the request — on any error we fall through to a normal proxied response. */
    if (s->cache && r->cache_ttl_s > 0 && r->is_get && !r->has_authorization) {
        /* Eligible for caching → this is at least a MISS (flips to HIT below, or
         * stays MISS once the origin runs). The store-on-miss happens in
         * origin_on_done; the key built here is reused there. */
        r->cache_state = MQ_CACHE_MISS;
        if (gw_cache_key(url, r->cache_key, sizeof(r->cache_key)) > 0) {
            const mq_gw_cache_entry_t *e =
                mq_gw_cache_lookup(s->cache, r->cache_key, gw_now_ms());
            if (e && gw_serve_from_cache(r, e) == 0) {
                /* HIT: response is now in flight from memory; no origin started.
                 * origin_dead stays 0 here → h3_on_close flips it (oreq==NULL, the
                 * reject precedent) → gw_req_maybe_free reclaims. */
                r->cache_state = MQ_CACHE_HIT;
                return;
            }
            /* lookup miss OR a copy-on-hit OOM: degrade to a normal proxied response
             * (cache_state stays MISS). gw_serve_from_cache cleared any partial state. */
        } else {
            /* Key too long to cache (pathological URL): leave cache_key empty so the
             * store path skips insert; still a normal proxied response. */
            r->cache_key[0] = '\0';
        }
    }

    /* Upload framing: body present → known CL (>=0) or chunked sentinel. */
    int64_t upload_len = -1; /* no body */
    if (r->has_body) {
        upload_len =
            ctx.content_length >= 0 ? ctx.content_length : MQ_ORIGIN_UPLOAD_CHUNKED;
    }

    mq_origin_cbs_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.on_status = origin_on_status;
    cbs.on_header = origin_on_header;
    cbs.on_body = origin_on_body;
    cbs.pull_body = origin_pull_body;
    cbs.on_done = origin_on_done;

    r->oreq = mq_origin_start(s->origin, url, ctx.method, ctx.fwd, ctx.n_fwd, upload_len,
                              ctx.origin_http_version, &cbs, r);
    if (!r->oreq) {
        /* Could not start the origin request → 502. Origin side never existed. */
        r->origin_dead = 1;
        gw_send_error(r, "502", "origin-start-failed");
        return;
    }
    /* origin_dead stays 0; on_done or our abort flips it. The request is now
     * live on both sides. If the request body already has bytes buffered in
     * the stream (rare), pump them so curl's first pull sees them; pull_body
     * also tops up on demand. */
}

/* ── H3 request callbacks ───────────────────────────────────────────────────*/

static void
h3_on_read(mq_h3_req_t *hr, int flag, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    if (r->h3_dead || !r->req) return;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        /* First (and only) request header section → parse, auth, dispatch. */
        gw_dispatch(r);
        /* If dispatch already finished/reset the request (error path), stop. */
        if (r->h3_dead || !r->req || r->finished) return;
    }

    if (flag & XQC_REQ_NOTIFY_READ_TRAILER) {
        /* Drain + ignore trailers (not forwarded in the MVP). */
        int tfin = 0;
        mq_h3_req_recv_headers(r->req, NULL, NULL, &tfin);
        if (tfin) r->h3_body_fin = 1;
    }

    /* Body bytes available (or empty-fin): feed the upload spill. Only relevant
     * once the origin request is live (otherwise we have nothing to feed). */
    if (flag & (XQC_REQ_NOTIFY_READ_BODY | XQC_REQ_NOTIFY_READ_EMPTY_FIN)) {
        if (!r->origin_dead) upload_recv(r);
    }
}

static void
h3_on_write(mq_h3_req_t *hr, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    if (r->h3_dead || !r->req) return;
    /* A previously flow-control-blocked response-body send can resume. */
    if (r->pend_off < r->pend_len || r->recv_paused) download_flush(r);
}

/* ── mq.req metrics emission ─────────────────────────────────────────────────
 * Stage-0 (Task 3b) finding, verified live against test_gw_server downloads:
 * the SEND-side stamps are the server's response timings and are reliably
 * populated > h3r_begin_time on a clean close:
 *   - h3r_header_send_time  → ttfb_ms     (e.g. +0.8ms..+1.9ms after begin)
 *   - stream_fin_send_time  → duration_ms (e.g. +2.0ms)
 *   - stream_fin_ack_time   → completion_ms (e.g. +2.1ms)
 * recv_body_size/send_body_size carry the request/response body sizes.
 * On an error/reset close, fin_send/fin_ack come back 0 (ms_since → -1, guarded)
 * and stream_err is nonzero. The receive-side stream_fin_time/h3r_end_time
 * measure the REQUEST upload finishing, NOT the response — not used here.
 * h3r_header_send_time is reliable, so the Step-3b TTFB fallback is NOT needed. */
static int
ms_since(xqc_usec_t begin, xqc_usec_t later)
{
    if (begin == 0 || later == 0 || later < begin) return -1;
    return (int)((later - begin) / 1000);
}

/* Copy `in` up to the first '?' (drop query) into out[0..cap). */
static void
emit_path_strip_query(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    for (const char *p = in; *p && *p != '?' && n + 1 < cap; p++)
        out[n++] = *p;
    out[n] = '\0';
}

/* metrics-only origin protocol token: h3/h2/h1/none. Do NOT reuse http_ver_token
 * (it returns "http/1.1"/"http/1.0" for H1, which violates the mq.req schema).
 * NONE/unknown → "none" so an origin that never negotiated a version (start-failure
 * or H3-first abort, where resp_http_ver stays at the NONE default) is not mislabeled. */
static const char *
origin_proto_token(long ver)
{
    switch (ver) {
    case CURL_HTTP_VERSION_3: return "h3";
    case CURL_HTTP_VERSION_2: return "h2";
    case CURL_HTTP_VERSION_1_1:
    case CURL_HTTP_VERSION_1_0: return "h1";
    default: return "none"; /* incl. CURL_HTTP_VERSION_NONE */
    }
}

static void
gw_emit_req_metrics(mq_gw_req_t *r, mq_h3_req_t *hr)
{
    if (!r->srv->request_metrics) return;
    xqc_request_stats_t st;
    int have = (mq_h3_req_get_stats(hr, &st) == 0);

    char pathbuf[MQ_GW_REQ_PATH_CAP + 1];
    emit_path_strip_query(r->path[0] ? r->path : "-", pathbuf, sizeof(pathbuf));

    /* origin_tls: origin_on_done set it for a COMPLETED origin (MQ_TLS_NA for a plain
     * http:// origin). If the origin is still live at close (oreq != NULL and not yet
     * dead), this request is closing with the origin in-flight (H3-first abort, which
     * fires no on_done) → no completed/verified origin. For a TLS origin that means
     * connect_fail; for a plain http:// origin there is no TLS handshake to fail, so
     * report "na" (same value origin_on_done would have set). */
    const char *otls = (r->oreq && !r->origin_dead)
                           ? (r->origin_is_tls ? "connect_fail" : "na")
                           : tls_token(r->origin_tls);

    mq_gw_req_metrics_t m = {
        .method = r->method[0] ? r->method : "-",
        .status = r->resp_status, /* client-visible status; set on BOTH the
                                     origin path (on_status) and gw_send_error
                                     (Task 5) so error rows are not status=0 */
        .authority = r->authority[0] ? r->authority : "-",
        .path = pathbuf,
        .req_bytes = have ? st.recv_body_size : 0,  /* server RECEIVES request body */
        .resp_bytes = have ? st.send_body_size : 0, /* server SENDS response body */
        /* SERVER-side response timings use SEND-side stamps (verified in Stage-0):
         * h3r_*send_time / stream_fin_send_time / stream_fin_ack_time. The receive-side
         * stream_fin_time ("receiving transport fin") / h3r_end_time measure the
         * REQUEST upload finishing, NOT the response — do not use them here. */
        .ttfb_ms = have ? ms_since(st.h3r_begin_time, st.h3r_header_send_time) : -1,
        .duration_ms = have ? ms_since(st.h3r_begin_time, st.stream_fin_send_time) : -1,
        .completion_ms = have ? ms_since(st.h3r_begin_time, st.stream_fin_ack_time) : -1,
        .origin_protocol =
            origin_proto_token(r->resp_http_ver), /* NONE-default → "none" */
        .origin_tls = otls,
        .content_encoding = r->content_encoding[0] ? r->content_encoding : "none",
        .cache = r->cache_state == MQ_CACHE_HIT ? "hit"
                 : r->cache_state == MQ_CACHE_MISS
                     ? "miss"
                     : "bypass",                   /* not opted in / disabled /
                                                      non-GET / Authorization */
        .origin_reuse = r->origin_reuse,           /* Phase 6: real (was honest 0) */
        .origin_connect_ms = r->origin_connect_ms, /* Phase 6: 0 reuse / -1 unknown */
        .mp_state = have ? st.mp_state : 0,
        .reset_reason = (have && st.stream_err)
                            ? (st.stream_close_msg ? st.stream_close_msg : "stream-err")
                            : "",
    };

    /* cid=- : 5c log lines carry no cid, so there is nothing to correlate a hex
     * cid against today. sid (the MPQUIC stream id) correlates within a conn. */
    char line[MQ_GW_REQ_LINE_CAP];
    uint64_t sid = mq_h3_req_stream_id(hr); /* Task 3.5 accessor */
    if (mq_gw_format_req_line(line, sizeof(line), "-", sid, &m) > 0)
        MQ_LOGI("%s", line);
    else
        MQ_LOGW("mq.req line truncated (dropped)"); /* MQ_LOGW exists, mq_log.h:28 */
}

static void
h3_on_close(mq_h3_req_t *hr, void *user)
{
    mq_gw_req_t *r = (mq_gw_req_t *)user;
    gw_emit_req_metrics(r, hr);
    r->h3_dead = 1;
    r->req = NULL; /* freed right after this returns */

    /* Flip the origin side dead so gw_req_maybe_free can reclaim the state.
     * Two cases, handled uniformly:
     *   - origin live (oreq != NULL): client reset / conn died before the origin
     *     completed → abort it. on_close is an mq_h3 callback — NOT a curl
     *     callback — so mq_origin_abort is safe here (re-entrancy contract).
     *     abort fires NO on_done, so we flip origin_dead ourselves.
     *   - origin NEVER existed (oreq == NULL): the request was rejected pre-origin
     *     (403/400/bad-header/bad-target) and the synthetic-error path did not run
     *     gw_dispatch's origin_dead=1 (those rejects leave it 0). The origin side
     *     cannot be live without an oreq, so flip origin_dead unconditionally —
     *     otherwise maybe_free never runs and the state leaks in s->reqs. */
    if (!r->origin_dead) {
        if (r->oreq) {
            mq_origin_abort(r->oreq);
            r->oreq = NULL;
        }
        r->origin_dead = 1;
    }
    gw_req_maybe_free(r);
}

/* ── mq_h3 server hooks ─────────────────────────────────────────────────────*/

/* Conn-state hook for accepted H3 tunnel conns: clear the observability slot on
 * close if it still points at this conn (a later accept may have replaced it),
 * so the metrics tick never dereferences a freed h3 conn. Mirrors the TCP
 * server's clear-if-self guard (mq_server.c). `established` is unused (we only
 * act on close). */
static void
gw_srv_conn_state(mq_h3_conn_t *c, int established, void *user)
{
    if (established) {
        return;
    }
    mq_gw_server_t *s = (mq_gw_server_t *)user;
    if (s->last_conn == c) {
        s->last_conn = NULL;
    }
}

static void
gw_on_new_conn(mq_h3_conn_t *c, void *user)
{
    mq_gw_server_t *s = (mq_gw_server_t *)user;
    /* Track the most-recent accepted conn for the periodic metrics dump, and
     * install a state cb to clear it on close (UAF guard). Per-request state is
     * still allocated lazily in on_new_req.
     *
     * DETACH the cb from the previously-tracked conn before overwriting, so AT
     * MOST ONE live conn ever carries gw_srv_conn_state(s). Otherwise an older
     * conn that is still live when a newer one is accepted would keep the cb, and
     * mq_h3_free's engine teardown (which runs AFTER mq_gw_server_free frees `s`)
     * would fire gw_srv_conn_state into the freed `s` — a use-after-free. With
     * this, mq_gw_server_free's single detach of last_conn fully covers it. */
    if (s->last_conn && s->last_conn != c) {
        mq_h3_conn_set_state_cb(s->last_conn, NULL, NULL);
    }
    s->last_conn = c;
    mq_h3_conn_set_state_cb(c, gw_srv_conn_state, s);
}

static void
gw_on_new_req(mq_h3_req_t *hr, void *user)
{
    mq_gw_server_t *s = (mq_gw_server_t *)user;
    s->requests++;

    mq_gw_req_t *r = calloc(1, sizeof(*r));
    if (!r) {
        MQ_LOGE("mq_gw_server: OOM allocating per-request state; resetting");
        mq_h3_req_reset(hr);
        return;
    }
    r->srv = s;
    r->req = hr;
    r->resp_http_ver =
        CURL_HTTP_VERSION_NONE; /* "none" until on_done sets the real version */
    r->cc_max_age = -1;         /* -1 = absent (calloc zeroes the other cache flags) */
    r->origin_reuse = 0;
    r->origin_connect_ms = -1;

    /* Link before wiring callbacks so teardown can find it. */
    r->next = s->reqs;
    s->reqs = r;

    mq_h3_req_set_cbs(hr, h3_on_read, h3_on_write, h3_on_close, r);

    /* Headers may already be pending (xquic can deliver on_new_req with the
     * header section ready). The on_read notify drives the parse; do not call
     * recv here to avoid double-draining. */
}

/* ── public API ─────────────────────────────────────────────────────────────*/

mq_gw_server_t *
mq_gw_server_new(mq_transport_t *t, mq_runtime_t *rt, const char *token,
                 const char *ca_file, long connect_timeout_s)
{
    if (!t || !rt || !token) return NULL;

    mq_gw_server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->t = t;
    s->rt = rt;
    snprintf(s->token, sizeof(s->token), "%s", token);
    s->token_len = strnlen(s->token, sizeof(s->token));

    struct event_base *base = mq_runtime_base(rt);
    if (!base) {
        free(s);
        return NULL;
    }
    s->origin = mq_origin_new(base, ca_file, connect_timeout_s);
    if (!s->origin) {
        free(s);
        return NULL;
    }

    /* The gw_server is the H3 hooks owner — init mq_h3 with our own hooks. */
    s->h3 = mq_h3_init(t, gw_on_new_conn, gw_on_new_req, s);
    if (!s->h3) {
        mq_origin_free(s->origin);
        free(s);
        return NULL;
    }
    return s;
}

mq_h3_t *
mq_gw_server_h3(const mq_gw_server_t *s)
{
    return s ? s->h3 : NULL;
}

mq_h3_conn_t *
mq_gw_server_active_conn(const mq_gw_server_t *s)
{
    return s ? s->last_conn : NULL;
}

unsigned
mq_gw_server_requests(const mq_gw_server_t *s)
{
    return s ? s->requests : 0;
}

unsigned
mq_gw_server_live_reqs(const mq_gw_server_t *s)
{
    if (!s) return 0;
    unsigned n = 0;
    for (const mq_gw_req_t *r = s->reqs; r; r = r->next)
        n++;
    return n;
}

void
mq_gw_server_set_request_metrics(mq_gw_server_t *s, int on)
{
    if (s) s->request_metrics = on ? 1 : 0;
}

void
mq_gw_server_set_cache(mq_gw_server_t *s, size_t max_bytes)
{
    if (!s) return;
    if (s->cache) {
        mq_gw_cache_free(s->cache);
        s->cache = NULL;
    }
    if (max_bytes > 0) {
        size_t obj = max_bytes < (4u << 20) ? max_bytes : (4u << 20); /* min(N,4MiB) */
        if (obj < MQ_GWS_RECV_CHUNK) obj = MQ_GWS_RECV_CHUNK; /* floor at a chunk */
        s->cache = mq_gw_cache_new(max_bytes, obj);
    }
}

void
mq_gw_server_free(mq_gw_server_t *s)
{
    if (!s) return;

    /* DETACH the conn-state cb on the tracked conn FIRST. gw_server_free runs
     * while the H3 engine is still live (sanctioned order); the subsequent
     * mq_h3_free destroys remaining conns and fires their close-notify — by then
     * `s` is freed, so a live gw_srv_conn_state(s) would be a use-after-free.
     * Mirrors the mq_gw_client_free detach. (Per-instance: one live conn.) */
    if (s->last_conn) {
        mq_h3_conn_set_state_cb(s->last_conn, NULL, NULL);
        s->last_conn = NULL;
    }

    /* Tear down in-flight requests. SANCTIONED ORDER (see header): gw_server_free
     * runs FIRST, while the H3 engine is STILL LIVE, so touching r->req is valid.
     * For each live request:
     *   1. ABORT the origin side (no on_done; the curl handle is reaped now).
     *   2. DETACH the H3 callbacks so the deferred on_close mq_h3_req_reset
     *      schedules cannot re-enter h3_on_close on the mq_gw_req_t we free here.
     *   3. RESET the H3 request (truncate the tunnel side).
     *   4. Free the per-request state (we own it; both sides detached). */
    mq_gw_req_t *r = s->reqs;
    while (r) {
        mq_gw_req_t *next = r->next;
        if (!r->origin_dead && r->oreq) {
            mq_origin_abort(r->oreq);
            r->oreq = NULL;
            r->origin_dead = 1;
        }
        if (!r->h3_dead && r->req) {
            mq_h3_req_set_cbs(r->req, NULL, NULL, NULL, NULL);
            mq_h3_req_reset(r->req);
            r->req = NULL;
            r->h3_dead = 1;
        }
        free(r->spill);
        free(r->cache_body); /* copy-on-hit body — a HIT can be live at shutdown */
        free(r->store_buf);  /* STORE accumulator — a cacheable miss can be in flight */
        free(r);
        r = next;
    }
    s->reqs = NULL;

    /* All requests aborted → safe to free the origin (no live easy handles). */
    if (s->origin) mq_origin_free(s->origin);

    /* Free the response cache (NULL when disabled). All in-flight requests are
     * already reclaimed above, so no live HIT borrows the entries. */
    if (s->cache) mq_gw_cache_free(s->cache);

    /* Do NOT free s->h3 here — the caller frees it (mq_gw_server_h3) in the
     * sanctioned order, before mq_transport_free. */
    free(s);
}
