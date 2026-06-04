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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <event2/event.h>

#include "gateway/mq_gw_headers.h"
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
    int hdrs_overflow; /* dropped a header (capacity) — diagnostic only */

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

    mq_gw_req_t *reqs; /* intrusive list of live per-request states */
};

/* ── forward decls ──────────────────────────────────────────────────────────*/
static void gw_req_unlink(mq_gw_server_t *s, mq_gw_req_t *r);
static void gw_req_maybe_free(mq_gw_req_t *r);
static void h3_on_read(mq_h3_req_t *hr, int flag, void *user);
static void h3_on_write(mq_h3_req_t *hr, void *user);
static void h3_on_close(mq_h3_req_t *hr, void *user);
static void download_flush(mq_gw_req_t *r);

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
    char st[8];
    snprintf(st, sizeof(st), "%s", status);
    mq_h3_header_t hs[] = {
        {":status", st},
        {"x-mq-error", xmq_error},
        {"content-length", "0"},
    };
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

    mq_h3_header_t hs[MQ_GWS_MAX_HDRS + 2];
    size_t nh = 0;

    char st[16];
    int code = (r->resp_status >= 100 && r->resp_status <= 599) ? r->resp_status : 502;
    snprintf(st, sizeof(st), "%d", code);
    hs[nh].name = ":status";
    hs[nh].value = st;
    nh++;

    hs[nh].name = "x-mq-origin-protocol";
    hs[nh].value = http_ver_token(r->resp_http_ver);
    nh++;

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
    if (mq_gw_strip_hop(n, nl)) return;
    if (r->n_hdrs >= MQ_GWS_MAX_HDRS) {
        r->hdrs_overflow = 1;
        return;
    }
    /* Drop any x-mq-origin-protocol the origin itself sent — we synthesize ours
     * from the negotiated http_ver, and a duplicate pseudo-ish diagnostic would
     * be confusing. */
    if (slice_ieq(n, nl, "x-mq-origin-protocol")) return;

    int i = r->n_hdrs++;
    size_t cnl = nl < sizeof(r->hdrs[i].name) - 1 ? nl : sizeof(r->hdrs[i].name) - 1;
    for (size_t j = 0; j < cnl; j++) {
        char ch = n[j];
        if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
        r->hdrs[i].name[j] = ch;
    }
    r->hdrs[i].name[cnl] = '\0';
    size_t cvl = vl < sizeof(r->hdrs[i].value) - 1 ? vl : sizeof(r->hdrs[i].value) - 1;
    memcpy(r->hdrs[i].value, v, cvl);
    r->hdrs[i].value[cvl] = '\0';
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
            mq_h3_req_reset(r->req);
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

/* curl on_done: terminal. result==CURLE_OK → finish; error → 502/mapped status
 * (if headers not yet sent) or RESET (if already sent). The origin side is freed
 * right after this returns — null r->oreq + set origin_dead FIRST. */
static void
origin_on_done(int curl_result, long http_ver, void *u)
{
    mq_gw_req_t *r = (mq_gw_req_t *)u;
    r->oreq = NULL; /* freed right after on_done returns */
    r->origin_dead = 1;
    r->resp_http_ver = http_ver;

    if (r->h3_dead || !r->req) {
        gw_req_maybe_free(r);
        return;
    }

    if (curl_result == 0) {
        /* Success. Send headers if we never got a body (no-body response). */
        if (!r->resp_headers_sent) {
            if (download_send_headers(r) != 0) {
                mq_h3_req_reset(r->req);
                gw_req_maybe_free(r);
                return;
            }
        }
        /* Mark the origin done so the fin is sent once any buffered tail drains. */
        r->origin_done_ok = 1;
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

    /* forwarded origin headers (minus x-mq-* / hop-by-hop / pseudo). */
    mq_h3_header_t fwd[MQ_GWS_MAX_HDRS];
    char fwd_name[MQ_GWS_MAX_HDRS][128];
    char fwd_val[MQ_GWS_MAX_HDRS][1024];
    size_t n_fwd;

    /* content-length from the request headers (for INFILESIZE), -1 if absent. */
    int64_t content_length;

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
    /* Remember content-length for the upload framing, but do NOT forward it to
     * the origin: CURLOPT_INFILESIZE_LARGE is the sole framing source, so
     * forwarding CL as a request header would create a divergence surface for
     * CL-based request-smuggling (defense mirrors mq_gw_strip_client's CL rule). */
    if (slice_ieq(n, nl, "content-length")) {
        int64_t cl = 0;
        int ok = vl > 0;
        for (size_t i = 0; i < vl; i++) {
            if (v[i] < '0' || v[i] > '9') {
                ok = 0;
                break;
            }
            cl = cl * 10 + (v[i] - '0');
        }
        if (ok) ctx->content_length = cl;
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
                              &cbs, r);
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

static void
h3_on_close(mq_h3_req_t *hr, void *user)
{
    (void)hr;
    mq_gw_req_t *r = (mq_gw_req_t *)user;
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

static void
gw_on_new_conn(mq_h3_conn_t *c, void *user)
{
    (void)c;
    (void)user;
    /* Nothing to do per-conn: per-request state is allocated in on_new_req. */
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
    r->resp_http_ver = CURL_HTTP_VERSION_1_1; /* sane default until on_done */

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
mq_gw_server_free(mq_gw_server_t *s)
{
    if (!s) return;

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
        free(r);
        r = next;
    }
    s->reqs = NULL;

    /* All requests aborted → safe to free the origin (no live easy handles). */
    if (s->origin) mq_origin_free(s->origin);

    /* Do NOT free s->h3 here — the caller frees it (mq_gw_server_h3) in the
     * sanctioned order, before mq_transport_free. */
    free(s);
}
