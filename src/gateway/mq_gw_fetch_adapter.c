// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_fetch_adapter.c — HTTP/1.1 fetch-listener adapter over the neutral
 * mq_gw_client intake boundary. See mq_gw_fetch_adapter.h.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ADAPTER_REQ OWNERSHIP
 * ─────────────────────────────────────────────────────────────────────────────
 * Each accepted fetch request owns one adapter_req_t (ar). Allocated in
 * adp_on_request on success; freed by exactly ONE of:
 *
 *   (A) Normal response path: the core drives the download to completion and
 *       calls adp_resp_finish(ar) or adp_resp_abort(ar). These free ar.
 *       mq_gw_client_req_body_done and adp_on_body_done do NOT free ar.
 *
 *   (B) Local-peer-died path: adp_on_aborted fires before the response is
 *       complete. mq_gw_client_req_aborted nulls r->sink / r->sink_user
 *       WITHOUT calling any sink op (it just resets H3 and eventually frees r
 *       once H3 on_close fires). ar is therefore freed by adp_on_aborted
 *       itself, after calling req_aborted.
 *
 * Paths A and B are MUTUALLY EXCLUSIVE (the core's local_dead flag + the
 * listener's per-connection detach ensure on_aborted cannot fire after
 * resp_finish/resp_abort, and vice versa). So ar is freed exactly once. */
#include "gateway/mq_gw_fetch_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gateway/mq_gw_headers.h"
#include "gateway/mq_gw_intake.h"
#include "gateway/mq_http1.h"
#include "util/mq_log.h"

/* ── per-request adapter state ──────────────────────────────────────────────*/

typedef struct {
    void *handle;       /* mq_fetch_listener per-conn handle (NULL once dead) */
    mq_gw_xreq_t *core; /* the core per-request state (valid until resp_finish/abort) */
    int resp_chunked;   /* response is framed as Transfer-Encoding: chunked */
} adapter_req_t;

/* ── adapter struct ─────────────────────────────────────────────────────────*/

struct mq_gw_fetch_adapter {
    mq_gw_client_t *core; /* borrowed */
};

/* ── helpers (moved verbatim from the former H1 path in mq_gw_client.c) ────*/

/* Serialize a complete HTTP/1.1 error response into buf. Returns byte length,
 * or 0 if it did not fit. Used by gw_reject_write (on_request reject path). */
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

/* on_request REJECTION path: write the error response. The listener's
 * on_request==-1 contract flushes + closes the connection itself, so we MUST
 * NOT call mq_fetch_conn_finish here. Write only. */
static void
gw_reject_write(void *handle, int code, const char *reason, const char *xmq_error)
{
    char buf[512];
    size_t n = gw_build_error(buf, sizeof(buf), code, reason, xmq_error);
    if (n) mq_fetch_conn_write(handle, buf, n);
}

/* Map mq_gw_reject_reason_t → X-Mq-Error string: now the SHARED helper
 * mq_gw_reject_xmq (mq_gw_intake.h, implemented in mq_gw_headers.c) so the H1 and
 * H2 adapters render byte-identical strings. The former static gw_reason_xmq was
 * extracted there (Slice 3 Task 8). */

/* H1 reason → status-line reason phrase (moved from mq_gw_client.c). */
static const char *
gw_status_phrase(int code)
{
    return code == 502 ? "Bad Gateway" : "Bad Request";
}

/* Case-insensitive equality: slice vs NUL-terminated lowercase literal. */
static int
slice_ieq_local(const char *s, size_t sl, const char *lit)
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

/* Find header value slice (case-insensitive) in mq_http1_req_t. */
static const char *
find_hdr_local(const mq_http1_req_t *req, const char *name, size_t *out_vl)
{
    for (size_t i = 0; i < req->nh; i++) {
        if (slice_ieq_local(req->h[i].n, req->h[i].nl, name)) {
            if (out_vl) *out_vl = req->h[i].vl;
            return req->h[i].v;
        }
    }
    return NULL;
}

/* ── local drain cb ─────────────────────────────────────────────────────────*/

/* Local output drained below the low watermark → notify the core so the
 * download read path can resume. */
static void
local_drain_cb(void *user)
{
    adapter_req_t *ar = (adapter_req_t *)user;
    mq_gw_client_req_drained(ar->core);
}

/* ── H1 sink callbacks ──────────────────────────────────────────────────────
 *
 * Invoked BY the core when the H3 response arrives. Render HTTP/1.1 response
 * bytes via mq_fetch_conn_* on ar->handle — byte-identical to the former
 * inline rendering in mq_gw_client.c. These callbacks MUST NOT call back into
 * the core: the core manages local_dead and gw_req_maybe_free; the sink's
 * only responsibility is to render + deliver the response to the local peer. */

static int
adp_resp_head(void *u, int status, const mq_h3_header_t *hs, size_t n,
              mq_gw_body_mode_t body_mode)
{
    adapter_req_t *ar = (adapter_req_t *)u;
    if (!ar->handle) return -1;

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
        ar->resp_chunked = 1;
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

    /* Register the drain cb so a highwater hit during body relay re-kicks the
     * download read path. */
    mq_fetch_conn_set_drain_cb(ar->handle, local_drain_cb, ar);
    int wr = mq_fetch_conn_write(ar->handle, head, head_len);
    if (wr < 0) return -1;
    return 1;
}

static int
adp_resp_body(void *u, const uint8_t *p, size_t len)
{
    adapter_req_t *ar = (adapter_req_t *)u;
    if (!ar->handle) return -1;

    if (ar->resp_chunked) {
        /* Frame the chunk: "<hex>\r\n<data>\r\n". */
        char hdr[32];
        int hn = snprintf(hdr, sizeof(hdr), "%lx\r\n", (unsigned long)len);
        if (hn <= 0) return -1;
        int wr = mq_fetch_conn_write(ar->handle, hdr, (size_t)hn);
        if (wr < 0) return -1;
        wr = mq_fetch_conn_write(ar->handle, p, len);
        if (wr < 0) return -1;
        int wr2 = mq_fetch_conn_write(ar->handle, "\r\n", 2);
        if (wr2 < 0) return -1;
        if (wr == 0 || wr2 == 0) return 0; /* highwater → defer */
        return 1;
    }

    int wr = mq_fetch_conn_write(ar->handle, p, len);
    if (wr < 0) return -1;
    return wr == 0 ? 0 : 1;
}

static void
adp_resp_finish(void *u)
{
    adapter_req_t *ar = (adapter_req_t *)u;
    /* Chunked response → write the terminating zero-length chunk. */
    if (ar->resp_chunked && ar->handle) {
        char term[8];
        size_t tn = mq_http1_chunk_frame(term, sizeof(term), NULL, 0);
        if (tn > 0) mq_fetch_conn_write(ar->handle, term, tn);
    }
    if (ar->handle) mq_fetch_conn_finish(ar->handle);
    ar->handle = NULL;
    free(ar);
}

static void
adp_resp_abort(void *u)
{
    adapter_req_t *ar = (adapter_req_t *)u;
    if (ar->handle) mq_fetch_conn_abort(ar->handle);
    ar->handle = NULL;
    free(ar);
}

static void
adp_resume_read(void *u)
{
    adapter_req_t *ar = (adapter_req_t *)u;
    if (ar->handle) mq_fetch_conn_resume_read(ar->handle);
}

static const mq_gw_sink_ops_t g_h1_sink = {
    .resp_head = adp_resp_head,
    .resp_body = adp_resp_body,
    .resp_finish = adp_resp_finish,
    .resp_abort = adp_resp_abort,
    .resume_read = adp_resume_read,
};

/* ── fetch listener callbacks (mq_fetch_cbs_t) ──────────────────────────────
 *
 * Translate the HTTP/1.1 mq_fetch_listener events into the neutral
 * mq_gw_client intake boundary. Observable reject ORDER is preserved exactly:
 *   dup-control-header → X-Mq-Auth → X-Mq-Target → X-Mq-Method
 *   → [req_begin: origin-proto / cache / size / tunnel] */

static int
adp_on_request(const mq_http1_req_t *req, void *handle, void *user, void **req_ctx)
{
    mq_gw_fetch_adapter_t *a = (mq_gw_fetch_adapter_t *)user;
    *req_ctx = NULL;

    /* Build a NEUTRAL, NUL-terminated copy of the request headers so the core's
     * strlen-based size checks observe the true lengths. */
    size_t hn = req->nh;
    mq_h3_header_t *H = NULL;
    char *namearena = NULL, *valarena = NULL;
    if (hn > 0) {
        H = calloc(hn, sizeof(*H));
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
    mq_gw_reject_reason_t pre = mq_gw_client_prevalidate(a->core, H, hn, &status);
    if (pre != MQ_GW_OK) {
        gw_reject_write(handle, status, gw_status_phrase(status), mq_gw_reject_xmq(pre));
        free(H);
        free(namearena);
        free(valarena);
        return -1;
    }

    /* Fetch envelope (fetch-specific): X-Mq-Target. */
    size_t tgt_vl = 0;
    const char *tgt = find_hdr_local(req, "x-mq-target", &tgt_vl);
    mq_gw_target_t target;
    if (!tgt || mq_gw_parse_target(tgt, tgt_vl, &target) != 0) {
        gw_reject_write(handle, 400, "Bad Request", "bad-target");
        free(H);
        free(namearena);
        free(valarena);
        return -1;
    }

    /* X-Mq-Method if present; default GET. */
    char method[16];
    size_t mth_vl = 0;
    const char *mth = find_hdr_local(req, "x-mq-method", &mth_vl);
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

    /* Allocate the per-request adapter state BEFORE req_begin so we have a live
     * ar to pass as sink_user. */
    adapter_req_t *ar = calloc(1, sizeof(*ar));
    if (!ar) {
        free(H);
        free(namearena);
        free(valarena);
        gw_reject_write(handle, 502, "Bad Gateway", "internal-error");
        return -1;
    }
    ar->handle = handle;

    /* Phase 2 (core): origin-proto / cache / header-size / tunnel + open+forward. */
    mq_gw_req_head_t head;
    head.method = method;
    head.scheme = target.scheme;
    head.authority = target.authority;
    head.path = target.path;
    head.headers = H;
    head.n_headers = hn;
    head.content_length = req->content_length;

    int err_status = 0;
    mq_gw_reject_reason_t reason = MQ_GW_OK;
    mq_gw_xreq_t *r =
        mq_gw_client_req_begin(a->core, &head, &g_h1_sink, ar, &err_status, &reason);

    free(H);
    free(namearena);
    free(valarena);

    if (!r) {
        free(ar);
        gw_reject_write(handle, err_status, gw_status_phrase(err_status),
                        mq_gw_reject_xmq(reason));
        return -1;
    }

    ar->core = r;
    *req_ctx = ar;
    return 0;
}

static int
adp_on_body(void *req_ctx, const uint8_t *p, size_t len)
{
    adapter_req_t *ar = (adapter_req_t *)req_ctx;
    return mq_gw_client_req_body(ar->core, p, len);
}

static void
adp_on_body_done(void *req_ctx)
{
    adapter_req_t *ar = (adapter_req_t *)req_ctx;
    mq_gw_client_req_body_done(ar->core);
    /* ar is freed when the core calls adp_resp_finish or adp_resp_abort (paths A
     * above). Do NOT free ar here — the response is still in progress. */
}

static void
adp_on_aborted(void *req_ctx)
{
    adapter_req_t *ar = (adapter_req_t *)req_ctx;
    /* The listener handle is being torn down — null it so no sink op ever touches
     * it. Do this BEFORE calling req_aborted so even a synchronous internal abort
     * notification (if any) sees handle=NULL. */
    ar->handle = NULL;
    /* mq_gw_client_req_aborted nulls r->sink / r->sink_user WITHOUT calling any
     * sink op, then tears down the H3 side and eventually frees r. ar will NOT be
     * freed by any sink callback (path B above), so we own it here. */
    mq_gw_client_req_aborted(ar->core);
    free(ar);
}

static const mq_fetch_cbs_t g_adp_cbs = {
    .on_request = adp_on_request,
    .on_body = adp_on_body,
    .on_body_done = adp_on_body_done,
    .on_aborted = adp_on_aborted,
};

/* ── public API ─────────────────────────────────────────────────────────────*/

mq_gw_fetch_adapter_t *
mq_gw_fetch_adapter_new(mq_gw_client_t *core)
{
    if (!core) return NULL;
    mq_gw_fetch_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->core = core;
    return a;
}

const mq_fetch_cbs_t *
mq_gw_fetch_adapter_cbs(mq_gw_fetch_adapter_t *a)
{
    (void)a;
    return &g_adp_cbs;
}

void *
mq_gw_fetch_adapter_user(mq_gw_fetch_adapter_t *a)
{
    return a;
}

void
mq_gw_fetch_adapter_free(mq_gw_fetch_adapter_t *a)
{
    free(a);
}
