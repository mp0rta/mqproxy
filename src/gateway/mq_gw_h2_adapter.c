// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_gw_h2_adapter.c — HTTP/2 (nghttp2) server adapter over the neutral
 * mq_gw_client intake boundary. See mq_gw_h2_adapter.h.
 *
 * SKELETON SCOPE (Task 5): create the nghttp2 SERVER session, submit the §5.2
 * SETTINGS, and plumb recv / want_write to the byte transport. No request
 * demux, header policy, response path or body handling yet (Tasks 6/7/8).
 *
 * The production wrapper mq_gw_h2_submit_ops_gwc() is NOT defined here — it is
 * built in Task 11 (its first live use), because it needs mq_gw_client_token()
 * which Task 6 adds. Declaring it in the header keeps the API complete without a
 * forward reference to a not-yet-existing symbol. */
#include "gateway/mq_gw_h2_adapter.h"

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── §5.2 resource limits (NORMATIVE) ──────────────────────────────────────── */

/* Cap concurrent streams to bound per-connection state / stream-flood DoS. */
#define MQ_H2_MAX_CONCURRENT_STREAMS 128
/* HTTP/2 default frame size; do NOT advertise larger (smaller read amplification
 * surface). 16384 = the protocol minimum/default. */
#define MQ_H2_MAX_FRAME_SIZE 16384
/* Bound the HPACK dynamic table (4 KiB) so a decoder-state-bloat attack is
 * capped. */
#define MQ_H2_HEADER_TABLE_SIZE 4096
/* Cumulative (name+value+per-field-overhead) cap for a single inbound header
 * block (16 KiB), advertised as SETTINGS_MAX_HEADER_LIST_SIZE.
 *
 * This SETTINGS entry is a COOPERATIVE HINT to the peer only: nghttp2 1.59.0
 * does NOT auto-enforce it on inbound header blocks (the recv/HPACK-inflate path
 * never compares decoded header-list size against local_settings; the inflater
 * caps only the HPACK dynamic table). The symbol that would enforce it,
 * nghttp2_option_set_max_header_list_size, is absent from 1.59.0.
 *
 * Therefore inbound header-bomb rejection is NOT provided by advertising this
 * setting — it must be enforced by application-side cumulative header-size
 * accounting in the on_header callback. That accounting is added in Task 6. */
#define MQ_H2_MAX_HEADER_LIST_SIZE 16384

/* Per RFC 7540 §6.5.2 each header field costs name_len + value_len + 32 toward
 * the header-list size. We enforce the SAME cap we advertise. */
#define MQ_H2_FIELD_OVERHEAD 32

/* Max regular (non-pseudo, non-x-mq-) headers we forward, PLUS the two injected
 * controls (x-mq-auth, x-mq-forward-cookie). A header block whose cumulative
 * size stays <= 16 KiB cannot hold an unbounded count of fields (each costs >=
 * 32 bytes), so this comfortably covers any block that survives the size cap. */
#define MQ_H2_MAX_REQ_HDRS 256

/* ── adapter struct ─────────────────────────────────────────────────────────── */

struct mq_h2_stream_s; /* fwd */

struct mq_gw_h2_adapter {
    nghttp2_session *session; /* server session */

    /* Submission boundary (BORROWED). Stored for Tasks 6/7/8; unused by the
     * skeleton beyond holding the references. */
    const mq_gw_submit_ops_t *submit;
    void *submit_user;

    /* Plaintext writer (BORROWED). */
    ssize_t (*send_cb)(void *io, const uint8_t *p, size_t n);
    void *io;

    /* Intrusive list of LIVE per-stream contexts. nghttp2_session_del does NOT
     * invoke on_stream_close for streams still open at teardown, so the adapter
     * tracks them and frees any survivors in mq_gw_h2_adapter_free. */
    struct mq_h2_stream_s *streams;
};

/* ── per-stream demux context (Task 6) ──────────────────────────────────────
 *
 * Created in on_begin_headers, attached as the nghttp2 stream user-data,
 * populated header-by-header in on_header, materialized in on_frame_recv
 * (END_HEADERS), and freed in on_stream_close.
 *
 * SECURITY (untrusted browser input):
 *   - All name/value bytes are COPIED out of nghttp2's transient buffers into
 *     `arena` as NUL-terminated C strings. The boundary uses strlen/strncmp, so
 *     a slice carrying an embedded NUL is REJECTED (codex H1) — never truncated.
 *   - The cumulative header-list size (RFC 7540 §6.5.2: name+value+32 per field)
 *     is accumulated across the whole block; exceeding MQ_H2_MAX_HEADER_LIST_SIZE
 *     trips `rejected` and RSTs the stream BEFORE materialization (inbound
 *     header-bomb defense — nghttp2 1.59.0 does NOT auto-enforce the advertised
 *     SETTINGS_MAX_HEADER_LIST_SIZE; see the #define above). `arena` is sized to
 *     that same cap, so the bomb defense also caps arena growth.
 *   - §4.5 header policy: EVERY browser-supplied x-mq-* header is dropped
 *     (total/unconditional) in on_header BEFORE the two controls are injected at
 *     materialization, so a page cannot smuggle a control.
 */
typedef struct mq_h2_stream_s {
    mq_gw_h2_adapter_t *a;
    struct mq_h2_stream_s *next; /* adapter->streams intrusive list */

    /* Bump arena for NUL-terminated header-string copies. Bounded by the
     * header-list cap so the header-bomb defense also caps memory. */
    char arena[MQ_H2_MAX_HEADER_LIST_SIZE];
    size_t arena_off;

    /* Pseudo-headers (point into arena once set). */
    const char *method, *scheme, *authority, *path;

    /* Regular (non-pseudo, non-x-mq-) browser headers, copies into arena. */
    mq_h3_header_t hdrs[MQ_H2_MAX_REQ_HDRS];
    size_t n_hdrs;

    /* Cumulative inbound header-list size accounting (RFC 7540 §6.5.2). */
    size_t hdr_list_size;

    int rejected; /* a fatal per-stream condition (RST on END_HEADERS / set now) */

    /* The core handle once req_begin succeeds; NULL until then / on reject. */
    mq_gw_xreq_t *xreq;

    int32_t stream_id;
    int materialized; /* req_begin already driven (guards re-entry) */
} mq_h2_stream_t;

/* Copy a (ptr,len) slice into the stream arena as a NUL-terminated string.
 * REJECTS an embedded NUL (codex H1): the boundary measures with strlen, so a
 * truncated-at-NUL value would smuggle/lose bytes. Returns the arena pointer, or
 * NULL on overflow / embedded NUL (caller sets `rejected`). */
static const char *
arena_dup(mq_h2_stream_t *s, const uint8_t *p, size_t len)
{
    if (s->arena_off + len + 1 > sizeof(s->arena)) return NULL; /* bomb cap */
    for (size_t i = 0; i < len; i++) {
        if (p[i] == '\0') return NULL; /* embedded NUL — reject, never truncate */
    }
    char *dst = s->arena + s->arena_off;
    memcpy(dst, p, len);
    dst[len] = '\0';
    s->arena_off += len + 1;
    return dst;
}

/* Case-insensitive ASCII prefix test: does `name` (len nl) start with "x-mq-"? */
static int
name_has_xmq_prefix(const uint8_t *name, size_t nl)
{
    static const char pfx[] = {'x', '-', 'm', 'q', '-'};
    if (nl < sizeof(pfx)) return 0;
    for (size_t i = 0; i < sizeof(pfx); i++) {
        unsigned char c = name[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        if (c != (unsigned char)pfx[i]) return 0;
    }
    return 1;
}

/* ── demux callbacks (Task 6) ───────────────────────────────────────────────*/

/* Drive a per-stream RST (TEMPORAL_CALLBACK_FAILURE semantics) and mark the
 * stream rejected. Used for the header-bomb / NUL / malformed cases. We submit
 * an explicit RST_STREAM so the chosen error code reaches the peer, then signal
 * the on_header / mem_recv path to stop processing this stream.
 *
 * NOTE for Task 8: the full X-Mq-Error error-RESPONSE rendering (an H2 response
 * with a body) for reject *reasons* is finalized via a shared helper there. For
 * the cases handled HERE (header-bomb / embedded-NUL / missing pseudo-header) we
 * cannot reliably send a response body mid-header-block, so RST_STREAM is the
 * correct, spec-clean signal (consistent with MQ_GW_REJ_HEADER_TOO_LONG intent).
 */
static void
stream_reject(mq_h2_stream_t *s, uint32_t error_code)
{
    if (s->rejected) return;
    s->rejected = 1;
    nghttp2_submit_rst_stream(s->a->session, NGHTTP2_FLAG_NONE, s->stream_id, error_code);
}

static int
on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    mq_gw_h2_adapter_t *a = (mq_gw_h2_adapter_t *)user_data;

    /* Only request HEADERS open a stream context. */
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }

    mq_h2_stream_t *s = calloc(1, sizeof(*s));
    if (!s) return NGHTTP2_ERR_CALLBACK_FAILURE; /* OOM → tear the connection down */
    s->a = a;
    s->stream_id = frame->hd.stream_id;

    if (nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, s) != 0) {
        free(s);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    s->next = a->streams;
    a->streams = s;
    return 0;
}

/* Unlink a stream context from the adapter's live list. */
static void
stream_unlink(mq_gw_h2_adapter_t *a, mq_h2_stream_t *s)
{
    mq_h2_stream_t **pp = &a->streams;
    while (*pp) {
        if (*pp == s) {
            *pp = s->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

static int
on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
          size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
          void *user_data)
{
    (void)flags;
    (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    mq_h2_stream_t *s = (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!s) return 0;          /* no context (e.g. already torn down) — ignore */
    if (s->rejected) return 0; /* already RST'd this stream — drop remaining fields */

    /* Inbound header-bomb accounting (RFC 7540 §6.5.2): name+value+32 per field,
     * accumulated across the WHOLE block. nghttp2 1.59.0 does not enforce the
     * advertised SETTINGS_MAX_HEADER_LIST_SIZE on inbound blocks, so we do it
     * here and RST before the block can grow memory unbounded. */
    s->hdr_list_size += namelen + valuelen + MQ_H2_FIELD_OVERHEAD;
    if (s->hdr_list_size > MQ_H2_MAX_HEADER_LIST_SIZE) {
        stream_reject(s, NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }

    /* §4.5 step 1: drop EVERY browser-supplied x-mq-* header, total and
     * unconditional. Skip BEFORE copying so the page cannot smuggle a control or
     * inflate the arena with controls we ignore. (Pseudo-headers start with ':'
     * and never match this prefix.) */
    if (name_has_xmq_prefix(name, namelen)) return 0;

    /* Copy NAME + VALUE into the arena as NUL-terminated strings, rejecting any
     * embedded NUL (codex H1). */
    const char *cn = arena_dup(s, name, namelen);
    if (!cn) {
        stream_reject(s, NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }
    const char *cv = arena_dup(s, value, valuelen);
    if (!cv) {
        stream_reject(s, NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }

    /* Pseudo-headers → request head. nghttp2 already validated that pseudo-headers
     * precede regular ones and are known request pseudos; we map the four we use
     * and ignore any others (none expected for a request). */
    if (namelen > 0 && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0)
            s->method = cv;
        else if (namelen == 7 && memcmp(name, ":scheme", 7) == 0)
            s->scheme = cv;
        else if (namelen == 10 && memcmp(name, ":authority", 10) == 0)
            s->authority = cv;
        else if (namelen == 5 && memcmp(name, ":path", 5) == 0)
            s->path = cv;
        /* else: unknown pseudo — copied but not referenced (dropped). */
        return 0;
    }

    /* Regular browser header — forward (§4.5 step 2). */
    if (s->n_hdrs >= MQ_H2_MAX_REQ_HDRS) {
        /* Unreachable under the 16 KiB cap (each field costs >= 32 bytes), but
         * fail closed rather than overflow. */
        stream_reject(s, NGHTTP2_ENHANCE_YOUR_CALM);
        return 0;
    }
    s->hdrs[s->n_hdrs].name = cn;
    s->hdrs[s->n_hdrs].value = cv;
    s->n_hdrs++;
    return 0;
}

/* Build the FINAL header list (forwarded browser headers + the two injected
 * controls) and drive the boundary: prevalidate → req_begin. Stores the returned
 * xreq on the stream. On any reject the stream is RST (full X-Mq-Error response
 * rendering is Task 8). */
static void
materialize_request(mq_h2_stream_t *s)
{
    mq_gw_h2_adapter_t *a = s->a;

    if (s->materialized) return;
    s->materialized = 1;

    /* A required pseudo-header missing → malformed request. */
    if (!s->method || !*s->method || !s->scheme || !*s->scheme || !s->authority ||
        !*s->authority || !s->path || !*s->path) {
        stream_reject(s, NGHTTP2_PROTOCOL_ERROR);
        return;
    }

    /* §4.5 step 3: inject EXACTLY two controls AFTER the strip. Build the final
     * array = forwarded browser headers + x-mq-auth + x-mq-forward-cookie. */
    mq_h3_header_t final[MQ_H2_MAX_REQ_HDRS + 2];
    size_t nf = 0;
    for (size_t i = 0; i < s->n_hdrs; i++)
        final[nf++] = s->hdrs[i];

    /* x-mq-auth: "Bearer " + raw token. Strip an existing "Bearer " on the token
     * to avoid doubling (codex H3); mq_gw_client_prevalidate REQUIRES the prefix.
     * The token storage must outlive req_begin — stash the formatted value in the
     * stream arena. */
    const char *raw = a->submit->auth_token ? a->submit->auth_token(a->submit_user) : "";
    if (!raw) raw = "";
    {
        static const char bearer[] = "Bearer ";
        const size_t bl = sizeof(bearer) - 1; /* 7 */
        /* Strip a leading case-sensitive "Bearer " (the boundary re-adds exactly
         * one; doubling would corrupt the secret). */
        if (strncmp(raw, bearer, bl) == 0) raw += bl;
        size_t rl = strlen(raw);
        if (s->arena_off + bl + rl + 1 > sizeof(s->arena)) {
            stream_reject(s, NGHTTP2_ENHANCE_YOUR_CALM);
            return;
        }
        char *vb = s->arena + s->arena_off;
        memcpy(vb, bearer, bl);
        memcpy(vb + bl, raw, rl);
        vb[bl + rl] = '\0';
        s->arena_off += bl + rl + 1;
        final[nf].name = "x-mq-auth";
        final[nf].value = vb;
        nf++;
    }
    /* x-mq-forward-cookie: true (single cookie-forward mechanism; req_begin has no
     * forward_cookie param). */
    final[nf].name = "x-mq-forward-cookie";
    final[nf].value = "true";
    nf++;

    /* prevalidate on the FINAL head: dup-control + auth format. Because the strip
     * is total, only the injected x-mq-auth exists → no dup; "Bearer <token>"
     * passes the format check. */
    int status = 0;
    mq_gw_reject_reason_t reason =
        a->submit->prevalidate(a->submit_user, final, nf, &status);
    if (reason != MQ_GW_OK) {
        stream_reject(s, NGHTTP2_INTERNAL_ERROR); /* Task 8: render X-Mq-Error body */
        return;
    }

    mq_gw_req_head_t head = {0};
    head.method = s->method;
    head.scheme = s->scheme;
    head.authority = s->authority;
    head.path = s->path;
    head.headers = final;
    head.n_headers = nf;
    head.content_length = -1; /* body framing is Task 7; head-only for now */

    /* h2_sink is implemented in Task 7; pass NULL here. CAUTION for Task 7: the
     * production boundary (mq_gw_client_req_begin) stores this sink and later
     * dereferences sink->resp_head on the response, so a NULL sink would crash
     * live. It is safe ONLY because the current tests bind a stub req_begin that
     * never drives a response, and the production submit vtable
     * (mq_gw_h2_submit_ops_gwc) is not built until Task 11. Task 7 MUST replace
     * this NULL with a real per-stream sink + sink_user BEFORE any live wiring. */
    int err_status = 0;
    reason = MQ_GW_OK;
    mq_gw_xreq_t *xreq =
        a->submit->req_begin(a->submit_user, &head, NULL, NULL, &err_status, &reason);
    if (!xreq) {
        stream_reject(s, NGHTTP2_INTERNAL_ERROR); /* Task 8: render X-Mq-Error body */
        return;
    }
    s->xreq = xreq;
    /* nghttp2 stream user-data already points at `s`; the core handle rides on
     * it (s->xreq). Task 7 wires the response sink to find s (and s->xreq). */
}

static int
on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    if (!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) return 0;

    mq_h2_stream_t *s = (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!s) return 0;
    if (s->rejected) return 0; /* already RST'd (bomb / NUL) — do not materialize */

    materialize_request(s);
    return 0;
}

static int
on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                void *user_data)
{
    (void)error_code;
    (void)user_data;
    mq_h2_stream_t *s =
        (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(session, stream_id);
    if (!s) return 0;
    /* If a request was begun, tell the core the local side is gone (Task 7 owns
     * the full upload/response lifecycle; header-only requests just abort). */
    if (s->xreq && s->a->submit->req_aborted) s->a->submit->req_aborted(s->xreq);
    nghttp2_session_set_stream_user_data(session, stream_id, NULL);
    stream_unlink(s->a, s);
    free(s);
    return 0;
}

/* ── public API ────────────────────────────────────────────────────────────── */

mq_gw_h2_adapter_t *
mq_gw_h2_adapter_new(const mq_gw_submit_ops_t *submit, void *submit_user,
                     ssize_t (*send_cb)(void *io, const uint8_t *p, size_t n), void *io)
{
    if (!submit || !send_cb) return NULL;

    mq_gw_h2_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->submit = submit;
    a->submit_user = submit_user;
    a->send_cb = send_cb;
    a->io = io;

    /* Session callbacks. Task 6 registers the request-demux callbacks
     * (on_begin_headers / on_header / on_frame_recv / on_stream_close); the body
     * (on_data_chunk) + response path are Tasks 7/8. */
    nghttp2_session_callbacks *cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        free(a);
        return NULL;
    }
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);

    int rc = nghttp2_session_server_new(&a->session, cbs, a);
    nghttp2_session_callbacks_del(cbs);
    if (rc != 0) {
        free(a);
        return NULL;
    }

    /* Submit the §5.2 SETTINGS. MAX_FRAME_SIZE is the default; advertising it
     * explicitly documents intent and locks the value. MAX_HEADER_LIST_SIZE is
     * the header-bomb guard (see the #define). */
    const nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MQ_H2_MAX_CONCURRENT_STREAMS},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, MQ_H2_MAX_FRAME_SIZE},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, MQ_H2_HEADER_TABLE_SIZE},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, MQ_H2_MAX_HEADER_LIST_SIZE},
    };
    if (nghttp2_submit_settings(a->session, NGHTTP2_FLAG_NONE, iv,
                                sizeof(iv) / sizeof(iv[0])) != 0) {
        nghttp2_session_del(a->session);
        free(a);
        return NULL;
    }

    return a;
}

int
mq_gw_h2_adapter_recv(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t n)
{
    if (!a) return -1;
    ssize_t r = nghttp2_session_mem_recv(a->session, p, n);
    if (r < 0) return -1;
    /* nghttp2 consumes the whole buffer or signals a fatal error; a partial
     * positive return is not expected from mem_recv, but treat any shortfall as
     * fatal to be safe. */
    if ((size_t)r != n) return -1;
    return 0;
}

int
mq_gw_h2_adapter_want_write(mq_gw_h2_adapter_t *a)
{
    if (!a) return -1;
    for (;;) {
        const uint8_t *data = NULL;
        ssize_t n = nghttp2_session_mem_send(a->session, &data);
        if (n < 0) return -1; /* fatal */
        if (n == 0) return 0; /* nothing more to write */
        ssize_t w = a->send_cb(a->io, data, (size_t)n);
        if (w < 0 || (size_t)w != (size_t)n) return -1; /* writer failed/partial */
    }
}

void
mq_gw_h2_adapter_free(mq_gw_h2_adapter_t *a)
{
    if (!a) return;
    /* nghttp2_session_del does NOT fire on_stream_close for streams still open at
     * teardown — free any survivors here (abort their core handle first, mirroring
     * on_stream_close). */
    mq_h2_stream_t *s = a->streams;
    while (s) {
        mq_h2_stream_t *next = s->next;
        if (s->xreq && a->submit->req_aborted) a->submit->req_aborted(s->xreq);
        free(s);
        s = next;
    }
    a->streams = NULL;
    nghttp2_session_del(a->session);
    free(a);
}
