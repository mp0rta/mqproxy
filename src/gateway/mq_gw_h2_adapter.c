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

/* §5.2 per-stream response (download) send-queue cap. The adapter buffers
 * response body bytes the core hands it (resp_body) until nghttp2's data
 * provider drains them onto the wire. Bounding it applies download backpressure:
 * once full, resp_body returns 0 (highwater) and the core stops reading the H3
 * tunnel until the queue drains below the cap, at which point the adapter calls
 * submit->req_drained(xreq) to resume the download pump (rigor IMP-1). 64 KiB is
 * a few nghttp2 max-frame-size (16 KiB) DATA frames in flight — enough to keep
 * the wire busy without unbounded per-stream memory under a stalled client. */
#define MQ_H2_RESP_QUEUE_CAP (64u * 1024u)

/* Max regular response headers we frame back (browser-bound). Same generous
 * bound as the request side; the core's response heads are small. */
#define MQ_H2_MAX_RESP_HDRS 256

/* §5.2 inbound (upload) backpressure buffer cap. When a stream's submit->req_body
 * returns -1 (pause), the adapter STOPS feeding nghttp2 and parks the not-yet-
 * processed input bytes here until the core releases the pause via
 * sink->resume_read. See the UPLOAD BACKPRESSURE block below for the full design;
 * 256 KiB comfortably exceeds the H2 connection flow-control window (nghttp2's
 * default 64 KiB), so under a well-behaved peer the buffer never approaches the
 * cap before HTTP/2 flow control throttles the browser. Overflow (a peer that
 * floods past its window) is a fatal protocol/DoS condition → tear the
 * connection down (return -1 from recv) rather than grow memory unbounded. */
#define MQ_H2_UPLOAD_PAUSE_CAP (256u * 1024u)

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

    /* ── UPLOAD BACKPRESSURE (Task 8) — adapter-level input gate ───────────────
     *
     * DESIGN (approach A: nghttp2 input pause + bounded re-feed buffer):
     *
     * When on_data_chunk_recv hands a chunk to submit->req_body and the core
     * returns -1 (PAUSE — the chunk IS consumed by the core; -1 only means "stop
     * feeding me more", per the mq_gw_intake.h req_body contract), the callback
     * returns NGHTTP2_ERR_PAUSE. nghttp2_session_mem_recv then stops and returns
     * the byte count it consumed SO FAR (a positive value that may be < n). The
     * unconsumed tail [r, n) is NOT lost: mq_gw_h2_adapter_recv parks it in
     * `pending_in` and sets `input_paused`. While paused, recv parks any further
     * input into the same bounded buffer (and does NOT feed nghttp2 — so nghttp2
     * sends no WINDOW_UPDATE and the browser is throttled by H2 flow control).
     *
     * sink->resume_read clears `input_paused` and RE-FEEDS the parked bytes
     * through nghttp2_session_mem_recv (which re-drives on_data_chunk_recv for the
     * buffered DATA), looping until the buffer drains or it pauses again.
     *
     * INVARIANT: no upload body byte is ever lost (every byte either reaches
     * req_body or sits in pending_in awaiting re-feed), and a stalled tunnel
     * (req_body=-1) throttles the browser without unbounded growth (the buffer is
     * bounded by MQ_H2_UPLOAD_PAUSE_CAP; H2 flow control keeps a well-behaved peer
     * far below it).
     *
     * NOTE: nghttp2_session_resume_data() is the OUTBOUND deferred-data-provider
     * resume; it is NOT used for inbound upload resume (re-feed is the correct
     * mechanism). The pause is connection-wide (one in-flight request per MITM
     * conn per the deployment model), which is simpler and sufficient. */
    uint8_t pending_in[MQ_H2_UPLOAD_PAUSE_CAP];
    size_t pending_len;
    int input_paused; /* a req_body returned -1; do not feed nghttp2 until resumed */
    int input_fatal;  /* pending_in overflowed (peer flooded past its window) */
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
    int upload_done;  /* req_body_done already fired (END_STREAM seen; guards re-entry) */

    /* ── response (download) path (Task 7) ──────────────────────────────────
     *
     * Per-stream FIFO ring of response body bytes the core handed us via
     * resp_body but nghttp2's data provider has not yet drained onto the wire.
     * resp_head submits the response with a data provider that pulls from here;
     * resp_finish sets resp_eof so the provider emits END_STREAM once drained.
     *
     * Backpressure (rigor IMP-1): resp_body returns 0 (highwater) at the cap and
     * sets sq_deferred; once want_write drains the ring below the cap we call
     * submit->req_drained(xreq) exactly once per highwater episode to resume the
     * core's download pump. */
    uint8_t sendq[MQ_H2_RESP_QUEUE_CAP];
    size_t sq_head;   /* index of the oldest queued byte */
    size_t sq_len;    /* bytes currently queued */
    int resp_started; /* resp_head submitted (data provider installed) */
    int resp_eof;     /* resp_finish seen → provider emits END_STREAM when drained */
    int sq_deferred;  /* resp_body hit highwater; owe a req_drained on drain */
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

/* fwd (defined in the recv section) — used by the resume_read re-feed loop. */
static int park_pending(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t len);

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

/* Render an H2 ERROR RESPONSE for a reject *reason* known after END_HEADERS
 * (prevalidate / req_begin verdicts). Unlike stream_reject (a bare RST used for
 * mid-header-block failures where no response can be framed), this submits a
 * complete header-only response: :status + x-mq-error: <reason text> with
 * END_STREAM, so the browser sees the same diagnostic the H1 fetch adapter
 * renders (§5/§5.2; strings byte-identical via the shared mq_gw_reject_xmq). The
 * stream is then marked rejected so no further demux/body touches it.
 *
 * `status` is the verdict's HTTP status (the boundary fills it; 0 → default 400
 * for the 4xx reasons / nothing reasonable, so we floor to 400). */
static void
stream_reject_response(mq_h2_stream_t *s, int status, mq_gw_reject_reason_t reason)
{
    if (s->rejected) return;
    s->rejected = 1;

    if (status < 100 || status > 999) status = 400; /* defensive floor */
    char status_str[4];
    status_str[0] = (char)('0' + (status / 100) % 10);
    status_str[1] = (char)('0' + (status / 10) % 10);
    status_str[2] = (char)('0' + status % 10);
    status_str[3] = '\0';

    const char *xmq = mq_gw_reject_xmq(reason); /* shared, byte-identical literal */

    nghttp2_nv nva[2];
    nva[0].name = (uint8_t *)":status";
    nva[0].namelen = 7;
    nva[0].value = (uint8_t *)status_str;
    nva[0].valuelen = 3;
    nva[0].flags = NGHTTP2_NV_FLAG_NONE;
    nva[1].name = (uint8_t *)"x-mq-error";
    nva[1].namelen = 10;
    nva[1].value = (uint8_t *)xmq;
    nva[1].valuelen = strlen(xmq);
    nva[1].flags = NGHTTP2_NV_FLAG_NONE;

    /* No data provider → nghttp2 sets END_STREAM on the HEADERS frame. If submit
     * fails (OOM), fall back to a RST so the browser still sees a clean failure. */
    if (nghttp2_submit_response(s->a->session, s->stream_id, nva, 2, NULL) != 0)
        nghttp2_submit_rst_stream(s->a->session, NGHTTP2_FLAG_NONE, s->stream_id,
                                  NGHTTP2_INTERNAL_ERROR);
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

/* ── response path: sink ops → H2 HEADERS/DATA + download backpressure (Task 7) ─
 *
 * The core (production: mq_gw_client via the Task 11 submit wrapper; tests: the
 * stub acting as the core) drives these to deliver the H3 response back out as
 * H2. sink_user is the per-stream context (mq_h2_stream_t) set at req_begin. */

/* Dequeue up to `cap` bytes from the stream's response FIFO into `dst`. Returns
 * the count copied. Handles the ring wrap. */
static size_t
sendq_pop(mq_h2_stream_t *s, uint8_t *dst, size_t cap)
{
    size_t n = s->sq_len < cap ? s->sq_len : cap;
    if (n == 0) return 0;
    size_t first = MQ_H2_RESP_QUEUE_CAP - s->sq_head; /* until the ring wraps */
    if (first > n) first = n;
    memcpy(dst, s->sendq + s->sq_head, first);
    if (n > first) memcpy(dst + first, s->sendq, n - first); /* wrapped tail */
    s->sq_head = (s->sq_head + n) % MQ_H2_RESP_QUEUE_CAP;
    s->sq_len -= n;
    return n;
}

/* nghttp2 data provider: pull response body bytes from the per-stream FIFO.
 * Empty + not finished → DEFER (resumed via nghttp2_session_resume_data in
 * resp_body / on drain). Empty + finished → EOF (nghttp2 sets END_STREAM since
 * we send no trailers). */
static ssize_t
resp_data_read(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
               uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    (void)session;
    (void)stream_id;
    (void)user_data;
    mq_h2_stream_t *s = (mq_h2_stream_t *)source->ptr;

    size_t n = sendq_pop(s, buf, length);
    if (n == 0) {
        if (s->resp_eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF; /* → END_STREAM (no trailers) */
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED; /* nothing queued yet; resume on next enqueue */
    }
    /* If the whole tail is queued AND the core signalled EOF, mark END_STREAM on
     * this final non-empty frame to avoid an extra empty DATA frame. */
    if (s->resp_eof && s->sq_len == 0) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

/* sink->resp_head: submit the response HEADERS with a data provider that pulls
 * the body from the per-stream FIFO. body_mode is advisory for H2 (nghttp2 owns
 * DATA framing); the core's head already carries any Content-Length it wants
 * forwarded, so we just render :status + the supplied headers. Returns 1 on
 * success, -1 on a hard failure (the core maps -1 → abort). */
static int
mq_h2_resp_head(void *u, int status, const mq_h3_header_t *hs, size_t n,
                mq_gw_body_mode_t body_mode)
{
    (void)body_mode;
    mq_h2_stream_t *s = (mq_h2_stream_t *)u;
    if (!s || s->rejected) return -1;
    if (n > MQ_H2_MAX_RESP_HDRS) return -1;

    /* :status as a string (3 ASCII digits for any HTTP status). */
    char status_str[4];
    if (status < 100 || status > 999) return -1;
    status_str[0] = (char)('0' + (status / 100) % 10);
    status_str[1] = (char)('0' + (status / 10) % 10);
    status_str[2] = (char)('0' + status % 10);
    status_str[3] = '\0';

    nghttp2_nv nva[MQ_H2_MAX_RESP_HDRS + 1];
    size_t nv = 0;
    nva[nv].name = (uint8_t *)":status";
    nva[nv].namelen = 7;
    nva[nv].value = (uint8_t *)status_str;
    nva[nv].valuelen = 3;
    nva[nv].flags = NGHTTP2_NV_FLAG_NONE;
    nv++;
    for (size_t i = 0; i < n; i++) {
        nva[nv].name = (uint8_t *)hs[i].name;
        nva[nv].namelen = strlen(hs[i].name);
        nva[nv].value = (uint8_t *)hs[i].value;
        nva[nv].valuelen = strlen(hs[i].value);
        nva[nv].flags = NGHTTP2_NV_FLAG_NONE;
        nv++;
    }

    nghttp2_data_provider prd;
    prd.source.ptr = s;
    prd.read_callback = resp_data_read;

    if (nghttp2_submit_response(s->a->session, s->stream_id, nva, nv, &prd) != 0)
        return -1;
    s->resp_started = 1;
    return 1;
}

/* sink->resp_body: enqueue body bytes into the per-stream FIFO and resume the
 * data provider. Contract (mq_gw_intake.h): >0 accepted byte count / 0 highwater
 * (queue at cap; NOT enqueued — the core retries after req_drained) / -1 dead.
 * Returns the FULL accepted count on the accept path so the core does not
 * spuriously set read_deferred. */
static int
mq_h2_resp_body(void *u, const uint8_t *p, size_t len)
{
    mq_h2_stream_t *s = (mq_h2_stream_t *)u;
    if (!s || s->rejected) return -1;
    if (len == 0) return 0; /* nothing to do; treat as a no-op accept */

    /* WHOLE-CHUNK-OR-HIGHWATER (NOT partial). The intake.h contract says ">0
     * accept / 0 highwater", but the production consumer (mq_gw_client.c
     * download_pump) treats ANY wr > 0 as full-chunk acceptance — it does NOT
     * compare the return against the chunk length, so a partial accept (0 < wr <
     * len) would silently DROP the unaccepted tail. The core's chunk is bounded
     * (MQ_GW_DOWNLOAD_CHUNK = 16 KiB) and our cap is 64 KiB, so refusing a chunk
     * that does not fit entirely is safe and lossless: the core defers it and
     * retries the WHOLE chunk after req_drained. */
    size_t room = MQ_H2_RESP_QUEUE_CAP - s->sq_len;
    if (len > room) {
        /* Won't fit in one piece → highwater. Do NOT enqueue any of it. Owe a
         * req_drained once the FIFO drains below the cap. */
        s->sq_deferred = 1;
        return 0;
    }
    size_t tail = (s->sq_head + s->sq_len) % MQ_H2_RESP_QUEUE_CAP;
    size_t first = MQ_H2_RESP_QUEUE_CAP - tail; /* until the ring wraps */
    if (first > len) first = len;
    memcpy(s->sendq + tail, p, first);
    if (len > first) memcpy(s->sendq, p + first, len - first); /* wrap */
    s->sq_len += len;

    /* Re-arm the (possibly deferred) data provider so the new bytes flush. */
    nghttp2_session_resume_data(s->a->session, s->stream_id);
    return (int)len;
}

/* sink->resp_finish: mark EOF. MUST tolerate being called while the send buffer
 * is still draining (codex M-1: the core's download_pump falls through to finish
 * when fin coincides with a highwater chunk). We do NOT assert an empty queue —
 * the EOF flag rides independently and resp_data_read emits END_STREAM once the
 * FIFO drains. */
static void
mq_h2_resp_finish(void *u)
{
    mq_h2_stream_t *s = (mq_h2_stream_t *)u;
    if (!s || s->rejected) return;
    s->resp_eof = 1;
    /* Resume in case the provider had deferred on an empty queue: now it can emit
     * the (possibly empty) END_STREAM DATA frame. */
    if (s->resp_started) nghttp2_session_resume_data(s->a->session, s->stream_id);
}

/* sink->resp_abort: mid-stream failure → RST_STREAM (never a fake clean finish).
 * If the response had not started we still RST: the browser sees a reset, which
 * is the correct signal for an aborted/truncated response. */
static void
mq_h2_resp_abort(void *u)
{
    mq_h2_stream_t *s = (mq_h2_stream_t *)u;
    if (!s) return;
    if (!s->rejected) {
        s->rejected = 1;
        nghttp2_submit_rst_stream(s->a->session, NGHTTP2_FLAG_NONE, s->stream_id,
                                  NGHTTP2_INTERNAL_ERROR);
    }
}

/* sink->resume_read: UPLOAD backpressure release (browser→origin). The core has
 * room again; clear the pause and re-feed the parked input bytes through nghttp2
 * (which re-drives on_data_chunk_recv → req_body). If req_body pauses again
 * mid-drain, mem_recv stops on the prefix and we re-park the unconsumed tail and
 * stay paused — bytes are never lost or re-delivered. Loops until the buffer
 * drains or the upload re-pauses. */
static void
mq_h2_resume_read(void *u)
{
    mq_h2_stream_t *s = (mq_h2_stream_t *)u;
    if (!s) return;
    mq_gw_h2_adapter_t *a = s->a;
    if (a->input_fatal) return;

    a->input_paused = 0;

    /* Drain the parked buffer. Each pass feeds the whole current buffer; a pause
     * re-arms input_paused and reports a short consume, so we snapshot, clear,
     * feed, then re-park the unconsumed tail (plus anything req_body→recv may
     * have parked re-entrantly — but recv is not called during a feed here). */
    while (a->pending_len > 0 && !a->input_paused && !a->input_fatal) {
        /* Move the parked bytes out so a re-park (on pause) appends cleanly. */
        static uint8_t scratch[MQ_H2_UPLOAD_PAUSE_CAP];
        size_t plen = a->pending_len;
        memcpy(scratch, a->pending_in, plen);
        a->pending_len = 0;

        ssize_t r = nghttp2_session_mem_recv(a->session, scratch, plen);
        if (r < 0) {
            a->input_fatal = 1; /* fatal parse error — surfaced by next recv */
            return;
        }
        if ((size_t)r != plen) {
            /* Paused (or unexpected shortfall) mid-drain: re-park the tail. */
            if (!a->input_paused) {
                a->input_fatal = 1;
                return;
            }
            if (park_pending(a, scratch + (size_t)r, plen - (size_t)r) != 0) return;
        }
    }
}

static const mq_gw_sink_ops_t mq_h2_sink = {
    .resp_head = mq_h2_resp_head,
    .resp_body = mq_h2_resp_body,
    .resp_finish = mq_h2_resp_finish,
    .resp_abort = mq_h2_resp_abort,
    .resume_read = mq_h2_resume_read,
};

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
        stream_reject_response(s, status, reason); /* :status + x-mq-error response */
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

    /* Bind the per-stream response sink (Task 7). The boundary stores `sink` +
     * `sink_user` and later drives resp_head/resp_body/resp_finish/resp_abort on
     * the response; sink_user is THIS per-stream context (s), which carries the
     * nghttp2 stream_id + the response FIFO the sink ops operate on. */
    int err_status = 0;
    reason = MQ_GW_OK;
    mq_gw_xreq_t *xreq =
        a->submit->req_begin(a->submit_user, &head, &mq_h2_sink, s, &err_status, &reason);
    if (!xreq) {
        stream_reject_response(s, err_status, reason); /* :status + x-mq-error response */
        return;
    }
    s->xreq = xreq;
    /* nghttp2 stream user-data already points at `s`; the core handle rides on
     * it (s->xreq). Task 7 wires the response sink to find s (and s->xreq). */
}

/* Signal the core that the upload body is complete (END_STREAM seen). Fired once
 * per stream, only if the request actually materialized (has an xreq). */
static void
finish_upload(mq_h2_stream_t *s)
{
    if (s->upload_done) return;
    s->upload_done = 1;
    if (s->xreq && s->a->submit->req_body_done) s->a->submit->req_body_done(s->xreq);
}

/* on_data_chunk_recv: forward request-body bytes to the core (upload path).
 *
 * Contract (mq_gw_intake.h req_body): the bytes are ALWAYS consumed by the core;
 * 0 = accepted (keep reading), -1 = pause (consumed, but stop feeding more). On
 * -1 we return NGHTTP2_ERR_PAUSE so nghttp2_session_mem_recv stops and reports
 * how much it consumed — the recv wrapper parks the unconsumed tail and the
 * adapter stays paused until sink->resume_read re-feeds it (see the UPLOAD
 * BACKPRESSURE block on the adapter struct). */
static int
on_data_chunk_recv(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                   const uint8_t *data, size_t len, void *user_data)
{
    (void)flags;
    (void)user_data;
    mq_h2_stream_t *s =
        (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(session, stream_id);
    if (!s) return 0;          /* no context — ignore */
    if (s->rejected) return 0; /* stream already RST'd — drop the body */
    if (!s->xreq) return 0;    /* not materialized (e.g. reject pending) — drop */
    if (len == 0) return 0;

    if (s->a->submit->req_body) {
        int rc = s->a->submit->req_body(s->xreq, data, len);
        if (rc < 0) {
            /* PAUSE: the core consumed these bytes but wants no more for now.
             * Stop nghttp2 here; mem_recv returns the consumed prefix and the
             * recv wrapper parks the tail. resume_read re-feeds. */
            s->a->input_paused = 1;
            return NGHTTP2_ERR_PAUSE;
        }
    }
    return 0;
}

static int
on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;

    /* DATA frame with END_STREAM → upload body complete. */
    if (frame->hd.type == NGHTTP2_DATA) {
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            mq_h2_stream_t *s = (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(
                session, frame->hd.stream_id);
            if (s && !s->rejected) finish_upload(s);
        }
        return 0;
    }

    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) return 0;
    if (!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) return 0;

    mq_h2_stream_t *s = (mq_h2_stream_t *)nghttp2_session_get_stream_user_data(
        session, frame->hd.stream_id);
    if (!s) return 0;
    if (s->rejected) return 0; /* already RST'd (bomb / NUL) — do not materialize */

    materialize_request(s);

    /* Body-less request (END_STREAM on HEADERS): the upload is already complete.
     * Fire req_body_done so the core sends fin and proceeds. Only if it actually
     * materialized (materialize_request may have rejected it). */
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) && !s->rejected && s->xreq)
        finish_upload(s);
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
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv);
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

/* Park `len` bytes from `p` into the bounded upload-pause buffer. Returns 0 on
 * success, -1 if it would overflow the cap (fatal — the peer flooded past its H2
 * flow-control window). */
static int
park_pending(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t len)
{
    if (len == 0) return 0;
    if (a->pending_len + len > sizeof(a->pending_in)) {
        a->input_fatal = 1;
        return -1;
    }
    memcpy(a->pending_in + a->pending_len, p, len);
    a->pending_len += len;
    return 0;
}

int
mq_gw_h2_adapter_recv(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t n)
{
    if (!a || a->input_fatal) return -1;

    /* While the upload is paused (a stream's req_body returned -1), do NOT feed
     * nghttp2 — park the new bytes so the browser is throttled by H2 flow control
     * (nghttp2 emits no WINDOW_UPDATE while we hold input). resume_read re-feeds
     * the parked bytes. Bounded: overflow → fatal (see MQ_H2_UPLOAD_PAUSE_CAP). */
    if (a->input_paused) return park_pending(a, p, n) == 0 ? 0 : -1;

    ssize_t r = nghttp2_session_mem_recv(a->session, p, n);
    if (r < 0) return -1;

    /* A short positive return means on_data_chunk_recv returned NGHTTP2_ERR_PAUSE
     * (upload backpressure): nghttp2 consumed [0, r) and stopped. The unconsumed
     * tail [r, n) is NOT lost — park it for re-feed on resume_read. (Absent a
     * pause, mem_recv consumes the whole buffer, so r == n and nothing is
     * parked.) */
    if ((size_t)r != n) {
        if (!a->input_paused) return -1; /* shortfall without a pause → fatal */
        if (park_pending(a, p + (size_t)r, n - (size_t)r) != 0) return -1;
    }
    return 0;
}

/* Drain the nghttp2 send queue fully through send_cb. Returns 0 on success, -1
 * on a fatal/writer error. The data provider (resp_data_read) pops response body
 * bytes from each stream's FIFO during this, so the FIFOs shrink here. */
static int
flush_session(mq_gw_h2_adapter_t *a)
{
    for (;;) {
        const uint8_t *data = NULL;
        ssize_t n = nghttp2_session_mem_send(a->session, &data);
        if (n < 0) return -1; /* fatal */
        if (n == 0) return 0; /* nothing more to write */
        ssize_t w = a->send_cb(a->io, data, (size_t)n);
        if (w < 0 || (size_t)w != (size_t)n) return -1; /* writer failed/partial */
    }
}

int
mq_gw_h2_adapter_want_write(mq_gw_h2_adapter_t *a)
{
    if (!a) return -1;

    /* Outer loop: flush, then resume any download-deferred streams whose FIFO
     * has drained below the cap. req_drained re-pumps the core, which may enqueue
     * more response bytes (resp_body → resume_data) and so can GROW the FIFO; if
     * it did, we flush again. Termination is NOT "the FIFO shrinks each pass":
     * each resumed pass clears at least one sq_deferred flag, and a flag is only
     * re-armed when resp_body hits highwater. Because resp_body appends in 16 KiB
     * chunks against a 64 KiB cap, a single resume admits at most a few chunks
     * before re-deferring, so flags are re-armed strictly slower than they are
     * cleared — a converging process that drains and quiesces. */
    for (;;) {
        if (flush_session(a) != 0) return -1;

        int resumed = 0;
        for (mq_h2_stream_t *s = a->streams; s; s = s->next) {
            /* Resume the core's download pump once our FIFO has room again. A
             * full FIFO (== cap) stays paused; any free byte releases it. */
            if (s->sq_deferred && s->sq_len < MQ_H2_RESP_QUEUE_CAP && s->xreq &&
                !s->rejected && a->submit->req_drained) {
                s->sq_deferred = 0; /* clear BEFORE the callback (it may re-defer) */
                a->submit->req_drained(s->xreq);
                resumed = 1;
            }
        }
        if (!resumed) return 0; /* quiescent: nothing flushed, nothing to resume */
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
