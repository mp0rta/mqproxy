// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_origin_curl.h — the libcurl-multi origin client, integrated into the
 * libevent loop (design §5.3 / §7.4 / §10, Phase 2 Task 4.2).
 *
 * The gateway SERVER (Task 4.3) receives an H3 request, then replays it to the
 * upstream origin through THIS module. One mq_origin_t owns a single
 * curl_multi handle bound to a struct event_base via the standard
 * curl_multi_socket_action ("hiperfifo") pattern:
 *
 *   - CURLMOPT_SOCKETFUNCTION maps curl's per-socket interest (read/write) onto
 *     libevent EV_READ/EV_WRITE events; an event fires →
 *     curl_multi_socket_action(fd) → completions are reaped via
 *     curl_multi_info_read.
 *   - CURLMOPT_TIMERFUNCTION drives a single evtimer; when it expires →
 *     curl_multi_socket_action(CURL_SOCKET_TIMEOUT).
 *
 * Each in-flight request is an mq_origin_req_t carrying a CURL easy handle. The
 * easy handle's CURLOPT_PRIVATE points back at the mq_origin_req_t so a DONE
 * message can be reaped to the right request.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * OWNERSHIP / LIFETIME
 * ─────────────────────────────────────────────────────────────────────────────
 *   - mq_origin_start returns a borrowed pointer. The owner (the gateway server)
 *     stashes its per-request state in `u`. `u` MUST outlive the request.
 *   - Exactly ONE of two terminal events ends a request:
 *       (a) on_done(result, http_ver, u) fires — the request completed (success
 *           or error). This is the LAST callback and the LAST time mqproxy
 *           touches the mq_origin_req_t: it is freed immediately after on_done
 *           returns. The owner frees its own `u` state from inside on_done.
 *       (b) mq_origin_abort(r) — the owner cancels. on_done does NOT fire; the
 *           request is removed from the multi handle and destroyed synchronously.
 *           After abort the pointer is dangling; the owner must not use it.
 *   - mq_origin_free destroys the multi handle and the timer event. The owner
 *     MUST abort or let complete all in-flight requests before freeing the
 *     origin (free does not walk live requests — it asserts none remain in the
 *     sense that the multi handle is torn down; outstanding easy handles would
 *     leak, so the gateway server tracks and aborts them).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * CALLBACK RE-ENTRANCY CONTRACT  (which control ops are legal from inside a cb)
 * ─────────────────────────────────────────────────────────────────────────────
 *   - mq_origin_resume_body / mq_origin_resume_pull: ALWAYS safe from inside any
 *     callback (on_status / on_header / on_body / pull_body / on_done) AND from
 *     outside. They never call curl_easy_pause synchronously — they only set a
 *     flag and arm a 0-delay event, so the actual unpause runs on the next loop
 *     turn, outside every curl callback. (Calling resume from on_done is a no-op
 *     race-loser but harmless: the request is torn down right after on_done.)
 *
 *   - mq_origin_abort: may be called from inside on_status / on_header / on_body
 *     / pull_body — i.e. a SELF-abort of the request whose callback is running.
 *     Curl supports curl_multi_remove_handle from within a transfer callback, and
 *     mq_origin_abort performs exactly that (synchronously freeing the request).
 *     HARD RULE: after a self-abort the callback MUST return IMMEDIATELY and must
 *     NOT touch the request pointer `r` or its owner context `u` again — both are
 *     freed the instant mq_origin_abort returns. (on_body should return the value
 *     it intends; the safest is to abort then `return len` so curl does not also
 *     flag a short write, but since the handle is already removed the return value
 *     is moot.) Do NOT call mq_origin_abort from inside on_done — on_done already
 *     IS the terminal teardown (the request is freed right after it returns); a
 *     second abort would be a double free.
 *
 *   - mq_origin_start: NOT re-entrancy-special, but note it may be called from
 *     inside on_done (e.g. to chain a follow-up request) since the completing
 *     request is fully destroyed before on_done runs.
 */
#ifndef MQ_GATEWAY_MQ_ORIGIN_CURL_H
#define MQ_GATEWAY_MQ_ORIGIN_CURL_H

#include <stddef.h>
#include <stdint.h>

#include "transport/mq_h3.h" /* mq_h3_header_t (reused for request headers) */

struct event_base;

typedef struct mq_origin_s mq_origin_t;
typedef struct mq_origin_req_s mq_origin_req_t;

/* Per-request callbacks. `u` is the owner context passed to mq_origin_start. */
typedef struct {
    /* The final (non-1xx) response header section is complete; http_status is
     * the status code. Fires exactly once per request. 1xx sections (incl. a
     * 100-continue) are skipped entirely and never surface here. */
    void (*on_status)(int http_status, void *u);

    /* One response header (name length nl, value length vl). Name/value are
     * borrowed for the duration of the call. The value is whitespace-trimmed.
     * Fires only for the final header section, after on_status. */
    void (*on_header)(const char *n, size_t nl, const char *v, size_t vl, void *u);

    /* Response body bytes. Returns the number of bytes ACCEPTED by the owner.
     * Returning 0 PAUSES the download (curl stops calling on_body until
     * mq_origin_resume_body). Returning < len without 0 is treated by curl as a
     * short write → request error. The simplest contract: accept all `len`
     * (return len) or accept none (return 0 to pause). */
    long (*on_body)(const uint8_t *p, size_t len, void *u);

    /* Upload source (only used when upload_len >= 0). Fill up to `cap` bytes
     * into buf and return the count: > 0 = that many body bytes, 0 = PAUSE the
     * upload (resume via mq_origin_resume_pull), -1 = end of upload (EOF). */
    long (*pull_body)(uint8_t *buf, size_t cap, void *u);

    /* Terminal callback. curl_result is the CURLE_* code (0 == CURLE_OK).
     * http_ver is the negotiated CURLINFO_HTTP_VERSION value (e.g.
     * CURL_HTTP_VERSION_1_1). ssl_verify is CURLINFO_SSL_VERIFYRESULT (0 =
     * verified ok; nonzero = verify failure). On a connect/handshake failure
     * curl_result is nonzero and ssl_verify may be unset (0) — classify by
     * curl_result first. This is the LAST touch of the request: the
     * mq_origin_req_t is freed right after this returns. Fires for completion
     * and error, but NOT for mq_origin_abort. */
    void (*on_done)(int curl_result, long http_ver, long ssl_verify, void *u);
} mq_origin_cbs_t;

/* Create an origin client bound to `base`. ca_file (nullable) sets CURLOPT_CAINFO
 * for TLS verification; verification ALWAYS stays on (never disabled).
 * connect_timeout_s sets CURLOPT_CONNECTTIMEOUT per request. Returns NULL on
 * failure. Calls curl_global_init once process-wide (idempotent guard). */
mq_origin_t *mq_origin_new(struct event_base *base, const char *ca_file,
                           long connect_timeout_s);

/* Destroy the origin: tears down the multi handle and the timer event. All
 * in-flight requests must already be terminated (on_done) or aborted. */
void mq_origin_free(mq_origin_t *o);

/* Sentinel for mq_origin_start's upload_len: a request body IS present but its
 * length is not known up front (no Content-Length). curl uploads it with
 * chunked Transfer-Encoding (CURLOPT_UPLOAD=1, no INFILESIZE), pulling bytes
 * from cbs->pull_body until pull_body returns -1 (EOF). Distinct from a plain
 * negative (no body): only this exact value enables the bodied-but-lengthless
 * upload, so existing `upload_len < 0 == no body` callers are unaffected. */
#define MQ_ORIGIN_UPLOAD_CHUNKED ((int64_t) - 2)

/* Start a request. url is the absolute origin URL; method is the HTTP method
 * verb. hs[0..n) are request headers (NUL-terminated name/value C strings,
 * mq_h3_header_t).
 *
 * PRECONDITION: every header NAME and VALUE must be free of CR and LF (and NUL,
 * implied by C-string termination). curl serializes "name: value\r\n" onto the
 * wire verbatim, so a CR/LF in a caller-supplied value would split the request
 * (header injection / request smuggling). The gateway server enforces this
 * upstream (mq_gw_hdr_name_ok / mq_gw_hdr_value_ok reject control bytes before
 * a header reaches here). As a SECOND line of defense, libcurl >= 7.84.0 itself
 * strips CR/LF from header values passed via CURLOPT_HTTPHEADER — this version
 * floor is load-bearing: on an older libcurl the caller-side check above is the
 * only barrier.
 *
 * upload semantics by upload_len:
 *   >= 0                       → upload exactly that many bytes (sets INFILESIZE)
 *                                sourced from cbs->pull_body.
 *   MQ_ORIGIN_UPLOAD_CHUNKED   → upload a body of unknown length via chunked TE,
 *                                sourced from cbs->pull_body (EOF = pull -1).
 *   any other negative (e.g. -1) → no request body.
 * cbs/u carry the response callbacks and owner context. Returns the request, or
 * NULL on failure (no callback fires on a NULL return). */
mq_origin_req_t *mq_origin_start(mq_origin_t *o, const char *url, const char *method,
                                 const mq_h3_header_t *hs, size_t n, int64_t upload_len,
                                 const mq_origin_cbs_t *cbs, void *u);

/* Un-PAUSE the download side after on_body returned 0. Safe to call any time the
 * request is live; the actual curl_easy_pause runs deferred (next loop turn) to
 * avoid re-entering curl callbacks synchronously. */
void mq_origin_resume_body(mq_origin_req_t *r);

/* Un-PAUSE the upload side after pull_body returned 0. Deferred like
 * mq_origin_resume_body. */
void mq_origin_resume_pull(mq_origin_req_t *r);

/* Cancel a request: remove it from the multi handle and destroy it WITHOUT
 * firing on_done. The pointer is dangling afterward. */
void mq_origin_abort(mq_origin_req_t *r);

/* Parse an HTTP status line ("HTTP/x.y SSS reason") and return its 3-digit code
 * (100..599), or -1 if the line is not a status line. Exposed for unit-testing
 * the 1xx-skip path directly: a live origin (evhttp) cannot easily emit a
 * 100-continue, so the test drives this parser with synthetic status lines. */
int mq_origin_parse_status_line(const char *line, size_t len);

#endif /* MQ_GATEWAY_MQ_ORIGIN_CURL_H */
