// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_origin_curl.c — libcurl-multi origin client on libevent. See
 * mq_origin_curl.h for the integration pattern, ownership, and lifetime.
 *
 * This is the canonical curl_multi_socket_action ("hiperfifo") glue:
 *
 *   - sock_cb (CURLMOPT_SOCKETFUNCTION): curl tells us which fd it wants to
 *     read/write; we maintain a per-socket struct event (created lazily, kept
 *     via curl_multi_assign so curl hands it back on the next interest change)
 *     and arm/disarm it to match. The event's callback runs
 *     curl_multi_socket_action(fd, ev_bitmask) then reaps completions.
 *   - timer_cb (CURLMOPT_TIMERFUNCTION): curl asks us to call socket_action with
 *     CURL_SOCKET_TIMEOUT after `timeout_ms`; we (re)arm a single evtimer. -1
 *     means "no timeout" (disarm). 0 means "as soon as possible" — we still go
 *     through a 0-delay timer so the action runs OUTSIDE the curl callback.
 *
 * After every socket_action we drain curl_multi_info_read for CURLMSG_DONE and
 * fire on_done → cleanup. on_done is the LAST touch of the request.
 */
#include "gateway/mq_origin_curl.h"

#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <event2/event.h>

#include "util/mq_log.h"

/* ── h3-ready runtime detection (design §5.3) ───────────────────────────────
 * curl_global_init runs once process-wide; we also probe curl_version_info for
 * HTTP/3 support and remember it so easy handles can opt into the h3→h2→h1
 * attempt. System curl 8.5.0 has no HTTP3 — the flag just stays 0 there. */
static int g_curl_inited;
static int g_curl_has_http3;

static void
origin_global_init(void)
{
    if (g_curl_inited) return;
    g_curl_inited = 1;
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
    if (vi) {
        g_curl_has_http3 = (vi->features & CURL_VERSION_HTTP3) ? 1 : 0;
        MQ_LOGI("mq_origin: libcurl %s (HTTP3=%s)", vi->version ? vi->version : "?",
                g_curl_has_http3 ? "yes" : "no");
    } else {
        MQ_LOGW("mq_origin: curl_version_info returned NULL");
    }
}

/* ── per-socket event tracking ──────────────────────────────────────────────
 * One sock_ctx per fd curl is interested in. Created on the first interest for
 * an fd and re-associated via curl_multi_assign so sock_cb finds it again. */
typedef struct {
    mq_origin_t *o;
    curl_socket_t fd;
    struct event *ev; /* EV_READ/EV_WRITE | EV_PERSIST, armed to match curl */
} sock_ctx_t;

struct mq_origin_s {
    struct event_base *base;
    CURLM *multi;
    struct event *timer_ev; /* single evtimer driven by CURLMOPT_TIMERFUNCTION */
    char *ca_file;          /* CURLOPT_CAINFO; NULL → curl default bundle */
    long connect_timeout_s;
    int still_running; /* curl's running-handle count from socket_action */
};

struct mq_origin_req_s {
    mq_origin_t *o;
    CURL *easy;
    struct curl_slist *hdrs; /* request header list (freed at teardown) */
    mq_origin_cbs_t cbs;
    void *u;

    int upload; /* 1 if this request uploads a body via pull_body */

    /* Header-section parse state (HEADERFUNCTION). curl delivers headers one
     * line at a time, including the status line(s) and the blank terminator.
     * We skip 1xx sections entirely and emit on_status once for the final. */
    int status_emitted; /* on_status fired for the final section */
    int in_1xx;         /* current section is an informational (1xx) one */

    /* Pause-state tracking. curl_easy_pause takes the DESIRED pause bitmask (the
     * directions that should REMAIN paused), so to resume one direction we clear
     * its bit and re-issue the remaining mask. write_cb/read_cb set these when
     * they return PAUSE; resume_* clear them. */
    int paused_recv; /* download paused (on_body returned 0) */
    int paused_send; /* upload paused (pull_body returned 0) */

    /* Deferred-unpause plumbing: calling curl_easy_pause from outside a curl
     * callback can re-enter callbacks synchronously, so resume_* sets a flag and
     * activates a 0-delay event; the event handler does the real easy_pause. */
    struct event *resume_ev;
    int want_resume; /* a resume is pending; on_resume_ev recomputes the mask */
};

/* ── completion reaping ─────────────────────────────────────────────────────*/

/* Tear down a request: remove its easy handle from the multi, free the slist
 * and per-request events, free the struct. Never fires on_done. */
static void
req_destroy(mq_origin_req_t *r)
{
    if (!r) return;
    if (r->easy) {
        curl_multi_remove_handle(r->o->multi, r->easy);
        curl_easy_cleanup(r->easy);
        r->easy = NULL;
    }
    if (r->hdrs) {
        curl_slist_free_all(r->hdrs);
        r->hdrs = NULL;
    }
    if (r->resume_ev) {
        event_free(r->resume_ev);
        r->resume_ev = NULL;
    }
    free(r);
}

/* Drain DONE messages from the multi handle: for each, recover the request via
 * CURLINFO_PRIVATE, capture the negotiated HTTP version, fire on_done, then
 * destroy the request. on_done is the LAST touch of r. */
static void
check_multi_info(mq_origin_t *o)
{
    CURLMsg *m;
    int pending;
    while ((m = curl_multi_info_read(o->multi, &pending)) != NULL) {
        if (m->msg != CURLMSG_DONE) continue;

        CURL *easy = m->easy_handle;
        CURLcode result = m->data.result;

        mq_origin_req_t *r = NULL;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &r);

        long http_ver = 0;
        curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &http_ver);

        if (r) {
            mq_origin_cbs_t cbs = r->cbs;
            void *u = r->u;
            /* Destroy BEFORE the callback so the request (and its easy handle)
             * is gone; on_done is the owner's cue to free its own `u`. The easy
             * handle is removed from the multi inside req_destroy, which is safe
             * here (we are between info_read calls, not mid-action). */
            req_destroy(r);
            if (cbs.on_done) cbs.on_done((int)result, http_ver, u);
        }
    }
}

/* ── socket_action driver ───────────────────────────────────────────────────*/

/* Run curl_multi_socket_action for `fd`/`ev_bitmask` (or CURL_SOCKET_TIMEOUT),
 * then reap any completions. */
static void
origin_action(mq_origin_t *o, curl_socket_t fd, int ev_bitmask)
{
    CURLMcode rc = curl_multi_socket_action(o->multi, fd, ev_bitmask, &o->still_running);
    if (rc != CURLM_OK) {
        MQ_LOGW("mq_origin: curl_multi_socket_action: %s", curl_multi_strerror(rc));
    }
    check_multi_info(o);
}

/* libevent callback for a curl-owned socket. */
static void
on_socket_ev(evutil_socket_t fd, short what, void *arg)
{
    sock_ctx_t *sc = (sock_ctx_t *)arg;
    int flags = 0;
    if (what & EV_READ) flags |= CURL_CSELECT_IN;
    if (what & EV_WRITE) flags |= CURL_CSELECT_OUT;
    origin_action(sc->o, fd, flags);
}

/* libevent callback for the curl multi timeout. */
static void
on_timer_ev(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_origin_t *o = (mq_origin_t *)arg;
    origin_action(o, CURL_SOCKET_TIMEOUT, 0);
}

/* CURLMOPT_SOCKETFUNCTION: curl announces (or revokes) read/write interest for
 * a socket. We mirror that onto a per-socket struct event. */
static int
sock_cb(CURL *easy, curl_socket_t fd, int action, void *userp, void *socketp)
{
    (void)easy;
    mq_origin_t *o = (mq_origin_t *)userp;
    sock_ctx_t *sc = (sock_ctx_t *)socketp;

    if (action == CURL_POLL_REMOVE) {
        if (sc) {
            if (sc->ev) {
                event_del(sc->ev);
                event_free(sc->ev);
            }
            free(sc);
            curl_multi_assign(o->multi, fd, NULL);
        }
        return 0;
    }

    if (!sc) {
        sc = (sock_ctx_t *)calloc(1, sizeof(*sc));
        if (!sc) return -1;
        sc->o = o;
        sc->fd = fd;
        curl_multi_assign(o->multi, fd, sc);
    }

    short kind = EV_PERSIST;
    if (action == CURL_POLL_IN)
        kind |= EV_READ;
    else if (action == CURL_POLL_OUT)
        kind |= EV_WRITE;
    else if (action == CURL_POLL_INOUT)
        kind |= EV_READ | EV_WRITE;

    /* Re-create the event when the interest set changes (the simplest correct
     * approach: event flags are fixed at event_new time). */
    if (sc->ev) {
        event_del(sc->ev);
        event_free(sc->ev);
        sc->ev = NULL;
    }
    sc->ev = event_new(o->base, fd, kind, on_socket_ev, sc);
    if (!sc->ev) return -1;
    event_add(sc->ev, NULL);
    return 0;
}

/* CURLMOPT_TIMERFUNCTION: curl asks for a single timeout. timeout_ms == -1 means
 * disarm; otherwise (re)arm the evtimer. 0 is honored as a near-immediate timer
 * so the resulting socket_action runs outside this callback. */
static int
timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
    (void)multi;
    mq_origin_t *o = (mq_origin_t *)userp;

    if (timeout_ms < 0) {
        if (o->timer_ev) event_del(o->timer_ev);
        return 0;
    }
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (o->timer_ev) {
        event_del(o->timer_ev);
        event_add(o->timer_ev, &tv);
    }
    return 0;
}

/* ── construction / teardown ────────────────────────────────────────────────*/

mq_origin_t *
mq_origin_new(struct event_base *base, const char *ca_file, long connect_timeout_s)
{
    if (!base) return NULL;
    origin_global_init();

    mq_origin_t *o = (mq_origin_t *)calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->base = base;
    o->connect_timeout_s = connect_timeout_s;
    if (ca_file) {
        size_t n = strlen(ca_file) + 1;
        o->ca_file = (char *)malloc(n);
        if (!o->ca_file) {
            free(o);
            return NULL;
        }
        memcpy(o->ca_file, ca_file, n);
    }

    o->multi = curl_multi_init();
    if (!o->multi) {
        free(o->ca_file);
        free(o);
        return NULL;
    }
    o->timer_ev = evtimer_new(base, on_timer_ev, o);
    if (!o->timer_ev) {
        curl_multi_cleanup(o->multi);
        free(o->ca_file);
        free(o);
        return NULL;
    }

    curl_multi_setopt(o->multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
    curl_multi_setopt(o->multi, CURLMOPT_SOCKETDATA, o);
    curl_multi_setopt(o->multi, CURLMOPT_TIMERFUNCTION, timer_cb);
    curl_multi_setopt(o->multi, CURLMOPT_TIMERDATA, o);
    return o;
}

void
mq_origin_free(mq_origin_t *o)
{
    if (!o) return;
    if (o->timer_ev) {
        event_del(o->timer_ev);
        event_free(o->timer_ev);
    }
    if (o->multi) {
        /* Any per-socket events still registered are torn down by curl issuing
         * CURL_POLL_REMOVE during cleanup of remaining handles; the gateway is
         * expected to have aborted/completed all requests first. */
        curl_multi_cleanup(o->multi);
    }
    free(o->ca_file);
    free(o);
}

/* ── per-request callbacks (curl easy options) ──────────────────────────────*/

/* WRITEFUNCTION: response body. Hand bytes to on_body; if the owner accepts 0,
 * pause the download (CURL_WRITEFUNC_PAUSE). Otherwise the owner must accept the
 * whole chunk (the documented contract); a partial-but-nonzero accept is a short
 * write and curl aborts the transfer. */
static size_t
write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
    mq_origin_req_t *r = (mq_origin_req_t *)userp;
    size_t len = size * nmemb;
    if (len == 0) return 0;
    if (!r->cbs.on_body) return len; /* discard */

    long accepted = r->cbs.on_body((const uint8_t *)ptr, len, r->u);
    if (accepted == 0) {
        r->paused_recv = 1;
        return CURL_WRITEFUNC_PAUSE;
    }
    if (accepted < 0 || (size_t)accepted != len) return 0; /* short write → error */
    return len;
}

/* READFUNCTION: upload source. pull_body returns >0 bytes, 0 = pause
 * (CURL_READFUNC_PAUSE), -1 = EOF (return 0 to signal end of upload). */
static size_t
read_cb(char *buffer, size_t size, size_t nitems, void *userp)
{
    mq_origin_req_t *r = (mq_origin_req_t *)userp;
    size_t cap = size * nitems;
    if (!r->cbs.pull_body) return 0; /* nothing to upload → EOF */

    long got = r->cbs.pull_body((uint8_t *)buffer, cap, r->u);
    if (got == 0) {
        r->paused_send = 1;
        return CURL_READFUNC_PAUSE;
    }
    if (got < 0) return 0; /* EOF */
    if ((size_t)got > cap) got = (long)cap;
    return (size_t)got;
}

/* Trim leading/trailing HTTP whitespace (SP/HTAB) from [p, p+len). */
static void
trim_ows(const char **p, size_t *len)
{
    const char *s = *p;
    size_t n = *len;
    while (n > 0 && (s[0] == ' ' || s[0] == '\t')) {
        s++;
        n--;
    }
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) {
        n--;
    }
    *p = s;
    *len = n;
}

/* Parse an HTTP status line into its 3-digit code. Returns the code (100..599)
 * or -1 if the line is not a status line. A status line looks like
 * "HTTP/x.y SSS reason" or "HTTP/2 SSS ..." (curl normalises HTTP/3 similarly).
 * Exposed (non-static) so the header-parse path is unit-testable without a live
 * 1xx origin (evhttp can't easily emit 100-continue). */
int
mq_origin_parse_status_line(const char *line, size_t len)
{
    if (len < 5 || memcmp(line, "HTTP/", 5) != 0) return -1;
    /* Skip the version token up to the first space. */
    size_t i = 5;
    while (i < len && line[i] != ' ')
        i++;
    while (i < len && line[i] == ' ')
        i++;
    if (i + 3 > len) return -1;
    if (line[i] < '0' || line[i] > '9' || line[i + 1] < '0' || line[i + 1] > '9' ||
        line[i + 2] < '0' || line[i + 2] > '9')
        return -1;
    int code = (line[i] - '0') * 100 + (line[i + 1] - '0') * 10 + (line[i + 2] - '0');
    if (code < 100 || code > 599) return -1;
    return code;
}

/* HEADERFUNCTION: one header line at a time (incl. status lines and the blank
 * terminator). curl invokes this for every header section, so a 1xx section
 * (e.g. 100-continue) arrives BEFORE the final one. We skip 1xx sections wholly:
 * their status line sets in_1xx, their header lines are ignored, and their blank
 * terminator just clears in_1xx. The final (non-1xx) status line emits on_status
 * once; its subsequent header lines emit on_header. */
static size_t
header_cb(char *buffer, size_t size, size_t nitems, void *userp)
{
    mq_origin_req_t *r = (mq_origin_req_t *)userp;
    size_t len = size * nitems;
    size_t raw = len;

    /* Strip the trailing CRLF (or lone LF) for parsing. */
    size_t l = len;
    while (l > 0 && (buffer[l - 1] == '\r' || buffer[l - 1] == '\n'))
        l--;

    /* Blank line: end of a header section. */
    if (l == 0) {
        r->in_1xx = 0; /* a skipped 1xx section ends; the final section's blank
                        * line is harmless (status already emitted). */
        return raw;
    }

    int code = mq_origin_parse_status_line(buffer, l);
    if (code >= 0) {
        /* A status line. */
        if (code >= 100 && code < 200) {
            r->in_1xx = 1; /* skip this whole informational section */
            return raw;
        }
        r->in_1xx = 0;
        if (!r->status_emitted) {
            r->status_emitted = 1;
            if (r->cbs.on_status) r->cbs.on_status(code, r->u);
        }
        return raw;
    }

    /* A field line. Ignore it if we're inside a skipped 1xx section, or before
     * the final status line was seen (defensive — shouldn't happen). */
    if (r->in_1xx || !r->status_emitted) return raw;

    /* Split "name: value". */
    const char *colon = memchr(buffer, ':', l);
    if (!colon) return raw; /* not a field line (folded/obs) — ignore */
    const char *name = buffer;
    size_t nl = (size_t)(colon - buffer);
    const char *val = colon + 1;
    size_t vl = l - nl - 1;
    trim_ows(&val, &vl);
    /* Field names have no surrounding OWS by spec; trim defensively anyway. */
    trim_ows(&name, &nl);
    if (nl == 0) return raw;

    if (r->cbs.on_header) r->cbs.on_header(name, nl, val, vl, r->u);
    return raw;
}

/* ── deferred unpause ───────────────────────────────────────────────────────*/

/* Apply the (now-updated) pause state to the easy handle. curl_easy_pause takes
 * the bitmask of directions that should REMAIN paused; resume_* already cleared
 * the bit(s) being resumed, so we just re-issue the current paused_* state. */
static void
on_resume_ev(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_origin_req_t *r = (mq_origin_req_t *)arg;
    if (!r->want_resume) return;
    r->want_resume = 0;
    if (!r->easy) return;

    int mask = 0;
    if (r->paused_recv) mask |= CURLPAUSE_RECV;
    if (r->paused_send) mask |= CURLPAUSE_SEND;
    /* mask == CURLPAUSE_CONT (0) un-pauses everything. */
    curl_easy_pause(r->easy, mask);
    /* easy_pause may have produced new socket activity / a new timeout; kick the
     * multi so curl re-evaluates the transfer immediately. */
    origin_action(r->o, CURL_SOCKET_TIMEOUT, 0);
}

static void
schedule_resume(mq_origin_req_t *r)
{
    r->want_resume = 1;
    if (!r->resume_ev) {
        r->resume_ev = evtimer_new(r->o->base, on_resume_ev, r);
        if (!r->resume_ev) {
            /* Fallback: unpause inline (documented risk). Better than a stall. */
            on_resume_ev(-1, 0, r);
            return;
        }
    }
    struct timeval z = {0, 0};
    evtimer_add(r->resume_ev, &z);
}

void
mq_origin_resume_body(mq_origin_req_t *r)
{
    if (!r) return;
    r->paused_recv = 0; /* download is no longer paused */
    schedule_resume(r);
}

void
mq_origin_resume_pull(mq_origin_req_t *r)
{
    if (!r) return;
    r->paused_send = 0; /* upload is no longer paused */
    schedule_resume(r);
}

/* ── start / abort ──────────────────────────────────────────────────────────*/

mq_origin_req_t *
mq_origin_start(mq_origin_t *o, const char *url, const char *method,
                const mq_h3_header_t *hs, size_t n, int64_t upload_len,
                const mq_origin_cbs_t *cbs, void *u)
{
    if (!o || !url || !method || !cbs) return NULL;

    mq_origin_req_t *r = (mq_origin_req_t *)calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->o = o;
    r->cbs = *cbs;
    r->u = u;
    /* Upload if a known length (>=0) OR the chunked sentinel. Any other negative
     * means no request body. */
    r->upload = (upload_len >= 0 || upload_len == MQ_ORIGIN_UPLOAD_CHUNKED);

    r->easy = curl_easy_init();
    if (!r->easy) {
        free(r);
        return NULL;
    }

    /* Build the request header list. Always suppress Expect: — the 100-continue
     * dance breaks streaming uploads (curl would wait for a 100 before sending
     * the body, stalling the pull source). Headers are forwarded verbatim. */
    struct curl_slist *hdrs = NULL;
    /* A small stack buffer covers the common case; oversize lines (a big
     * Authorization / Cookie the gateway must forward verbatim) heap-allocate
     * exactly the needed size rather than being silently dropped. */
    char stackline[1024];
    for (size_t i = 0; i < n; i++) {
        if (!hs[i].name) continue;
        const char *v = hs[i].value ? hs[i].value : "";
        /* Compute the exact length: strlen(name) + ": " + strlen(value). */
        size_t need = strlen(hs[i].name) + 2 + strlen(v) + 1; /* +1 for NUL */
        char *line = stackline;
        char *heapline = NULL;
        if (need > sizeof(stackline)) {
            heapline = (char *)malloc(need);
            if (!heapline) {
                curl_slist_free_all(hdrs);
                curl_easy_cleanup(r->easy);
                free(r);
                return NULL;
            }
            line = heapline;
        }
        int wn = snprintf(line, need, "%s: %s", hs[i].name, v);
        if (wn <= 0 || (size_t)wn >= need) {
            free(heapline);
            continue; /* defensive: should not happen given `need` is exact */
        }
        struct curl_slist *nl = curl_slist_append(hdrs, line);
        free(heapline);
        if (!nl) {
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(r->easy);
            free(r);
            return NULL;
        }
        hdrs = nl;
    }
    {
        struct curl_slist *nl = curl_slist_append(hdrs, "Expect:");
        if (!nl) {
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(r->easy);
            free(r);
            return NULL;
        }
        hdrs = nl;
    }
    r->hdrs = hdrs;

    CURL *e = r->easy;
    curl_easy_setopt(e, CURLOPT_URL, url);
    curl_easy_setopt(e, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(e, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(e, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(e, CURLOPT_CONNECTTIMEOUT, o->connect_timeout_s);
    curl_easy_setopt(e, CURLOPT_PRIVATE, r);

    /* TLS verification stays DEFAULT ON; only point at a custom CA if given. */
    if (o->ca_file) curl_easy_setopt(e, CURLOPT_CAINFO, o->ca_file);

    /* Raw passthrough: do NOT advertise Accept-Encoding (no transparent
     * decompression — the gateway forwards the origin's bytes verbatim). */

    /* h3-ready: if libcurl supports HTTP/3, request it with h3→h2→h1 fallback.
     * On system curl 8.5.0 (no HTTP3) this branch never triggers; the default
     * (HTTP/2 ALPN with h1 fallback) applies. */
    if (g_curl_has_http3) {
        curl_easy_setopt(e, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_3);
    }

    curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(e, CURLOPT_WRITEDATA, r);
    curl_easy_setopt(e, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(e, CURLOPT_HEADERDATA, r);

    if (r->upload) {
        curl_easy_setopt(e, CURLOPT_UPLOAD, 1L);
        /* Known length → set INFILESIZE (curl frames an exact-length body).
         * Chunked sentinel → leave INFILESIZE unset so curl uploads with chunked
         * Transfer-Encoding, pulling until pull_body signals EOF (-1). */
        if (upload_len >= 0)
            curl_easy_setopt(e, CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload_len);
        curl_easy_setopt(e, CURLOPT_READFUNCTION, read_cb);
        curl_easy_setopt(e, CURLOPT_READDATA, r);
    }

    CURLMcode mc = curl_multi_add_handle(o->multi, e);
    if (mc != CURLM_OK) {
        MQ_LOGW("mq_origin: curl_multi_add_handle: %s", curl_multi_strerror(mc));
        curl_slist_free_all(hdrs);
        r->hdrs = NULL;
        curl_easy_cleanup(e);
        r->easy = NULL;
        free(r);
        return NULL;
    }
    /* curl_multi_add_handle arms a 0ms timeout via timer_cb; the loop will drive
     * the transfer from there. */
    return r;
}

void
mq_origin_abort(mq_origin_req_t *r)
{
    if (!r) return;
    /* No on_done. req_destroy removes the handle from the multi (which triggers
     * CURL_POLL_REMOVE for its sockets) and frees everything. */
    req_destroy(r);
}
