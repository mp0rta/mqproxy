// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_HTTP1_H
#define MQ_HTTP1_H
#include <stddef.h>
#include <stdint.h>

/* Minimal, allocation-free HTTP/1.1 request-head parser + response serializer.
 *
 * This feeds the gateway client's local "fetch API" listener
 * (POST /_mqproxy/fetch). It sits on a TRUST BOUNDARY: the bytes come from a
 * local-but-untrusted client, so the parser is deliberately strict and rejects
 * request-smuggling-prone constructs rather than trying to be lenient:
 *
 *   - obs-fold (header continuation lines starting with SP/HTAB) -> BAD
 *   - bare CR or NUL inside a header value -> BAD
 *   - multiple Content-Length headers (even identical) -> BAD
 *   - non-numeric / overflowing Content-Length -> BAD
 *
 * Header (name,value) pairs are returned as SLICES into the caller's buffer;
 * nothing is copied and no allocations are performed. The caller MUST keep the
 * source buffer alive (and unmodified) for as long as it uses the slices.
 *
 * Duplicate header NAMES are not collapsed: every header line is preserved as a
 * slice, in arrival order. Upstream (mq_gw_headers) performs duplicate-name
 * detection on the X-Mq-* control headers.
 */

/* Max size of the request head (request line + headers + the blank line). A
 * request whose terminating CRLFCRLF is not seen within this many bytes is
 * rejected as BAD (bound on buffering / DoS surface). 16 KiB. */
#define MQ_HTTP1_MAX_HEAD (16 * 1024)

#define MQ_HTTP1_MAX_HEADERS 64

typedef enum {
    MQ_HTTP1_NEED_MORE = 0, /* terminator not yet seen and head still < max */
    MQ_HTTP1_DONE = 1,      /* a complete, valid request head; *out is filled */
    MQ_HTTP1_BAD = 2        /* malformed / rejected (see strictness notes above) */
} mq_http1_status_t;

typedef struct {
    char method[16]; /* NUL-terminated; RFC 7230 token, <= 15 chars */
    char path[1024]; /* NUL-terminated; origin-form, must start with '/' */

    /* Header (name,value) slices into the caller's buffer. NOT copied. Values
     * are OWS-trimmed; names are verified token-only. */
    struct {
        const char *n;
        size_t nl;
        const char *v;
        size_t vl;
    } h[MQ_HTTP1_MAX_HEADERS];
    size_t nh;

    int64_t content_length; /* parsed Content-Length, or -1 if absent */
    int has_chunked_te;     /* 1 if a Transfer-Encoding header listed "chunked" */
    size_t head_len;        /* bytes up to AND INCLUDING the terminating blank line */
} mq_http1_req_t;

/* Parse a request head from a single contiguous buffer. The caller accumulates
 * bytes and passes the whole buffer each call (like mq_http_connect_parse).
 * Returns NEED_MORE if no CRLFCRLF terminator yet (and head still under the
 * cap), DONE with *out filled on success, or BAD on any rejection.
 *
 * On CL + TE both present: both content_length and has_chunked_te are set; the
 * parser does NOT reject this -- the caller (fetch listener) decides policy
 * (e.g. 400). On has_chunked_te set, the caller typically answers 411. */
mq_http1_status_t mq_http1_parse_req(const uint8_t *buf, size_t len, mq_http1_req_t *out);

/* Response serializers. Each returns the number of bytes written, or a negative
 * value (status/header) / 0 (chunk_frame) if cap is too small -- in which case
 * nothing is written. */

/* "HTTP/1.1 <code> <reason>\r\n" */
int mq_http1_write_status(char *dst, size_t cap, int code, const char *reason);

/* "<n>: <v>\r\n" */
int mq_http1_write_header(char *dst, size_t cap, const char *n, const char *v);

/* "<lowercase-hex-len>\r\n<data>\r\n". Returns bytes written, or 0 if cap is
 * too small to hold the whole frame. */
size_t mq_http1_chunk_frame(char *dst, size_t cap, const uint8_t *p, size_t len);

#endif
