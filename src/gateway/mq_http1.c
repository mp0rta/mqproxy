// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "gateway/mq_http1.h"

#include "gateway/mq_gw_headers.h" /* mq_gw_is_tchar (shared token-char class) */
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Character classes (RFC 7230)
 *
 * tchar (token char) is shared with the header-policy / target-parsing layer;
 * see mq_gw_is_tchar in mq_gw_headers.h. There is intentionally a single
 * definition so the HTTP/1 field-name parser and the method/target validators
 * can never drift apart.
 * ------------------------------------------------------------------------- */

static char
lc(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

/* Case-insensitive equality of a slice against a NUL-terminated lowercase key. */
static int
slice_ci_eq(const char *s, size_t sl, const char *key)
{
    size_t kl = strlen(key);
    if (sl != kl) return 0;
    for (size_t i = 0; i < sl; i++)
        if (lc(s[i]) != key[i]) return 0;
    return 1;
}

/* Find end (one past last byte) of first "\r\n\r\n". Returns 0 if not found
 * within [0,len). */
static size_t
find_head_end(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n')
            return i + 4;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Content-Length parse: strict decimal into [0, INT64_MAX]. Returns 0 on
 * success (writes *out), -1 on any error (empty / non-digit / overflow).
 * Leading zeros are accepted by design: the numeric value is unambiguous
 * ("007" == 7), and rejecting them would add complexity with no security gain
 * on this trust boundary.
 * ------------------------------------------------------------------------- */
static int
parse_content_length(const char *s, size_t sl, int64_t *out)
{
    if (sl == 0) return -1;
    int64_t v = 0;
    for (size_t i = 0; i < sl; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return -1;
        int d = c - '0';
        /* overflow guard: v*10 + d must stay <= INT64_MAX (9223372036854775807) */
        if (v > (int64_t)922337203685477580LL ||
            (v == (int64_t)922337203685477580LL && d > 7))
            return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

/* Does an OWS-trimmed Transfer-Encoding value list "chunked" (case-insensitive)
 * as one of its comma-separated tokens? */
static int
te_lists_chunked(const char *s, size_t sl)
{
    size_t i = 0;
    while (i < sl) {
        /* skip leading OWS / commas */
        while (i < sl && (s[i] == ' ' || s[i] == '\t' || s[i] == ','))
            i++;
        size_t start = i;
        while (i < sl && s[i] != ',')
            i++;
        /* token = s[start..i); trim trailing OWS */
        size_t end = i;
        while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
            end--;
        if (slice_ci_eq(s + start, end - start, "chunked")) return 1;
    }
    return 0;
}

mq_http1_status_t
mq_http1_parse_req(const uint8_t *buf, size_t len, mq_http1_req_t *out)
{
    size_t hend = find_head_end(buf, len);
    if (hend == 0) {
        /* No terminator yet. If we've already buffered more than the cap with no
         * terminator, give up rather than buffer unboundedly. */
        if (len > MQ_HTTP1_MAX_HEAD) return MQ_HTTP1_BAD;
        return MQ_HTTP1_NEED_MORE;
    }
    if (hend > MQ_HTTP1_MAX_HEAD) return MQ_HTTP1_BAD;

    memset(out, 0, sizeof(*out));
    out->content_length = -1;

    const char *p = (const char *)buf;

    /* ---- request line: ends at first CRLF within [0,hend) ---- */
    size_t line_end = 0;
    for (size_t i = 0; i + 1 < hend; i++) {
        if (p[i] == '\r' && p[i + 1] == '\n') {
            line_end = i;
            break;
        }
    }
    /* hend contains CRLFCRLF, so a CRLF exists; line_end==0 means empty line. */

    /* METHOD SP PATH SP HTTP/x.y */
    size_t m_end = 0;
    while (m_end < line_end && p[m_end] != ' ')
        m_end++;
    if (m_end == 0 || m_end >= line_end) return MQ_HTTP1_BAD; /* no method/path */
    if (m_end > 15) return MQ_HTTP1_BAD;                      /* method too long */
    for (size_t i = 0; i < m_end; i++)
        if (!mq_gw_is_tchar((unsigned char)p[i])) return MQ_HTTP1_BAD;

    size_t path_start = m_end + 1;
    size_t path_end = path_start;
    while (path_end < line_end && p[path_end] != ' ')
        path_end++;
    if (path_end >= line_end) return MQ_HTTP1_BAD;   /* no version field */
    if (path_end == path_start) return MQ_HTTP1_BAD; /* empty path */
    if (p[path_start] != '/') return MQ_HTTP1_BAD;   /* origin-form must start '/' */

    size_t path_len = path_end - path_start;
    if (path_len >= sizeof(out->path)) return MQ_HTTP1_BAD; /* +1 for NUL */

    /* Reject any control byte (< 0x20) or DEL (0x7f) in the path span.
     * A NUL byte would silently truncate the NUL-terminated out->path, so
     * downstream strlen consumers would see a different path than the wire
     * (NUL-injection / path-confusion vector).  Other bytes < 0x20 and 0x7f
     * are in the same injection class as the NUL/CR guard on header values. */
    for (size_t i = path_start; i < path_end; i++) {
        unsigned char b = (unsigned char)p[i];
        if (b < 0x20 || b == 0x7f) return MQ_HTTP1_BAD;
    }

    /* Method span: mq_gw_is_tchar() already rejects every byte < 0x20 and 0x7f
     * (including NUL), so no additional check is needed here. */

    /* Version field: validated only as "HTTP/"-prefixed and non-empty; the
     * gateway never branches on the minor version number (HTTP/1.0 vs 1.1
     * distinction is handled by the caller, not here). */
    size_t v_start = path_end + 1;
    if (v_start >= line_end) return MQ_HTTP1_BAD;
    if (line_end - v_start < 5 || memcmp(p + v_start, "HTTP/", 5) != 0)
        return MQ_HTTP1_BAD;

    memcpy(out->method, p, m_end);
    out->method[m_end] = '\0';
    memcpy(out->path, p + path_start, path_len);
    out->path[path_len] = '\0';

    /* ---- header lines: from (line_end+2) up to hend-2 (the blank CRLF) ---- */
    size_t pos = line_end + 2;
    size_t headers_end = hend - 2; /* index of the final blank line's CR */

    int seen_cl = 0;
    while (pos < headers_end) {
        /* obs-fold: a header line MUST NOT start with SP/HTAB. This is a
         * request-smuggling vector (ambiguous re-folding between hops), so we
         * reject outright rather than unfold. */
        if (p[pos] == ' ' || p[pos] == '\t') return MQ_HTTP1_BAD;

        /* find CRLF ending this line */
        size_t le = pos;
        while (le + 1 < hend && !(p[le] == '\r' && p[le + 1] == '\n'))
            le++;
        if (le + 1 >= hend) return MQ_HTTP1_BAD; /* unterminated header line */
        /* [pos, le) is the header line bytes */

        if (out->nh >= MQ_HTTP1_MAX_HEADERS) return MQ_HTTP1_BAD;

        /* name = token up to ':' */
        size_t colon = pos;
        while (colon < le && p[colon] != ':')
            colon++;
        if (colon >= le) return MQ_HTTP1_BAD;  /* no colon */
        if (colon == pos) return MQ_HTTP1_BAD; /* empty name */
        for (size_t i = pos; i < colon; i++)
            if (!mq_gw_is_tchar((unsigned char)p[i])) return MQ_HTTP1_BAD;

        const char *nm = p + pos;
        size_t nml = colon - pos;

        /* value = everything after ':', OWS-trimmed. */
        size_t vs = colon + 1;
        size_t ve = le;
        while (vs < ve && (p[vs] == ' ' || p[vs] == '\t'))
            vs++;
        while (ve > vs && (p[ve - 1] == ' ' || p[ve - 1] == '\t'))
            ve--;

        /* Reject bare CR or NUL anywhere in the (pre-trim) value span — both are
         * smuggling / header-injection vectors. (LF can't appear: the line ends
         * at CRLF.) */
        for (size_t i = colon + 1; i < le; i++)
            if (p[i] == '\0' || p[i] == '\r') return MQ_HTTP1_BAD;

        const char *vv = p + vs;
        size_t vvl = ve - vs;

        out->h[out->nh].n = nm;
        out->h[out->nh].nl = nml;
        out->h[out->nh].v = vv;
        out->h[out->nh].vl = vvl;
        out->nh++;

        /* Content-Length: parse; multiple CL headers (even identical) -> BAD.
         * Strictness is intentional on this trust boundary. */
        if (slice_ci_eq(nm, nml, "content-length")) {
            if (seen_cl) return MQ_HTTP1_BAD;
            seen_cl = 1;
            int64_t cl;
            if (parse_content_length(vv, vvl, &cl) != 0) return MQ_HTTP1_BAD;
            out->content_length = cl;
        } else if (slice_ci_eq(nm, nml, "transfer-encoding")) {
            if (te_lists_chunked(vv, vvl)) out->has_chunked_te = 1;
        }

        pos = le + 2; /* past the CRLF */
    }

    out->head_len = hend;
    return MQ_HTTP1_DONE;
}

/* ---------------------------------------------------------------------------
 * Response serializers
 * ------------------------------------------------------------------------- */

/* Size the formatted output first (snprintf to a 0-cap buffer returns the
 * length it WOULD write, without touching dst), then only format into dst if
 * the whole thing — including the trailing NUL snprintf needs — fits. This
 * guarantees "nothing written" on failure, so dst is left byte-for-byte
 * untouched. Returns bytes written (excluding NUL) or -1 if it won't fit. */
int
mq_http1_write_status(char *dst, size_t cap, int code, const char *reason)
{
    int need = snprintf(NULL, 0, "HTTP/1.1 %d %s\r\n", code, reason);
    if (need < 0 || (size_t)need + 1 > cap) return -1;
    snprintf(dst, cap, "HTTP/1.1 %d %s\r\n", code, reason);
    return need;
}

int
mq_http1_write_header(char *dst, size_t cap, const char *n_, const char *v)
{
    /* Defense-in-depth for the download path: the value (and, less plausibly,
     * the name) may carry bytes that originate from the origin's response. A CR
     * or LF embedded here would split the serialized response (header injection
     * / response splitting); a NUL would truncate it. Reject rather than emit a
     * malformed/dangerous header section. (NUL cannot appear inside these C
     * strings, but we check defensively in case callers ever pass slices.) */
    for (const char *p = n_; *p; p++)
        if (*p == '\r' || *p == '\n') return -1;
    for (const char *p = v; *p; p++)
        if (*p == '\r' || *p == '\n') return -1;

    int need = snprintf(NULL, 0, "%s: %s\r\n", n_, v);
    if (need < 0 || (size_t)need + 1 > cap) return -1;
    snprintf(dst, cap, "%s: %s\r\n", n_, v);
    return need;
}

size_t
mq_http1_chunk_frame(char *dst, size_t cap, const uint8_t *p, size_t len)
{
    /* "<lowercase-hex-len>\r\n<data>\r\n" */
    char hex[20]; /* enough for 64-bit hex */
    int hl = snprintf(hex, sizeof hex, "%zx", len);
    if (hl < 0) return 0;
    size_t total = (size_t)hl + 2 + len + 2;
    if (cap < total) return 0;

    size_t o = 0;
    memcpy(dst + o, hex, (size_t)hl);
    o += (size_t)hl;
    dst[o++] = '\r';
    dst[o++] = '\n';
    if (len) memcpy(dst + o, p, len);
    o += len;
    dst[o++] = '\r';
    dst[o++] = '\n';
    return o;
}
