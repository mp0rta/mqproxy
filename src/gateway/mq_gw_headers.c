// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "gateway/mq_gw_headers.h"

#include <curl/curl.h>
#include <string.h>

/* The MQ_GW_CURL_* constants in mq_gw_headers.h are mirrors of CURLE_* values
 * so that Chunk-3 unit tests compile without libcurl.  These asserts pin the
 * mirrors to the real libcurl values; any future divergence is caught at
 * compile time rather than silently producing wrong HTTP status codes. */
_Static_assert(MQ_GW_CURL_RESOLVE == CURLE_COULDNT_RESOLVE_HOST,
               "MQ_GW_CURL_RESOLVE must equal CURLE_COULDNT_RESOLVE_HOST");
_Static_assert(MQ_GW_CURL_CONNECT == CURLE_COULDNT_CONNECT,
               "MQ_GW_CURL_CONNECT must equal CURLE_COULDNT_CONNECT");
_Static_assert(MQ_GW_CURL_TIMEDOUT == CURLE_OPERATION_TIMEDOUT,
               "MQ_GW_CURL_TIMEDOUT must equal CURLE_OPERATION_TIMEDOUT");
_Static_assert(MQ_GW_CURL_PEER_VERIFY == CURLE_PEER_FAILED_VERIFICATION,
               "MQ_GW_CURL_PEER_VERIFY must equal CURLE_PEER_FAILED_VERIFICATION");

/* ---------------------------------------------------------------------------
 * Small ASCII helpers (locale-independent; we never want locale to influence
 * what counts as a token char / how a name is folded).
 * ------------------------------------------------------------------------- */
static char
lc(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static char
uc(char c)
{
    return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
}

/* Case-insensitive compare of an (n,nl) name against a NUL-terminated literal.
 * Returns 1 if equal. */
static int
name_eq(const char *n, size_t nl, const char *lit)
{
    if (nl != strlen(lit)) return 0;
    for (size_t i = 0; i < nl; i++)
        if (lc(n[i]) != lc(lit[i])) return 0;
    return 1;
}

/* Case-insensitive prefix test: does (n,nl) start with NUL-terminated pfx? */
static int
name_has_prefix(const char *n, size_t nl, const char *pfx)
{
    size_t pl = strlen(pfx);
    if (nl < pl) return 0;
    for (size_t i = 0; i < pl; i++)
        if (lc(n[i]) != lc(pfx[i])) return 0;
    return 1;
}

/* RFC 7230 token char: tchar = "!#$%&'*+-.^_`|~" / DIGIT / ALPHA */
int
mq_gw_is_tchar(unsigned char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return 1;
    switch (c) {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~': return 1;
    default: return 0;
    }
}

/* A byte we forbid inside authority / path: controls (<0x20), DEL (0x7f), or
 * SP. The caller handles '#' (fragment) and '@' (userinfo) separately. */
static int
is_forbidden_uri_byte(unsigned char c)
{
    return c < 0x20 || c == 0x7f || c == ' ';
}

/* ---------------------------------------------------------------------------
 * Target parsing
 * ------------------------------------------------------------------------- */
int
mq_gw_parse_target(const char *s, size_t len, mq_gw_target_t *out)
{
    /* scheme (lowercase, fixed) */
    const char *scheme;
    size_t off;
    if (len >= 8 && memcmp(s, "https://", 8) == 0) {
        scheme = "https";
        off = 8;
    } else if (len >= 7 && memcmp(s, "http://", 7) == 0) {
        scheme = "http";
        off = 7;
    } else {
        return -1;
    }

    /* authority = bytes up to first '/' or '?' (or end).
     * Bracket tracking is only honoured when '[' appears at the very first
     * byte of the authority (IPv6 literal).  A '[' anywhere else is illegal
     * in a host and must cause the whole target to be rejected. */
    size_t a_start = off;
    size_t i = off;
    int in_brackets = 0;
    int bracket_err = 0; /* set if '[' seen at a non-zero authority offset */
    for (; i < len; i++) {
        char c = s[i];
        if (c == '[') {
            if (i == a_start)
                in_brackets = 1;
            else
                bracket_err = 1; /* stray '[' — mark and keep scanning */
        } else if (c == ']') {
            in_brackets = 0;
        } else if (!in_brackets && (c == '/' || c == '?')) {
            break;
        }
    }
    if (bracket_err) return -1;

    size_t a_len = i - a_start;
    if (a_len == 0 || a_len > 255) return -1;

    const char *auth = s + a_start;

    /* Reject userinfo, forbidden bytes, and any '['/']' that are not part
     * of a well-formed leading IPv6 literal (i.e. auth[0] == '[' with a
     * matching ']').  A lone ']' when the authority is not bracketed is
     * illegal. */
    int is_bracketed = (auth[0] == '[');
    for (size_t k = 0; k < a_len; k++) {
        unsigned char c = (unsigned char)auth[k];
        if (c == '@') return -1; /* userinfo — credential-injection surface */
        if (c == '#') return -1; /* fragment cannot appear in authority */
        if (is_forbidden_uri_byte(c)) return -1;
        /* '[' at k>0 was already caught by bracket_err above (the scan loop
         * continued past a stray '[' only if bracket_err was set, which
         * triggered an early return).  Guard here too for safety. */
        if (c == '[' && k != 0) return -1;
        /* ']' is only legal inside a bracketed IPv6 literal. */
        if (c == ']' && !is_bracketed) return -1;
    }

    /* Validate host:port split. For a bracketed IPv6 literal "[...]", the
     * colon scan starts after ']'; otherwise split on the LAST ':'. */
    size_t colon_scan_from = 0;
    if (is_bracketed) {
        /* find closing ']' */
        size_t rb = 0;
        int found = 0;
        for (size_t k = 1; k < a_len; k++) {
            if (auth[k] == ']') {
                rb = k;
                found = 1;
                break;
            }
        }
        if (!found || rb == 1) return -1; /* unterminated or empty "[]" */
        colon_scan_from = rb + 1;
        /* after ']' only an optional ":port" may follow */
        if (colon_scan_from < a_len && auth[colon_scan_from] != ':') return -1;
    }

    /* locate port colon (last ':' at/after colon_scan_from) */
    size_t pc = a_len; /* a_len == "no port" */
    for (size_t k = colon_scan_from; k < a_len; k++)
        if (auth[k] == ':') pc = k;
    if (pc != a_len) {
        /* port present: must be non-empty, digits only */
        if (pc + 1 >= a_len) return -1; /* "host:" with empty port */
        for (size_t k = pc + 1; k < a_len; k++)
            if (auth[k] < '0' || auth[k] > '9') return -1;
        /* host part must be non-empty (e.g. ":8443" is invalid) */
        if (pc == 0) return -1;
        /* non-bracketed host must not itself contain ':' (e.g. "h:80:90") */
        if (!is_bracketed) {
            for (size_t k = 0; k < pc; k++)
                if (auth[k] == ':') return -1;
        }
    }

    /* path+query = the rest (from index i to end). */
    const char *rest = s + i;
    size_t rest_len = len - i;

    /* reject fragment and forbidden bytes in path+query */
    for (size_t k = 0; k < rest_len; k++) {
        unsigned char c = (unsigned char)rest[k];
        if (c == '#') return -1; /* fragment — caller bug */
        if (is_forbidden_uri_byte(c)) return -1;
    }

    /* Build the canonical path string. */
    char pathbuf[1024];
    size_t pl;
    if (rest_len == 0) {
        pathbuf[0] = '/';
        pl = 1;
    } else if (rest[0] == '?') {
        /* query only → prepend "/" */
        if (rest_len + 1 > sizeof(pathbuf) - 1) return -1;
        pathbuf[0] = '/';
        memcpy(pathbuf + 1, rest, rest_len);
        pl = rest_len + 1;
    } else {
        /* starts with '/' */
        if (rest_len > sizeof(pathbuf) - 1) return -1;
        memcpy(pathbuf, rest, rest_len);
        pl = rest_len;
    }
    /* pl is now <= 1023; NUL terminates within bounds */

    /* Commit to *out only after every check passed. */
    memcpy(out->scheme, scheme, strlen(scheme) + 1);
    memcpy(out->authority, auth, a_len);
    out->authority[a_len] = '\0';
    memcpy(out->path, pathbuf, pl);
    out->path[pl] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------------
 * Method parsing
 * ------------------------------------------------------------------------- */
int
mq_gw_parse_method(const char *s, size_t len, char out[16])
{
    if (len == 0 || len > 15) return -1;
    char tmp[16];
    for (size_t i = 0; i < len; i++) {
        if (!mq_gw_is_tchar((unsigned char)s[i])) return -1;
        tmp[i] = uc(s[i]);
    }
    memcpy(out, tmp, len);
    out[len] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------------
 * Strip predicates
 * ------------------------------------------------------------------------- */
int
mq_gw_strip_hop(const char *n, size_t nl)
{
    static const char *const hop[] = {
        "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
        "TE",         "Trailer",    "Transfer-Encoding",  "Upgrade",
    };
    for (size_t i = 0; i < sizeof(hop) / sizeof(hop[0]); i++)
        if (name_eq(n, nl, hop[i])) return 1;
    return 0;
}

int
mq_gw_strip_client(const char *n, size_t nl)
{
    if (mq_gw_strip_hop(n, nl)) return 1;
    if (name_has_prefix(n, nl, "X-Mq-")) return 1;
    if (name_eq(n, nl, "Host")) return 1;
    if (name_eq(n, nl, "Content-Length")) return 1;
    if (name_eq(n, nl, "Cookie")) return 1;
    return 0;
}

int
mq_gw_strip_server(const char *n, size_t nl)
{
    if (mq_gw_strip_hop(n, nl)) return 1;
    if (name_has_prefix(n, nl, "X-Mq-")) return 1;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Duplicate X-Mq-* detection
 * ------------------------------------------------------------------------- */
int
mq_gw_has_dup_xmq(const mq_http1_req_t *req)
{
    for (size_t i = 0; i < req->nh; i++) {
        if (!name_has_prefix(req->h[i].n, req->h[i].nl, "X-Mq-")) continue;
        for (size_t j = i + 1; j < req->nh; j++) {
            if (req->h[i].nl != req->h[j].nl) continue;
            int eq = 1;
            for (size_t k = 0; k < req->h[i].nl; k++)
                if (lc(req->h[i].n[k]) != lc(req->h[j].n[k])) {
                    eq = 0;
                    break;
                }
            if (eq) return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Control-byte rejection
 * ------------------------------------------------------------------------- */
int
mq_gw_hdr_name_ok(const char *s, size_t sl)
{
    for (size_t i = 0; i < sl; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return 0; /* controls (incl. TAB) + DEL */
    }
    return 1;
}

int
mq_gw_hdr_value_ok(const char *s, size_t sl)
{
    for (size_t i = 0; i < sl; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x09) continue;             /* HTAB is permitted in values */
        if (c < 0x20 || c == 0x7f) return 0; /* other controls + DEL */
    }
    return 1;
}

int
mq_gw_uri_field_ok(const char *s, size_t sl)
{
    /* is_forbidden_uri_byte already covers SP, all controls (<0x20, includes
     * CR/LF), and 0x7f. */
    for (size_t i = 0; i < sl; i++)
        if (is_forbidden_uri_byte((unsigned char)s[i])) return 0;
    return 1;
}

/* ---------------------------------------------------------------------------
 * curl result code → HTTP status (design §10.1)
 * ------------------------------------------------------------------------- */
int
mq_gw_status_from_curl(int curl_code)
{
    switch (curl_code) {
    case MQ_GW_CURL_TIMEDOUT: return 504;
    case MQ_GW_CURL_RESOLVE:
    case MQ_GW_CURL_CONNECT:
    case MQ_GW_CURL_PEER_VERIFY:
    default: return 502;
    }
}
