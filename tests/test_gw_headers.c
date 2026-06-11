// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "gateway/mq_gw_headers.h"
#include "gateway/mq_http1.h"
#include "mqtest.h"
#include <stdint.h>
#include <string.h>

/* ===================================================================
 * mq_gw_parse_target
 * =================================================================== */

/* small helper: parse a NUL-terminated literal, return rc */
static int
pt(const char *s, mq_gw_target_t *out)
{
    return mq_gw_parse_target(s, strlen(s), out);
}

/* ---- https with path+query preserved ---- */
static void
test_target_https_full(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://example.com/foo/bar?x=1&y=2", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.scheme, "https"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "example.com"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/foo/bar?x=1&y=2"), 0);
}

/* ---- plain http ---- */
static void
test_target_http(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("http://example.com/x", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.scheme, "http"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "example.com"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/x"), 0);
}

/* ---- no path → "/" ---- */
static void
test_target_no_path(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://example.com", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "example.com"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/"), 0);
}

/* ---- "?q=1" only (no path segment) → "/?q=1" ---- */
static void
test_target_query_only(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://example.com?q=1", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "example.com"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/?q=1"), 0);
}

/* ---- explicit port preserved in authority ---- */
static void
test_target_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h:8443/x", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "h:8443"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/x"), 0);
}

/* ---- bracketed IPv6 with port ---- */
static void
test_target_ipv6(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[::1]:443/", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "[::1]:443"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/"), 0);
}

/* ---- bracketed IPv6 without port ---- */
static void
test_target_ipv6_no_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[2001:db8::1]/p", &t), 0);
    MQ_CHECK_EQ_INT(strcmp(t.authority, "[2001:db8::1]"), 0);
    MQ_CHECK_EQ_INT(strcmp(t.path, "/p"), 0);
}

/* ---- bad port (non-digit) → reject ---- */
static void
test_target_bad_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h:12ab/x", &t), -1);
}

/* ---- empty port "h:" → reject ---- */
static void
test_target_empty_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h:/x", &t), -1);
}

/* ---- unsupported scheme ftp → reject ---- */
static void
test_target_ftp(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("ftp://example.com/x", &t), -1);
}

/* ---- uppercase scheme rejected (documented: lowercase only) ---- */
static void
test_target_upper_scheme(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("HTTPS://example.com/x", &t), -1);
}

/* ---- empty authority → reject ---- */
static void
test_target_empty_authority(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https:///path", &t), -1);
}

/* ---- userinfo (u@h) → reject (credential-injection surface) ---- */
static void
test_target_userinfo(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://u@h/x", &t), -1);
    MQ_CHECK_EQ_INT(pt("https://u:p@h/x", &t), -1);
}

/* ---- space in path → reject ---- */
static void
test_target_space_in_path(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h/a b", &t), -1);
}

/* ---- control byte 0x1f in path → reject ---- */
static void
test_target_ctrl_in_path(void)
{
    mq_gw_target_t t;
    static const char S[] = "https://h/a\x1f"
                            "b";
    MQ_CHECK_EQ_INT(mq_gw_parse_target(S, sizeof(S) - 1, &t), -1);
}

/* ---- control byte / space in authority → reject ---- */
static void
test_target_ctrl_in_authority(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h ost/x", &t), -1);
    static const char S[] = "https://h\x01"
                            "ost/x";
    MQ_CHECK_EQ_INT(mq_gw_parse_target(S, sizeof(S) - 1, &t), -1);
}

/* ---- fragment → reject (fetch target with fragment is a caller bug) ---- */
static void
test_target_fragment(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://h/x#frag", &t), -1);
    /* fragment with no path */
    MQ_CHECK_EQ_INT(pt("https://h#frag", &t), -1);
}

/* ---- authority > 255 bytes → reject ---- */
static void
test_target_authority_too_long(void)
{
    char buf[8 + 300 + 8];
    int n = snprintf(buf, sizeof buf, "https://");
    for (int i = 0; i < 256; i++) /* 256 > 255 */
        buf[n++] = 'a';
    n += snprintf(buf + n, sizeof buf - (size_t)n, "/x");
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(mq_gw_parse_target(buf, (size_t)n, &t), -1);
}

/* ---- path+query > 1023 bytes → reject ---- */
static void
test_target_path_too_long(void)
{
    char buf[8 + 16 + 1200];
    int n = snprintf(buf, sizeof buf, "https://h/");
    for (int i = 0; i < 1024; i++) /* path becomes 1+1024 = 1025 > 1023 */
        buf[n++] = 'a';
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(mq_gw_parse_target(buf, (size_t)n, &t), -1);
}

/* ---- empty input → reject ---- */
static void
test_target_empty(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(mq_gw_parse_target("", 0, &t), -1);
}

/* ---- [DEFECT-1] stray '[' not at position 0 → authority injection → reject ---- */
static void
test_target_stray_open_bracket(void)
{
    mq_gw_target_t t;
    /* '[' at offset 3 in authority: the '/' after the bracket is swallowed
     * and the entire "foo[bar/x" would reach the backend as host — reject. */
    MQ_CHECK_EQ_INT(pt("https://foo[bar/x", &t), -1);
}

/* ---- [DEFECT-2] non-bracket host with embedded colon (h:80:90) → reject ---- */
static void
test_target_double_colon_port(void)
{
    mq_gw_target_t t;
    /* last-colon split leaves "h:80" as host which contains ':' — illegal */
    MQ_CHECK_EQ_INT(pt("https://h:80:90/x", &t), -1);
}

/* ---- [DEFECT-3] leading ']' with no opening '[' → reject ---- */
static void
test_target_lone_close_bracket(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://]nobracket/x", &t), -1);
    MQ_CHECK_EQ_INT(pt("https://]/x", &t), -1);
}

/* ---- IPv6: junk immediately after ']' (no ':') → reject ---- */
static void
test_target_ipv6_junk_after_bracket(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[::1]x80/", &t), -1);
}

/* ---- IPv6: empty port after ']' → reject ---- */
static void
test_target_ipv6_empty_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[::1]:/", &t), -1);
}

/* ---- IPv6: non-digit port after ']' → reject ---- */
static void
test_target_ipv6_bad_port(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[::1]:80x/", &t), -1);
}

/* ---- IPv6: unclosed '[' → reject ---- */
static void
test_target_ipv6_unclosed(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[unclosed/", &t), -1);
}

/* ---- IPv6: empty bracket host '[]:80' → reject ---- */
static void
test_target_ipv6_empty_host(void)
{
    mq_gw_target_t t;
    MQ_CHECK_EQ_INT(pt("https://[]:80/", &t), -1);
}

/* ===================================================================
 * mq_gw_parse_method
 * =================================================================== */

static void
test_method_lower(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("get", 3, out), 0);
    MQ_CHECK_EQ_INT(strcmp(out, "GET"), 0);
}

static void
test_method_mixed(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("PuT", 3, out), 0);
    MQ_CHECK_EQ_INT(strcmp(out, "PUT"), 0);
}

/* token chars (RFC 7230) acceptable, e.g. with '-' '!' '.' */
static void
test_method_token_chars(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("M-E.T!", 6, out), 0);
    MQ_CHECK_EQ_INT(strcmp(out, "M-E.T!"), 0);
}

/* 16-char method → reject (>15) */
static void
test_method_too_long(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("ABCDEFGHIJKLMNOP", 16, out), -1);
}

/* 15-char method → ok (boundary) */
static void
test_method_15_ok(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("ABCDEFGHIJKLMNO", 15, out), 0);
    MQ_CHECK_EQ_INT(strcmp(out, "ABCDEFGHIJKLMNO"), 0);
}

/* space in method → reject (not a token char) */
static void
test_method_space(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("GE T", 4, out), -1);
}

/* empty method → reject */
static void
test_method_empty(void)
{
    char out[16];
    MQ_CHECK_EQ_INT(mq_gw_parse_method("", 0, out), -1);
}

/* ===================================================================
 * strip predicates
 * =================================================================== */

/* helper to call by NUL-terminated name */
static int
sc(const char *n)
{
    return mq_gw_strip_client(n, strlen(n), 0);
}
static int
scf(const char *n)
{
    return mq_gw_strip_client(n, strlen(n), 1);
}
static int
ss(const char *n)
{
    return mq_gw_strip_server(n, strlen(n));
}
static int
sh(const char *n)
{
    return mq_gw_strip_hop(n, strlen(n));
}

/* hop-by-hop names: stripped by all three predicates, mixed case */
static void
test_strip_hop_names(void)
{
    static const char *hop[] = {
        "Connection", "keep-alive", "Proxy-Authenticate", "proxy-authorization",
        "TE",         "Trailer",    "Transfer-Encoding",  "Upgrade",
    };
    for (size_t i = 0; i < sizeof(hop) / sizeof(hop[0]); i++) {
        MQ_CHECK_EQ_INT(sh(hop[i]), 1);
        MQ_CHECK_EQ_INT(sc(hop[i]), 1); /* client strips hop too */
        MQ_CHECK_EQ_INT(ss(hop[i]), 1); /* server strips hop too */
    }
    /* mixed case variant */
    MQ_CHECK_EQ_INT(sh("CoNnEcTiOn"), 1);
    MQ_CHECK_EQ_INT(sh("TRANSFER-ENCODING"), 1);
}

/* client→tunnel: X-Mq-*, Host, Content-Length, Cookie all stripped */
static void
test_strip_client_names(void)
{
    MQ_CHECK_EQ_INT(sc("X-Mq-Target"), 1);
    MQ_CHECK_EQ_INT(sc("X-Mq-Anything"), 1);
    MQ_CHECK_EQ_INT(sc("x-mq-auth"), 1);
    MQ_CHECK_EQ_INT(sc("Host"), 1);
    MQ_CHECK_EQ_INT(sc("host"), 1);
    MQ_CHECK_EQ_INT(sc("Content-Length"), 1);
    MQ_CHECK_EQ_INT(sc("Cookie"), 1);
    MQ_CHECK_EQ_INT(sc("COOKIE"), 1);
}

/* server→origin: x-mq-* stripped, but Host/Content-Length/Cookie NOT */
static void
test_strip_server_names(void)
{
    MQ_CHECK_EQ_INT(ss("X-Mq-Target"), 1);
    MQ_CHECK_EQ_INT(ss("x-mq-auth"), 1);
    /* server does NOT strip these (only x-mq-* + hop-by-hop) */
    MQ_CHECK_EQ_INT(ss("Host"), 0);
    MQ_CHECK_EQ_INT(ss("Cookie"), 0);
    MQ_CHECK_EQ_INT(ss("Content-Length"), 0);
}

/* CRITICAL: Authorization is default-forwarded — stripped by NONE */
static void
test_authorization_forwarded(void)
{
    MQ_CHECK_EQ_INT(sc("Authorization"), 0);
    MQ_CHECK_EQ_INT(ss("Authorization"), 0);
    MQ_CHECK_EQ_INT(sh("Authorization"), 0);
    /* mixed case too */
    MQ_CHECK_EQ_INT(sc("authorization"), 0);
}

/* Accept: ordinary header, stripped by none */
static void
test_accept_forwarded(void)
{
    MQ_CHECK_EQ_INT(sc("Accept"), 0);
    MQ_CHECK_EQ_INT(ss("Accept"), 0);
    MQ_CHECK_EQ_INT(sh("Accept"), 0);
}

/* Cookie: client strips, server does not */
static void
test_cookie_asymmetry(void)
{
    MQ_CHECK_EQ_INT(sc("Cookie"), 1);
    MQ_CHECK_EQ_INT(ss("Cookie"), 0);
}

/* Content-Length: client strips but it is NOT hop-by-hop */
static void
test_content_length_not_hop(void)
{
    MQ_CHECK_EQ_INT(sc("Content-Length"), 1);
    MQ_CHECK_EQ_INT(sh("Content-Length"), 0);
}

/* X-Mq prefix boundary: "X-Mqx" is NOT x-mq-* (needs "x-mq-" prefix) */
static void
test_xmq_prefix_boundary(void)
{
    /* "X-Mq" exactly and "X-Mqq" should NOT match the X-Mq-* family. */
    MQ_CHECK_EQ_INT(sc("X-Mq"), 0);
    MQ_CHECK_EQ_INT(sc("X-Mqq"), 0);
    MQ_CHECK_EQ_INT(ss("X-Mq"), 0);
}

/* ===================================================================
 * mq_gw_has_dup_xmq
 * =================================================================== */

/* tiny req builder: set header slices directly (no parser needed) */
static void
set_h(mq_http1_req_t *r, size_t i, const char *n, const char *v)
{
    r->h[i].n = n;
    r->h[i].nl = strlen(n);
    r->h[i].v = v;
    r->h[i].vl = strlen(v);
}

/* two X-Mq-Auth → dup */
static void
test_dup_two_xmq(void)
{
    mq_http1_req_t r;
    memset(&r, 0, sizeof r);
    set_h(&r, 0, "X-Mq-Auth", "a");
    set_h(&r, 1, "X-Mq-Auth", "b");
    r.nh = 2;
    MQ_CHECK_EQ_INT(mq_gw_has_dup_xmq(&r), 1);
}

/* X-Mq-Auth + X-Mq-Target (different x-mq names) → not dup */
static void
test_dup_distinct_xmq(void)
{
    mq_http1_req_t r;
    memset(&r, 0, sizeof r);
    set_h(&r, 0, "X-Mq-Auth", "a");
    set_h(&r, 1, "X-Mq-Target", "https://h/");
    r.nh = 2;
    MQ_CHECK_EQ_INT(mq_gw_has_dup_xmq(&r), 0);
}

/* two Accept (non x-mq) → not dup (only x-mq-* counted) */
static void
test_dup_non_xmq(void)
{
    mq_http1_req_t r;
    memset(&r, 0, sizeof r);
    set_h(&r, 0, "Accept", "a");
    set_h(&r, 1, "Accept", "b");
    r.nh = 2;
    MQ_CHECK_EQ_INT(mq_gw_has_dup_xmq(&r), 0);
}

/* case-insensitive dup: x-mq-auth + X-MQ-AUTH → dup */
static void
test_dup_case_insensitive(void)
{
    mq_http1_req_t r;
    memset(&r, 0, sizeof r);
    set_h(&r, 0, "x-mq-auth", "a");
    set_h(&r, 1, "X-MQ-AUTH", "b");
    r.nh = 2;
    MQ_CHECK_EQ_INT(mq_gw_has_dup_xmq(&r), 1);
}

/* no headers → not dup */
static void
test_dup_empty(void)
{
    mq_http1_req_t r;
    memset(&r, 0, sizeof r);
    r.nh = 0;
    MQ_CHECK_EQ_INT(mq_gw_has_dup_xmq(&r), 0);
}

/* ===================================================================
 * mq_gw_forward_cookie_requested
 * =================================================================== */

static void
test_forward_cookie_requested(void)
{
    mq_http1_req_t r;
    set_h(&r, 0, "X-Mq-Forward-Cookie", "true");
    r.nh = 1;
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 1);
    set_h(&r, 0, "x-mq-forward-cookie", "TRUE");
    r.nh = 1; /* name + value case-insensitive */
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 1);
    /* No OWS-padded case: mq_http1_parse_req OWS-trims values before the helper sees
     * them, so the helper sees only trimmed values and intentionally does not trim. */
    set_h(&r, 0, "X-Mq-Forward-Cookie", "false");
    r.nh = 1;
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 0);
    set_h(&r, 0, "X-Mq-Forward-Cookie", "1");
    r.nh = 1;
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 0);
    set_h(&r, 0, "X-Mq-Forward-Cookie", "");
    r.nh = 1;
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 0);
    set_h(&r, 0, "Accept", "*/*");
    r.nh = 1; /* header absent */
    MQ_CHECK_EQ_INT(mq_gw_forward_cookie_requested(&r), 0);
}

static void
test_cookie_forward_optin(void)
{
    /* forward_cookie=1 (scf): ONLY Cookie's strip decision flips; every other strip is
     * unaffected by the flag, and the opt-in header itself is still stripped.
     * (sc("Cookie")==1 for forward_cookie=0 is already covered by test_cookie_asymmetry /
     * test_strip_client_names.) */
    MQ_CHECK_EQ_INT(scf("Cookie"), 0); /* opted in: NOT stripped */
    MQ_CHECK_EQ_INT(scf("cookie"), 0); /* case-insensitive */
    MQ_CHECK_EQ_INT(scf("Host"), 1);   /* a non-Cookie strip is flag-independent */
    MQ_CHECK_EQ_INT(scf("X-Mq-Forward-Cookie"),
                    1); /* the opt-in header is still stripped */
}

/* ===================================================================
 * mq_gw_status_from_curl
 * =================================================================== */

static void
test_curl_map(void)
{
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(MQ_GW_CURL_RESOLVE), 502);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(MQ_GW_CURL_CONNECT), 502);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(MQ_GW_CURL_TIMEDOUT), 504);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(MQ_GW_CURL_PEER_VERIFY), 502);
    /* raw constants per design §10.1 */
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(6), 502);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(7), 502);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(28), 504);
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(60), 502);
    /* unknown / unexpected → 502 */
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(999), 502);
    /* 0 (CURLE_OK) — should not be called with success; defensive 502 */
    MQ_CHECK_EQ_INT(mq_gw_status_from_curl(0), 502);
}

/* ===================================================================
 * mq_gw_parse_http_ver
 * =================================================================== */

static void
test_parse_http_ver(void)
{
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("h3", 2), MQ_HTTP_VER_H3);
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("H3", 2), MQ_HTTP_VER_H3); /* case-insensitive */
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("h2", 2), MQ_HTTP_VER_H2);
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("h1", 2), MQ_HTTP_VER_H1);
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("h0", 2), MQ_HTTP_VER_DEFAULT); /* unknown */
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("h3x", 3),
                    MQ_HTTP_VER_DEFAULT); /* valid prefix + junk */
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("http3", 5), MQ_HTTP_VER_DEFAULT); /* unknown */
    MQ_CHECK_EQ_INT(mq_gw_parse_http_ver("", 0), MQ_HTTP_VER_DEFAULT);      /* empty */
}

MQ_TEST_MAIN({
    /* target */
    test_target_https_full();
    test_target_http();
    test_target_no_path();
    test_target_query_only();
    test_target_port();
    test_target_ipv6();
    test_target_ipv6_no_port();
    test_target_bad_port();
    test_target_empty_port();
    test_target_ftp();
    test_target_upper_scheme();
    test_target_empty_authority();
    test_target_userinfo();
    test_target_space_in_path();
    test_target_ctrl_in_path();
    test_target_ctrl_in_authority();
    test_target_fragment();
    test_target_authority_too_long();
    test_target_path_too_long();
    test_target_empty();
    /* bracket/colon defects */
    test_target_stray_open_bracket();
    test_target_double_colon_port();
    test_target_lone_close_bracket();
    test_target_ipv6_junk_after_bracket();
    test_target_ipv6_empty_port();
    test_target_ipv6_bad_port();
    test_target_ipv6_unclosed();
    test_target_ipv6_empty_host();
    /* method */
    test_method_lower();
    test_method_mixed();
    test_method_token_chars();
    test_method_too_long();
    test_method_15_ok();
    test_method_space();
    test_method_empty();
    /* strip */
    test_strip_hop_names();
    test_strip_client_names();
    test_strip_server_names();
    test_authorization_forwarded();
    test_accept_forwarded();
    test_cookie_asymmetry();
    test_content_length_not_hop();
    test_xmq_prefix_boundary();
    /* dup */
    test_dup_two_xmq();
    test_dup_distinct_xmq();
    test_dup_non_xmq();
    test_dup_case_insensitive();
    test_dup_empty();
    /* forward cookie */
    test_forward_cookie_requested();
    test_cookie_forward_optin();
    /* curl map */
    test_curl_map();
    /* origin http version parse */
    test_parse_http_ver();
})
