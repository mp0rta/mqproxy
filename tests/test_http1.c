// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "gateway/mq_http1.h"
#include "mqtest.h"
#include <stdint.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Helper: find a header slice by (case-insensitive) name. Returns index or -1.
 * ------------------------------------------------------------------------- */
static int
find_h(const mq_http1_req_t *r, const char *name)
{
    size_t nl = strlen(name);
    for (size_t i = 0; i < r->nh; i++) {
        if (r->h[i].nl == nl) {
            int eq = 1;
            for (size_t j = 0; j < nl; j++) {
                char a = r->h[i].n[j], b = name[j];
                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                if (a != b) {
                    eq = 0;
                    break;
                }
            }
            if (eq) return (int)i;
        }
    }
    return -1;
}

/* ---- normal POST /_mqproxy/fetch with headers + Content-Length ---- */
static void
test_normal_post(void)
{
    static const char REQ[] = "POST /_mqproxy/fetch HTTP/1.1\r\n"
                              "Host: localhost\r\n"
                              "Content-Type: application/json\r\n"
                              "Content-Length: 11\r\n"
                              "\r\n"
                              "hello world"; /* body — not consumed by head parse */
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(strcmp(r.method, "POST"), 0);
    MQ_CHECK_EQ_INT(strcmp(r.path, "/_mqproxy/fetch"), 0);
    MQ_CHECK_EQ_INT(r.content_length, 11);
    MQ_CHECK_EQ_INT(r.has_chunked_te, 0);
    MQ_CHECK_EQ_INT(r.nh, 3);

    int idx = find_h(&r, "content-type");
    MQ_CHECK(idx >= 0);
    if (idx >= 0) {
        MQ_CHECK_EQ_INT(r.h[idx].vl, strlen("application/json"));
        MQ_CHECK_MEM(r.h[idx].v, "application/json", r.h[idx].vl);
    }
    /* head_len = bytes up to and including blank line (not the body). */
    MQ_CHECK_EQ_INT(r.head_len, (size_t)((sizeof(REQ) - 1) - 11));
}

/* ---- OWS trimming: value with leading/trailing spaces+tabs ---- */
static void
test_ows_trim(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "X-Trim: \t  value here  \t\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    int idx = find_h(&r, "x-trim");
    MQ_CHECK(idx >= 0);
    if (idx >= 0) {
        MQ_CHECK_EQ_INT(r.h[idx].vl, strlen("value here"));
        MQ_CHECK_MEM(r.h[idx].v, "value here", r.h[idx].vl);
    }
}

/* ---- split arrival: prefix -> NEED_MORE, full -> DONE, same out ---- */
static void
test_split_arrival(void)
{
    static const char FULL[] = "POST /_mqproxy/fetch HTTP/1.1\r\n"
                               "Content-Length: 0\r\n"
                               "\r\n";
    size_t full_len = sizeof(FULL) - 1;

    /* Feed everything except the final LF (terminator incomplete). */
    mq_http1_req_t r1;
    mq_http1_status_t st1 = mq_http1_parse_req((const uint8_t *)FULL, full_len - 1, &r1);
    MQ_CHECK_EQ_INT(st1, MQ_HTTP1_NEED_MORE);

    /* Feed the whole thing → DONE. */
    mq_http1_req_t r2;
    mq_http1_status_t st2 = mq_http1_parse_req((const uint8_t *)FULL, full_len, &r2);
    MQ_CHECK_EQ_INT(st2, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(strcmp(r2.method, "POST"), 0);
    MQ_CHECK_EQ_INT(strcmp(r2.path, "/_mqproxy/fetch"), 0);
    MQ_CHECK_EQ_INT(r2.content_length, 0);
    MQ_CHECK_EQ_INT(r2.head_len, full_len);
}

/* ---- obs-fold (continuation line) → BAD (smuggling vector) ---- */
static void
test_obs_fold(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "X-Fold: a\r\n"
                              " continued\r\n" /* leading SP = obs-fold */
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);

    static const char REQ_TAB[] = "GET / HTTP/1.1\r\n"
                                  "X-Fold: a\r\n"
                                  "\tcontinued\r\n" /* leading HTAB = obs-fold */
                                  "\r\n";
    mq_http1_req_t r2;
    st = mq_http1_parse_req((const uint8_t *)REQ_TAB, sizeof(REQ_TAB) - 1, &r2);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- method too long (>15) → BAD ---- */
static void
test_method_too_long(void)
{
    static const char REQ[] = "ABCDEFGHIJKLMNOP / HTTP/1.1\r\n\r\n"; /* 16 chars */
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- non-token method char → BAD ---- */
static void
test_method_non_token(void)
{
    static const char REQ[] = "PO()ST / HTTP/1.1\r\n\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- path not starting with '/' → BAD ---- */
static void
test_path_not_slash(void)
{
    static const char REQ[] = "GET http://x/ HTTP/1.1\r\n\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- duplicate Content-Length: identical → BAD ---- */
static void
test_cl_dup_identical(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 5\r\n"
                              "Content-Length: 5\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- duplicate Content-Length: differing → BAD ---- */
static void
test_cl_dup_differing(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 5\r\n"
                              "Content-Length: 6\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- Content-Length non-numeric → BAD ---- */
static void
test_cl_non_numeric(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 12x\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- Content-Length empty → BAD ---- */
static void
test_cl_empty(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: \r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- Content-Length valid big value (fits int64) ---- */
static void
test_cl_big(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 9223372036854775807\r\n" /* INT64_MAX */
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.content_length, (int64_t)9223372036854775807LL);
}

/* ---- Content-Length overflow (> INT64_MAX) → BAD ---- */
static void
test_cl_overflow(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 99999999999999999999\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- Transfer-Encoding chunked detection (mixed case) ---- */
static void
test_te_chunked(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Transfer-Encoding: Chunked\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.has_chunked_te, 1);
    MQ_CHECK_EQ_INT(r.content_length, -1);
}

/* ---- TE chunked among a comma list (gzip, chunked) ---- */
static void
test_te_chunked_list(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Transfer-Encoding: gzip, chunked\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.has_chunked_te, 1);
}

/* ---- CL + TE simultaneously: both populated; caller decides ---- */
static void
test_cl_and_te(void)
{
    static const char REQ[] = "POST / HTTP/1.1\r\n"
                              "Content-Length: 5\r\n"
                              "Transfer-Encoding: chunked\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.content_length, 5);
    MQ_CHECK_EQ_INT(r.has_chunked_te, 1);
}

/* ---- Content-Length absent → -1 ---- */
static void
test_cl_absent(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.content_length, -1);
}

/* ---- >64 headers → BAD ---- */
static void
test_too_many_headers(void)
{
    char buf[4096];
    int n = snprintf(buf, sizeof buf, "GET / HTTP/1.1\r\n");
    for (int i = 0; i < 65; i++) /* 65 > 64 */
        n += snprintf(buf + n, sizeof buf - (size_t)n, "X-H%d: v\r\n", i);
    n += snprintf(buf + n, sizeof buf - (size_t)n, "\r\n");
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)buf, (size_t)n, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- exactly 64 headers → DONE (boundary) ---- */
static void
test_exactly_64_headers(void)
{
    char buf[4096];
    int n = snprintf(buf, sizeof buf, "GET / HTTP/1.1\r\n");
    for (int i = 0; i < 64; i++)
        n += snprintf(buf + n, sizeof buf - (size_t)n, "X-H%d: v\r\n", i);
    n += snprintf(buf + n, sizeof buf - (size_t)n, "\r\n");
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)buf, (size_t)n, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.nh, 64);
}

/* ---- head exceeds max (16 KiB) with no terminator → BAD ---- */
static void
test_head_too_big(void)
{
    /* 17 KiB of a never-terminating request line. */
    size_t cap = 17 * 1024;
    char *buf = malloc(cap);
    memset(buf, 'a', cap);
    memcpy(buf, "GET /", 5); /* keep it superficially valid-looking */
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)buf, cap, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
    free(buf);
}

/* ---- embedded NUL in value → BAD ---- */
static void
test_embedded_nul(void)
{
    /* "X-Bad: a\0b" — NUL inside the value. Build manually (can't use strlen). */
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "X-Bad: a\0b\r\n"
                              "\r\n";
    /* sizeof includes the trailing implicit NUL; we want the exact crafted len. */
    size_t len = sizeof(REQ) - 1;
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, len, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- embedded bare CR in value → BAD ---- */
static void
test_embedded_cr(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "X-Bad: a\rb\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- header with no colon → BAD ---- */
static void
test_header_no_colon(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "NoColonHere\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- empty header name (leading colon) → BAD ---- */
static void
test_header_empty_name(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              ": value\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- non-token char in header name → BAD ---- */
static void
test_header_name_non_token(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "Bad Name: v\r\n" /* space in name */
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- duplicate non-CL header names preserved in order (not collapsed) ---- */
static void
test_dup_headers_preserved(void)
{
    static const char REQ[] = "GET / HTTP/1.1\r\n"
                              "X-Mq-Tag: a\r\n"
                              "X-Mq-Tag: b\r\n"
                              "\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_DONE);
    MQ_CHECK_EQ_INT(r.nh, 2);
    MQ_CHECK_EQ_INT(r.h[0].vl, 1);
    MQ_CHECK_MEM(r.h[0].v, "a", 1);
    MQ_CHECK_EQ_INT(r.h[1].vl, 1);
    MQ_CHECK_MEM(r.h[1].v, "b", 1);
}

/* ---- embedded NUL in path → BAD (NUL-injection/truncation vector) ---- */
static void
test_path_nul(void)
{
    /* "GET /a\0b HTTP/1.1\r\n\r\n" — must use sizeof, not strlen. */
    static const char REQ[] = "GET /a\0b HTTP/1.1\r\n\r\n";
    size_t len = sizeof(REQ) - 1;
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, len, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- control byte 0x1f in path → BAD (same injection class) ---- */
static void
test_path_ctrl_1f(void)
{
    /* "GET /a\x1fb HTTP/1.1\r\n\r\n" — split to avoid \x1fb being treated as
     * a single (out-of-range) hex escape. */
    static const char REQ[] = "GET /a\x1f"
                              "b HTTP/1.1\r\n\r\n";
    size_t len = sizeof(REQ) - 1;
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, len, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- DEL (0x7f) in path → BAD (same injection class) ---- */
static void
test_path_del(void)
{
    /* "GET /a\x7fb HTTP/1.1\r\n\r\n" — split to avoid \x7fb being treated as
     * a single (out-of-range) hex escape by some compilers. */
    static const char REQ[] = "GET /a\x7f"
                              "b HTTP/1.1\r\n\r\n";
    size_t len = sizeof(REQ) - 1;
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, len, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- oversized path (> path buffer) → BAD ---- */
static void
test_path_too_long(void)
{
    char buf[2048];
    int n = snprintf(buf, sizeof buf, "GET /");
    for (int i = 0; i < 1100; i++) /* path > 1024 */
        buf[n++] = 'a';
    n += snprintf(buf + n, sizeof buf - (size_t)n, " HTTP/1.1\r\n\r\n");
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)buf, (size_t)n, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ---- missing HTTP version field → BAD ---- */
static void
test_no_version(void)
{
    static const char REQ[] = "GET /\r\n\r\n";
    mq_http1_req_t r;
    mq_http1_status_t st = mq_http1_parse_req((const uint8_t *)REQ, sizeof(REQ) - 1, &r);
    MQ_CHECK_EQ_INT(st, MQ_HTTP1_BAD);
}

/* ====================  serializer  ==================== */

/* ---- write_status exact format ---- */
static void
test_write_status(void)
{
    char buf[64];
    memset(buf, 0xAB, sizeof buf);
    int n = mq_http1_write_status(buf, sizeof buf, 200, "OK");
    static const char expect[] = "HTTP/1.1 200 OK\r\n";
    MQ_CHECK_EQ_INT(n, (int)(sizeof(expect) - 1));
    MQ_CHECK_MEM(buf, expect, sizeof(expect) - 1);

    int n2 = mq_http1_write_status(buf, sizeof buf, 411, "Length Required");
    static const char expect2[] = "HTTP/1.1 411 Length Required\r\n";
    MQ_CHECK_EQ_INT(n2, (int)(sizeof(expect2) - 1));
    MQ_CHECK_MEM(buf, expect2, sizeof(expect2) - 1);
}

/* ---- write_status cap too small → negative, nothing written ---- */
static void
test_write_status_too_small(void)
{
    char buf[8];
    memset(buf, 0xAB, sizeof buf);
    int n = mq_http1_write_status(buf, sizeof buf, 200, "OK"); /* needs 17 */
    MQ_CHECK(n < 0);
    MQ_CHECK_EQ_INT((unsigned char)buf[0], 0xAB);
}

/* ---- write_header exact format ---- */
static void
test_write_header(void)
{
    char buf[64];
    memset(buf, 0xAB, sizeof buf);
    int n = mq_http1_write_header(buf, sizeof buf, "Content-Length", "42");
    static const char expect[] = "Content-Length: 42\r\n";
    MQ_CHECK_EQ_INT(n, (int)(sizeof(expect) - 1));
    MQ_CHECK_MEM(buf, expect, sizeof(expect) - 1);
}

/* ---- write_header cap too small → negative, nothing written ---- */
static void
test_write_header_too_small(void)
{
    char buf[4];
    memset(buf, 0xAB, sizeof buf);
    int n = mq_http1_write_header(buf, sizeof buf, "Content-Length", "42");
    MQ_CHECK(n < 0);
    MQ_CHECK_EQ_INT((unsigned char)buf[0], 0xAB);
}

/* ---- chunk_frame exact bytes for a known 5-byte payload ---- */
static void
test_chunk_frame(void)
{
    char buf[64];
    size_t n = mq_http1_chunk_frame(buf, sizeof buf, (const uint8_t *)"hello", 5);
    static const char expect[] = "5\r\nhello\r\n";
    MQ_CHECK_EQ_INT(n, sizeof(expect) - 1);
    MQ_CHECK_MEM(buf, expect, sizeof(expect) - 1);
}

/* ---- chunk_frame hex for length > 0xf (26 -> "1a") ---- */
static void
test_chunk_frame_hex(void)
{
    char payload[26];
    memset(payload, 'z', sizeof payload);
    char buf[64];
    size_t n =
        mq_http1_chunk_frame(buf, sizeof buf, (const uint8_t *)payload, sizeof payload);
    static const char prefix[] = "1a\r\n"; /* lowercase hex of 26 */
    MQ_CHECK(n >= sizeof(prefix) - 1);
    MQ_CHECK_MEM(buf, prefix, sizeof(prefix) - 1);
    /* total = "1a\r\n" + 26 + "\r\n" = 4 + 26 + 2 = 32 */
    MQ_CHECK_EQ_INT(n, 4 + 26 + 2);
    MQ_CHECK_MEM(buf + 4, payload, 26);
    MQ_CHECK_MEM(buf + 4 + 26, "\r\n", 2);
}

/* ---- chunk_frame returns 0 when cap too small ---- */
static void
test_chunk_frame_too_small(void)
{
    char buf[6]; /* needs 10 for a 5-byte payload */
    memset(buf, 0xAB, sizeof buf);
    size_t n = mq_http1_chunk_frame(buf, sizeof buf, (const uint8_t *)"hello", 5);
    MQ_CHECK_EQ_INT(n, 0);
    MQ_CHECK_EQ_INT((unsigned char)buf[0], 0xAB);
}

MQ_TEST_MAIN({
    /* parser */
    test_normal_post();
    test_ows_trim();
    test_split_arrival();
    test_obs_fold();
    test_method_too_long();
    test_method_non_token();
    test_path_not_slash();
    test_path_nul();
    test_path_ctrl_1f();
    test_path_del();
    test_cl_dup_identical();
    test_cl_dup_differing();
    test_cl_non_numeric();
    test_cl_empty();
    test_cl_big();
    test_cl_overflow();
    test_te_chunked();
    test_te_chunked_list();
    test_cl_and_te();
    test_cl_absent();
    test_too_many_headers();
    test_exactly_64_headers();
    test_head_too_big();
    test_embedded_nul();
    test_embedded_cr();
    test_header_no_colon();
    test_header_empty_name();
    test_header_name_non_token();
    test_dup_headers_preserved();
    test_path_too_long();
    test_no_version();
    /* serializer */
    test_write_status();
    test_write_status_too_small();
    test_write_header();
    test_write_header_too_small();
    test_chunk_frame();
    test_chunk_frame_hex();
    test_chunk_frame_too_small();
})
