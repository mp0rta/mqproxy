// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// Unit tests for mq_mitm_conn's DECISION seam (Phase 7 Slice 3 Task 10): given a
// fully-drained ClientHello buffer + the recovered orig-dst, route to the opaque
// relay (ignore-hosts hit) or the MITM path (miss), and hard-fail on no/invalid
// SNI. The seam is exercised WITHOUT sockets/TLS: we feed a synthetic ClientHello
// to mq_mitm_conn_decide_for_test with a stub opaque_open (capturing its args)
// and an injected MITM-start hook (capturing branch selection). The live libevent
// drain (on_readable/on_deadline) is covered by the Chunk 6 e2e, not here.
#include "mqtest.h"

#include "mitm/mq_ignore_hosts.h"
#include "mitm/mq_mitm_conn.h"
#include "wire/mq_wire.h"

#include <stdint.h>
#include <string.h>

// Decision-seam entry (declared in the .c without a header — test-only).
typedef enum { R_OPAQUE = 0, R_MITM = 1, R_FAIL = -1 } route_t;
extern int mq_mitm_conn_decide_for_test(mq_mitm_ctx_t *ctx, const uint8_t *buf,
                                        size_t len, const uint8_t *host, size_t host_len,
                                        mq_addr_type_t atype, uint16_t port,
                                        int local_fd);

// ---------------------------------------------------------------------------
// ClientHello byte-array builder (copied from tests/test_clienthello.c).
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t buf[2048];
    size_t len;
} chb_t;

static void
chb_u8(chb_t *b, uint8_t v)
{
    b->buf[b->len++] = v;
}
static void
chb_u16(chb_t *b, uint16_t v)
{
    b->buf[b->len++] = (uint8_t)(v >> 8);
    b->buf[b->len++] = (uint8_t)(v & 0xff);
}
static void
chb_bytes(chb_t *b, const uint8_t *p, size_t n)
{
    memcpy(b->buf + b->len, p, n);
    b->len += n;
}

static void
build_extensions(chb_t *ext, int want_sni, const char *host, int alpn_mode)
{
    if (want_sni) {
        size_t hlen = strlen(host);
        chb_u16(ext, 0x0000);
        uint16_t list_len = (uint16_t)(1 + 2 + hlen);
        chb_u16(ext, (uint16_t)(2 + list_len));
        chb_u16(ext, list_len);
        chb_u8(ext, 0x00);
        chb_u16(ext, (uint16_t)hlen);
        chb_bytes(ext, (const uint8_t *)host, hlen);
    }
    if (alpn_mode != 0) {
        chb_u16(ext, 0x0010);
        chb_t list;
        list.len = 0;
        if (alpn_mode == 1) {
            chb_u8(&list, 2);
            chb_bytes(&list, (const uint8_t *)"h2", 2);
            chb_u8(&list, 8);
            chb_bytes(&list, (const uint8_t *)"http/1.1", 8);
        } else {
            chb_u8(&list, 8);
            chb_bytes(&list, (const uint8_t *)"http/1.1", 8);
        }
        chb_u16(ext, (uint16_t)(2 + list.len));
        chb_u16(ext, (uint16_t)list.len);
        chb_bytes(ext, list.buf, list.len);
    }
}

static void
build_clienthello(chb_t *out, int want_sni, const char *host, int alpn_mode)
{
    chb_t body;
    body.len = 0;
    chb_u16(&body, 0x0303);
    static const uint8_t random32[32] = {0};
    chb_bytes(&body, random32, 32);
    chb_u8(&body, 0x00);
    chb_u16(&body, 0x0002);
    chb_u16(&body, 0x1301);
    chb_u8(&body, 0x01);
    chb_u8(&body, 0x00);

    chb_t ext;
    ext.len = 0;
    build_extensions(&ext, want_sni, host, alpn_mode);
    chb_u16(&body, (uint16_t)ext.len);
    chb_bytes(&body, ext.buf, ext.len);

    chb_t hs;
    hs.len = 0;
    chb_u8(&hs, 0x01);
    chb_u8(&hs, (uint8_t)((body.len >> 16) & 0xff));
    chb_u8(&hs, (uint8_t)((body.len >> 8) & 0xff));
    chb_u8(&hs, (uint8_t)(body.len & 0xff));
    chb_bytes(&hs, body.buf, body.len);

    out->len = 0;
    chb_u8(out, 0x16);
    chb_u16(out, 0x0301);
    chb_u16(out, (uint16_t)hs.len);
    chb_bytes(out, hs.buf, hs.len);
}

// ---------------------------------------------------------------------------
// Stubs / captures
// ---------------------------------------------------------------------------

static struct {
    int called;
    uint8_t host[16];
    size_t host_len;
    mq_addr_type_t atype;
    uint16_t port;
    int local_fd;
    uint8_t prebuf[2048];
    size_t prebuf_len;
} g_opaque;

static void
stub_opaque_open(void *core, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                 uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
                 void *user, mq_tcp_open_cb cb)
{
    (void)core;
    (void)user;
    (void)cb;
    g_opaque.called++;
    g_opaque.host_len =
        host_len <= sizeof(g_opaque.host) ? host_len : sizeof(g_opaque.host);
    memcpy(g_opaque.host, host, g_opaque.host_len);
    g_opaque.atype = atype;
    g_opaque.port = port;
    g_opaque.local_fd = local_fd;
    g_opaque.prebuf_len =
        prebuf_len <= sizeof(g_opaque.prebuf) ? prebuf_len : sizeof(g_opaque.prebuf);
    if (prebuf) memcpy(g_opaque.prebuf, prebuf, g_opaque.prebuf_len);
}

static struct {
    int called;
    char sni[256];
    size_t buf_len;
    int local_fd;
} g_mitm;

static void
mitm_hook(void *hook_user, int local_fd, const uint8_t *buf, size_t len,
          const char *normalized_sni)
{
    (void)hook_user;
    (void)buf;
    g_mitm.called++;
    g_mitm.local_fd = local_fd;
    g_mitm.buf_len = len;
    if (normalized_sni) {
        strncpy(g_mitm.sni, normalized_sni, sizeof(g_mitm.sni) - 1);
        g_mitm.sni[sizeof(g_mitm.sni) - 1] = '\0';
    } else {
        g_mitm.sni[0] = '\0';
    }
}

static void
reset_captures(void)
{
    memset(&g_opaque, 0, sizeof(g_opaque));
    memset(&g_mitm, 0, sizeof(g_mitm));
}

// The recovered orig-dst the tproxy listener would pass: 93.184.216.34:443
// (deliberately NOT the SNI's resolved address — we assert it is forwarded
// UNCHANGED and the SNI is never substituted as the host).
static const uint8_t ORIG_IP[4] = {93, 184, 216, 34};
#define ORIG_PORT 443

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// ignore-hosts HIT → opaque relay called with the drained buffer as prebuf and
// the ORIGINAL host/port (not the SNI).
static void
test_ignore_hit_routes_opaque(void)
{
    reset_captures();
    mq_ignore_hosts_t *ign = mq_ignore_hosts_new();
    MQ_CHECK(ign != NULL);
    MQ_CHECK(mq_ignore_hosts_add(ign, "example.com") == 0); // exact apex

    mq_mitm_ctx_t *ctx =
        mq_mitm_ctx_new(NULL, ign, NULL, stub_opaque_open, (void *)0xC0FFEE,
                        (struct event_base *)0x1 /* base unused by the seam */);
    MQ_CHECK(ctx != NULL);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    chb_t b;
    build_clienthello(&b, 1, "example.com", 1); // SNI=example.com, ALPN h2

    int r = mq_mitm_conn_decide_for_test(ctx, b.buf, b.len, ORIG_IP, sizeof(ORIG_IP),
                                         MQ_ADDR_IPV4, ORIG_PORT, /*local_fd=*/-1);
    MQ_CHECK_EQ_INT(r, R_OPAQUE);
    MQ_CHECK_EQ_INT(g_opaque.called, 1);
    MQ_CHECK_EQ_INT(g_mitm.called, 0);
    // ORIGINAL orig-dst forwarded unchanged (NOT the SNI).
    MQ_CHECK_EQ_INT(g_opaque.atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT(g_opaque.port, ORIG_PORT);
    MQ_CHECK_EQ_INT(g_opaque.host_len, sizeof(ORIG_IP));
    MQ_CHECK_MEM(g_opaque.host, ORIG_IP, sizeof(ORIG_IP));
    MQ_CHECK_EQ_INT(g_opaque.local_fd, -1);
    // The drained ClientHello is replayed verbatim as prebuf.
    MQ_CHECK_EQ_INT(g_opaque.prebuf_len, (long long)b.len);
    MQ_CHECK_MEM(g_opaque.prebuf, b.buf, b.len);

    mq_mitm_ctx_free(ctx);
    mq_ignore_hosts_free(ign);
}

// Suffix entry ".example.com" matches a strict subdomain → opaque.
static void
test_ignore_suffix_routes_opaque(void)
{
    reset_captures();
    mq_ignore_hosts_t *ign = mq_ignore_hosts_new();
    MQ_CHECK(mq_ignore_hosts_add(ign, ".example.com") == 0); // suffix

    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, ign, NULL, stub_opaque_open, NULL,
                                         (struct event_base *)0x1);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    chb_t b;
    build_clienthello(&b, 1, "api.example.com", 1);
    int r = mq_mitm_conn_decide_for_test(ctx, b.buf, b.len, ORIG_IP, sizeof(ORIG_IP),
                                         MQ_ADDR_IPV4, ORIG_PORT, -1);
    MQ_CHECK_EQ_INT(r, R_OPAQUE);
    MQ_CHECK_EQ_INT(g_opaque.called, 1);
    MQ_CHECK_EQ_INT(g_mitm.called, 0);

    mq_mitm_ctx_free(ctx);
    mq_ignore_hosts_free(ign);
}

// ignore-hosts MISS → MITM branch SELECTED (observed via the injected hook).
static void
test_ignore_miss_routes_mitm(void)
{
    reset_captures();
    mq_ignore_hosts_t *ign = mq_ignore_hosts_new();
    MQ_CHECK(mq_ignore_hosts_add(ign, "signal.org") == 0); // not our SNI

    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, ign, NULL, stub_opaque_open, NULL,
                                         (struct event_base *)0x1);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    chb_t b;
    build_clienthello(&b, 1, "Example.COM", 1); // mixed case → normalizes
    int r = mq_mitm_conn_decide_for_test(ctx, b.buf, b.len, ORIG_IP, sizeof(ORIG_IP),
                                         MQ_ADDR_IPV4, ORIG_PORT, -1);
    MQ_CHECK_EQ_INT(r, R_MITM);
    MQ_CHECK_EQ_INT(g_mitm.called, 1);
    MQ_CHECK_EQ_INT(g_opaque.called, 0);
    MQ_CHECK(strcmp(g_mitm.sni, "example.com") == 0); // normalized lowercase
    MQ_CHECK_EQ_INT(g_mitm.buf_len, (long long)b.len);

    mq_mitm_ctx_free(ctx);
    mq_ignore_hosts_free(ign);
}

// NULL ignore-hosts list → nothing opaque → MITM.
static void
test_null_ignore_routes_mitm(void)
{
    reset_captures();
    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL,
                                         (struct event_base *)0x1);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    chb_t b;
    build_clienthello(&b, 1, "example.com", 1);
    int r = mq_mitm_conn_decide_for_test(ctx, b.buf, b.len, ORIG_IP, sizeof(ORIG_IP),
                                         MQ_ADDR_IPV4, ORIG_PORT, -1);
    MQ_CHECK_EQ_INT(r, R_MITM);
    MQ_CHECK_EQ_INT(g_mitm.called, 1);
    MQ_CHECK_EQ_INT(g_opaque.called, 0);

    mq_mitm_ctx_free(ctx);
}

// No SNI in the ClientHello → hard-fail (no opaque, no MITM).
static void
test_no_sni_hard_fail(void)
{
    reset_captures();
    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL,
                                         (struct event_base *)0x1);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    chb_t b;
    build_clienthello(&b, 0, NULL, 1); // no SNI, ALPN h2
    int r = mq_mitm_conn_decide_for_test(ctx, b.buf, b.len, ORIG_IP, sizeof(ORIG_IP),
                                         MQ_ADDR_IPV4, ORIG_PORT, -1);
    MQ_CHECK_EQ_INT(r, R_FAIL);
    MQ_CHECK_EQ_INT(g_opaque.called, 0);
    MQ_CHECK_EQ_INT(g_mitm.called, 0);

    mq_mitm_ctx_free(ctx);
}

// Non-TLS / incomplete leading bytes → hard-fail (parse not OK).
static void
test_not_tls_hard_fail(void)
{
    reset_captures();
    mq_mitm_ctx_t *ctx = mq_mitm_ctx_new(NULL, NULL, NULL, stub_opaque_open, NULL,
                                         (struct event_base *)0x1);
    mq_mitm_ctx_set_mitm_hook_for_test(ctx, mitm_hook, NULL);

    const uint8_t junk[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    int r = mq_mitm_conn_decide_for_test(ctx, junk, sizeof(junk) - 1, ORIG_IP,
                                         sizeof(ORIG_IP), MQ_ADDR_IPV4, ORIG_PORT, -1);
    MQ_CHECK_EQ_INT(r, R_FAIL);
    MQ_CHECK_EQ_INT(g_opaque.called, 0);
    MQ_CHECK_EQ_INT(g_mitm.called, 0);

    mq_mitm_ctx_free(ctx);
}

MQ_TEST_MAIN({
    test_ignore_hit_routes_opaque();
    test_ignore_suffix_routes_opaque();
    test_ignore_miss_routes_mitm();
    test_null_ignore_routes_mitm();
    test_no_sni_hard_fail();
    test_not_tls_hard_fail();
})
