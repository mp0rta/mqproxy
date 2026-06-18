// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// Unit tests for mq_clienthello_parse — the TLS ClientHello SNI/ALPN peek
// parser. Input here is ATTACKER-CONTROLLED network data: every case that is
// not a well-formed ClientHello must hard-fail (NOT_TLS / INVALID) or ask for
// more bytes (NEED_MORE), and NONE may read past `len` (ASan gate).
#include "mqtest.h"
#include "ingress/mq_clienthello.h"
#include <stdint.h>
#include <string.h>

// ---------------------------------------------------------------------------
// ClientHello byte-array builder (test-only). Builds a single TLS plaintext
// record carrying one ClientHello handshake, with optional SNI + ALPN.
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

// Build the extensions block body (without the outer u16 length) into `ext`.
//   want_sni:  0 = omit, 1 = include server_name=host
//   alpn_mode: 0 = omit ALPN, 1 = ALPN with h2 + http/1.1, 2 = ALPN http/1.1 only
static void
build_extensions(chb_t *ext, int want_sni, const char *host, int alpn_mode)
{
    if (want_sni) {
        size_t hlen = strlen(host);
        // server_name extension (type 0x0000)
        chb_u16(ext, 0x0000);
        // ext_data: server_name_list (u16) { name_type(u8)=0 + host_name(u16) host }
        uint16_t list_len = (uint16_t)(1 + 2 + hlen);
        chb_u16(ext, (uint16_t)(2 + list_len)); // ext_data length
        chb_u16(ext, list_len);                 // server_name_list length
        chb_u8(ext, 0x00);                      // name_type = host_name
        chb_u16(ext, (uint16_t)hlen);           // host_name length
        chb_bytes(ext, (const uint8_t *)host, hlen);
    }
    if (alpn_mode != 0) {
        // application_layer_protocol_negotiation extension (type 0x0010 = 16)
        chb_u16(ext, 0x0010);
        chb_t list;
        list.len = 0;
        if (alpn_mode == 1) {
            chb_u8(&list, 2);
            chb_bytes(&list, (const uint8_t *)"h2", 2);
            chb_u8(&list, 8);
            chb_bytes(&list, (const uint8_t *)"http/1.1", 8);
        } else { // alpn_mode == 2: http/1.1 only
            chb_u8(&list, 8);
            chb_bytes(&list, (const uint8_t *)"http/1.1", 8);
        }
        // ext_data: ProtocolNameList length (u16) + list
        chb_u16(ext, (uint16_t)(2 + list.len));
        chb_u16(ext, (uint16_t)list.len);
        chb_bytes(ext, list.buf, list.len);
    }
}

// Build the raw handshake message (4-byte handshake header + ClientHello body)
// into `hs`, WITHOUT the surrounding TLS record. Used by both the single-record
// builder and the multi-record (fragmented) builders below.
static void
build_handshake(chb_t *hs, int want_sni, const char *host, int alpn_mode)
{
    chb_t body;
    body.len = 0;
    chb_u16(&body, 0x0303); // legacy_version TLS 1.2
    static const uint8_t random32[32] = {0};
    chb_bytes(&body, random32, 32); // random
    chb_u8(&body, 0x00);            // session_id length = 0
    chb_u16(&body, 0x0002);         // cipher_suites length = 2
    chb_u16(&body, 0x1301);         // TLS_AES_128_GCM_SHA256
    chb_u8(&body, 0x01);            // compression_methods length = 1
    chb_u8(&body, 0x00);            // null compression

    chb_t ext;
    ext.len = 0;
    build_extensions(&ext, want_sni, host, alpn_mode);
    chb_u16(&body, (uint16_t)ext.len); // extensions length
    chb_bytes(&body, ext.buf, ext.len);

    hs->len = 0;
    chb_u8(hs, 0x01); // msg_type = ClientHello
    chb_u8(hs, (uint8_t)((body.len >> 16) & 0xff));
    chb_u8(hs, (uint8_t)((body.len >> 8) & 0xff));
    chb_u8(hs, (uint8_t)(body.len & 0xff));
    chb_bytes(hs, body.buf, body.len);
}

// Wrap a raw byte slice into a single TLS record of the given content_type and
// append it to `out`.
static void
append_record(chb_t *out, uint8_t content_type, const uint8_t *p, size_t n)
{
    chb_u8(out, content_type);
    chb_u16(out, 0x0301); // legacy record version
    chb_u16(out, (uint16_t)n);
    chb_bytes(out, p, n);
}

// Build a full record+handshake ClientHello. Returns it in `out`.
static void
build_clienthello(chb_t *out, int want_sni, const char *host, int alpn_mode)
{
    chb_t hs;
    build_handshake(&hs, want_sni, host, alpn_mode);
    // Single TLS handshake record carrying the whole ClientHello.
    out->len = 0;
    append_record(out, 0x16, hs.buf, hs.len);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

static void
test_good_sni_and_h2(void)
{
    chb_t b;
    build_clienthello(&b, 1, "example.com", 1);
    mq_clienthello_t out;
    memset(&out, 0xff, sizeof(out));
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK(strcmp(out.sni, "example.com") == 0);
    MQ_CHECK_EQ_INT(out.has_alpn, 1);
    MQ_CHECK_EQ_INT(out.has_h2, 1);
}

static void
test_alpn_without_h2(void)
{
    chb_t b;
    build_clienthello(&b, 1, "example.com", 2); // http/1.1 only
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK(strcmp(out.sni, "example.com") == 0);
    MQ_CHECK_EQ_INT(out.has_alpn, 1);
    MQ_CHECK_EQ_INT(out.has_h2, 0);
}

static void
test_sni_absent(void)
{
    chb_t b;
    build_clienthello(&b, 0, NULL, 1); // no SNI, has ALPN h2
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK_EQ_INT((int)strlen(out.sni), 0);
    MQ_CHECK_EQ_INT(out.has_alpn, 1);
    MQ_CHECK_EQ_INT(out.has_h2, 1);
}

static void
test_no_alpn(void)
{
    chb_t b;
    build_clienthello(&b, 1, "host.test", 0); // SNI present, no ALPN
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK(strcmp(out.sni, "host.test") == 0);
    MQ_CHECK_EQ_INT(out.has_alpn, 0);
    MQ_CHECK_EQ_INT(out.has_h2, 0);
}

static void
test_truncated_prefix(void)
{
    // A valid ClientHello but only the first 20 bytes delivered → NEED_MORE.
    chb_t b;
    build_clienthello(&b, 1, "example.com", 1);
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, 20, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_NEED_MORE);
}

static void
test_empty(void)
{
    // Zero bytes → not enough to even read the record header → NEED_MORE.
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse((const uint8_t *)"", 0, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_NEED_MORE);
}

static void
test_not_tls(void)
{
    // First byte != 0x16 (here an HTTP/1.1 plaintext GET) → NOT_TLS.
    const uint8_t http[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(http, sizeof(http) - 1, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_NOT_TLS);
}

static void
test_sslv2_garbage(void)
{
    // SSLv2-style ClientHello starts with a high bit set length, not 0x16.
    const uint8_t sslv2[] = {0x80, 0x2e, 0x01, 0x00, 0x02, 0x00, 0x15};
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(sslv2, sizeof(sslv2), &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_NOT_TLS);
}

static void
test_handshake_not_clienthello(void)
{
    // Valid record header, complete fragment, but msg_type != 0x01 (here 0x02
    // ServerHello) → structurally impossible for our peek → INVALID.
    chb_t b;
    b.len = 0;
    chb_u8(&b, 0x16);
    chb_u16(&b, 0x0301);
    chb_u16(&b, 0x0004); // fragment length = 4
    chb_u8(&b, 0x02);    // ServerHello
    chb_u8(&b, 0x00);
    chb_u8(&b, 0x00);
    chb_u8(&b, 0x00); // 24-bit handshake length = 0
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_INVALID);
}

static void
test_ext_length_overflow(void)
{
    // Build a good ClientHello, then corrupt the extensions length to claim far
    // more bytes than are present. Must NEVER OOB-read; result is NEED_MORE
    // (claimed inner length runs past `len`) — never OK, never a crash.
    chb_t b;
    build_clienthello(&b, 1, "example.com", 1);
    // The record fragment length is bytes [3..4]; inflate it so the handshake
    // claims more than we have, but keep `len` short.
    b.buf[3] = 0xff;
    b.buf[4] = 0xff;
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK(r == MQ_CH_NEED_MORE || r == MQ_CH_INVALID);
}

static void
test_inner_ext_overruns_complete_block(void)
{
    // A FULLY-PRESENT, single-record ClientHello whose inner extensions-block
    // length field overruns the (complete) handshake body → structurally
    // impossible → INVALID (no OOB). This is an overrun WITHIN a complete
    // enclosing field, which reassembly does not turn into NEED_MORE: there are
    // no missing bytes, the framing is self-contradictory.
    chb_t b;
    build_clienthello(&b, 1, "example.com", 1);
    // Compute the extensions-block u16 length offset exactly. Within the body the
    // fixed prefix is legacy_version(2) + random(32) + sid_len(1) + cs_len(2) +
    // cs(2) + cm_len(1) + cm(1) = 41 bytes, then the extensions-block u16 length.
    // The body itself starts at record_hdr(5) + handshake_hdr(4) = 9.
    const size_t ext_total_off = 9 + 41;
    MQ_CHECK(ext_total_off + 1 < b.len);
    // Inflate it so it claims far more than the handshake body can hold — but keep
    // every byte of the buffer present (record + handshake fully complete).
    b.buf[ext_total_off] = 0xff;
    b.buf[ext_total_off + 1] = 0xff;
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_INVALID);
}

static void
test_long_sni_rejected(void)
{
    // host_name > 253 chars → SNI skipped (out.sni empty), parse still OK.
    char host[300];
    memset(host, 'a', 254);
    host[254] = '\0';
    chb_t b;
    build_clienthello(&b, 1, host, 1);
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK_EQ_INT((int)strlen(out.sni), 0); // over-long → skipped, empty
    MQ_CHECK_EQ_INT(out.has_h2, 1);
}

static void
test_len_over_cap_rejected(void)
{
    // Top-level DoS guard: any buffer larger than the 8 KiB cap is rejected
    // outright (INVALID), before any record parsing — len == 8193 is one over.
    // The record header declares a fragment far larger than the buffer, so
    // WITHOUT the top-level cap this would parse to NEED_MORE; the cap must
    // turn it into INVALID. First byte is a valid handshake type (not NOT_TLS).
    static uint8_t big[8193];
    memset(big, 0x00, sizeof(big));
    big[0] = 0x16; // handshake content type
    big[1] = 0x03; // legacy_version high
    big[2] = 0x01; // legacy_version low
    big[3] = 0xff; // fragment length high (0xffff >> len)
    big[4] = 0xff; // fragment length low
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(big, sizeof(big), &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_INVALID);
}

static void
test_record_frag_over_cap_rejected(void)
{
    // A valid 5-byte record header whose declared fragment length makes
    // 5 + frag_len > 8192, with only the header actually present. The cap
    // rejects (INVALID) BEFORE reassembly — it must NOT degrade to NEED_MORE.
    // frag_len = 8188 → 5 + 8188 = 8193 > 8192.
    uint8_t hdr[5];
    hdr[0] = 0x16;                   // handshake
    hdr[1] = 0x03;                   // legacy_version high
    hdr[2] = 0x01;                   // legacy_version low
    hdr[3] = (uint8_t)(8188 >> 8);   // frag_len high
    hdr[4] = (uint8_t)(8188 & 0xff); // frag_len low
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(hdr, sizeof(hdr), &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_INVALID);
}

static void
test_split_record_first_half_need_more(void)
{
    // RFC 8446 §5.1: a handshake message MAY be fragmented across multiple TLS
    // handshake records. Build the ClientHello, then carry only its FIRST half in
    // record 1. The 24-bit handshake length declares more than record 1 carries,
    // so the parser must ask for more — NOT reject as INVALID.
    chb_t hs;
    build_handshake(&hs, 1, "split.example.com", 1);
    size_t half = hs.len / 2;
    MQ_CHECK(half > 4 && half < hs.len); // ensure a real boundary mid-body
    chb_t b;
    b.len = 0;
    append_record(&b, 0x16, hs.buf, half);
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_NEED_MORE);
}

static void
test_split_record_both_halves_ok(void)
{
    // Same fragmented ClientHello, now both records present (handshake split
    // across a record boundary). The parser must reassemble across the boundary
    // and extract SNI + has_h2 correctly. The split point lands mid-body so the
    // extensions (and thus SNI/ALPN) straddle the two records.
    chb_t hs;
    build_handshake(&hs, 1, "split.example.com", 1);
    size_t half = hs.len / 2;
    chb_t b;
    b.len = 0;
    append_record(&b, 0x16, hs.buf, half);                 // record 1
    append_record(&b, 0x16, hs.buf + half, hs.len - half); // record 2
    mq_clienthello_t out;
    memset(&out, 0xff, sizeof(out));
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK(strcmp(out.sni, "split.example.com") == 0);
    MQ_CHECK_EQ_INT(out.has_alpn, 1);
    MQ_CHECK_EQ_INT(out.has_h2, 1);
}

static void
test_split_record_many_fragments_ok(void)
{
    // Pathological-but-legal fragmentation: chop the handshake into 1-byte
    // records. Reassembly must still recover the complete ClientHello.
    chb_t hs;
    build_handshake(&hs, 1, "tiny.example.com", 1);
    chb_t b;
    b.len = 0;
    for (size_t i = 0; i < hs.len; i++) {
        append_record(&b, 0x16, hs.buf + i, 1);
    }
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_OK);
    MQ_CHECK(strcmp(out.sni, "tiny.example.com") == 0);
    MQ_CHECK_EQ_INT(out.has_h2, 1);
}

static void
test_interleaved_non_handshake_record_invalid(void)
{
    // A non-handshake record (content_type 23 = application_data) interleaved
    // BETWEEN handshake records while the ClientHello is still incomplete is a
    // protocol violation → INVALID (never NEED_MORE, never an OOB read).
    chb_t hs;
    build_handshake(&hs, 1, "evil.example.com", 1);
    size_t half = hs.len / 2;
    chb_t b;
    b.len = 0;
    append_record(&b, 0x16, hs.buf, half); // handshake, partial
    const uint8_t junk[4] = {0xde, 0xad, 0xbe, 0xef};
    append_record(&b, 0x17, junk, sizeof(junk)); // application_data mid-handshake
    append_record(&b, 0x16, hs.buf + half, hs.len - half); // continuation
    mq_clienthello_t out;
    mq_ch_result_t r = mq_clienthello_parse(b.buf, b.len, &out);
    MQ_CHECK_EQ_INT(r, MQ_CH_INVALID);
}

MQ_TEST_MAIN(test_good_sni_and_h2(); test_alpn_without_h2(); test_sni_absent();
             test_no_alpn(); test_truncated_prefix(); test_empty(); test_not_tls();
             test_sslv2_garbage(); test_handshake_not_clienthello();
             test_ext_length_overflow(); test_inner_ext_overruns_complete_block();
             test_long_sni_rejected(); test_len_over_cap_rejected();
             test_record_frag_over_cap_rejected();
             test_split_record_first_half_need_more(); test_split_record_both_halves_ok();
             test_split_record_many_fragments_ok();
             test_interleaved_non_handshake_record_invalid();)
