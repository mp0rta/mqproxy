// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "wire/mq_udp_msg.h"
#include "mqtest.h"

/* ---- encode→decode round-trip (fixed-length BE) ---- */
static void
test_hdr_roundtrip(void)
{
    mq_udp_msg_hdr_t in;
    in.session_id = 0xDEADBEEFU;
    in.packet_id = 0x1234U;
    in.flags = 0xABU;
    in.frag_id = 7U;
    in.frag_count = 12U;

    uint8_t buf[MQ_UDP_MSG_HDR];
    MQ_CHECK_EQ_INT(mq_udp_msg_encode_hdr(buf, &in), 0);

    mq_udp_msg_hdr_t out;
    MQ_CHECK_EQ_INT(mq_udp_msg_decode_hdr(buf, MQ_UDP_MSG_HDR, &out), 0);

    MQ_CHECK_EQ_INT((long long)out.session_id, (long long)in.session_id);
    MQ_CHECK_EQ_INT((long long)out.packet_id, (long long)in.packet_id);
    MQ_CHECK_EQ_INT((long long)out.flags, (long long)in.flags);
    MQ_CHECK_EQ_INT((long long)out.frag_id, (long long)in.frag_id);
    MQ_CHECK_EQ_INT((long long)out.frag_count, (long long)in.frag_count);
}

/* ---- BE byte-order: hand-crafted bytes, not just round-trip ---- */
static void
test_hdr_byte_order(void)
{
    /* session_id=0x01020304, packet_id=0x0506, flags=0x07, frag_id=0x08, frag_count=0x09
     */
    uint8_t wire[MQ_UDP_MSG_HDR] = {0x01, 0x02, 0x03, 0x04, /* session_id BE */
                                    0x05, 0x06,             /* packet_id BE  */
                                    0x07,                   /* flags         */
                                    0x08,                   /* frag_id       */
                                    0x09};                  /* frag_count    */
    mq_udp_msg_hdr_t h;
    MQ_CHECK_EQ_INT(mq_udp_msg_decode_hdr(wire, MQ_UDP_MSG_HDR, &h), 0);
    MQ_CHECK_EQ_INT((long long)h.session_id, 0x01020304LL);
    MQ_CHECK_EQ_INT((long long)h.packet_id, 0x0506LL);
    MQ_CHECK_EQ_INT((long long)h.flags, 0x07LL);
    MQ_CHECK_EQ_INT((long long)h.frag_id, 0x08LL);
    MQ_CHECK_EQ_INT((long long)h.frag_count, 0x09LL);

    /* also verify that encode produces the same bytes */
    uint8_t out[MQ_UDP_MSG_HDR];
    MQ_CHECK_EQ_INT(mq_udp_msg_encode_hdr(out, &h), 0);
    MQ_CHECK_MEM(out, wire, MQ_UDP_MSG_HDR);
}

/* ---- decode rejects len < 9 ---- */
static void
test_hdr_decode_truncation(void)
{
    mq_udp_msg_hdr_t in;
    in.session_id = 1;
    in.packet_id = 2;
    in.flags = 0;
    in.frag_id = 0;
    in.frag_count = 1;
    uint8_t buf[MQ_UDP_MSG_HDR];
    MQ_CHECK_EQ_INT(mq_udp_msg_encode_hdr(buf, &in), 0);

    mq_udp_msg_hdr_t out;
    for (size_t k = 0; k < MQ_UDP_MSG_HDR; k++) {
        MQ_CHECK_EQ_INT(mq_udp_msg_decode_hdr(buf, k, &out), -1);
    }
    /* exactly 9 bytes must succeed */
    MQ_CHECK_EQ_INT(mq_udp_msg_decode_hdr(buf, MQ_UDP_MSG_HDR, &out), 0);
}

/* ---- collect frags from split ---- */
typedef struct {
    mq_udp_msg_hdr_t hdrs[512];
    const uint8_t *slices[512];
    size_t lens[512];
    size_t count;
} frag_log_t;

static void
collect_emit(const mq_udp_msg_hdr_t *h, const uint8_t *p, size_t len, void *user)
{
    frag_log_t *log = (frag_log_t *)user;
    if (log->count < 512) {
        log->hdrs[log->count] = *h;
        log->slices[log->count] = p;
        log->lens[log->count] = len;
        log->count++;
    }
}

/* ---- frag split: 2500-byte payload, mss=1000 → 3 frags ---- */
static void
test_split_3frags(void)
{
    static uint8_t payload[2500];
    for (size_t i = 0; i < sizeof payload; i++)
        payload[i] = (uint8_t)(i & 0xFF);

    frag_log_t log;
    log.count = 0;
    int r =
        mq_udp_msg_split(0xAABBCCDDU, 0x0042U, payload, 2500, 1000, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, 0);
    MQ_CHECK_EQ_INT((long long)log.count, 3LL);

    /* sizes: 1000, 1000, 500 */
    MQ_CHECK_EQ_INT((long long)log.lens[0], 1000LL);
    MQ_CHECK_EQ_INT((long long)log.lens[1], 1000LL);
    MQ_CHECK_EQ_INT((long long)log.lens[2], 500LL);

    /* same session_id and packet_id across all frags */
    for (int i = 0; i < 3; i++) {
        MQ_CHECK_EQ_INT((long long)log.hdrs[i].session_id, (long long)0xAABBCCDDU);
        MQ_CHECK_EQ_INT((long long)log.hdrs[i].packet_id, 0x0042LL);
        MQ_CHECK_EQ_INT((long long)log.hdrs[i].frag_count, 3LL);
        MQ_CHECK_EQ_INT((long long)log.hdrs[i].frag_id, (long long)i);
    }

    /* slices must point into the original payload */
    MQ_CHECK(log.slices[0] == payload);
    MQ_CHECK(log.slices[1] == payload + 1000);
    MQ_CHECK(log.slices[2] == payload + 2000);
}

/* ---- frag split: payload <= mss → 1 frag ---- */
static void
test_split_1frag(void)
{
    static uint8_t payload[64];

    frag_log_t log;
    log.count = 0;
    int r = mq_udp_msg_split(1U, 2U, payload, 64, 1000, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, 0);
    MQ_CHECK_EQ_INT((long long)log.count, 1LL);
    MQ_CHECK_EQ_INT((long long)log.lens[0], 64LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[0].frag_id, 0LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[0].frag_count, 1LL);
}

/* ---- frag split: zero-length payload → 1 frag of length 0 ----
 * Design doc is silent on len==0; we define 1 frag of 0 bytes (consistent
 * with the "1 frag" rule for payload <= mss). */
static void
test_split_empty_payload(void)
{
    static uint8_t dummy[1];

    frag_log_t log;
    log.count = 0;
    int r = mq_udp_msg_split(1U, 0U, dummy, 0, 1000, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, 0);
    MQ_CHECK_EQ_INT((long long)log.count, 1LL);
    MQ_CHECK_EQ_INT((long long)log.lens[0], 0LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[0].frag_id, 0LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[0].frag_count, 1LL);
}

/* ---- boundary: exactly 255 frags succeeds ---- */
static void
test_split_255frags_ok(void)
{
    /* 255 * 1000 = 255000 bytes, mss=1000 → exactly 255 frags */
    static uint8_t payload[255 * 1000];

    frag_log_t log;
    log.count = 0;
    int r = mq_udp_msg_split(1U, 0U, payload, 255 * 1000, 1000, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, 0);
    MQ_CHECK_EQ_INT((long long)log.count, 255LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[0].frag_count, 255LL);
    MQ_CHECK_EQ_INT((long long)log.hdrs[254].frag_id, 254LL);
}

/* ---- boundary: 256 frags needed → -1, no emit calls ---- */
static void
test_split_256frags_rejected(void)
{
    /* 255*1000 + 1 bytes, mss=1000 → ceil = 256 frags → must reject */
    static uint8_t payload[255 * 1000 + 1];

    frag_log_t log;
    log.count = 0;
    int r = mq_udp_msg_split(1U, 0U, payload, 255 * 1000 + 1, 1000, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, -1);
    MQ_CHECK_EQ_INT((long long)log.count, 0LL); /* no emit on error */
}

/* ---- mss_payload == 0 → -1, no emit calls ---- */
static void
test_split_mss_zero_rejected(void)
{
    static uint8_t payload[64];

    frag_log_t log;
    log.count = 0;
    int r = mq_udp_msg_split(1U, 0U, payload, 64, 0, collect_emit, &log);
    MQ_CHECK_EQ_INT(r, -1);
    MQ_CHECK_EQ_INT((long long)log.count, 0LL);
}

MQ_TEST_MAIN({
    test_hdr_roundtrip();
    test_hdr_byte_order();
    test_hdr_decode_truncation();
    test_split_3frags();
    test_split_1frag();
    test_split_empty_payload();
    test_split_255frags_ok();
    test_split_256frags_rejected();
    test_split_mss_zero_rejected();
})
