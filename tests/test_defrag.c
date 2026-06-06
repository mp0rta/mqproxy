// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "proxy/mq_defrag.h"
#include "wire/mq_udp_msg.h"
#include "mqtest.h"
#include <string.h>
#include <stdlib.h>

/* Helper: build a header with frag_count==1 (single unfragmented packet). */
static mq_udp_msg_hdr_t
make_hdr(uint16_t packet_id, uint8_t frag_id, uint8_t frag_count)
{
    mq_udp_msg_hdr_t h;
    h.session_id = 1;
    h.packet_id = packet_id;
    h.flags = 0;
    h.frag_id = frag_id;
    h.frag_count = frag_count;
    return h;
}

/* ---- 1. Single-frag passthrough ----------------------------------------- */
static void
test_single_frag_passthrough(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload[] = {0x01, 0x02, 0x03};
    mq_udp_msg_hdr_t h = make_hdr(10, 0, 1);

    uint8_t *out = NULL;
    size_t out_len = 0;
    int r = mq_defrag_feed(d, &h, payload, sizeof payload, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 3LL);
    MQ_CHECK_MEM(out, payload, 3);
    free(out);

    mq_defrag_free(d);
}

/* ---- 2. 2-frag assembly (in-order) -------------------------------------- */
static void
test_two_frag_in_order(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t f0[] = {0xAA, 0xBB};
    uint8_t f1[] = {0xCC, 0xDD, 0xEE};
    uint8_t expected[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    mq_udp_msg_hdr_t h0 = make_hdr(20, 0, 2);
    mq_udp_msg_hdr_t h1 = make_hdr(20, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    int r = mq_defrag_feed(d, &h0, f0, sizeof f0, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 0);

    r = mq_defrag_feed(d, &h1, f1, sizeof f1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 5LL);
    MQ_CHECK_MEM(out, expected, 5);
    free(out);

    mq_defrag_free(d);
}

/* ---- 3. 2-frag assembly (reverse order) --------------------------------- */
static void
test_two_frag_reverse_order(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t f0[] = {0x11, 0x22};
    uint8_t f1[] = {0x33, 0x44};
    uint8_t expected[] = {0x11, 0x22, 0x33, 0x44};

    mq_udp_msg_hdr_t h0 = make_hdr(30, 0, 2);
    mq_udp_msg_hdr_t h1 = make_hdr(30, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Feed frag 1 first */
    int r = mq_defrag_feed(d, &h1, f1, sizeof f1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 0);

    /* Then frag 0 completes */
    r = mq_defrag_feed(d, &h0, f0, sizeof f0, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 4LL);
    MQ_CHECK_MEM(out, expected, 4);
    free(out);

    mq_defrag_free(d);
}

/* ---- 4. Two packet_ids interleaved -------------------------------------- */
static void
test_two_packet_ids_interleaved(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* pkt A: id=40, 2 frags; pkt B: id=41, 2 frags. Feed interleaved. */
    uint8_t a0[] = {0xA0};
    uint8_t a1[] = {0xA1};
    uint8_t b0[] = {0xB0};
    uint8_t b1[] = {0xB1};

    mq_udp_msg_hdr_t ha0 = make_hdr(40, 0, 2);
    mq_udp_msg_hdr_t ha1 = make_hdr(40, 1, 2);
    mq_udp_msg_hdr_t hb0 = make_hdr(41, 0, 2);
    mq_udp_msg_hdr_t hb1 = make_hdr(41, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &ha0, a0, 1, &out, &out_len), 0);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &hb0, b0, 1, &out, &out_len), 0);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &ha1, a1, 1, &out, &out_len), 1);
    MQ_CHECK(out_len == 2 && out[0] == 0xA0 && out[1] == 0xA1);
    free(out);
    out = NULL;

    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &hb1, b1, 1, &out, &out_len), 1);
    MQ_CHECK(out_len == 2 && out[0] == 0xB0 && out[1] == 0xB1);
    free(out);

    mq_defrag_free(d);
}

/* ---- 5. 5 distinct packet_ids → LRU evict ------------------------------ */
static void
test_lru_evict(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* Feed frag 0 of 5 different packet_ids (2-frag each).
     * The 5th packet_id must evict the LRU slot (the one for packet_id 0).
     * After the eviction, the slot for id=0 is gone; feeding its frag 1
     * should allocate a *new* slot (returns 0, not complete yet). */
    uint8_t payload[] = {0xFF};
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Fill 4 slots: ids 100..103 */
    for (uint16_t id = 100; id < 104; id++) {
        mq_udp_msg_hdr_t h = make_hdr(id, 0, 2);
        int r = mq_defrag_feed(d, &h, payload, 1, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 0);
    }

    /* Touch id=101 to make it recently used (so id=100 remains LRU) */
    {
        mq_udp_msg_hdr_t h = make_hdr(101, 0, 2); /* duplicate frag → 0 */
        int r = mq_defrag_feed(d, &h, payload, 1, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 0); /* duplicate ignored, still 0 */
    }

    /* Feed id=104 → must evict LRU (id=100).  Returns 0 (incomplete). */
    {
        mq_udp_msg_hdr_t h = make_hdr(104, 0, 2);
        int r = mq_defrag_feed(d, &h, payload, 1, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 0);
    }

    /* Complete id=104 → should work (the slot is present) */
    {
        mq_udp_msg_hdr_t h = make_hdr(104, 1, 2);
        int r = mq_defrag_feed(d, &h, payload, 1, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 1);
        MQ_CHECK(out != NULL && out_len == 2);
        free(out);
        out = NULL;
    }

    /* id=100 slot was evicted.  Sending frag 1 of id=100 should start a
     * *new* slot (returns 0, can't complete with just frag 1 of 2). */
    {
        mq_udp_msg_hdr_t h = make_hdr(100, 1, 2);
        int r = mq_defrag_feed(d, &h, payload, 1, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 0); /* new slot, not complete */
    }

    mq_defrag_free(d);
}

/* ---- 6. Duplicate frag ignored (return 0) ------------------------------ */
static void
test_duplicate_frag_ignored(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload[] = {0x55};
    mq_udp_msg_hdr_t h = make_hdr(50, 0, 3);

    uint8_t *out = NULL;
    size_t out_len = 0;

    /* First feed: accepted */
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, payload, 1, &out, &out_len), 0);
    /* Duplicate: silently ignored, not an error */
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, payload, 1, &out, &out_len), 0);
    /* Another duplicate */
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, payload, 1, &out, &out_len), 0);

    mq_defrag_free(d);
}

/* ---- 7. frag_count mismatch → slot drop (return -1) ------------------- */
static void
test_frag_count_mismatch_drops_slot(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* First frag: frag_count=3 → slot created */
    mq_udp_msg_hdr_t h1 = make_hdr(60, 0, 3);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h1, payload, 1, &out, &out_len), 0);

    /* Second frag: frag_count=2 (mismatch) → -1, slot dropped */
    mq_udp_msg_hdr_t h2 = make_hdr(60, 1, 2);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h2, payload, 1, &out, &out_len), -1);

    /* Slot should now be gone; a new frag for id=60 starts fresh (returns 0) */
    mq_udp_msg_hdr_t h3 = make_hdr(60, 0, 2);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h3, payload, 1, &out, &out_len), 0);

    mq_defrag_free(d);
}

/* ---- 8. frag_id >= frag_count → drop (return -1) ---------------------- */
static void
test_frag_id_out_of_range(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* frag_id == frag_count (== 2) → invalid */
    mq_udp_msg_hdr_t h = make_hdr(70, 2, 2);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, payload, 1, &out, &out_len), -1);

    /* frag_id > frag_count */
    mq_udp_msg_hdr_t h2 = make_hdr(71, 5, 2);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h2, payload, 1, &out, &out_len), -1);

    mq_defrag_free(d);
}

/* ---- 9. frag_count == 0 → drop (return -1) ----------------------------- */
static void
test_frag_count_zero_rejected(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload[] = {0x01};
    uint8_t *out = NULL;
    size_t out_len = 0;

    mq_udp_msg_hdr_t h = make_hdr(80, 0, 0);
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, payload, 1, &out, &out_len), -1);

    mq_defrag_free(d);
}

/* ---- 10. Reassembled > 65535 → slot drop (return -1) ------------------- */
static void
test_reassembled_too_large(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* 2-frag packet: each frag is 32768 bytes → total 65536 > 65535. */
    static uint8_t big[32768];
    memset(big, 0xAB, sizeof big);

    mq_udp_msg_hdr_t h0 = make_hdr(90, 0, 2);
    mq_udp_msg_hdr_t h1 = make_hdr(90, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    int r0 = mq_defrag_feed(d, &h0, big, sizeof big, &out, &out_len);
    /* First frag (32768) is below 65535; slot accepted → 0 */
    MQ_CHECK_EQ_INT(r0, 0);

    /* Second frag would push total to 65536 → slot dropped → -1 */
    int r1 = mq_defrag_feed(d, &h1, big, sizeof big, &out, &out_len);
    MQ_CHECK_EQ_INT(r1, -1);

    mq_defrag_free(d);
}

/* ---- 11. packet_id wrap: completed id reused as new packet -------------- */
static void
test_packet_id_wrap(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t payload_a[] = {0xAA};
    uint8_t payload_b[] = {0xBB};
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* First use of packet_id=200: single-frag → completes immediately. */
    mq_udp_msg_hdr_t h1 = make_hdr(200, 0, 1);
    int r = mq_defrag_feed(d, &h1, payload_a, 1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL && out_len == 1 && out[0] == 0xAA);
    free(out);
    out = NULL;

    /* Second use of packet_id=200: new single-frag (slot was released) → 1. */
    mq_udp_msg_hdr_t h2 = make_hdr(200, 0, 1);
    r = mq_defrag_feed(d, &h2, payload_b, 1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL && out_len == 1 && out[0] == 0xBB);
    free(out);

    mq_defrag_free(d);
}

/* ---- 12. Single-frag zero-length payload -------------------------------- */
static void
test_single_frag_zero_len(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* len==0 single-frag: returns 1, *out non-NULL (freeable), out_len==0 */
    uint8_t dummy[1] = {0};
    mq_udp_msg_hdr_t h = make_hdr(300, 0, 1);
    uint8_t *out = NULL;
    size_t out_len = 99; /* sentinel */

    int r = mq_defrag_feed(d, &h, dummy, 0, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL); /* must be freeable */
    MQ_CHECK_EQ_INT((long long)out_len, 0LL);
    free(out);

    mq_defrag_free(d);
}

/* ---- T1. Payload-copy proof ---------------------------------------------- */
/* Feed frag 0, clobber the source buffer, feed frag 1, clobber that buffer
 * too, then verify the assembled output still has the ORIGINAL bytes.      */
static void
test_payload_copy_proof(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t src0[] = {0x11, 0x22, 0x33};
    uint8_t src1[] = {0x44, 0x55, 0x66};
    uint8_t expected[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    mq_udp_msg_hdr_t h0 = make_hdr(400, 0, 2);
    mq_udp_msg_hdr_t h1 = make_hdr(400, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Feed frag 0, then clobber the source buffer */
    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h0, src0, sizeof src0, &out, &out_len), 0);
    memset(src0, 0xFF, sizeof src0);

    /* Feed frag 1 (completing), then clobber that buffer too */
    int r = mq_defrag_feed(d, &h1, src1, sizeof src1, &out, &out_len);
    memset(src1, 0xFF, sizeof src1);

    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 6LL);
    /* Output must still contain the original bytes, not 0xFF */
    MQ_CHECK_MEM(out, expected, 6);
    free(out);

    mq_defrag_free(d);
}

/* ---- T2. LRU survivors complete with correct content --------------------- */
/* After the 5th packet_id evicts the LRU slot (id=100), the three surviving
 * non-evicted slots (ids 101, 102, 103) should each complete correctly.    */
static void
test_lru_survivors_complete(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* Each packet_id i gets frag 0 with payload {i_lo, i_hi}. */
    uint8_t *out = NULL;
    size_t out_len = 0;

    /* Fill all 4 slots with ids 100..103, frag 0 of 2. */
    for (uint16_t id = 100; id <= 103; id++) {
        uint8_t p[2] = {(uint8_t)(id & 0xFF), 0xF0};
        mq_udp_msg_hdr_t h = make_hdr(id, 0, 2);
        MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, p, 2, &out, &out_len), 0);
    }

    /* Touch id=101 so id=100 stays LRU. */
    {
        uint8_t p[2] = {0x65, 0xF0}; /* duplicate frag → ignored */
        mq_udp_msg_hdr_t h = make_hdr(101, 0, 2);
        MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, p, 2, &out, &out_len), 0);
    }

    /* id=104 evicts id=100. */
    {
        uint8_t p[2] = {0x68, 0xF1};
        mq_udp_msg_hdr_t h = make_hdr(104, 0, 2);
        MQ_CHECK_EQ_INT(mq_defrag_feed(d, &h, p, 2, &out, &out_len), 0);
    }

    /* Complete surviving ids 101, 102, 103 and check content. */
    for (uint16_t id = 101; id <= 103; id++) {
        uint8_t completing[2] = {0xA0, (uint8_t)(id & 0xFF)};
        mq_udp_msg_hdr_t h = make_hdr(id, 1, 2);
        int r = mq_defrag_feed(d, &h, completing, 2, &out, &out_len);
        MQ_CHECK_EQ_INT(r, 1);
        MQ_CHECK(out != NULL);
        MQ_CHECK_EQ_INT((long long)out_len, 4LL);
        /* frag 0: {id_lo, 0xF0}, frag 1: {0xA0, id_lo} */
        uint8_t expected[4] = {(uint8_t)(id & 0xFF), 0xF0, 0xA0, (uint8_t)(id & 0xFF)};
        MQ_CHECK_MEM(out, expected, 4);
        free(out);
        out = NULL;
    }

    mq_defrag_free(d);
}

/* ---- T3. packet_id reuse via multi-frag ---------------------------------- */
/* Same packet_id X completes a 2-frag assembly, then is reused for a NEW
 * 2-frag assembly with DIFFERENT content and completes correctly.           */
static void
test_packet_id_wrap_multi_frag(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    uint8_t *out = NULL;
    size_t out_len = 0;
    const uint16_t PID = 500;

    /* First assembly with packet_id=PID */
    uint8_t a0[] = {0x01, 0x02};
    uint8_t a1[] = {0x03, 0x04};
    uint8_t expected_a[] = {0x01, 0x02, 0x03, 0x04};

    mq_udp_msg_hdr_t ha0 = make_hdr(PID, 0, 2);
    mq_udp_msg_hdr_t ha1 = make_hdr(PID, 1, 2);

    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &ha0, a0, sizeof a0, &out, &out_len), 0);
    int r = mq_defrag_feed(d, &ha1, a1, sizeof a1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 4LL);
    MQ_CHECK_MEM(out, expected_a, 4);
    free(out);
    out = NULL;

    /* Second assembly with same packet_id=PID, different content */
    uint8_t b0[] = {0xAA, 0xBB, 0xCC};
    uint8_t b1[] = {0xDD, 0xEE};
    uint8_t expected_b[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    mq_udp_msg_hdr_t hb0 = make_hdr(PID, 0, 2);
    mq_udp_msg_hdr_t hb1 = make_hdr(PID, 1, 2);

    MQ_CHECK_EQ_INT(mq_defrag_feed(d, &hb0, b0, sizeof b0, &out, &out_len), 0);
    r = mq_defrag_feed(d, &hb1, b1, sizeof b1, &out, &out_len);
    MQ_CHECK_EQ_INT(r, 1);
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 5LL);
    MQ_CHECK_MEM(out, expected_b, 5);
    free(out);

    mq_defrag_free(d);
}

/* ---- T4. Exactly-65535 bytes → accepted ---------------------------------- */
/* A 2-frag reassembly whose frags total exactly 65535 bytes must be ACCEPTED
 * (65536 is already tested as a rejection boundary).                        */
static void
test_reassembled_exactly_65535(void)
{
    mq_defrag_t *d = mq_defrag_new();
    MQ_CHECK(d != NULL);

    /* frag 0: 32767 bytes; frag 1: 32768 bytes → total 65535 */
    static uint8_t f0[32767];
    static uint8_t f1[32768];
    memset(f0, 0x5A, sizeof f0);
    memset(f1, 0xA5, sizeof f1);

    mq_udp_msg_hdr_t h0 = make_hdr(600, 0, 2);
    mq_udp_msg_hdr_t h1 = make_hdr(600, 1, 2);

    uint8_t *out = NULL;
    size_t out_len = 0;

    int r0 = mq_defrag_feed(d, &h0, f0, sizeof f0, &out, &out_len);
    MQ_CHECK_EQ_INT(r0, 0);

    int r1 = mq_defrag_feed(d, &h1, f1, sizeof f1, &out, &out_len);
    MQ_CHECK_EQ_INT(r1, 1); /* must be accepted, not rejected */
    MQ_CHECK(out != NULL);
    MQ_CHECK_EQ_INT((long long)out_len, 65535LL);
    /* Spot-check: first and last bytes of each segment */
    MQ_CHECK_EQ_INT((long long)out[0], 0x5ALL);
    MQ_CHECK_EQ_INT((long long)out[32766], 0x5ALL);
    MQ_CHECK_EQ_INT((long long)out[32767], 0xA5LL);
    MQ_CHECK_EQ_INT((long long)out[65534], 0xA5LL);
    free(out);

    mq_defrag_free(d);
}

MQ_TEST_MAIN({
    test_single_frag_passthrough();
    test_two_frag_in_order();
    test_two_frag_reverse_order();
    test_two_packet_ids_interleaved();
    test_lru_evict();
    test_duplicate_frag_ignored();
    test_frag_count_mismatch_drops_slot();
    test_frag_id_out_of_range();
    test_frag_count_zero_rejected();
    test_reassembled_too_large();
    test_packet_id_wrap();
    test_single_frag_zero_len();
    test_payload_copy_proof();
    test_lru_survivors_complete();
    test_packet_id_wrap_multi_frag();
    test_reassembled_exactly_65535();
})
