// SPDX-License-Identifier: Apache-2.0
#include "gateway/mq_gw_cache.h"
#include "mqtest.h"
#include <string.h>

static const mq_gw_cache_hdr_t H1[] = {{"content-type", "text/plain"}};

static void
test_insert_lookup_hit(void)
{
    mq_gw_cache_t *c = mq_gw_cache_new(1 << 20, 1 << 20);
    MQ_CHECK(c != NULL);
    MQ_CHECK_EQ_INT(mq_gw_cache_insert(c, "GET http://o/a", 200, H1, 1,
                                       (const uint8_t *)"hello", 5, 10000, 0),
                    0);
    const mq_gw_cache_entry_t *e =
        mq_gw_cache_lookup(c, "GET http://o/a", 5000); /* fresh */
    MQ_CHECK(e != NULL);
    MQ_CHECK_EQ_INT(e->status, 200);
    MQ_CHECK_EQ_INT((int)e->body_len, 5);
    MQ_CHECK_EQ_INT(memcmp(e->body, "hello", 5), 0);
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/MISSING", 5000) == NULL);
    mq_gw_cache_free(c);
}

static void
test_expiry(void)
{
    mq_gw_cache_t *c = mq_gw_cache_new(1 << 20, 1 << 20);
    mq_gw_cache_insert(c, "GET http://o/a", 200, H1, 1, (const uint8_t *)"x", 1, 1000, 0);
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/a", 999) != NULL); /* fresh < ttl */
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/a", 1000) ==
             NULL); /* expired (now>=stored+ttl) */
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/a", 2000) == NULL); /* and dropped */
    mq_gw_cache_free(c);
}

static void
test_lru_evict(void)
{
    /* small cap: each ~ key+body fits 2 but not 3 */
    mq_gw_cache_t *c = mq_gw_cache_new(64, 64);
    mq_gw_cache_insert(c, "GET http://o/aaaaaaaa", 200, NULL, 0,
                       (const uint8_t *)"123456", 6, 100000, 0);
    mq_gw_cache_insert(c, "GET http://o/bbbbbbbb", 200, NULL, 0,
                       (const uint8_t *)"123456", 6, 100000, 0);
    /* touch a → MRU */
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/aaaaaaaa", 1) != NULL);
    /* insert c → evicts LRU (b), keeps a */
    mq_gw_cache_insert(c, "GET http://o/cccccccc", 200, NULL, 0,
                       (const uint8_t *)"123456", 6, 100000, 0);
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/aaaaaaaa", 1) !=
             NULL); /* survived (was MRU) */
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/bbbbbbbb", 1) == NULL); /* evicted */
    mq_gw_cache_free(c);
}

static void
test_per_object_cap(void)
{
    mq_gw_cache_t *c = mq_gw_cache_new(1 << 20, 8 /* tiny per-obj */);
    MQ_CHECK_EQ_INT(mq_gw_cache_insert(c, "GET http://o/a", 200, NULL, 0,
                                       (const uint8_t *)"way too big body", 16, 1000, 0),
                    -1); /* refused */
    MQ_CHECK(mq_gw_cache_lookup(c, "GET http://o/a", 1) == NULL);
    mq_gw_cache_free(c);
}

static void
test_disabled(void)
{
    MQ_CHECK(mq_gw_cache_new(0, 0) == NULL); /* 0 total ⇒ disabled */
}

static void
test_replace_dup_key(void)
{
    mq_gw_cache_t *c = mq_gw_cache_new(1 << 20, 1 << 20);
    mq_gw_cache_insert(c, "GET http://o/a", 200, NULL, 0, (const uint8_t *)"old", 3,
                       100000, 0);
    mq_gw_cache_insert(c, "GET http://o/a", 200, NULL, 0, (const uint8_t *)"newer", 5,
                       100000, 0);
    const mq_gw_cache_entry_t *e = mq_gw_cache_lookup(c, "GET http://o/a", 1);
    MQ_CHECK(e != NULL && e->body_len == 5 && memcmp(e->body, "newer", 5) == 0);
    mq_gw_cache_free(c);
}

MQ_TEST_MAIN({
    test_insert_lookup_hit();
    test_expiry();
    test_lru_evict();
    test_per_object_cap();
    test_disabled();
    test_replace_dup_key();
})
