// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#ifndef MQ_GW_CACHE_H
#define MQ_GW_CACHE_H
#include <stddef.h>
#include <stdint.h>

/* Minimal in-memory LRU HTTP response cache for the gateway server (design
 * 2026-06-12-cache-integration). Single-threaded (the libevent loop) — NO locks.
 * Clock-free: callers pass a monotonic now_ms (CLOCK_MONOTONIC ms). */

typedef struct mq_gw_cache_hdr_s {
    char *name;  /* lowercase header name (NUL-term) */
    char *value; /* header value (NUL-term) */
} mq_gw_cache_hdr_t;

typedef struct mq_gw_cache_entry_s mq_gw_cache_entry_t;
struct mq_gw_cache_entry_s {
    char *key;  /* "GET <url>" (NUL-term) */
    int status; /* HTTP status (200) */
    mq_gw_cache_hdr_t *hdrs;
    size_t n_hdrs;
    uint8_t *body;
    size_t body_len;
    uint64_t stored_at_ms;
    uint64_t ttl_ms;
    size_t size_bytes;                        /* key + hdrs + body accounting */
    mq_gw_cache_entry_t *lru_prev, *lru_next; /* MRU at head */
};

typedef struct mq_gw_cache_s mq_gw_cache_t;

/* max_bytes 0 ⇒ returns NULL (disabled). max_obj_bytes is the per-object cap. */
mq_gw_cache_t *mq_gw_cache_new(size_t max_bytes, size_t max_obj_bytes);
void mq_gw_cache_free(mq_gw_cache_t *c);

/* Lookup a FRESH entry (drops it if expired). Returns a BORROWED const view or NULL.
 * The caller must COPY the body before yielding the loop (copy-on-hit — the entry can be
 * evicted by a later insert). Moves the entry to MRU on hit. */
const mq_gw_cache_entry_t *mq_gw_cache_lookup(mq_gw_cache_t *c, const char *key,
                                              uint64_t now_ms);

/* Build + insert an entry from copied inputs (the cache deep-copies all of them; the
 * caller keeps ownership of its buffers). Evicts LRU until it fits; refuses (returns -1,
 * stores nothing) if the single object exceeds max_obj_bytes. Returns 0 on insert. A
 * duplicate key replaces the old entry. */
int mq_gw_cache_insert(mq_gw_cache_t *c, const char *key, int status,
                       const mq_gw_cache_hdr_t *hdrs, size_t n_hdrs, const uint8_t *body,
                       size_t body_len, uint64_t ttl_ms, uint64_t now_ms);

size_t mq_gw_cache_bytes(const mq_gw_cache_t *c); /* current total (tests/diag) */
size_t
mq_gw_cache_max_obj_bytes(const mq_gw_cache_t *c); /* per-object cap (store gate) */

#endif
