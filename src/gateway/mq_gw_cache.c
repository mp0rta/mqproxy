// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "gateway/mq_gw_cache.h"

#include <stdlib.h>
#include <string.h>

/* Minimal in-memory LRU response cache (design 2026-06-12-cache-integration).
 * Single-threaded (no locks); clock-free (callers pass now_ms). The store is a
 * doubly-linked LRU list (MRU at head, LRU at tail) with a LINEAR key search —
 * the cache is byte-bounded and per-instance small, so O(n) lookup is fine
 * (a hash index is a documented future optimization). */

struct mq_gw_cache_s {
    size_t max_bytes;          /* hard total byte budget */
    size_t max_obj_bytes;      /* per-object cap (refuse larger) */
    size_t cur_bytes;          /* sum of all entries' size_bytes */
    mq_gw_cache_entry_t *head; /* MRU */
    mq_gw_cache_entry_t *tail; /* LRU */
};

/* ---------------------------------------------------------------------------
 * Entry helpers
 * ------------------------------------------------------------------------- */

/* Free every heap allocation owned by an entry, then the entry itself.
 * NULL-safe on the entry and on every sub-allocation (free(NULL) is a no-op). */
static void
entry_free(mq_gw_cache_entry_t *e)
{
    if (!e) return;
    free(e->key);
    if (e->hdrs) {
        for (size_t i = 0; i < e->n_hdrs; i++) {
            free(e->hdrs[i].name);
            free(e->hdrs[i].value);
        }
        free(e->hdrs);
    }
    free(e->body);
    free(e);
}

/* Detach an entry from the LRU list (does NOT free it, does NOT touch cur_bytes). */
static void
unlink_entry(mq_gw_cache_t *c, mq_gw_cache_entry_t *e)
{
    if (e->lru_prev)
        e->lru_prev->lru_next = e->lru_next;
    else
        c->head = e->lru_next; /* e was the head */
    if (e->lru_next)
        e->lru_next->lru_prev = e->lru_prev;
    else
        c->tail = e->lru_prev; /* e was the tail */
    e->lru_prev = e->lru_next = NULL;
}

/* Link an entry at the head (MRU). Caller adjusts cur_bytes. */
static void
link_head(mq_gw_cache_t *c, mq_gw_cache_entry_t *e)
{
    e->lru_prev = NULL;
    e->lru_next = c->head;
    if (c->head) c->head->lru_prev = e;
    c->head = e;
    if (!c->tail) c->tail = e;
}

/* Remove + free an entry, fixing cur_bytes. */
static void
drop_entry(mq_gw_cache_t *c, mq_gw_cache_entry_t *e)
{
    unlink_entry(c, e);
    c->cur_bytes -= e->size_bytes;
    entry_free(e);
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

mq_gw_cache_t *
mq_gw_cache_new(size_t max_bytes, size_t max_obj_bytes)
{
    if (max_bytes == 0) return NULL; /* disabled */
    mq_gw_cache_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->max_bytes = max_bytes;
    c->max_obj_bytes = max_obj_bytes;
    return c;
}

void
mq_gw_cache_free(mq_gw_cache_t *c)
{
    if (!c) return;
    mq_gw_cache_entry_t *e = c->head;
    while (e) {
        mq_gw_cache_entry_t *next = e->lru_next;
        entry_free(e);
        e = next;
    }
    free(c);
}

const mq_gw_cache_entry_t *
mq_gw_cache_lookup(mq_gw_cache_t *c, const char *key, uint64_t now_ms)
{
    if (!c || !key) return NULL;
    for (mq_gw_cache_entry_t *e = c->head; e; e = e->lru_next) {
        if (strcmp(e->key, key) != 0) continue;
        if (now_ms < e->stored_at_ms + e->ttl_ms) {
            /* fresh → promote to MRU and return a borrowed view */
            if (e != c->head) {
                unlink_entry(c, e);
                link_head(c, e);
            }
            return e;
        }
        /* found but expired → drop it, report miss */
        drop_entry(c, e);
        return NULL;
    }
    return NULL;
}

int
mq_gw_cache_insert(mq_gw_cache_t *c, const char *key, int status,
                   const mq_gw_cache_hdr_t *hdrs, size_t n_hdrs, const uint8_t *body,
                   size_t body_len, uint64_t ttl_ms, uint64_t now_ms)
{
    if (!c || !key) return -1;

    size_t klen = strlen(key);
    /* Early per-object-cap reject BEFORE the deep-copy: header bytes only add
     * more, so (klen + 1 + body_len) > max_obj_bytes is a conservative-safe
     * lower bound — avoids mallocing then freeing a too-large blob. The exact
     * size (with headers) is re-checked after the copy below. */
    if (klen + 1 + body_len > c->max_obj_bytes) return -1;

    /* Build a deep-copied entry; any failure on the way frees what we've
     * allocated so far (entry_free is NULL-safe on partial entries). */
    mq_gw_cache_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return -1;

    /* Byte accounting is PAYLOAD-only: key + headers + body. The fixed
     * per-entry struct overhead (sizeof(*e)) is deliberately EXCLUDED so that
     * max_bytes / max_obj_bytes mean "payload bytes" — what an operator setting
     * --cache-max-bytes expects, and what the unit tests assume (test_lru_evict
     * sizes two ~28-byte payload entries into a 64-byte cap; including the
     * 88-byte struct would refuse every insert). The plan's draft formula listed
     * a +sizeof(entry) term that contradicts the verbatim test; the test is the
     * ground truth, so payload-only accounting is used. */
    size_t size = klen + 1 + body_len;

    e->status = status;
    e->stored_at_ms = now_ms;
    e->ttl_ms = ttl_ms;
    e->body_len = body_len;

    e->key = malloc(klen + 1);
    if (!e->key) {
        entry_free(e);
        return -1;
    }
    memcpy(e->key, key, klen + 1);

    if (n_hdrs > 0 && hdrs) {
        e->hdrs = calloc(n_hdrs, sizeof(*e->hdrs));
        if (!e->hdrs) {
            entry_free(e);
            return -1;
        }
        /* n_hdrs is set incrementally so a mid-loop failure only frees the
         * names/values copied so far. */
        for (size_t i = 0; i < n_hdrs; i++) {
            size_t nl = strlen(hdrs[i].name);
            size_t vl = strlen(hdrs[i].value);
            e->hdrs[i].name = malloc(nl + 1);
            e->hdrs[i].value = malloc(vl + 1);
            if (!e->hdrs[i].name || !e->hdrs[i].value) {
                free(e->hdrs[i].name);
                free(e->hdrs[i].value);
                e->hdrs[i].name = e->hdrs[i].value = NULL;
                e->n_hdrs = i;
                entry_free(e);
                return -1;
            }
            memcpy(e->hdrs[i].name, hdrs[i].name, nl + 1);
            memcpy(e->hdrs[i].value, hdrs[i].value, vl + 1);
            size += nl + 1 + vl + 1;
        }
        e->n_hdrs = n_hdrs;
    }

    if (body_len > 0) {
        e->body = malloc(body_len);
        if (!e->body) {
            entry_free(e);
            return -1;
        }
        if (body) memcpy(e->body, body, body_len);
    }

    e->size_bytes = size;

    /* Single object too large for the per-object cap → refuse, store nothing. */
    if (size > c->max_obj_bytes) {
        entry_free(e);
        return -1;
    }

    /* Duplicate key replaces the old entry (drop it before sizing/eviction). */
    for (mq_gw_cache_entry_t *o = c->head; o; o = o->lru_next) {
        if (strcmp(o->key, key) == 0) {
            drop_entry(c, o);
            break;
        }
    }

    /* Evict LRU until the newcomer fits the total budget. (size <= max_obj_bytes
     * <= max_bytes is the caller's invariant via set_cache, but even if not, the
     * per-object cap already refused anything that can never fit.) */
    while (c->tail && c->cur_bytes + size > c->max_bytes)
        drop_entry(c, c->tail);

    link_head(c, e);
    c->cur_bytes += size;
    return 0;
}

size_t
mq_gw_cache_bytes(const mq_gw_cache_t *c)
{
    return c ? c->cur_bytes : 0;
}

size_t
mq_gw_cache_max_obj_bytes(const mq_gw_cache_t *c)
{
    return c ? c->max_obj_bytes : 0;
}
