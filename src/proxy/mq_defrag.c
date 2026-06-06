// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "proxy/mq_defrag.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---- constants ---------------------------------------------------------- */

#define DEFRAG_SLOTS     4      /* number of concurrent reassembly slots */
#define DEFRAG_MAX_FRAGS 255    /* frag_count is u8, max value 255 */
#define DEFRAG_MAX_TOTAL 65535U /* max reassembled packet size (bytes) */

/* Bitmap storage: 256 bits = 32 bytes covers all possible frag_id values
 * (0..254 for frag_count up to 255). */
#define DEFRAG_BITMAP_BYTES 32

/* ---- per-fragment storage ----------------------------------------------- */

typedef struct {
    uint8_t *data; /* malloc'd copy of the fragment payload */
    size_t len;
} defrag_frag_t;

/* ---- reassembly slot ---------------------------------------------------- */

typedef struct {
    int active; /* 1 if this slot is in use */
    uint16_t packet_id;
    uint8_t frag_count;     /* expected number of fragments */
    uint8_t frags_received; /* count of distinct frags seen so far */
    size_t total_len;       /* accumulated byte count (incremental 65535 check) */
    uint64_t use_seq;       /* LRU: updated on every feed touching this slot */

    /* Per-frag storage: lazily allocated array of frag_count pointers. */
    defrag_frag_t *frags; /* malloc'd[frag_count] or NULL before first frag */

    /* Bitmap: bit i is set when frag_id==i has been received. */
    uint8_t bitmap[DEFRAG_BITMAP_BYTES];
} defrag_slot_t;

/* ---- top-level defragmenter -------------------------------------------- */

struct mq_defrag {
    defrag_slot_t slots[DEFRAG_SLOTS];
    uint64_t seq; /* monotonically increasing use counter */
};

/* ---- helpers ------------------------------------------------------------ */

static int
bitmap_test(const uint8_t bm[DEFRAG_BITMAP_BYTES], uint8_t bit)
{
    return (bm[bit >> 3] >> (bit & 7)) & 1;
}

static void
bitmap_set(uint8_t bm[DEFRAG_BITMAP_BYTES], uint8_t bit)
{
    bm[bit >> 3] |= (uint8_t)(1u << (bit & 7));
}

/* Free all frag copies stored in slot and reset it to inactive. */
static void
slot_reset(defrag_slot_t *s)
{
    if (s->frags) {
        for (int i = 0; i < (int)s->frag_count; i++) {
            free(s->frags[i].data);
            s->frags[i].data = NULL;
            s->frags[i].len = 0;
        }
        free(s->frags);
        s->frags = NULL;
    }
    memset(s->bitmap, 0, DEFRAG_BITMAP_BYTES);
    s->active = 0;
    s->packet_id = 0;
    s->frag_count = 0;
    s->frags_received = 0;
    s->total_len = 0;
    s->use_seq = 0;
}

/* Find an active slot with the given packet_id.  Returns pointer or NULL. */
static defrag_slot_t *
slot_find(mq_defrag_t *d, uint16_t packet_id)
{
    for (int i = 0; i < DEFRAG_SLOTS; i++) {
        if (d->slots[i].active && d->slots[i].packet_id == packet_id) return &d->slots[i];
    }
    return NULL;
}

/* Find a free slot.  Returns pointer or NULL if all slots are active. */
static defrag_slot_t *
slot_find_free(mq_defrag_t *d)
{
    for (int i = 0; i < DEFRAG_SLOTS; i++) {
        if (!d->slots[i].active) return &d->slots[i];
    }
    return NULL;
}

/* Evict the LRU slot (lowest use_seq among active slots), reset it, and
 * return a pointer to it (now free).  Must only be called when all slots are
 * active. */
static defrag_slot_t *
slot_evict_lru(mq_defrag_t *d)
{
    defrag_slot_t *lru = &d->slots[0];
    for (int i = 1; i < DEFRAG_SLOTS; i++) {
        if (d->slots[i].use_seq < lru->use_seq) lru = &d->slots[i];
    }
    slot_reset(lru);
    return lru;
}

/* Allocate and initialise a new slot for the given packet_id / frag_count.
 * Returns the slot on success, NULL on OOM. */
static defrag_slot_t *
slot_open(mq_defrag_t *d, uint16_t packet_id, uint8_t frag_count, uint64_t seq)
{
    defrag_slot_t *s = slot_find_free(d);
    if (!s) s = slot_evict_lru(d);

    /* Allocate per-frag storage array (frag_count entries). */
    s->frags = calloc((size_t)frag_count, sizeof(defrag_frag_t));
    if (!s->frags) return NULL;

    s->active = 1;
    s->packet_id = packet_id;
    s->frag_count = frag_count;
    s->frags_received = 0;
    s->total_len = 0;
    s->use_seq = seq;
    memset(s->bitmap, 0, DEFRAG_BITMAP_BYTES);

    return s;
}

/* Concatenate all stored fragments (in frag_id order) into a single malloc'd
 * buffer.  Returns the buffer via out/out_len, then resets the slot. */
static int
slot_assemble(defrag_slot_t *s, uint8_t **out, size_t *out_len)
{
    size_t total = s->total_len;
    /* Allocate at least 1 byte so the pointer is always non-NULL and freeable
     * even when total == 0 (shouldn't happen for multi-frag, but be safe). */
    uint8_t *buf = malloc(total > 0 ? total : 1);
    if (!buf) return -1;

    size_t off = 0;
    for (int i = 0; i < (int)s->frag_count; i++) {
        if (s->frags[i].len > 0) {
            memcpy(buf + off, s->frags[i].data, s->frags[i].len);
            off += s->frags[i].len;
        }
    }

    *out = buf;
    *out_len = total;
    slot_reset(s);
    return 0;
}

/* ---- public API --------------------------------------------------------- */

mq_defrag_t *
mq_defrag_new(void)
{
    mq_defrag_t *d = calloc(1, sizeof *d);
    return d;
}

void
mq_defrag_free(mq_defrag_t *d)
{
    if (!d) return;
    for (int i = 0; i < DEFRAG_SLOTS; i++)
        slot_reset(&d->slots[i]);
    free(d);
}

int
mq_defrag_feed(mq_defrag_t *d, const mq_udp_msg_hdr_t *h, const uint8_t *p, size_t len,
               uint8_t **out, size_t *out_len)
{
    /* --- input validation --- */
    if (h->frag_count == 0) return -1;
    if (h->frag_id >= h->frag_count) return -1;

    /* --- fast path: single-frag packet --- */
    if (h->frag_count == 1) {
        /* malloc(len+1): the +1 guarantees a non-NULL, freeable pointer even
         * when len==0.  Only len bytes are exposed to the caller (out_len=len). */
        uint8_t *buf = malloc(len + 1);
        if (!buf) return -1;
        if (len > 0) memcpy(buf, p, len);
        *out = buf;
        *out_len = len;
        return 1;
    }

    /* --- multi-frag path --- */
    uint64_t seq = ++d->seq;

    defrag_slot_t *s = slot_find(d, h->packet_id);

    if (s) {
        /* Existing slot: check frag_count consistency. */
        if (s->frag_count != h->frag_count) {
            /* Mismatch: drop the entire slot. */
            slot_reset(s);
            return -1;
        }
        /* Update LRU timestamp. */
        s->use_seq = seq;
    } else {
        /* New packet_id: open a slot (evicts LRU if all full). */
        s = slot_open(d, h->packet_id, h->frag_count, seq);
        if (!s) return -1; /* OOM */
    }

    /* Duplicate check: if the bit is already set, ignore silently. */
    if (bitmap_test(s->bitmap, h->frag_id)) return 0;

    /* Incremental 65535 check: would adding this fragment overflow? */
    if (s->total_len + len > DEFRAG_MAX_TOTAL) {
        slot_reset(s);
        return -1;
    }

    /* Copy the fragment payload (caller's buffer is transient). */
    uint8_t *frag_copy = NULL;
    if (len > 0) {
        frag_copy = malloc(len);
        if (!frag_copy) {
            slot_reset(s);
            return -1; /* OOM */
        }
        memcpy(frag_copy, p, len);
    }

    s->frags[h->frag_id].data = frag_copy;
    s->frags[h->frag_id].len = len;
    bitmap_set(s->bitmap, h->frag_id);
    s->frags_received++;
    s->total_len += len;

    /* Check if all fragments have arrived. */
    if (s->frags_received == s->frag_count) {
        if (slot_assemble(s, out, out_len) != 0) return -1; /* OOM on final assembly */
        return 1;
    }

    return 0;
}
