// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_DEFRAG_H
#define MQ_DEFRAG_H
#include <stddef.h>
#include <stdint.h>

#include "wire/mq_udp_msg.h"

/* Datagram defragmenter — per-session, pure logic (no I/O, no clocks).
 *
 * Internally keeps 4 reassembly slots keyed by packet_id, evicting the
 * least-recently-used slot when all 4 are occupied and a new packet_id arrives.
 *
 * Caller is responsible for demultiplexing by session_id before calling
 * mq_defrag_feed(); session_id in the header is ignored by this module. */
typedef struct mq_defrag mq_defrag_t;

/* Allocate a new defragmenter.  Returns NULL on OOM. */
mq_defrag_t *mq_defrag_new(void);

/* Free all resources owned by d.  Safe to call with NULL. */
void mq_defrag_free(mq_defrag_t *d);

/* Feed one fragment into the defragmenter.
 *
 * h    — decoded header for this fragment (session_id ignored)
 * p    — payload bytes for this fragment (caller's buffer, may be transient)
 * len  — length of p
 * out     — set to newly malloc'd reassembled packet on return 1; caller frees
 * out_len — set to reassembled length on return 1
 *
 * Returns:
 *   1   Packet complete: *out (malloc'd, caller must free) and *out_len are set.
 *       For frag_count==1 the assembly loop is skipped; *out is malloc(len+1)
 *       (minimum 1 byte to guarantee a non-NULL freeable pointer, extra byte
 *       never exposed) and *out_len == len.
 *   0   Fragment accepted; packet not yet complete (or duplicate fragment ignored).
 *   -1  Fragment rejected; slot dropped if applicable.  Counted by caller.
 *
 * Rejection conditions (return -1):
 *   frag_count == 0
 *   frag_id >= frag_count
 *   frag_count mismatch vs the slot's recorded frag_count (whole slot dropped)
 *   reassembled total would exceed 65535 bytes (whole slot dropped)
 *
 * Duplicate fragment (bitmap already set for frag_id): silently ignored,
 * returns 0 (not -1). */
int mq_defrag_feed(mq_defrag_t *d, const mq_udp_msg_hdr_t *h, const uint8_t *p,
                   size_t len, uint8_t **out, size_t *out_len);

#endif /* MQ_DEFRAG_H */
