// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_CT_H
#define MQ_CT_H

#include <stddef.h>

/* Constant-time comparison of two byte ranges. Returns 1 if equal (same length
 * AND same bytes), 0 otherwise. The comparison time depends only on the shorter
 * length, not on WHERE the bytes differ: a volatile accumulator folds every
 * byte difference (and the length difference) so the compiler cannot
 * short-circuit and a timing side channel cannot leak how much of a secret
 * (e.g. an auth token) matched.
 *
 * Header-only so both the proxy server (proxy/mq_server.c) and the gateway
 * server (gateway/mq_gw_server.c) share ONE definition across the layering
 * boundary instead of each carrying a "keep in sync" static copy. */
static inline int
mq_ct_equal(const void *a, size_t alen, const void *b, size_t blen)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    volatile unsigned char acc = 0;
    /* Fold the length difference into the accumulator so a mismatching length
     * cannot pass even if the shorter is a prefix of the longer. */
    acc |= (unsigned char)((alen ^ blen) | ((alen ^ blen) >> 8) | ((alen ^ blen) >> 16) |
                           ((alen ^ blen) >> 24));
    size_t n = alen < blen ? alen : blen;
    for (size_t i = 0; i < n; i++)
        acc |= (unsigned char)(pa[i] ^ pb[i]);
    return acc == 0;
}

#endif /* MQ_CT_H */
