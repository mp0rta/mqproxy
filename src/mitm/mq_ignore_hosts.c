// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_ignore_hosts — bounded host list with exact + leading-dot-suffix matching.
// See mq_ignore_hosts.h for the entry-normalization vs match-input contract.
#include "mitm/mq_ignore_hosts.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// A normalized DNS name is <= 253 chars (RFC 1035 presentation form). A suffix
// entry additionally carries a leading '.', so the longest stored pattern is
// 1 ('.') + 253 + 1 (NUL) = 255 bytes. 256 leaves a byte of slack.
#define MQ_IGNORE_HOST_LEN 256
#define MQ_DNS_NAME_MAX    253

struct mq_ignore_hosts {
    char entries[MQ_IGNORE_HOSTS_MAX][MQ_IGNORE_HOST_LEN];
    size_t count;
};

mq_ignore_hosts_t *
mq_ignore_hosts_new(void)
{
    return calloc(1, sizeof(struct mq_ignore_hosts));
}

void
mq_ignore_hosts_free(mq_ignore_hosts_t *l)
{
    free(l);
}

int
mq_ignore_hosts_add(mq_ignore_hosts_t *l, const char *pattern)
{
    if (l == NULL || pattern == NULL) return -1;
    if (l->count >= MQ_IGNORE_HOSTS_MAX) return -1;

    size_t plen = strlen(pattern);
    if (plen == 0) return -1;

    // Strip a single trailing dot (FQDN root). A leading dot is preserved as
    // the suffix marker, so only strip from the end, never collapsing the
    // leading-dot marker of a name like ".com." down past its own ".".
    if (pattern[plen - 1] == '.') plen--;
    if (plen == 0) return -1; // pattern was just "." (or "..") → bare marker, no host

    // The "host" portion (after any leading suffix-marker dot) must be a
    // non-empty DNS name; reject ".", which after the trailing-strip above
    // would leave nothing but the marker.
    size_t host_off = (pattern[0] == '.') ? 1 : 0;
    if (host_off >= plen) return -1; // e.g. just "." → marker with no host

    size_t host_len = plen - host_off;
    if (host_len > MQ_DNS_NAME_MAX) return -1; // over-long host portion

    // plen excludes the (stripped) trailing dot; it still fits with NUL since
    // plen <= 1 (marker) + 253 = 254 < MQ_IGNORE_HOST_LEN.
    char *dst = l->entries[l->count];
    for (size_t i = 0; i < plen; i++)
        dst[i] = (char)tolower((unsigned char)pattern[i]);
    dst[plen] = '\0';

    l->count++;
    return 0;
}

int
mq_ignore_hosts_match(const mq_ignore_hosts_t *l, const char *normalized_sni)
{
    if (l == NULL || normalized_sni == NULL) return 0;

    size_t slen = strlen(normalized_sni);
    for (size_t i = 0; i < l->count; i++) {
        const char *pat = l->entries[i];
        if (pat[0] == '.') {
            // Suffix entry: the SNI must be STRICTLY longer than the entry and
            // end with it (the leading '.' is part of pat, so "x.apple.com"
            // ends with ".apple.com" but "apple.com" does not, and
            // "notapple.com" ends with "apple.com" but the byte at the suffix
            // boundary is 't', not '.', so the compare fails).
            size_t plen = strlen(pat);
            if (slen > plen && strcmp(normalized_sni + (slen - plen), pat) == 0) return 1;
        } else {
            if (strcmp(normalized_sni, pat) == 0) return 1;
        }
    }
    return 0;
}
