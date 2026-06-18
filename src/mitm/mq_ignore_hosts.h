// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_ignore_hosts — Phase 7 Slice 3 MITM "leave this flow opaque" host list.
// Operators populate it from config [Mitm] IgnoreHosts / CLI --ignore-host(s);
// the live MITM orchestrator asks "should I splice this connection through
// untouched instead of terminating + forging?" once it has the ClientHello SNI.
//
// Two entry kinds:
//   exact  "signal.org"  — matches ONLY the apex "signal.org".
//   suffix ".apple.com"  — matches every strict subdomain ("x.apple.com",
//                          "a.b.apple.com") but NOT the apex "apple.com".
//
// Entry normalization (mq_ignore_hosts_add) uses this module's OWN rules:
// lowercase + strip a single trailing dot, but PRESERVE a leading '.' (it is
// the suffix marker). Entries are deliberately NOT run through
// mq_mitm_normalize_sni, which rejects a leading dot as an empty label.
//
// The SNI handed to mq_ignore_hosts_match is ALREADY normalized by the caller
// via mq_mitm_normalize_sni (lowercase, no leading/trailing dot), so match()
// only compares — it does not re-normalize.
#ifndef MQ_IGNORE_HOSTS_H
#define MQ_IGNORE_HOSTS_H

// Maximum number of entries in one list (bounded to cap memory + match cost).
#define MQ_IGNORE_HOSTS_MAX 256

typedef struct mq_ignore_hosts mq_ignore_hosts_t;

// Allocate an empty list. Returns NULL on allocation failure.
mq_ignore_hosts_t *mq_ignore_hosts_new(void);

// Add one pattern (normalized with this module's rules). Returns 0 on success,
// <0 on invalid input (NULL/empty/bare "."/over-long) or when the list is full.
int mq_ignore_hosts_add(mq_ignore_hosts_t *l, const char *pattern);

// Returns 1 if `normalized_sni` (already mq_mitm_normalize_sni-normalized by the
// caller) should be left OPAQUE, else 0. NULL list or NULL sni → 0.
int mq_ignore_hosts_match(const mq_ignore_hosts_t *l, const char *normalized_sni);

// Free the list. mq_ignore_hosts_free(NULL) is a no-op.
void mq_ignore_hosts_free(mq_ignore_hosts_t *l);

#endif // MQ_IGNORE_HOSTS_H
