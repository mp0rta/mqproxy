// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_core — Phase 7 Slice 2 MITM crypto core. I/O-free: owns CA + per-SNI
// leaf forge + LRU cache + a server-mode SSL_CTX. The CALLER owns the socket/BIO
// and pumps the handshake. NOT wired into the live tproxy path (Slice 3).
#ifndef MQ_MITM_CORE_H
#define MQ_MITM_CORE_H

#include <openssl/ssl.h>
#include <stddef.h>
#include <time.h>

typedef struct mq_mitm_core mq_mitm_core_t;

typedef struct {
    size_t cache_size; // forged-leaf LRU capacity; 0 disables caching (always forge)
    int leaf_ttl_sec;  // forged-leaf validity = now-1h .. now+ttl; clamped to [60,
                       // 86400*30]
} mq_mitm_opts_t;

// Load CA from PEM paths. Validates CA eligibility (CA:TRUE; keyCertSign when
// keyUsage present; EXFLAG_INVALID clear; NAME_CONSTRAINTS rejected), key<->cert
// match, and key-file safety (regular file, owner-only perms, no symlink, not
// encrypted). Generates the single shared P-256 leaf key. Returns NULL on any
// failure. opts==NULL uses defaults (cache_size=256, leaf_ttl_sec=86400).
mq_mitm_core_t *mq_mitm_core_create(const char *ca_cert_pem_path,
                                    const char *ca_key_pem_path,
                                    const mq_mitm_opts_t *opts);

// Returns a server-mode SSL* with the select-certificate callback (no-ALPN guard
// + SNI normalize + forge/cache + attach) and h2 ALPN selector installed. The
// core pointer is stashed on the SSL via ex_data so the user-data-less callback
// can recover it. OWNERSHIP: caller owns the returned SSL* and MUST SSL_free it
// before mq_mitm_core_destroy(). Attaching BIO(s) via SSL_set_bio transfers BIO
// ownership to the SSL. Returns NULL on allocation failure.
SSL *mq_mitm_core_new_ssl(mq_mitm_core_t *core);

void mq_mitm_core_destroy(mq_mitm_core_t *core);

// TEST-ONLY: override the clock used for leaf validity + cache expiry. Pass NULL
// to restore the default (time(NULL)). Not for production use.
void mq_mitm_core_set_clock_for_test(mq_mitm_core_t *core, time_t (*now_fn)(void));

#endif // MQ_MITM_CORE_H
