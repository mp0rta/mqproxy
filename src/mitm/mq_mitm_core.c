// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_core — Phase 7 Slice 2 MITM crypto core. I/O-free crypto module:
// loads + validates a CA, owns the shared P-256 leaf key (forge/cache/SSL_CTX
// land in later Slice 2 tasks). NOT wired into the live tproxy path (Slice 3).
#include "mitm/mq_mitm_core.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MQ_DNS_NAME_MAX  253 /* RFC 1035 presentation-form name limit */
#define MQ_DNS_LABEL_MAX 63  /* RFC 1035 label limit */

#define MQ_MITM_LEAF_SERIAL_BITS  64   /* random leaf serial width */
#define MQ_MITM_LEAF_BACKDATE_SEC 3600 /* notBefore clock-skew tolerance */

#define MQ_MITM_CACHE_SKEW_SEC 30 /* treat a leaf within SKEW of not_after as stale */

// One bounded-LRU cache entry: a forged leaf keyed by its normalized SNI.
// REFCOUNT OWNERSHIP: the entry holds ONE X509 ref on `leaf` (taken via
// X509_up_ref / inherited from forge_leaf at insert). cache_get_or_forge hands
// the CALLER a SEPARATE ref. The cache's ref is released only by eviction or by
// destroy (X509_free). MRU is the head of the doubly-linked list; LRU is the tail.
typedef struct mq_cache_entry {
    char norm_sni[256];          // normalized DNS name key
    X509 *leaf;                  // cache-owned ref (one)
    time_t not_after;            // expiry instant (forge-time now + leaf_ttl_sec)
    struct mq_cache_entry *prev; // toward MRU/head
    struct mq_cache_entry *next; // toward LRU/tail
} mq_cache_entry_t;

struct mq_mitm_core {
    // Lifetime refcount. Starts at 1 (the create()/destroy() owner ref). Each SSL
    // built by mq_mitm_core_new_ssl takes ANOTHER ref (stashed in SSL ex-data) and
    // releases it from the SSL ex-data free callback on SSL_free. The core's
    // resources are torn down only when the count reaches 0, so destroy() may run
    // while SSLs are still alive without dangling the core pointer they hold.
    // Non-atomic: the 1-client/process model means one owner thread (same
    // assumption as the lazy SSL_CTX build below).
    int refcount;
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    EVP_PKEY *leaf_key; // shared across all forged leaves
    size_t cache_size;
    int leaf_ttl_sec;
    time_t (*now_fn)(void);
    SSL_CTX *ssl_ctx; // created lazily in new_ssl (Task 6); NULL here
    // Bounded LRU leaf cache (Task 5). Intrusive doubly-linked list, MRU at head,
    // LRU at tail; linear scan (cache_size <= 256, small — no hashing). `count`
    // tracks current entries. All NULL/0 when cache_size == 0 (caching disabled).
    mq_cache_entry_t *lru_head;
    mq_cache_entry_t *lru_tail;
    size_t cache_count;
};

static time_t
mq_default_now(void)
{
    return time(NULL);
}

// Normalize an SNI host name for use as a forge key / SAN entry. On success
// returns 0 and writes a NUL-terminated, lowercased DNS name (<= 253 chars)
// into out. Returns -1 for: NULL/empty input, total length > 253, any label
// > 63 bytes, empty label (e.g. "a..b" or leading dot), an IP literal
// (IPv4/IPv6, via inet_pton), a wildcard (any '*'), or any byte outside
// [A-Za-z0-9.-]. A single trailing dot is stripped before validation.
int
mq_mitm_normalize_sni(const char *sni, size_t sni_len, char out[256])
{
    if (!sni || sni_len == 0) return -1;

    // Strip a single trailing dot (root label), then re-check for emptiness.
    if (sni[sni_len - 1] == '.') sni_len--;
    if (sni_len == 0) return -1;

    // Total length cap (DNS presentation name, excluding the stripped dot).
    if (sni_len > MQ_DNS_NAME_MAX) return -1;

    // Reject wildcards and any byte outside [A-Za-z0-9.-]; lowercase ASCII;
    // enforce per-label length (1..63, no empty labels).
    char tmp[MQ_DNS_NAME_MAX + 1];
    size_t label_len = 0;
    for (size_t i = 0; i < sni_len; i++) {
        unsigned char ch = (unsigned char)sni[i];
        if (ch == '.') {
            if (label_len == 0) return -1; // empty label (leading/double dot)
            label_len = 0;
            tmp[i] = '.';
            continue;
        }
        if (ch == '*') return -1; // wildcard
        char c;
        if (ch >= 'A' && ch <= 'Z') {
            c = (char)(ch - 'A' + 'a');
        } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
            c = (char)ch;
        } else {
            return -1; // any other byte (control chars, '_', etc.)
        }
        if (++label_len > MQ_DNS_LABEL_MAX) return -1; // label too long
        tmp[i] = c;
    }
    // Reject a trailing empty label. The single-dot strip above only removes ONE
    // root dot, so multi-dot suffixes ("example.com..") arrive here with the loop
    // having reset label_len to 0 on the final '.'. This MUST be a runtime check,
    // not an assert: SNI is attacker-controlled and reaches this on the live
    // cert-selection path — an assert would abort the data plane (debug) or, under
    // NDEBUG, let a trailing-dot name through as a forge key / SAN (normalization
    // bypass → cache amplification).
    if (label_len == 0) return -1;
    tmp[sni_len] = '\0';

    // Reject IP literals — they must not be treated as DNS names. inet_pton on
    // the lowercased copy covers IPv4 (and IPv6, which the charset filter above
    // already rejects via ':' but we check defensively).
    unsigned char addr[16];
    if (inet_pton(AF_INET, tmp, addr) == 1) return -1;
    if (inet_pton(AF_INET6, tmp, addr) == 1) return -1;

    memcpy(out, tmp, sni_len + 1);
    return 0;
}

// Password callback that always declines: an encrypted PEM (which needs a
// passphrase) fails to decode rather than prompting on a tty.
static int
no_password_cb(char *buf, int size, int rw, void *u)
{
    (void)buf;
    (void)size;
    (void)rw;
    (void)u;
    return 0;
}

// Read a PEM file with TOCTOU-free safety checks. Opens with O_NOFOLLOW (reject
// symlinks) + O_CLOEXEC, then fstat()s the fd (not the path) to reject
// non-regular files. When `require_private_perms` is set (the CA *key*), the
// fstat also rejects any group/other access bits and non-owner files; the CA
// *cert* is public material, so it loads with the symlink/cloexec protection
// only (no perms gate — the cert is routinely group/world-readable).
// On success returns a memory BIO holding the file contents (caller frees).
static BIO *
read_pem_file_safely(const char *path, int require_private_perms)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    if (require_private_perms &&
        ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0 || st.st_uid != geteuid())) {
        close(fd);
        return NULL;
    }

    // Read the whole file. CA cert/key PEMs are small; cap defensively at 1 MiB.
    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem) {
        close(fd);
        return NULL;
    }
    unsigned char buf[4096];
    size_t total = 0;
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r < 0) {
            BIO_free(mem);
            close(fd);
            return NULL;
        }
        if (r == 0) break;
        total += (size_t)r;
        if (total > (1u << 20)) {
            BIO_free(mem);
            close(fd);
            return NULL;
        }
        if (BIO_write(mem, buf, (int)r) != r) {
            BIO_free(mem);
            close(fd);
            return NULL;
        }
    }
    close(fd);
    return mem;
}

mq_mitm_core_t *
mq_mitm_core_create(const char *ca_cert_pem_path, const char *ca_key_pem_path,
                    const mq_mitm_opts_t *opts)
{
    if (!ca_cert_pem_path || !ca_key_pem_path) return NULL;

    mq_mitm_core_t *core = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL;
    EVP_PKEY *leaf_key = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    BIO *key_bio = NULL;
    BIO *cert_bio = NULL;

    // --- 1. Load the CA private key with key-file safety checks first ---
    // (perms gate runs BEFORE PEM parse — see MINOR-2 in the plan.)
    key_bio = read_pem_file_safely(ca_key_pem_path, 1 /*require_private_perms*/);
    if (!key_bio) goto fail;
    ca_key = PEM_read_bio_PrivateKey(key_bio, NULL, no_password_cb, NULL);
    if (!ca_key) goto fail; // unparseable, or encrypted (no_password_cb declines)

    // --- 2. Load the CA certificate. Route through the SAME safe-open helper as
    // the key (O_NOFOLLOW|O_CLOEXEC, TOCTOU-free) but WITHOUT the perms gate: the
    // cert is public material and routinely group/world-readable. ---
    cert_bio = read_pem_file_safely(ca_cert_pem_path, 0 /*require_private_perms*/);
    if (!cert_bio) goto fail;
    ca_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!ca_cert) goto fail;

    // --- 3. CA eligibility (I4: ca_cert is a MUTABLE handle; the accessors
    // below lazily compute the extension flags, so call them in this order). ---
    // X509_check_ca() also triggers flag computation; do it first.
    if (X509_check_ca(ca_cert) < 1)
        goto fail; // not a CA (CA:FALSE or no basicConstraints)
    uint32_t exflags = X509_get_extension_flags(ca_cert);
    if (exflags & EXFLAG_INVALID) goto fail; // malformed/contradictory extensions
    // X509_check_ca() treats an X509v1 cert (which has NO extensions) as
    // CA-eligible. Require a real basicConstraints extension so a v1 / no-BCONS
    // cert can't be loaded as a signing CA — i.e. demand explicit CA:TRUE.
    if (!(exflags & EXFLAG_BCONS)) goto fail;
    // keyUsage stays CONDITIONAL on purpose: RFC 5280 §4.2.1.3 makes keyUsage
    // OPTIONAL, and an absent keyUsage permits all usages (incl. cert signing).
    // We reject only a PRESENT keyUsage that withholds keyCertSign — tightening
    // this to "keyUsage mandatory" would wrongly reject conformant CAs that omit it.
    if (exflags & EXFLAG_KUSAGE) {
        if (!(X509_get_key_usage(ca_cert) & KU_KEY_CERT_SIGN))
            goto fail; // keyUsage present but cannot sign certs
    }
    // NAME_CONSTRAINTS unsupported in v1 — reject if present.
    {
        void *nc = X509_get_ext_d2i(ca_cert, NID_name_constraints, NULL, NULL);
        if (nc) {
            NAME_CONSTRAINTS_free((NAME_CONSTRAINTS *)nc);
            goto fail;
        }
    }

    // --- 4. key <-> cert match ---
    if (X509_check_private_key(ca_cert, ca_key) != 1) goto fail;

    // --- 5. Shared P-256 leaf key (C2: EVP_EC_gen is ABSENT here — use the
    // EVP_PKEY_CTX paramgen path). ---
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kctx, &leaf_key) <= 0)
        goto fail;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    // --- 6. Assemble the core ---
    core = calloc(1, sizeof *core);
    if (!core) goto fail;
    core->refcount = 1; // owner ref, released by mq_mitm_core_destroy
    core->ca_cert = ca_cert;
    core->ca_key = ca_key;
    core->leaf_key = leaf_key;
    core->ssl_ctx = NULL;
    core->now_fn = mq_default_now;

    size_t cache_size = 256;
    int leaf_ttl_sec = 86400;
    if (opts) {
        cache_size = opts->cache_size;
        leaf_ttl_sec = opts->leaf_ttl_sec;
    }
    if (leaf_ttl_sec < 60)
        leaf_ttl_sec = 60;
    else if (leaf_ttl_sec > 86400 * 30)
        leaf_ttl_sec = 86400 * 30;
    if (cache_size > 256) cache_size = 256;
    core->cache_size = cache_size;
    core->leaf_ttl_sec = leaf_ttl_sec;

    BIO_free(key_bio);
    BIO_free(cert_bio);
    return core;

fail:
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (leaf_key) EVP_PKEY_free(leaf_key);
    if (ca_cert) X509_free(ca_cert);
    if (ca_key) EVP_PKEY_free(ca_key);
    if (cert_bio) BIO_free(cert_bio);
    if (key_bio) BIO_free(key_bio);
    return NULL;
}

// Add a v3 extension to `leaf` from a config string (e.g. "critical,CA:FALSE")
// using the X509V3 config-string mechanism. Returns 0 on success, -1 on failure.
static int
add_ext_conf(X509 *leaf, int nid, const char *value)
{
    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    // issuer = leaf's own issuer (already set), subject = leaf — sufficient for
    // basicConstraints / keyUsage / extendedKeyUsage which don't reference names.
    X509V3_set_ctx(&v3ctx, leaf, leaf, NULL, NULL, 0);
    // Use the nconf variant (conf=NULL): the thin X509V3_EXT_conf_nid wrapper is
    // not present in the vendored BoringSSL static archive.
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &v3ctx, nid, (char *)value);
    if (!ext) return -1;
    int rc = X509_add_ext(leaf, ext, -1);
    X509_EXTENSION_free(ext);
    return rc == 1 ? 0 : -1;
}

// Build a per-SNI leaf per the spec §3 profile, signed by the CA. `ku_str` is the
// keyUsage extension config string ("critical,digitalSignature" in production).
// The forge_leaf production wrapper pins the spec keyUsage; the parameter exists
// so the test suite can prove the SSL-server purpose gate is load-bearing.
// Returns a new X509* owned by the caller, or NULL on failure (no leaks).
static X509 *
forge_leaf_ku(mq_mitm_core_t *core, const char *norm_sni, const char *ku_str)
{
    if (!core || !norm_sni) return NULL;

    X509 *leaf = NULL;
    GENERAL_NAME *gen = NULL;
    GENERAL_NAMES *gens = NULL;
    ASN1_IA5STRING *ia5 = NULL;
    BIGNUM *bn = NULL;
    ASN1_INTEGER *serial = NULL;
    X509_NAME *subj = NULL;
    int ok = 0;

    leaf = X509_new();
    if (!leaf) goto done;
    if (X509_set_version(leaf, 2) != 1) goto done; // v3

    // Issuer = CA subject name.
    if (X509_set_issuer_name(leaf, X509_get_subject_name(core->ca_cert)) != 1) goto done;

    // Subject CN = fixed literal (NOT the SNI — DNS names can exceed CN limit).
    subj = X509_get_subject_name(leaf);
    if (!subj) goto done;
    if (X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_ASC,
                                   (const unsigned char *)"mqproxy-mitm", -1, -1, 0) != 1)
        goto done;

    // Public key = shared leaf key.
    if (X509_set_pubkey(leaf, core->leaf_key) != 1) goto done;

    // Serial = positive random (~64 bits).
    bn = BN_new();
    if (!bn) goto done;
    if (BN_rand(bn, MQ_MITM_LEAF_SERIAL_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1)
        goto done;
    serial = BN_to_ASN1_INTEGER(bn, NULL);
    if (!serial) goto done;
    if (X509_set_serialNumber(leaf, serial) != 1) goto done;

    // Validity: notBefore = now-1h, notAfter = now + leaf_ttl_sec.
    {
        time_t now = core->now_fn();
        if (!X509_time_adj_ex(X509_getm_notBefore(leaf), 0, -MQ_MITM_LEAF_BACKDATE_SEC,
                              &now))
            goto done;
        if (!X509_time_adj_ex(X509_getm_notAfter(leaf), 0, core->leaf_ttl_sec, &now))
            goto done;
    }

    // SAN: DNS = normalized SNI, built via GENERAL_NAME/GEN_DNS (NOT a conf string).
    gens = sk_GENERAL_NAME_new_null();
    if (!gens) goto done;
    gen = GENERAL_NAME_new();
    if (!gen) goto done;
    ia5 = ASN1_IA5STRING_new();
    if (!ia5) goto done;
    if (ASN1_STRING_set(ia5, norm_sni, -1) != 1) goto done;
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    ia5 = NULL; // ownership transferred to gen
    if (!sk_GENERAL_NAME_push(gens, gen)) goto done;
    gen = NULL; // ownership transferred to gens
    if (X509_add1_ext_i2d(leaf, NID_subject_alt_name, gens, 0, 0) != 1) goto done;

    // basicConstraints / keyUsage / extendedKeyUsage.
    if (add_ext_conf(leaf, NID_basic_constraints, "critical,CA:FALSE") != 0) goto done;
    if (add_ext_conf(leaf, NID_key_usage, ku_str) != 0) goto done;
    if (add_ext_conf(leaf, NID_ext_key_usage, "serverAuth") != 0) goto done;

    // Sign with the CA key.
    if (X509_sign(leaf, core->ca_key, EVP_sha256()) == 0) goto done;

    ok = 1;

done:
    if (gens) GENERAL_NAMES_free(gens); // frees any remaining pushed GENERAL_NAMEs
    if (gen) GENERAL_NAME_free(gen);    // only if not yet pushed
    if (ia5) ASN1_IA5STRING_free(ia5);  // only if ownership not transferred
    if (serial) ASN1_INTEGER_free(serial);
    if (bn) BN_free(bn);
    if (!ok && leaf) {
        X509_free(leaf);
        leaf = NULL;
    }
    return leaf;
}

// Production forge: spec §3 keyUsage = critical, digitalSignature.
static X509 *
forge_leaf(mq_mitm_core_t *core, const char *norm_sni)
{
    return forge_leaf_ku(core, norm_sni, "critical,digitalSignature");
}

// --- Bounded LRU leaf cache (Task 5) ---

// Unlink `e` from the intrusive list (does not free it).
static void
cache_unlink(mq_mitm_core_t *core, mq_cache_entry_t *e)
{
    if (e->prev)
        e->prev->next = e->next;
    else
        core->lru_head = e->next;
    if (e->next)
        e->next->prev = e->prev;
    else
        core->lru_tail = e->prev;
    e->prev = e->next = NULL;
}

// Push `e` at the MRU (head) of the list.
static void
cache_push_front(mq_mitm_core_t *core, mq_cache_entry_t *e)
{
    e->prev = NULL;
    e->next = core->lru_head;
    if (core->lru_head) core->lru_head->prev = e;
    core->lru_head = e;
    if (!core->lru_tail) core->lru_tail = e;
}

// Free one entry: release its single cache-owned X509 ref + the node.
static void
cache_entry_free(mq_cache_entry_t *e)
{
    if (!e) return;
    if (e->leaf) X509_free(e->leaf);
    free(e);
}

// Drop and free the LRU (tail) entry. Caller ensures cache is non-empty.
static void
cache_evict_lru(mq_mitm_core_t *core)
{
    mq_cache_entry_t *victim = core->lru_tail;
    if (!victim) return;
    cache_unlink(core, victim);
    cache_entry_free(victim);
    core->cache_count--;
}

// Bounded LRU leaf cache keyed by normalized SNI, TTL-aware.
//
// REFCOUNT CONTRACT: returns a NEW X509 ref the CALLER owns and MUST X509_free.
//  - HIT (fresh): X509_up_ref the cached leaf, move it to MRU, return that ref.
//    The cache keeps its own ref.
//  - HIT (expired / within SKEW of not_after): evict the stale entry, fall to MISS.
//  - MISS: forge once (ref=1). If caching is enabled and we can store it, take a
//    SECOND ref (X509_up_ref) for the cache and hand the ORIGINAL ref to the
//    caller; otherwise (cache disabled, or storage allocation failed) hand the
//    original ref straight to the caller and store nothing. Either way the caller
//    gets exactly one ref and nothing leaks.
static X509 *
cache_get_or_forge(mq_mitm_core_t *core, const char *norm_sni)
{
    if (!core || !norm_sni) return NULL;

    time_t now = core->now_fn();

    // Caching disabled → always forge, never store. forge_leaf returns ref=1,
    // which is exactly the caller's ref.
    if (core->cache_size == 0) return forge_leaf(core, norm_sni);

    // Linear scan for a hit.
    for (mq_cache_entry_t *e = core->lru_head; e; e = e->next) {
        if (strcmp(e->norm_sni, norm_sni) != 0) continue;
        // Fresh only if comfortably before not_after.
        if (now < e->not_after - MQ_MITM_CACHE_SKEW_SEC) {
            cache_unlink(core, e); // move to MRU
            cache_push_front(core, e);
            (void)X509_up_ref(e->leaf); // caller's ref; cache keeps its own
                                        // (never fails in practice — internal lock)
            return e->leaf;
        }
        // Stale → evict and fall through to a fresh forge.
        cache_unlink(core, e);
        cache_entry_free(e);
        core->cache_count--;
        break;
    }

    // MISS → forge (ref=1, the caller's ref).
    X509 *leaf = forge_leaf(core, norm_sni);
    if (!leaf) return NULL;

    // Try to store a SECOND ref. On any allocation failure, skip caching and
    // still return the caller's ref (degrade gracefully, never leak/double-free).
    mq_cache_entry_t *e = calloc(1, sizeof *e);
    if (e) {
        size_t n = strlen(norm_sni);
        if (n < sizeof e->norm_sni) {
            memcpy(e->norm_sni, norm_sni, n + 1);
            e->leaf = leaf;
            (void)X509_up_ref(e->leaf); // cache-owned ref (caller keeps the original)
                                        // (never fails in practice — internal lock)
            e->not_after = now + core->leaf_ttl_sec;
            if (core->cache_count >= core->cache_size) cache_evict_lru(core);
            cache_push_front(core, e);
            core->cache_count++;
        } else {
            free(e); // pathological key (can't happen: norm_sni <= 253); skip caching
        }
    }
    return leaf;
}

// TEST-ONLY hooks (no header; forward-declared extern in the test).
X509 *
mq_mitm_cache_get_or_forge_for_test(mq_mitm_core_t *core, const char *norm_sni)
{
    return cache_get_or_forge(core, norm_sni);
}

X509 *
mq_mitm_forge_for_test(mq_mitm_core_t *core, const char *norm_sni)
{
    return forge_leaf(core, norm_sni);
}

X509 *
mq_mitm_forge_ku_for_test(mq_mitm_core_t *core, const char *norm_sni, const char *ku_str)
{
    return forge_leaf_ku(core, norm_sni, ku_str);
}

// --- Task 6: server SSL_CTX + select-certificate callback + ALPN h2 ---

// Process-wide SSL ex-data slot used to stash the mq_mitm_core_t* on each SSL so
// the user-data-less select-certificate callback can recover it. Registered ONCE
// (pthread_once); never per-core. -1 means "not yet registered".
static int g_core_idx = -1;
static pthread_once_t g_core_idx_once = PTHREAD_ONCE_INIT;

// Defined below (near destroy); registered as the ex-data free callback so each
// SSL releases its core ref on SSL_free.
static void core_ssl_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int index,
                             long argl, void *argp);

static void
init_core_idx(void)
{
    g_core_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, core_ssl_ex_free);
}

// Server-advertised ALPN protocol list (length-prefixed wire form): just "h2".
static const uint8_t k_alpn_h2[] = {0x02, 'h', '2'};

// ALPN selection: negotiate h2 if the client offers it, otherwise fatal alert.
// MINOR-3: SSL_select_next_proto's out param is uint8_t** while the cb signature
// gives us const uint8_t**; bridge with a one-line cast (don't fight -Werror).
static int
alpn_select_cb(SSL *ssl, const uint8_t **out, uint8_t *outlen, const uint8_t *in,
               unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    // Documented arg order: SSL_select_next_proto(out, out_len, peer, peer_len,
    // supported, supported_len) selects from `supported` (OURS) the first entry
    // the peer offered. Pass the client's list as `peer` and our h2-only list as
    // `supported`. (Today our list is a single proto so the intersection is
    // order-insensitive, but keep the positions correct for when it grows.)
    int rc = SSL_select_next_proto((uint8_t **)out, outlen, in, inlen, k_alpn_h2,
                                   (unsigned int)sizeof k_alpn_h2);
    if (rc == OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL; // OPENSSL_NPN_NO_OVERLAP (no h2 offered)
}

// select-certificate callback: runs the no-ALPN guard, normalizes the SNI,
// forges/caches the leaf, and attaches it (+ the shared leaf key). Any failure
// returns ssl_select_cert_error so no half-configured connection proceeds.
static enum ssl_select_cert_result_t
select_certificate_cb(const SSL_CLIENT_HELLO *ch)
{
    mq_mitm_core_t *core = SSL_get_ex_data(ch->ssl, g_core_idx);
    if (!core) return ssl_select_cert_error;

    // No-ALPN guard: refuse handshakes that don't offer ALPN at all (closes the
    // "TLS completes with no ALPN" hole). Returns 1 if the extension is present.
    const uint8_t *alpn_ext = NULL; // presence-only guard; the protocol contents are
                                    // negotiated in alpn_select_cb
    size_t alpn_len = 0;
    if (SSL_early_callback_ctx_extension_get(
            ch, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn_ext,
            &alpn_len) == 0)
        return ssl_select_cert_error;

    // SNI is mandatory: we forge per host name.
    const char *sni = SSL_get_servername(ch->ssl, TLSEXT_NAMETYPE_host_name);
    if (!sni) return ssl_select_cert_error;

    char norm[256];
    if (mq_mitm_normalize_sni(sni, strlen(sni), norm) != 0) return ssl_select_cert_error;

    // Forge/cache the leaf (caller-owned ref).
    X509 *leaf = cache_get_or_forge(core, norm);
    if (!leaf) return ssl_select_cert_error;

    // Attach leaf + shared key. SSL_use_certificate takes its OWN ref, so drop
    // our ref afterwards (avoid leak) regardless of success.
    // Order matters: SSL_use_certificate silently drops an inconsistent private key, so
    // attach the cert first and the matching key last.
    int used = (SSL_use_certificate(ch->ssl, leaf) == 1) &&
               (SSL_use_PrivateKey(ch->ssl, core->leaf_key) == 1);
    X509_free(leaf);
    if (!used) return ssl_select_cert_error;

    return ssl_select_cert_success;
}

// Build the shared server SSL_CTX with TLS 1.2 floor + both callbacks. Returns
// the ctx or NULL on failure (no half-built ctx leaks). Lazily invoked.
static SSL_CTX *
build_ssl_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_select_certificate_cb(ctx, select_certificate_cb);
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    return ctx;
}

SSL *
mq_mitm_core_new_ssl(mq_mitm_core_t *core)
{
    if (!core) return NULL;

    pthread_once(&g_core_idx_once, init_core_idx);
    if (g_core_idx < 0) return NULL; // ex-data registration failed

    // Lazily build the shared SSL_CTX on first use.
    // Lazy ctx build is not thread-safe: assumes a single owner thread per core (the
    // 1-client/process MITM deployment model). The process-wide ex-data index IS
    // pthread_once-guarded.
    if (!core->ssl_ctx) {
        core->ssl_ctx = build_ssl_ctx();
        if (!core->ssl_ctx) return NULL;
    }

    SSL *s = SSL_new(core->ssl_ctx);
    if (!s) return NULL;
    // Hand this SSL its own core ref BEFORE stashing the pointer, so the ref the
    // ex-data free callback will release on SSL_free is already accounted for.
    core->refcount++;
    if (SSL_set_ex_data(s, g_core_idx, core) != 1) {
        core->refcount--; // ex-data slot not set → callback won't fire for it
        SSL_free(s);
        return NULL;
    }
    SSL_set_accept_state(s);
    return s;
}

// Drop one ref; tear down only when the last ref goes away. Shared by the public
// destroy() (owner ref) and the SSL ex-data free callback (per-SSL ref).
static void
core_release(mq_mitm_core_t *core)
{
    if (--core->refcount > 0) return;
    // Order: SSL_CTX first, then cache, then keys/cert. Each cache entry holds
    // one X509 ref on its leaf; release them all before freeing the keys/cert.
    // (SSL_CTX_free here only drops the core's own ctx ref — any SSL still alive
    // holds its own ref, so the ctx outlives this call until that SSL is freed.)
    if (core->ssl_ctx) SSL_CTX_free(core->ssl_ctx);
    for (mq_cache_entry_t *e = core->lru_head; e;) {
        mq_cache_entry_t *next = e->next;
        cache_entry_free(e);
        e = next;
    }
    core->lru_head = core->lru_tail = NULL;
    core->cache_count = 0;
    if (core->leaf_key) EVP_PKEY_free(core->leaf_key);
    if (core->ca_key) EVP_PKEY_free(core->ca_key);
    if (core->ca_cert) X509_free(core->ca_cert);
    free(core);
}

// SSL ex-data free callback: releases the per-SSL core ref on SSL_free. `ptr` is
// the stashed core (NULL if the slot was never set — see SSL_set_ex_data failure
// path in mq_mitm_core_new_ssl). Per the BoringSSL contract, `parent`/`ad` are
// NULL and must not be touched; `core` is a separate object and is safe to use.
static void
core_ssl_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int index, long argl,
                 void *argp)
{
    (void)parent;
    (void)ad;
    (void)index;
    (void)argl;
    (void)argp;
    if (ptr) core_release((mq_mitm_core_t *)ptr);
}

void
mq_mitm_core_destroy(mq_mitm_core_t *core)
{
    if (!core) return;
    core_release(core); // drops the owner ref (actual teardown when refcount==0)
}

void
mq_mitm_core_set_clock_for_test(mq_mitm_core_t *core, time_t (*now_fn)(void))
{
    if (!core) return;
    core->now_fn = now_fn ? now_fn : mq_default_now;
}
