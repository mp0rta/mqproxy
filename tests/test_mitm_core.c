// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#include "mqtest.h"
#include "mitm/mq_mitm_core.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Internal (no header) — forward-declared for direct unit testing.
extern int mq_mitm_normalize_sni(const char *, size_t, char[256]);
extern X509 *mq_mitm_forge_for_test(mq_mitm_core_t *core, const char *norm_sni);
// Forge with a caller-chosen keyUsage extension string (e.g. "critical,cRLSign")
// — otherwise identical to the production profile. CA-signed. Test-only hook used
// to prove the SSL-server purpose gate (I1) is load-bearing.
extern X509 *mq_mitm_forge_ku_for_test(mq_mitm_core_t *core, const char *norm_sni,
                                       const char *ku_str);
// Task 5: bounded LRU leaf cache. Returns a NEW ref to the caller (X509_up_ref on
// hit; on miss the freshly-forged leaf is up_ref'd into the cache and the caller
// gets the original ref). Caller MUST X509_free the returned X509.
extern X509 *mq_mitm_cache_get_or_forge_for_test(mq_mitm_core_t *core,
                                                 const char *norm_sni);

static void
test_sni_norm(void)
{
    char out[256];
    MQ_CHECK(mq_mitm_normalize_sni("Example.COM", 11, out) == 0);
    MQ_CHECK(strcmp(out, "example.com") == 0);
    MQ_CHECK(mq_mitm_normalize_sni("host.example.com.", 17, out) == 0); // trailing dot
    MQ_CHECK(strcmp(out, "host.example.com") == 0);
    MQ_CHECK(mq_mitm_normalize_sni("", 0, out) == -1);               // empty
    MQ_CHECK(mq_mitm_normalize_sni("*.example.com", 13, out) == -1); // wildcard
    MQ_CHECK(mq_mitm_normalize_sni("203.0.113.5", 11, out) == -1);   // IPv4 literal
    MQ_CHECK(mq_mitm_normalize_sni("a\tb.com", 7, out) == -1);       // control char

    // Length boundary: exactly 253 accepted, 254 rejected. Built from valid
    // (<= 63-byte) labels so ONLY the name-length cap is exercised, not the
    // per-label cap. 253 = 63+1+63+1+63+1+61; 254 = 63+1+63+1+63+1+62.
    char n253[254];
    memset(n253, 'a', 63);
    n253[63] = '.';
    memset(n253 + 64, 'a', 63);
    n253[127] = '.';
    memset(n253 + 128, 'a', 63);
    n253[191] = '.';
    memset(n253 + 192, 'a', 61);
    n253[253] = '\0';
    MQ_CHECK(mq_mitm_normalize_sni(n253, 253, out) == 0);
    char n254[255];
    memset(n254, 'a', 63);
    n254[63] = '.';
    memset(n254 + 64, 'a', 63);
    n254[127] = '.';
    memset(n254 + 128, 'a', 63);
    n254[191] = '.';
    memset(n254 + 192, 'a', 62);
    n254[254] = '\0';
    MQ_CHECK(mq_mitm_normalize_sni(n254, 254, out) == -1);
    // Leading dot / double dot rejected (empty label).
    MQ_CHECK(mq_mitm_normalize_sni(".example.com", 12, out) == -1);
    MQ_CHECK(mq_mitm_normalize_sni("a..b.com", 8, out) == -1);
}

static void
test_create_valid(void)
{
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, NULL);
    MQ_CHECK(c != NULL);
    mq_mitm_core_destroy(c);
}

static void
test_reject_non_ca(void)
{
    // matched CA:FALSE leaf pair → rejected for exactly one reason: not a CA
    MQ_CHECK(mq_mitm_core_create(MITM_LEAF_CRT, MITM_LEAF_KEY, NULL) == NULL);
}

static void
test_reject_key_mismatch(void)
{
    // valid P-256 CA cert + a DIFFERENT same-curve (P-256) key → exercises the
    // real X509_check_private_key mismatch path (not an algorithm shortcut).
    // chmod 0600 defensively (MINOR-2) so the perms gate doesn't pre-empt the
    // mismatch path and falsely green this case.
    chmod(MITM_LEAF_KEY, 0600);
    MQ_CHECK(mq_mitm_core_create(MITM_CA_CRT, MITM_LEAF_KEY, NULL) == NULL);
}

static void
test_reject_encrypted_key(void)
{
    // MINOR-2: the perms gate rejects group/other access BEFORE PEM parsing, so the
    // encrypted-PEM path only gets exercised when the fixture is owner-only. openssl
    // emits key files 0600 regardless of umask, but chmod defensively so a future
    // umask/tooling change can't silently turn this into a perms-rejection false pass.
    chmod(MITM_CA_ENC_KEY, 0600);
    MQ_CHECK(mq_mitm_core_create(MITM_CA_CRT, MITM_CA_ENC_KEY, NULL) == NULL);
}

static void
test_reject_symlink_key(void)
{
    char link[] = "/tmp/mq_mitm_link_XXXXXX";
    int fd = mkstemp(link);
    MQ_CHECK(fd >= 0);
    close(fd);
    unlink(link);
    MQ_CHECK(symlink(MITM_CA_KEY, link) == 0);
    MQ_CHECK(mq_mitm_core_create(MITM_CA_CRT, link, NULL) == NULL); // O_NOFOLLOW rejects
    unlink(link);
}

static void
test_reject_world_readable_key(void)
{
    // copy CA key to a 0644 temp file → fstat perms check must reject
    char path[] = "/tmp/mq_mitm_key_XXXXXX";
    int fd = mkstemp(path);
    MQ_CHECK(fd >= 0);
    FILE *src = fopen(MITM_CA_KEY, "rb");
    MQ_CHECK(src != NULL);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, src)) > 0)
        MQ_CHECK(write(fd, buf, n) == (ssize_t)n);
    fclose(src);
    close(fd);
    MQ_CHECK(chmod(path, 0644) == 0);
    MQ_CHECK(mq_mitm_core_create(MITM_CA_CRT, path, NULL) == NULL);
    unlink(path);
}

// ---- Task 4: leaf forge ----

// Build an X509_STORE trusting the test CA, then verify `leaf` against it under
// the SSL-server purpose. Returns the X509_verify_cert result (1 == ok) and, on
// failure, writes the verify-error code into *err (else 0).
static int
verify_leaf_with_ca(X509 *leaf, int *err)
{
    if (err) *err = 0;
    FILE *fp = fopen(MITM_CA_CRT, "rb");
    MQ_CHECK(fp != NULL);
    X509 *ca = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    MQ_CHECK(ca != NULL);

    X509_STORE *store = X509_STORE_new();
    MQ_CHECK(store != NULL);
    MQ_CHECK(X509_STORE_add_cert(store, ca) == 1);

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    MQ_CHECK(ctx != NULL);
    MQ_CHECK(X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1);
    MQ_CHECK(X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_SERVER) == 1);

    int rv = X509_verify_cert(ctx);
    if (rv != 1 && err) *err = X509_STORE_CTX_get_error(ctx);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(ca);
    return rv;
}

// Extract the single SAN DNS name from `leaf` into out (NUL-terminated). Returns
// 0 on success, -1 if no SAN DNS entry present.
static int
leaf_san_dns(X509 *leaf, char *out, size_t outsz)
{
    GENERAL_NAMES *gens = X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
    if (!gens) return -1;
    int rc = -1;
    for (size_t i = 0; i < (size_t)sk_GENERAL_NAME_num(gens); i++) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        int type = 0;
        const ASN1_IA5STRING *ia5 = GENERAL_NAME_get0_value((GENERAL_NAME *)gn, &type);
        if (type == GEN_DNS && ia5) {
            int len = ASN1_STRING_length(ia5);
            const unsigned char *data = ASN1_STRING_get0_data(ia5);
            if (len >= 0 && (size_t)len < outsz) {
                memcpy(out, data, (size_t)len);
                out[len] = '\0';
                rc = 0;
            }
            break;
        }
    }
    GENERAL_NAMES_free(gens);
    return rc;
}

// Read the leaf's subject CN into out. Returns 0 on success.
static int
leaf_cn(X509 *leaf, char *out, int outsz)
{
    X509_NAME *subj = X509_get_subject_name(leaf);
    if (!subj) return -1;
    int n = X509_NAME_get_text_by_NID(subj, NID_commonName, out, outsz);
    return n >= 0 ? 0 : -1;
}

static void
test_forge_chains_to_ca(void)
{
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, NULL);
    MQ_CHECK(c != NULL);

    X509 *leaf = mq_mitm_forge_for_test(c, "host.example.com");
    MQ_CHECK(leaf != NULL);

    int err = 0;
    MQ_CHECK(verify_leaf_with_ca(leaf, &err) == 1); // chains to CA, SSL-server purpose

    // SAN DNS == the (already-normalized) name.
    char san[256];
    MQ_CHECK(leaf_san_dns(leaf, san, sizeof san) == 0);
    MQ_CHECK(strcmp(san, "host.example.com") == 0);

    // CA:FALSE and CN == "mqproxy-mitm".
    MQ_CHECK(X509_check_ca(leaf) == 0);
    char cn[64];
    MQ_CHECK(leaf_cn(leaf, cn, (int)sizeof cn) == 0);
    MQ_CHECK(strcmp(cn, "mqproxy-mitm") == 0);

    X509_free(leaf);
    mq_mitm_core_destroy(c);
}

// I1 — prove the SSL-server purpose gate is load-bearing (not vacuous). Forge a
// leaf that is CA-signed and otherwise valid, but whose keyUsage omits ALL THREE
// of digitalSignature/keyEncipherment/keyAgreement (here: cRLSign only). Per
// BoringSSL v3_purp.cc, X509v3_KU_TLS accepts ANY of those three, so omitting
// only digitalSignature would still PASS — all three must be absent. Such a leaf
// must FAIL X509_verify_cert with X509_V_ERR_INVALID_PURPOSE.
static void
test_forge_purpose_gate_is_load_bearing(void)
{
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, NULL);
    MQ_CHECK(c != NULL);

    // keyUsage omits ALL THREE TLS-server usages (cRLSign only) → otherwise valid,
    // CA-signed leaf that must fail the SSL-server purpose check.
    X509 *leaf = mq_mitm_forge_ku_for_test(c, "host.example.com", "critical,cRLSign");
    MQ_CHECK(leaf != NULL);

    // Sanity: it really does chain (signature/trust/time all fine) — so the only
    // possible failure reason is the purpose gate, not a broken negative.
    int err0 = 0;
    {
        FILE *fp = fopen(MITM_CA_CRT, "rb");
        MQ_CHECK(fp != NULL);
        X509 *ca = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        MQ_CHECK(ca != NULL);
        X509_STORE *store = X509_STORE_new();
        MQ_CHECK(X509_STORE_add_cert(store, ca) == 1);
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        MQ_CHECK(X509_STORE_CTX_init(ctx, store, leaf, NULL) == 1);
        // No purpose set → trust/time/signature only → should pass.
        MQ_CHECK(X509_verify_cert(ctx) == 1);
        (void)err0;
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(ca);
    }

    int err = 0;
    int rv = verify_leaf_with_ca(leaf, &err);
    MQ_CHECK(rv != 1);                           // must FAIL
    MQ_CHECK(err == X509_V_ERR_INVALID_PURPOSE); // for the right reason

    X509_free(leaf);
    mq_mitm_core_destroy(c);
}

// ---- Task 5: LRU leaf cache with TTL expiry ----

// Return the leaf's serial as a heap BIGNUM (caller BN_free's). Serial equality
// is the durable cache-identity invariant (NOT pointer identity, which a future
// refactor could break by returning a duplicated cert).
static BIGNUM *
leaf_serial_bn(X509 *leaf)
{
    const ASN1_INTEGER *s = X509_get_serialNumber(leaf);
    MQ_CHECK(s != NULL);
    BIGNUM *bn = ASN1_INTEGER_to_BN(s, NULL);
    MQ_CHECK(bn != NULL);
    return bn;
}

// Controllable test clock (the cache + forge read time via core->now_fn).
static time_t g_fake_now = 1000000000; // fixed base
static time_t
fake_now(void)
{
    return g_fake_now;
}

static void
test_cache_hit_same_serial(void)
{
    mq_mitm_opts_t opts = {.cache_size = 8, .leaf_ttl_sec = 86400};
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
    MQ_CHECK(c != NULL);
    g_fake_now = 1000000000;
    mq_mitm_core_set_clock_for_test(c, fake_now);

    X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    MQ_CHECK(a != NULL && b != NULL);

    BIGNUM *sa = leaf_serial_bn(a), *sb = leaf_serial_bn(b);
    MQ_CHECK(BN_cmp(sa, sb) == 0); // cache hit → same serial → one forge
    BN_free(sa);
    BN_free(sb);

    X509_free(a);
    X509_free(b);
    mq_mitm_core_destroy(c);
}

static void
test_cache_distinct_sni_distinct_serial(void)
{
    mq_mitm_opts_t opts = {.cache_size = 8, .leaf_ttl_sec = 86400};
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
    MQ_CHECK(c != NULL);
    g_fake_now = 1000000000;
    mq_mitm_core_set_clock_for_test(c, fake_now);

    X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "one.example.com");
    X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "two.example.com");
    MQ_CHECK(a != NULL && b != NULL);

    BIGNUM *sa = leaf_serial_bn(a), *sb = leaf_serial_bn(b);
    MQ_CHECK(BN_cmp(sa, sb) != 0); // distinct SNI → distinct serial
    BN_free(sa);
    BN_free(sb);

    X509_free(a);
    X509_free(b);
    mq_mitm_core_destroy(c);
}

static void
test_cache_lru_eviction(void)
{
    // cache_size=2: insert 3 distinct SNIs; the first is LRU and gets evicted.
    // Re-requesting it → miss → reforge → new serial.
    mq_mitm_opts_t opts = {.cache_size = 2, .leaf_ttl_sec = 86400};
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
    MQ_CHECK(c != NULL);
    g_fake_now = 1000000000;
    mq_mitm_core_set_clock_for_test(c, fake_now);

    X509 *first1 = mq_mitm_cache_get_or_forge_for_test(c, "a.example.com");
    BIGNUM *s_first1 = leaf_serial_bn(first1);

    X509 *bb = mq_mitm_cache_get_or_forge_for_test(c, "b.example.com"); // fill
    X509 *cc = mq_mitm_cache_get_or_forge_for_test(c, "c.example.com"); // evicts "a"

    X509 *first2 =
        mq_mitm_cache_get_or_forge_for_test(c, "a.example.com"); // miss → reforge
    BIGNUM *s_first2 = leaf_serial_bn(first2);

    MQ_CHECK(BN_cmp(s_first1, s_first2) != 0); // evicted → new serial

    BN_free(s_first1);
    BN_free(s_first2);
    X509_free(first1);
    X509_free(bb);
    X509_free(cc);
    X509_free(first2);
    mq_mitm_core_destroy(c);
}

static void
test_cache_disabled(void)
{
    // cache_size=0 → caching disabled: two requests for the same SNI always forge.
    mq_mitm_opts_t opts = {.cache_size = 0, .leaf_ttl_sec = 86400};
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
    MQ_CHECK(c != NULL);
    g_fake_now = 1000000000;
    mq_mitm_core_set_clock_for_test(c, fake_now);

    X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    MQ_CHECK(a != NULL && b != NULL);

    BIGNUM *sa = leaf_serial_bn(a), *sb = leaf_serial_bn(b);
    MQ_CHECK(BN_cmp(sa, sb) != 0); // no caching → distinct serials
    BN_free(sa);
    BN_free(sb);

    X509_free(a);
    X509_free(b);
    mq_mitm_core_destroy(c);
}

static void
test_cache_ttl_expiry(void)
{
    // Forge at t0; advance the clock past not_after; the same SNI must reforge.
    mq_mitm_opts_t opts = {.cache_size = 8, .leaf_ttl_sec = 60}; // clamped min TTL
    mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
    MQ_CHECK(c != NULL);
    g_fake_now = 1000000000;
    mq_mitm_core_set_clock_for_test(c, fake_now);

    X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    BIGNUM *sa = leaf_serial_bn(a);

    // Advance well past not_after (now + 60). Even with the near-expiry SKEW this
    // is unambiguously expired.
    g_fake_now += 600;

    X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
    BIGNUM *sb = leaf_serial_bn(b);

    MQ_CHECK(BN_cmp(sa, sb) != 0); // expired → reforged → new serial

    BN_free(sa);
    BN_free(sb);
    X509_free(a);
    X509_free(b);
    mq_mitm_core_destroy(c);
}

// Lock the SKEW freshness boundary (off-by-one). Freshness is the STRICT test
// `now < not_after - SKEW` (SKEW = MQ_MITM_CACHE_SKEW_SEC = 30s). With ttl=120
// (> 2*SKEW so the boundary is unambiguous), not_after = t0+120 and the boundary
// instant is t0+90. At EXACTLY the boundary (t0+90) the entry is NOT fresh → must
// REFORGE; one second earlier (t0+89) it is still fresh → cache HIT.
static void
test_cache_skew_boundary(void)
{
    const int SKEW = 30; // == MQ_MITM_CACHE_SKEW_SEC in mq_mitm_core.c
    const int TTL = 120; // > 2*SKEW so not_after-SKEW is unambiguous

    // --- At exactly not_after - SKEW (t0+90): boundary is NOT fresh → reforge. ---
    {
        mq_mitm_opts_t opts = {.cache_size = 8, .leaf_ttl_sec = TTL};
        mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
        MQ_CHECK(c != NULL);
        g_fake_now = 1000000000;
        mq_mitm_core_set_clock_for_test(c, fake_now);

        X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
        BIGNUM *sa = leaf_serial_bn(a);

        // Advance to EXACTLY not_after - SKEW (= t0 + TTL - SKEW = t0 + 90).
        g_fake_now += TTL - SKEW;

        X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
        BIGNUM *sb = leaf_serial_bn(b);

        MQ_CHECK(BN_cmp(sa, sb) != 0); // boundary not fresh → reforged → new serial

        BN_free(sa);
        BN_free(sb);
        X509_free(a);
        X509_free(b);
        mq_mitm_core_destroy(c);
    }

    // --- One second before the boundary (t0+89): still fresh → cache HIT. ---
    {
        mq_mitm_opts_t opts = {.cache_size = 8, .leaf_ttl_sec = TTL};
        mq_mitm_core_t *c = mq_mitm_core_create(MITM_CA_CRT, MITM_CA_KEY, &opts);
        MQ_CHECK(c != NULL);
        g_fake_now = 1000000000;
        mq_mitm_core_set_clock_for_test(c, fake_now);

        X509 *a = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
        BIGNUM *sa = leaf_serial_bn(a);

        // Advance to one second BEFORE the boundary (t0 + 89).
        g_fake_now += TTL - SKEW - 1;

        X509 *b = mq_mitm_cache_get_or_forge_for_test(c, "host.example.com");
        BIGNUM *sb = leaf_serial_bn(b);

        MQ_CHECK(BN_cmp(sa, sb) == 0); // still fresh → cache hit → same serial

        BN_free(sa);
        BN_free(sb);
        X509_free(a);
        X509_free(b);
        mq_mitm_core_destroy(c);
    }
}

MQ_TEST_MAIN(test_sni_norm(); test_create_valid(); test_reject_non_ca();
             test_reject_key_mismatch(); test_reject_encrypted_key();
             test_reject_symlink_key(); test_reject_world_readable_key();
             test_forge_chains_to_ca(); test_forge_purpose_gate_is_load_bearing();
             test_cache_hit_same_serial(); test_cache_distinct_sni_distinct_serial();
             test_cache_lru_eviction(); test_cache_disabled(); test_cache_ttl_expiry();
             test_cache_skew_boundary();)
