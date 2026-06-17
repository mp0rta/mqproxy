// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_core — Phase 7 Slice 2 MITM crypto core. I/O-free crypto module:
// loads + validates a CA, owns the shared P-256 leaf key (forge/cache/SSL_CTX
// land in later Slice 2 tasks). NOT wired into the live tproxy path (Slice 3).
#include "mitm/mq_mitm_core.h"

#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct mq_mitm_core {
    X509 *ca_cert;
    EVP_PKEY *ca_key;
    EVP_PKEY *leaf_key; // shared across all forged leaves
    size_t cache_size;
    int leaf_ttl_sec;
    time_t (*now_fn)(void);
    SSL_CTX *ssl_ctx; // created lazily in new_ssl (Task 6); NULL here
    /* cache fields added in Task 5 */
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
    if (sni_len > 253) return -1;

    // Reject wildcards and any byte outside [A-Za-z0-9.-]; lowercase ASCII;
    // enforce per-label length (1..63, no empty labels).
    char tmp[254];
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
        if (++label_len > 63) return -1; // label too long
        tmp[i] = c;
    }
    if (label_len == 0) return -1; // trailing empty label (shouldn't happen)
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

// Read a private-key PEM file with TOCTOU-free safety checks. Opens with
// O_NOFOLLOW (reject symlinks) + O_CLOEXEC, then fstat()s the fd (not the path):
// reject non-regular files, any group/other access bits, and non-owner files.
// On success returns a memory BIO holding the file contents (caller frees).
static BIO *
read_key_file_safely(const char *path)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return NULL;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
        st.st_uid != geteuid()) {
        close(fd);
        return NULL;
    }

    // Read the whole file. Key PEMs are small; cap defensively at 1 MiB.
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
    FILE *cert_fp = NULL;

    // --- 1. Load the CA private key with key-file safety checks first ---
    // (perms gate runs BEFORE PEM parse — see MINOR-2 in the plan.)
    key_bio = read_key_file_safely(ca_key_pem_path);
    if (!key_bio) goto fail;
    ca_key = PEM_read_bio_PrivateKey(key_bio, NULL, no_password_cb, NULL);
    if (!ca_key) goto fail; // unparseable, or encrypted (no_password_cb declines)

    // --- 2. Load the CA certificate ---
    cert_fp = fopen(ca_cert_pem_path, "rb");
    if (!cert_fp) goto fail;
    cert_bio = BIO_new_fp(cert_fp, BIO_NOCLOSE);
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
    core->cache_size = cache_size;
    core->leaf_ttl_sec = leaf_ttl_sec;

    BIO_free(key_bio);
    BIO_free(cert_bio);
    fclose(cert_fp);
    return core;

fail:
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (leaf_key) EVP_PKEY_free(leaf_key);
    if (ca_cert) X509_free(ca_cert);
    if (ca_key) EVP_PKEY_free(ca_key);
    if (cert_bio) BIO_free(cert_bio);
    if (cert_fp) fclose(cert_fp);
    if (key_bio) BIO_free(key_bio);
    return NULL;
}

SSL *
mq_mitm_core_new_ssl(mq_mitm_core_t *core)
{
    (void)core;
    return NULL; // real impl in Task 6
}

void
mq_mitm_core_destroy(mq_mitm_core_t *core)
{
    if (!core) return;
    // Order: SSL_CTX first, then cache (none yet), then keys/cert.
    if (core->ssl_ctx) SSL_CTX_free(core->ssl_ctx);
    /* cache freed here in Task 5 */
    if (core->leaf_key) EVP_PKEY_free(core->leaf_key);
    if (core->ca_key) EVP_PKEY_free(core->ca_key);
    if (core->ca_cert) X509_free(core->ca_cert);
    free(core);
}

void
mq_mitm_core_set_clock_for_test(mq_mitm_core_t *core, time_t (*now_fn)(void))
{
    if (!core) return;
    core->now_fn = now_fn ? now_fn : mq_default_now;
}
