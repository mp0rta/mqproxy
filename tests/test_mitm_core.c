// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#include "mqtest.h"
#include "mitm/mq_mitm_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Internal (no header) — forward-declared for direct unit testing.
extern int mq_mitm_normalize_sni(const char *, size_t, char[256]);

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

MQ_TEST_MAIN(test_sni_norm(); test_create_valid(); test_reject_non_ca();
             test_reject_key_mismatch(); test_reject_encrypted_key();
             test_reject_symlink_key(); test_reject_world_readable_key();)
