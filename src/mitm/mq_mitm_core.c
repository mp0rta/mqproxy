// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#include "mitm/mq_mitm_core.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bytestring.h>
#include <stdlib.h>

struct mq_mitm_core {
    int placeholder;
};

mq_mitm_core_t *
mq_mitm_core_create(const char *ca_cert_pem_path, const char *ca_key_pem_path,
                    const mq_mitm_opts_t *opts)
{
    (void)ca_cert_pem_path;
    (void)ca_key_pem_path;
    (void)opts;
    // Reference the APIs the spike must prove link:
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx) SSL_CTX_free(ctx);
    X509 *x = X509_new();
    if (x) X509_free(x);
    return NULL; // real impl in Task 2
}

SSL *
mq_mitm_core_new_ssl(mq_mitm_core_t *core)
{
    (void)core;
    return NULL;
}

void
mq_mitm_core_destroy(mq_mitm_core_t *core)
{
    free(core);
}

void
mq_mitm_core_set_clock_for_test(mq_mitm_core_t *c, time_t (*f)(void))
{
    (void)c;
    (void)f;
}
