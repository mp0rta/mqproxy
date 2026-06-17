// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/*
 * mitm_smoke_server.c — Phase 7 Slice 2 Task 8 cross-implementation smoke helper.
 *
 * Usage:
 *   mitm_smoke_server <ca.crt> <ca.key> <port>
 *
 * Loads the MITM CA via mq_mitm_core, binds 127.0.0.1:<port>, accepts exactly
 * ONE TCP connection, and terminates the browser-facing TLS handshake through
 * mq_mitm_core (forging a per-SNI leaf signed by the CA, negotiating ALPN). On a
 * successful SSL_accept it prints "ALPN=<negotiated>" to stdout (flushed) so the
 * driving shell can assert what was negotiated, cleanly shuts the TLS session
 * down, frees everything, and exits 0. Any failure exits non-zero.
 *
 * This is the ONLY place the MITM module is driven against a real socket — and it
 * lives in a test helper, not in mq_mitm_core itself (the module stays I/O-free).
 * It is deliberately minimal, single-shot, and leak-conscious.
 */
#include "mitm/mq_mitm_core.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ca.crt> <ca.key> <port>\n", argv[0]);
        return 2;
    }
    const char *ca_crt = argv[1];
    const char *ca_key = argv[2];
    int port = atoi(argv[3]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "mitm_smoke_server: invalid port: %s\n", argv[3]);
        return 2;
    }

    mq_mitm_core_t *core = mq_mitm_core_create(ca_crt, ca_key, NULL);
    if (!core) {
        fprintf(stderr, "mitm_smoke_server: mq_mitm_core_create failed\n");
        return 1;
    }

    int rc = 1; /* default: failure */
    int lfd = -1, cfd = -1;
    SSL *ssl = NULL;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("mitm_smoke_server: socket");
        goto out;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    sa.sin_port = htons((uint16_t)port);

    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("mitm_smoke_server: bind");
        goto out;
    }
    if (listen(lfd, 1) != 0) {
        perror("mitm_smoke_server: listen");
        goto out;
    }
    /* Signal readiness so the driver can stop its retry-connect loop. */
    fprintf(stdout, "LISTENING\n");
    fflush(stdout);

    cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("mitm_smoke_server: accept");
        goto out;
    }

    ssl = mq_mitm_core_new_ssl(core);
    if (!ssl) {
        fprintf(stderr, "mitm_smoke_server: mq_mitm_core_new_ssl failed\n");
        goto out;
    }
    if (SSL_set_fd(ssl, cfd) != 1) {
        fprintf(stderr, "mitm_smoke_server: SSL_set_fd failed\n");
        goto out;
    }
    /* BoringSSL SSL_set_fd uses BIO_NOCLOSE: caller retains fd ownership. */

    if (SSL_accept(ssl) != 1) {
        fprintf(stderr, "mitm_smoke_server: SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        goto out;
    }

    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    fprintf(stdout, "ALPN=%.*s\n", (int)alpn_len, alpn ? (const char *)alpn : "");
    fflush(stdout);

    SSL_shutdown(ssl);
    rc = 0; /* success */

out:
    if (ssl) SSL_free(ssl);   /* BIO_NOCLOSE: does NOT close the accepted fd */
    if (cfd >= 0) close(cfd); /* sole owner of the accepted fd: close exactly once */
    if (lfd >= 0) close(lfd);
    mq_mitm_core_destroy(core);
    return rc;
}
