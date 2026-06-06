// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/*
 * udp_echo.c — simple UDP echo server for e2e UDP relay tests.
 *
 * Usage:
 *   udp_echo --port <p> [--max-size <n>]
 *
 * Binds to 127.0.0.1:<p>, receives datagrams up to --max-size bytes (default
 * 65535 — fragmentation test range) and sends each one back to the sender.
 * Runs until SIGTERM / SIGINT; exits 0 on signal, 1 on startup failure.
 *
 * Note: blocking recvfrom loop is intentional — this utility is single-threaded
 * and driven by a shell e2e harness which kills it when done.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int g_stop = 0;

static void
sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void
usage(void)
{
    fprintf(stderr, "Usage: udp_echo --port <p> [--max-size <n>]\n"
                    "\n"
                    "  --port <p>       UDP port to bind on 127.0.0.1 (required).\n"
                    "  --max-size <n>   Receive buffer size in bytes (default 65535).\n");
}

int
main(int argc, char **argv)
{
    int port = 0;
    int max_size = 65535;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
            max_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "udp_echo: unknown argument: %s\n", argv[i]);
            usage();
            return 1;
        }
    }

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "udp_echo: --port is required and must be 1-65535\n");
        usage();
        return 1;
    }
    if (max_size <= 0 || max_size > 65535) {
        fprintf(stderr, "udp_echo: --max-size must be 1-65535\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("udp_echo: socket");
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    sa.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        perror("udp_echo: bind");
        close(fd);
        return 1;
    }

    /* Print the actual bound port (useful if --port 0 were used, and for
     * diagnosing bind on fixed ports). */
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    if (getsockname(fd, (struct sockaddr *)&bound, &blen) == 0) {
        fprintf(stdout, "udp_echo: bound 127.0.0.1:%d\n", ntohs(bound.sin_port));
        fflush(stdout);
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    uint8_t *buf = (uint8_t *)malloc((size_t)max_size);
    if (!buf) {
        fprintf(stderr, "udp_echo: malloc(%d) failed\n", max_size);
        close(fd);
        return 1;
    }

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        ssize_t n =
            recvfrom(fd, buf, (size_t)max_size, 0, (struct sockaddr *)&peer, &plen);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (!g_stop) perror("udp_echo: recvfrom");
            break;
        }
        /* Echo back to sender. */
        ssize_t sent = sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, plen);
        if (sent < 0 && !g_stop) {
            perror("udp_echo: sendto");
            /* non-fatal — keep running for next datagram */
        }
    }

    free(buf);
    close(fd);
    return 0;
}
