// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/*
 * udpsocks.c — SOCKS5 UDP ASSOCIATE client / forwarder shim for e2e UDP relay
 * tests.
 *
 * Usage (echo-client mode):
 *   udpsocks --proxy <ip:port> --target <host:port>
 *            [--send <hexfile|size>] [--count <N>] [--timeout-ms <T>]
 *            [--verbose]
 *
 * Usage (forwarder / bench-shim mode):
 *   udpsocks --proxy <ip:port> --target <host:port> --listen <port>
 *            [--verbose]
 *
 * ── Echo-client flow ────────────────────────────────────────────────────────
 *   1. TCP connect to --proxy.
 *   2. SOCKS5 greeting (VER=5, 1 method, NO-AUTH).
 *   3. UDP ASSOCIATE request (CMD=0x03, DST=0.0.0.0:0).
 *   4. Parse ASSOCIATE reply — extract BND.ADDR:BND.PORT.
 *   5. Create UDP socket.
 *   6. For each of --count iterations:
 *        a. Build [SOCKS5 UDP header (target as DST) | payload] via
 *           mq_socks5_build_udp_hdr and send to BND.
 *        b. recvfrom with --timeout-ms deadline.
 *        c. Strip SOCKS5 UDP header with mq_socks5_parse_udp_hdr.
 *        d. Hex-dump the inner payload to stdout (one line per response).
 *        e. If payload was specified: verify echo == sent; print
 *           "OK <n> bytes" or "MISMATCH" to stderr.
 *   7. Exit 0 if all --count responses received and all verified OK;
 *      exit 1 otherwise (missing responses / mismatches).
 *
 * --send argument:
 *   - If the arg is a readable file path: treat contents as hex-encoded
 *     payload (whitespace/newlines ignored, must be even hex digits).
 *   - Else: parse as decimal integer N and generate N bytes of
 *     deterministic patterned data (byte i = (uint8_t)(i & 0xff)).
 *
 * --target host:port:
 *   - If host is an IPv4 literal (a.b.c.d): use ATYP=0x01.
 *   - Otherwise: use ATYP=0x03 (domain).
 *
 * ── Forwarder / bench-shim mode (--listen) ──────────────────────────────────
 * Performs SOCKS5 ASSOCIATE setup as above, then binds 127.0.0.1:<listen-port>
 * and relays plain UDP traffic between the local listener and the SOCKS5 relay.
 *
 * Forwarder contract:
 *   - Sticky single peer: the source address of the first inbound datagram is
 *     remembered for the process lifetime and used as the return address for
 *     all unwrapped datagrams.  Inner-address / port migration is out of scope.
 *   - Wrap path (local peer → relay): prepend the prebuilt SOCKS5 UDP header
 *     (built from --target) and forward to BND.
 *   - Unwrap path (relay → local peer): parse and strip the SOCKS5 UDP header,
 *     forward inner payload to the learned peer address.
 *   - Oversize datagrams that would exceed the tx buffer are silently dropped
 *     on the wrap path and counted.
 *   - The process exits (cleanly, status 0) when the ASSOCIATE control TCP
 *     connection reaches EOF — the proxy session has been torn down.
 *   - SIGTERM / SIGINT also cause a clean (status 0) exit.
 *   - In all exit paths a one-line summary is printed to stderr:
 *       udpsocks: forwarder stats wrap_fail=N unwrap_fail=N no_peer_drop=N
 *
 * Links mqproxy static library for mq_socks5_build_udp_hdr /
 * mq_socks5_parse_udp_hdr (pure functions — no event loop).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "ingress/mq_socks5.h"
#include "wire/mq_wire.h"

/* ── helpers ─────────────────────────────────────────────────────────────────*/

static void
usage(void)
{
    fprintf(
        stderr,
        "Usage: udpsocks --proxy <ip:port> --target <host:port>\n"
        "                [--send <hexfile|size>] [--count <N>]\n"
        "                [--timeout-ms <T>] [--verbose]\n"
        "                [--listen <port>]\n"
        "\n"
        "  --proxy  <ip:port>    SOCKS5 TCP proxy address (required).\n"
        "  --target <host:port>  UDP echo target (required); host is IP literal\n"
        "                        (ATYP=IPv4) or domain name (ATYP=DOMAIN).\n"
        "  --send   <hexfile|N>  Payload: path to hex file OR byte count N\n"
        "                        (deterministic pattern, default 8).\n"
        "  --count  <N>          Send/recv cycles (default 1).\n"
        "  --timeout-ms <T>      Per-response receive deadline in ms (default 3000).\n"
        "  --verbose             Hex-dump even on successful match.\n"
        "  --listen <port>       Forwarder mode: bind 127.0.0.1:<port>, relay plain\n"
        "                        UDP <-> SOCKS5 UDP encapsulation (bench shim).\n"
        "                        Mutually exclusive with --send/--count.\n");
}

/* Write all bytes; returns 0 on success, -1 on error. */
static int
write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Read exactly want bytes from fd; returns 0 on success, -1 on error/EOF. */
static int
read_exact(int fd, uint8_t *out, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t n = recv(fd, out + got, want - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

/* Hex dump buf to stdout (no newline at end — caller adds it). */
static void
hex_dump(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

/* Convert nybble char to value 0-15; returns -1 on bad char. */
static int
hex_nybble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Load hex-encoded file into *out (caller frees). Returns byte count or -1. */
static ssize_t
load_hex_file(const char *path, uint8_t **out)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* Read whole file into a temp string buffer. */
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0) {
        fclose(f);
        *out = (uint8_t *)malloc(1); /* empty payload */
        if (!*out) return -1;
        return 0;
    }

    char *raw = (char *)malloc((size_t)fsz + 1);
    if (!raw) {
        fclose(f);
        return -1;
    }
    size_t rn = fread(raw, 1, (size_t)fsz, f);
    fclose(f);
    raw[rn] = '\0';

    /* Count non-whitespace chars (must be even). */
    size_t nhex = 0;
    for (size_t i = 0; i < rn; i++) {
        char c = raw[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        nhex++;
    }
    if (nhex % 2 != 0) {
        fprintf(stderr, "udpsocks: hex file has odd number of hex digits\n");
        free(raw);
        return -1;
    }

    size_t blen = nhex / 2;
    uint8_t *bytes = (uint8_t *)malloc(blen + 1);
    if (!bytes) {
        free(raw);
        return -1;
    }

    size_t bi = 0;
    int hi = -1;
    for (size_t i = 0; i < rn; i++) {
        char c = raw[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        int v = hex_nybble(c);
        if (v < 0) {
            fprintf(stderr, "udpsocks: invalid hex char '%c' in file\n", c);
            free(raw);
            free(bytes);
            return -1;
        }
        if (hi < 0) {
            hi = v;
        } else {
            bytes[bi++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }

    free(raw);
    *out = bytes;
    return (ssize_t)blen;
}

/* Generate N bytes of deterministic pattern (byte i = i & 0xff). */
static uint8_t *
gen_pattern(size_t n)
{
    uint8_t *buf = (uint8_t *)malloc(n + 1);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)(i & 0xff);
    }
    return buf;
}

/* Wait for readable on fd up to timeout_ms; returns 1 if readable, 0 if
 * timeout, -1 on error. */
static int
wait_readable(int fd, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r > 0) return 1;
    if (r == 0) return 0;
    return -1;
}

/* ── arg parsing helpers ──────────────────────────────────────────────────────*/

/* Parse "host:port" — host may contain colons (IPv6 literals in brackets are
 * not supported here; IPv4 and domain names only). The LAST colon separates
 * host from port. Returns 0 on success, -1 on parse error. */
static int
parse_hostport(const char *arg, char *host_out, size_t host_cap, uint16_t *port_out)
{
    const char *colon = strrchr(arg, ':');
    if (!colon) return -1;
    size_t hlen = (size_t)(colon - arg);
    if (hlen == 0 || hlen >= host_cap) return -1;
    memcpy(host_out, arg, hlen);
    host_out[hlen] = '\0';
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port_out = (uint16_t)p;
    return 0;
}

/* ── forwarder mode (--listen) ───────────────────────────────────────────────
 * Plain-UDP <-> SOCKS5-UDP shim for the A/B lanes bench: bind
 * 127.0.0.1:listen_port, learn the single peer from the first datagram
 * (sticky for the process lifetime — inner port migration is out of scope),
 * prepend the prebuilt SOCKS5 UDP header toward BND, strip it on the way
 * back. Runs until killed or the ASSOCIATE control connection drops.
 */

static volatile sig_atomic_t g_stop = 0;

static void
sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int
run_forwarder(uint16_t listen_port, int tcp_fd, int udp_fd,
              const struct sockaddr_in *bnd_sa, const uint8_t *hdr_buf, int hdr_len,
              int verbose)
{
    /* Install signal handlers so SIGTERM/SIGINT cause a clean exit. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int lfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (lfd < 0) {
        perror("udpsocks: socket(listen)");
        return 1;
    }
    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &la.sin_addr);
    la.sin_port = htons(listen_port);
    if (bind(lfd, (struct sockaddr *)&la, sizeof(la)) != 0) {
        perror("udpsocks: bind(listen)");
        close(lfd);
        return 1;
    }

    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer)); /* read only after learn, but keep
                                     * -Wmaybe-uninitialized quiet */
    socklen_t peer_len = 0;         /* 0 = not learned yet */
    static uint8_t rx[65535 + 300];
    static uint8_t tx[65535 + 300];

    uint64_t wrap_fail = 0;    /* sendto < 0 or oversize-skipped on wrap path */
    uint64_t unwrap_fail = 0;  /* parse failed or sendto < 0 on unwrap path */
    uint64_t no_peer_drop = 0; /* inbound datagram dropped before peer learned */

    fprintf(stderr, "udpsocks: forwarding 127.0.0.1:%u <-> SOCKS5 UDP relay\n",
            (unsigned)listen_port);

    for (;;) {
        if (g_stop) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        FD_SET(udp_fd, &rfds);
        FD_SET(tcp_fd, &rfds);
        int maxfd = lfd;
        if (udp_fd > maxfd) maxfd = udp_fd;
        if (tcp_fd > maxfd) maxfd = tcp_fd;
        if (select(maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                /* Interrupted by signal — recheck g_stop at top of loop. */
                continue;
            }
            perror("udpsocks: select");
            close(lfd);
            fprintf(stderr,
                    "udpsocks: forwarder stats wrap_fail=%llu unwrap_fail=%llu"
                    " no_peer_drop=%llu\n",
                    (unsigned long long)wrap_fail, (unsigned long long)unwrap_fail,
                    (unsigned long long)no_peer_drop);
            return 1;
        }

        /* ASSOCIATE control EOF => proxy session torn down => exit cleanly. */
        if (FD_ISSET(tcp_fd, &rfds)) {
            uint8_t b;
            if (recv(tcp_fd, &b, 1, 0) <= 0) {
                fprintf(stderr, "udpsocks: ASSOCIATE control connection closed\n");
                close(lfd);
                fprintf(stderr,
                        "udpsocks: forwarder stats wrap_fail=%llu unwrap_fail=%llu"
                        " no_peer_drop=%llu\n",
                        (unsigned long long)wrap_fail, (unsigned long long)unwrap_fail,
                        (unsigned long long)no_peer_drop);
                return 0;
            }
        }

        /* peer -> proxy: wrap. */
        if (FD_ISSET(lfd, &rfds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(lfd, rx, sizeof(rx), 0, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                if (peer_len == 0) {
                    peer = from;
                    peer_len = flen;
                    if (verbose) {
                        fprintf(stderr, "udpsocks: learned peer 127.0.0.1:%u\n",
                                (unsigned)ntohs(from.sin_port));
                    }
                }
                if ((size_t)n + (size_t)hdr_len <= sizeof(tx)) {
                    memcpy(tx, hdr_buf, (size_t)hdr_len);
                    memcpy(tx + hdr_len, rx, (size_t)n);
                    ssize_t sent =
                        sendto(udp_fd, tx, (size_t)n + (size_t)hdr_len, 0,
                               (const struct sockaddr *)bnd_sa, sizeof(*bnd_sa));
                    if (sent < 0) wrap_fail++;
                } else {
                    /* Datagram too large for tx buffer — drop and count. */
                    wrap_fail++;
                }
            }
        }

        /* proxy -> peer: unwrap. */
        if (FD_ISSET(udp_fd, &rfds)) {
            ssize_t n = recvfrom(udp_fd, rx, sizeof(rx), 0, NULL, NULL);
            if (n > 0) {
                if (peer_len == 0) {
                    no_peer_drop++;
                } else {
                    mq_socks5_udp_hdr_t h;
                    memset(&h, 0, sizeof(h));
                    if (mq_socks5_parse_udp_hdr(rx, (size_t)n, &h) >= 0 &&
                        (size_t)n >= h.hdr_len) {
                        ssize_t sent = sendto(lfd, rx + h.hdr_len, (size_t)n - h.hdr_len,
                                              0, (struct sockaddr *)&peer, peer_len);
                        if (sent < 0) unwrap_fail++;
                    } else {
                        unwrap_fail++;
                    }
                }
            }
        }
    }

    /* Signal-initiated exit — clean. */
    close(lfd);
    fprintf(stderr,
            "udpsocks: forwarder stats wrap_fail=%llu unwrap_fail=%llu"
            " no_peer_drop=%llu\n",
            (unsigned long long)wrap_fail, (unsigned long long)unwrap_fail,
            (unsigned long long)no_peer_drop);
    return 0;
}

/* ── main ─────────────────────────────────────────────────────────────────────*/

int
main(int argc, char **argv)
{
    char proxy_host[256] = {0};
    uint16_t proxy_port = 0;
    char target_host[256] = {0};
    uint16_t target_port = 0;
    const char *send_arg = NULL;
    int count = 1;
    int timeout_ms = 3000;
    int verbose = 0;
    uint16_t listen_port = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--proxy") == 0 && i + 1 < argc) {
            if (parse_hostport(argv[++i], proxy_host, sizeof(proxy_host), &proxy_port) !=
                0) {
                fprintf(stderr, "udpsocks: bad --proxy: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            if (parse_hostport(argv[++i], target_host, sizeof(target_host),
                               &target_port) != 0) {
                fprintf(stderr, "udpsocks: bad --target: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) {
            send_arg = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
            if (count <= 0) {
                fprintf(stderr, "udpsocks: --count must be >= 1\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
            if (timeout_ms <= 0) {
                fprintf(stderr, "udpsocks: --timeout-ms must be > 0\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            char *endp = NULL;
            unsigned long lp = strtoul(argv[++i], &endp, 10);
            if (!endp || *endp != '\0' || lp < 1 || lp > 65535) {
                fprintf(stderr, "udpsocks: --listen: invalid port: %s\n", argv[i]);
                usage();
                return 1;
            }
            listen_port = (uint16_t)lp;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "udpsocks: unknown argument: %s\n", argv[i]);
            usage();
            return 1;
        }
    }

    if (proxy_host[0] == '\0' || proxy_port == 0) {
        fprintf(stderr, "udpsocks: --proxy is required\n");
        usage();
        return 1;
    }
    if (target_host[0] == '\0' || target_port == 0) {
        fprintf(stderr, "udpsocks: --target is required\n");
        usage();
        return 1;
    }

    if (listen_port != 0 && (send_arg != NULL || count != 1)) {
        fprintf(stderr, "udpsocks: --listen is mutually exclusive with --send/--count\n");
        usage();
        return 2;
    }

    /* ── Build payload ──────────────────────────────────────────────────────*/
    uint8_t *payload = NULL;
    size_t plen = 0;
    int payload_check = 0; /* 1 = verify echo response matches payload */

    if (send_arg != NULL) {
        /* Try opening as file first. */
        FILE *probe = fopen(send_arg, "r");
        if (probe) {
            fclose(probe);
            ssize_t n = load_hex_file(send_arg, &payload);
            if (n < 0) {
                fprintf(stderr, "udpsocks: failed to load hex file: %s\n", send_arg);
                return 1;
            }
            plen = (size_t)n;
            payload_check = 1;
        } else {
            /* Interpret as integer size. */
            char *endp = NULL;
            long sz = strtol(send_arg, &endp, 10);
            if (!endp || *endp != '\0' || sz <= 0 || sz > 65535) {
                fprintf(
                    stderr,
                    "udpsocks: --send: not a readable file and not a valid size: %s\n",
                    send_arg);
                return 1;
            }
            plen = (size_t)sz;
            payload = gen_pattern(plen);
            if (!payload) {
                fprintf(stderr, "udpsocks: malloc failed\n");
                return 1;
            }
            payload_check = 1;
        }
    } else {
        /* Default: 8-byte deterministic pattern. */
        plen = 8;
        payload = gen_pattern(plen);
        if (!payload) {
            fprintf(stderr, "udpsocks: malloc failed\n");
            return 1;
        }
        payload_check = 1;
    }

    /* ── Build mq_socks5_req_t for the target ───────────────────────────────*/
    mq_socks5_req_t dst;
    memset(&dst, 0, sizeof(dst));
    dst.port = target_port;

    /* Try parsing as IPv4 literal. */
    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, target_host, &ipv4_addr) == 1) {
        dst.atype = MQ_ADDR_IPV4;
        dst.host_len = 4;
        memcpy(dst.host, &ipv4_addr.s_addr, 4); /* network byte order */
    } else {
        /* Treat as domain. */
        size_t dlen = strlen(target_host);
        if (dlen == 0 || dlen > MQ_MAX_HOST) {
            fprintf(stderr, "udpsocks: target host too long\n");
            free(payload);
            return 1;
        }
        dst.atype = MQ_ADDR_DOMAIN;
        dst.host_len = dlen;
        memcpy(dst.host, target_host, dlen);
    }

    /* ── TCP connect to SOCKS5 proxy ────────────────────────────────────────*/
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd < 0) {
        perror("udpsocks: socket(TCP)");
        free(payload);
        return 1;
    }

    struct sockaddr_in proxy_sa;
    memset(&proxy_sa, 0, sizeof(proxy_sa));
    proxy_sa.sin_family = AF_INET;
    proxy_sa.sin_port = htons(proxy_port);
    if (inet_pton(AF_INET, proxy_host, &proxy_sa.sin_addr) != 1) {
        fprintf(stderr, "udpsocks: invalid proxy IP: %s\n", proxy_host);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    if (connect(tcp_fd, (struct sockaddr *)&proxy_sa, sizeof(proxy_sa)) != 0) {
        perror("udpsocks: connect");
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* ── SOCKS5 greeting (VER=5, NMETHODS=1, METHOD=0 NO-AUTH) ─────────────*/
    {
        uint8_t greeting[] = {0x05, 0x01, 0x00};
        if (write_all(tcp_fd, greeting, sizeof(greeting)) != 0) {
            fprintf(stderr, "udpsocks: send greeting failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        uint8_t method_reply[2];
        if (read_exact(tcp_fd, method_reply, 2) != 0) {
            fprintf(stderr, "udpsocks: read method reply failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        if (method_reply[0] != 0x05 || method_reply[1] != 0x00) {
            fprintf(stderr, "udpsocks: method reply rejected (VER=%02x METHOD=%02x)\n",
                    method_reply[0], method_reply[1]);
            close(tcp_fd);
            free(payload);
            return 1;
        }
    }

    /* ── SOCKS5 ASSOCIATE request (CMD=0x03, DST=0.0.0.0:0) ────────────────*/
    {
        /* VER CMD RSV ATYP IPv4(0.0.0.0) PORT(0) */
        uint8_t assoc_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        if (write_all(tcp_fd, assoc_req, sizeof(assoc_req)) != 0) {
            fprintf(stderr, "udpsocks: send ASSOCIATE request failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
    }

    /* ── Read ASSOCIATE reply — hand-parse the 10-byte IPv4 response ────────*/
    /* RFC 1928 §6: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR BND.PORT(2)
     * We expect ATYP=0x01 (IPv4) → total 10 bytes.
     * If ATYP=0x03 (domain) we'd need to read the length byte first, but
     * mqproxy always replies IPv4 for ASSOCIATE. */
    uint8_t assoc_reply[10];
    if (read_exact(tcp_fd, assoc_reply, 4) != 0) {
        fprintf(stderr, "udpsocks: read ASSOCIATE reply header failed\n");
        close(tcp_fd);
        free(payload);
        return 1;
    }
    if (assoc_reply[0] != 0x05) {
        fprintf(stderr, "udpsocks: ASSOCIATE reply: bad VER=0x%02x\n", assoc_reply[0]);
        close(tcp_fd);
        free(payload);
        return 1;
    }
    if (assoc_reply[1] != 0x00) {
        fprintf(stderr, "udpsocks: ASSOCIATE reply: REP=0x%02x (failed)\n",
                assoc_reply[1]);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    uint8_t bnd_atyp = assoc_reply[3];
    uint32_t bnd_ip_be = 0;
    uint16_t bnd_port = 0;

    if (bnd_atyp == 0x01) {
        /* IPv4 — read 4+2 = 6 more bytes. */
        uint8_t rest[6];
        if (read_exact(tcp_fd, rest, 6) != 0) {
            fprintf(stderr, "udpsocks: read ASSOCIATE reply BND failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        memcpy(&bnd_ip_be, rest, 4);
        bnd_port = (uint16_t)((rest[4] << 8) | rest[5]);
    } else if (bnd_atyp == 0x03) {
        /* Domain — read length byte, then N bytes + 2 port bytes. */
        uint8_t dlen_byte;
        if (read_exact(tcp_fd, &dlen_byte, 1) != 0) {
            fprintf(stderr, "udpsocks: read ASSOCIATE reply domain length failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        uint8_t domain_and_port[256 + 2];
        if (read_exact(tcp_fd, domain_and_port, (size_t)dlen_byte + 2) != 0) {
            fprintf(stderr, "udpsocks: read ASSOCIATE reply domain+port failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        /* We need an IP to sendto — try to resolve, but for loopback e2e the
         * proxy should have replied with an IPv4 BND.  Fail clearly. */
        fprintf(stderr,
                "udpsocks: ASSOCIATE reply ATYP=domain not supported for UDP socket\n");
        close(tcp_fd);
        free(payload);
        return 1;
    } else if (bnd_atyp == 0x04) {
        /* IPv6 — read 16+2 = 18 bytes. */
        uint8_t rest[18];
        if (read_exact(tcp_fd, rest, 18) != 0) {
            fprintf(stderr, "udpsocks: read ASSOCIATE reply BND (IPv6) failed\n");
            close(tcp_fd);
            free(payload);
            return 1;
        }
        fprintf(stderr, "udpsocks: ASSOCIATE reply ATYP=IPv6 not supported\n");
        close(tcp_fd);
        free(payload);
        return 1;
    } else {
        fprintf(stderr, "udpsocks: ASSOCIATE reply unknown ATYP=0x%02x\n", bnd_atyp);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    if (bnd_port == 0) {
        fprintf(stderr, "udpsocks: ASSOCIATE reply BND.PORT=0 (invalid)\n");
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* ── Create UDP socket ──────────────────────────────────────────────────*/
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        perror("udpsocks: socket(UDP)");
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* Bind to 127.0.0.1:0 so the proxy can reach us back. */
    struct sockaddr_in udp_self;
    memset(&udp_self, 0, sizeof(udp_self));
    udp_self.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &udp_self.sin_addr);
    udp_self.sin_port = 0;
    if (bind(udp_fd, (struct sockaddr *)&udp_self, sizeof(udp_self)) != 0) {
        perror("udpsocks: bind(UDP)");
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* BND.ADDR endpoint to sendto. */
    struct sockaddr_in bnd_sa;
    memset(&bnd_sa, 0, sizeof(bnd_sa));
    bnd_sa.sin_family = AF_INET;
    bnd_sa.sin_addr.s_addr = bnd_ip_be; /* already network byte order */
    bnd_sa.sin_port = htons(bnd_port);

    /* ── Pre-build the SOCKS5 UDP encapsulation header ─────────────────────*/
    /* Max header: RSV(2)+FRAG(1)+ATYP(1)+LEN(1)+255+PORT(2) = 262 */
    uint8_t hdr_buf[300];
    int hdr_len = mq_socks5_build_udp_hdr(hdr_buf, sizeof(hdr_buf), &dst);
    if (hdr_len < 0) {
        fprintf(stderr, "udpsocks: mq_socks5_build_udp_hdr failed\n");
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* ── Forwarder mode (--listen) ──────────────────────────────────────────*/
    if (listen_port != 0) {
        int frc = run_forwarder(listen_port, tcp_fd, udp_fd, &bnd_sa, hdr_buf, hdr_len,
                                verbose);
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return frc;
    }

    /* ── Build full outgoing datagram: header + payload ─────────────────────*/
    size_t dgram_len = (size_t)hdr_len + plen;
    if (dgram_len > 65535) {
        fprintf(stderr, "udpsocks: datagram too large (%zu)\n", dgram_len);
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return 1;
    }
    uint8_t *dgram = (uint8_t *)malloc(dgram_len);
    if (!dgram) {
        fprintf(stderr, "udpsocks: malloc dgram failed\n");
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return 1;
    }
    memcpy(dgram, hdr_buf, (size_t)hdr_len);
    if (plen > 0) memcpy(dgram + hdr_len, payload, plen);

    /* Receive buffer — sized to hold the largest possible echo (header + payload). */
    size_t rxbuf_sz = 65535 + 300;
    uint8_t *rxbuf = (uint8_t *)malloc(rxbuf_sz);
    if (!rxbuf) {
        fprintf(stderr, "udpsocks: malloc rxbuf failed\n");
        free(dgram);
        close(udp_fd);
        close(tcp_fd);
        free(payload);
        return 1;
    }

    /* ── Send/receive loop ──────────────────────────────────────────────────*/
    int ok_count = 0;
    int fail_count = 0;

    for (int iter = 0; iter < count; iter++) {
        /* Send the datagram to BND. */
        ssize_t sent = sendto(udp_fd, dgram, dgram_len, 0, (struct sockaddr *)&bnd_sa,
                              sizeof(bnd_sa));
        if (sent < 0) {
            fprintf(stderr, "udpsocks: sendto failed (iter %d): %s\n", iter + 1,
                    strerror(errno));
            fail_count++;
            continue;
        }

        /* Wait for a response within timeout_ms. */
        int rdy = wait_readable(udp_fd, timeout_ms);
        if (rdy <= 0) {
            if (rdy == 0) {
                fprintf(stderr, "udpsocks: timeout waiting for response (iter %d)\n",
                        iter + 1);
            } else {
                fprintf(stderr, "udpsocks: select error (iter %d): %s\n", iter + 1,
                        strerror(errno));
            }
            fail_count++;
            continue;
        }

        ssize_t rn = recvfrom(udp_fd, rxbuf, rxbuf_sz, 0, NULL, NULL);
        if (rn < 0) {
            fprintf(stderr, "udpsocks: recvfrom failed (iter %d): %s\n", iter + 1,
                    strerror(errno));
            fail_count++;
            continue;
        }

        /* Strip SOCKS5 UDP encapsulation header. */
        mq_socks5_udp_hdr_t rx_hdr;
        memset(&rx_hdr, 0, sizeof(rx_hdr));
        int parsed = mq_socks5_parse_udp_hdr(rxbuf, (size_t)rn, &rx_hdr);
        if (parsed < 0) {
            fprintf(stderr,
                    "udpsocks: mq_socks5_parse_udp_hdr failed (iter %d, ret=%d)\n",
                    iter + 1, parsed);
            fail_count++;
            continue;
        }

        size_t inner_len = (size_t)rn - rx_hdr.hdr_len;
        const uint8_t *inner = rxbuf + rx_hdr.hdr_len;

        /* Hex dump inner payload to stdout (always). */
        hex_dump(inner, inner_len);
        printf("\n");
        fflush(stdout);

        /* Verify echo match if requested. */
        int match = 1;
        if (payload_check) {
            if (inner_len != plen) {
                match = 0;
            } else if (plen > 0 && memcmp(inner, payload, plen) != 0) {
                match = 0;
            }
        }

        if (match) {
            if (verbose) {
                fprintf(stderr, "udpsocks: OK %zu bytes (iter %d)\n", inner_len,
                        iter + 1);
            } else {
                fprintf(stderr, "OK %zu bytes\n", inner_len);
            }
            ok_count++;
        } else {
            fprintf(stderr, "udpsocks: MISMATCH (iter %d): got %zu bytes, expected %zu\n",
                    iter + 1, inner_len, plen);
            if (verbose) {
                fprintf(stderr, "  sent: ");
                for (size_t k = 0; k < plen && k < 64; k++)
                    fprintf(stderr, "%02x", payload[k]);
                if (plen > 64) fprintf(stderr, "...");
                fprintf(stderr, "\n");
                fprintf(stderr, "  recv: ");
                for (size_t k = 0; k < inner_len && k < 64; k++)
                    fprintf(stderr, "%02x", inner[k]);
                if (inner_len > 64) fprintf(stderr, "...");
                fprintf(stderr, "\n");
            }
            fail_count++;
        }
    }

    free(rxbuf);
    free(dgram);
    free(payload);
    close(udp_fd);
    close(tcp_fd);

    if (fail_count > 0) {
        fprintf(stderr, "udpsocks: %d/%d responses OK, %d failed\n", ok_count, count,
                fail_count);
        return 1;
    }
    return 0;
}
