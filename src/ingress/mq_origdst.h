// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#ifndef MQ_ORIGDST_H
#define MQ_ORIGDST_H
#include <sys/socket.h> /* struct sockaddr_storage */
#include <stdint.h>
#include "wire/mq_wire.h" /* MQ_ADDR_IPV4 / MQ_ADDR_IPV6 */

/* Convert an original-destination sockaddr into the binary (host_bytes, atype, port)
 * the mq_tcp_open_fn / CONNECT_TCP wire contract expects. host receives the RAW
 * address bytes (4 for IPv4, 16 for IPv6) — NOT a printable string. Returns 0 on
 * success, -1 on unsupported family or cap < needed. */
int mq_origdst_to_target(const struct sockaddr_storage *ss, uint8_t *host, size_t cap,
                         size_t *host_len, int *atype, uint16_t *port);

/* Thin syscall wrappers (not unit-tested; need a live socket). v1 is IPv4-only. */
int mq_origdst_from_fd_tproxy(int fd, struct sockaddr_storage *out); /* getsockname */
int mq_origdst_from_fd_redirect(
    int fd, struct sockaddr_storage *out); /* getsockopt SO_ORIGINAL_DST */
#endif
