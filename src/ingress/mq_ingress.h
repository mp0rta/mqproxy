// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_INGRESS_H
#define MQ_INGRESS_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>
/* delivered asynchronously when the proxy core has a result for a tcp_open */
typedef void (*mq_tcp_open_cb)(int ok, mq_tcp_err_t err, void *user);
/* implemented later by mq_client; ingress calls this and never touches xquic.
 *
 * prebuf/prebuf_len carry app bytes that arrived in the SAME read as the request
 * head (e.g. a TLS ClientHello pipelined behind the SOCKS5/HTTP CONNECT request).
 * The ingress has already consumed them off local_fd, so they cannot be re-read
 * from the socket; the core MUST relay them toward the origin ahead of any fresh
 * local_fd reads or they are silently dropped. prebuf is borrowed (valid only
 * for the duration of the call); the core copies what it needs. prebuf_len may
 * be 0 (prebuf then NULL or ignored). */
typedef void (*mq_tcp_open_fn)(void *core, const uint8_t *host, size_t host_len,
                               mq_addr_type_t atype, uint16_t port, int local_fd,
                               const uint8_t *prebuf, size_t prebuf_len, void *user,
                               mq_tcp_open_cb cb);
#endif
