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

/* UDP session boundary. The ingress layer (mq_udp_assoc) has no knowledge of
 * xquic; all QUIC interaction is hidden behind these function-pointer hooks.
 *
 * open returns a session handle SYNCHRONOUSLY (local allocation only — it does
 * not wait for auth or RESP). NULL means immediate failure (session limit hit /
 * negative-cache hit / pre-auth queue full). A non-NULL handle may be passed to
 * send immediately (optimistic send).
 * Remote-side failures and terminations (RESP error / stream close / idle
 * timeout) are reported back via on_err AT MOST ONCE; after that the handle is
 * invalid (the caller MUST NOT call send or close — close is unnecessary because
 * the core has already freed the session). Caller-initiated termination uses
 * close.
 *
 * CALLBACK SUPPRESSION CONTRACT — required to prevent use-after-free:
 *   - After close returns, on_rx and on_err for that session are NEVER called
 *     again (close completes callback detachment synchronously).
 *   - The same guarantee holds if close is called re-entrantly during an on_err
 *     or on_rx dispatch (the core marks the session as closing and suppresses
 *     all further user callbacks for it).
 *   - Deferred events that arrive immediately after close (RESP error, idle
 *     expiry, stream close notify) are silently discarded inside the core. */
typedef void (*mq_udp_rx_fn)(const uint8_t *payload, size_t len, void *user);
typedef void (*mq_udp_err_fn)(void *session, mq_udp_err_t err, void *user);
typedef void *(*mq_udp_open_fn)(void *core, const uint8_t *host, size_t host_len,
                                mq_addr_type_t atype, uint16_t port, mq_udp_rx_fn on_rx,
                                mq_udp_err_fn on_err, void *user);
typedef void (*mq_udp_send_fn)(void *session, const uint8_t *payload, size_t len);
typedef void (*mq_udp_close_fn)(void *session);
#endif
