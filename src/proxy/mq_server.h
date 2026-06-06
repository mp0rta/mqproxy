// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_server.h — proxy server: accepts mqproxy connections and authenticates
 * each on its control stream.
 *
 * mq_server_new registers the "mqproxy-tcp/1" ALPN hooks on a server engine.
 * For each accepted connection it tracks a small per-conn state and treats the
 * FIRST bidi stream as the control stream: it decodes AUTH_REQUEST, compares
 * the token in constant time against the configured token, and replies with
 * AUTH_RESPONSE. On failure it closes the connection. Later (non-control)
 * streams are NOT auth-checked here (Task 12 handles data streams).
 *
 * Per-conn state home: hung off the mq_conn owner slot (mq_conn_set_user /
 * mq_conn_user), which starts NULL for server-accepted conns.
 */
#ifndef MQ_PROXY_MQ_SERVER_H
#define MQ_PROXY_MQ_SERVER_H

#include "proxy/mq_udp_session.h" /* mq_udp_srv_t (observability accessor) */
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h" /* mq_cc_t */
#include "transport/mq_transport.h"

typedef struct mq_server_s mq_server_t;

/* Create a server bound to transport `t` (xquic/streams/conn) and runtime `rt`
 * (libevent base for origin-fd relays) that expects `auth_token`. Registers the
 * ALPN + on_new_conn/on_new_stream hooks. The token string is copied.
 *
 * udp_idle_timeout_ms: idle timeout for UDP relay sessions in milliseconds
 *   (stored for Chunk 5 consumption; pass 60000 for the default). A value of 0
 *   is NOT validated here (the CLI rejects 0 — Task 6.4); passing 0 yields a
 *   degenerate immediately-expiring idle timer.
 * udp_enabled: if non-zero, advertise MQ_FEAT_UDP_RELAY in AUTH_RESPONSE.features.
 *
 * Returns NULL on bad args / OOM / ALPN registration failure. */
mq_server_t *mq_server_new(mq_transport_t *t, mq_runtime_t *rt, const char *auth_token,
                           mq_cc_t cc, uint64_t udp_idle_timeout_ms, int udp_enabled);

/* Total number of control-stream auth attempts processed across all
 * connections (test/observability hook). */
unsigned mq_server_auth_attempts(const mq_server_t *s);

/* Observability accessor: the UDP relay state of the most-recently-accepted
 * connection (or NULL if none accepted yet / that conn had no UDP state / it
 * has since closed). Intended for single-connection in-process observation
 * (integration tests read its counters via mq_udp_srv_counters). With one
 * client per server instance the "most recent" conn is unambiguous. The pointer
 * is owned by the connection and dangles after that conn closes — do not retain
 * it across a conn teardown. */
mq_udp_srv_t *mq_server_last_udp_srv(const mq_server_t *s);

/* Free the server. Safe on NULL. (Per-conn state is freed as conns close.) */
void mq_server_free(mq_server_t *s);

#endif /* MQ_PROXY_MQ_SERVER_H */
