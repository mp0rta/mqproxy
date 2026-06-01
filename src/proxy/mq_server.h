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

#include "transport/mq_engine.h"

typedef struct mq_server_s mq_server_t;

/* Create a server bound to `eng` that expects `auth_token`. Registers the ALPN
 * + on_new_conn/on_new_stream hooks. The token string is copied. Returns NULL
 * on bad args / OOM / ALPN registration failure. */
mq_server_t *mq_server_new(mq_engine_t *eng, const char *auth_token);

/* Total number of control-stream auth attempts processed across all
 * connections (test/observability hook). */
unsigned mq_server_auth_attempts(const mq_server_t *s);

/* Free the server. Safe on NULL. (Per-conn state is freed as conns close.) */
void mq_server_free(mq_server_t *s);

#endif /* MQ_PROXY_MQ_SERVER_H */
