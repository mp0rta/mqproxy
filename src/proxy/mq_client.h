/* mq_client.h — proxy client: connects to an mqproxy server and performs the
 * control-stream AUTH handshake.
 *
 * The client wraps one mq_conn to the server. On ESTABLISHED it opens the
 * control stream (the first client-initiated bidi stream), sends an
 * AUTH_REQUEST, and waits for the AUTH_RESPONSE on the same stream. The auth
 * outcome is reported via mq_client_set_on_auth.
 *
 * This is the first capability of the client; Tasks 12/13 extend it with TCP
 * data streams. The control stream is kept open after auth so later
 * capabilities can reuse the connection.
 */
#ifndef MQ_PROXY_MQ_CLIENT_H
#define MQ_PROXY_MQ_CLIENT_H

#include <stdint.h>

#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "wire/mq_wire.h"

typedef struct mq_client_s mq_client_t;

/* Auth result callback: ok!=0 iff the server accepted (status==OK); err is the
 * server-reported error code (meaningful when ok==0). Fires exactly once per
 * connection. */
typedef void (*mq_client_on_auth_fn)(int ok, mq_auth_err_t err, void *user);

/* Create a client targeting server_ip:server_port, authenticating as client_id
 * with auth_token. The strings are copied. Returns NULL on bad args / OOM. */
mq_client_t *mq_client_new(mq_engine_t *eng, const char *server_ip, uint16_t server_port,
                           const char *client_id, const char *auth_token);

/* Register the auth-result callback (call before mq_client_start). */
void mq_client_set_on_auth(mq_client_t *c, mq_client_on_auth_fn fn, void *user);

/* Register a connection-state callback (established/closed) forwarded from the
 * underlying mq_conn. Optional; useful to observe peer-initiated close. */
void mq_client_set_on_state(mq_client_t *c, mq_conn_on_state_fn fn, void *user);

/* Initiate the connection to the server. Returns 0 on success, -1 on failure. */
int mq_client_start(mq_client_t *c);

/* 1 once the server accepted auth, else 0. */
int mq_client_is_authed(const mq_client_t *c);

/* The underlying mq_conn (valid after mq_client_start, until close), or NULL. */
mq_conn_t *mq_client_conn(const mq_client_t *c);

/* Free the client. Does not close the connection on its own; callers tear down
 * the engine/paths which closes outstanding conns. Safe on NULL. */
void mq_client_free(mq_client_t *c);

#endif /* MQ_PROXY_MQ_CLIENT_H */
