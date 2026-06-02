// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

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

#include "ingress/mq_ingress.h"
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

/* ── Multipath: request extra paths (Task 19) ────────────────────────────────
 *
 * Register up to `n` extra local bind IPs to bring up as additional MPQUIC
 * paths once the underlying connection becomes multipath-ready (xquic has fired
 * ready_to_create_path_notify, i.e. cids are exchanged). The IP strings are
 * copied. Because path creation can only happen after mp-ready, this DEFERS:
 * after mq_client_start the client arms a short recurring libevent timer that
 * polls mq_conn_mp_ready and calls mq_conn_add_path for each pending IP once
 * ready (each on an ephemeral local UDP port), then disarms.
 *
 * Call after mq_client_new and before/after mq_client_start (the timer is armed
 * on the engine's base, which must exist). Returns the number of IPs accepted
 * (clamped to the internal max), or -1 on bad args. */
int mq_client_add_paths(mq_client_t *c, const char *const *ips, size_t n);

/* 1 once the server accepted auth, else 0. */
int mq_client_is_authed(const mq_client_t *c);

/* The underlying mq_conn (valid after mq_client_start, until close), or NULL. */
mq_conn_t *mq_client_conn(const mq_client_t *c);

/* ── TCP open (the ingress→core boundary, mq_ingress.h) ──────────────────────
 *
 * Open a proxied TCP connection to host:port on behalf of a local app socket
 * (local_fd). Implements mq_tcp_open_fn: `core` is the mq_client_t* (see
 * mq_client_tcp_open_core / mq_client_tcp_open_fn). Behaviour:
 *
 *   - If not yet authed, the request is QUEUED (bounded) and drained when auth
 *     succeeds.
 *   - When authed, a new bidi stream is opened carrying CONNECT_TCP_REQUEST;
 *     the CONNECT_TCP_RESPONSE is buffered (bounded) and decoded.
 *       · status OK    → cb(1, MQ_TCP_OK, user), then a relay binds the stream
 *                        ⇄ local_fd (the client owns local_fd from here, closing
 *                        it on relay completion / teardown).
 *       · status ERROR → cb(0, error_code, user); the client closes the stream
 *                        and CLOSES local_fd itself (ownership note below).
 *
 * local_fd ownership: the client takes ownership of local_fd the moment
 * mq_client_tcp_open is invoked. On EVERY terminal outcome (success-then-relay
 * completion, error response, malformed response, queue overflow, connection
 * teardown) the client closes local_fd exactly once. The ingress must NOT close
 * local_fd after calling tcp_open; it only writes its app-side reply (driven by
 * the cb's ok flag) — on ok=0 the ingress sends its error reply on its OWN app
 * socket, which is distinct from local_fd here in Phase 1 the ingress hands the
 * very socket it will relay, so for ok=0 the client closing local_fd also
 * terminates the app connection, which is the desired SOCKS/HTTP error
 * behaviour. */
void mq_client_tcp_open(void *core, const uint8_t *host, size_t host_len,
                        mq_addr_type_t atype, uint16_t port, int local_fd, void *user,
                        mq_tcp_open_cb cb);

/* The function pointer + core pointer for the ingress (Task 14) to call without
 * knowing the concrete client type. core is the mq_client_t*. */
mq_tcp_open_fn mq_client_tcp_open_fn(void);
void *mq_client_tcp_open_core(mq_client_t *c);

/* Free the client. Does not close the connection on its own; callers tear down
 * the engine/paths which closes outstanding conns. Safe on NULL. */
void mq_client_free(mq_client_t *c);

#endif /* MQ_PROXY_MQ_CLIENT_H */
