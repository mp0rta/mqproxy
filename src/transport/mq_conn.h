/* mq_conn.h — wrapper around one raw MPQUIC (xqc_connection_t) connection.
 *
 * mq_conn ties an xquic connection (identified by its scid) to an owner. It
 * is the application-protocol layer for the "mqproxy-tcp/1" ALPN: the
 * connection and stream callback tables registered via mq_conn_register_alpn
 * recover the mq_conn from xquic's per-connection app-proto user_data and
 * surface lifecycle + new-stream events to the owner.
 *
 * USER_DATA SCHEME (see mq_engine's send callback):
 *   - transport user_data  = the mq_engine_t* (so write_socket[_ex] recovers
 *                            the engine by casting conn_user_data).
 *   - app-proto user_data  = the mq_conn_t* (so the ALP conn/stream callbacks
 *                            recover the mq_conn).
 * The engine pointer is also stashed via xqc_engine_set_priv_ctx so the ALP
 * conn_create_notify can locate the per-engine registration context.
 */
#ifndef MQ_TRANSPORT_MQ_CONN_H
#define MQ_TRANSPORT_MQ_CONN_H

#include <sys/socket.h>

#include <xquic/xquic.h>

#include "transport/mq_engine.h"
#include "transport/mq_stream.h"

typedef struct mq_conn_s mq_conn_t;

/* Connection lifecycle state reported to the owner. */
typedef enum {
    MQ_CONN_ESTABLISHED = 1, /* handshake finished */
    MQ_CONN_CLOSED = 2,      /* connection closed (mq_conn freed right after) */
} mq_conn_state_t;

typedef void (*mq_conn_on_state_fn)(mq_conn_t *c, mq_conn_state_t st, void *user);

/* Server-side hooks: invoked when xquic accepts a connection / creates a peer
 * stream for the registered ALPN. on_new_conn yields a freshly-created
 * mq_conn (owner may attach its own context via mq_conn_set_on_state / the
 * stream's mq_stream_set_cbs). on_new_stream yields a freshly-created
 * mq_stream. Either may be NULL (e.g. on a client engine). */
typedef void (*mq_conn_on_new_fn)(mq_conn_t *c, void *user);
typedef void (*mq_stream_on_new_fn)(mq_stream_t *s, void *user);

/* Register the ALP callback tables for `alpn` on `eng`. Both client and
 * server engines must register before connecting / accepting. on_new_conn /
 * on_new_stream / user describe how accepted connections and peer-initiated
 * streams are surfaced (server side); pass NULL on a pure client.
 * Returns 0 on success, -1 on failure. */
int mq_conn_register_alpn(mq_engine_t *eng, const char *alpn,
                          mq_conn_on_new_fn on_new_conn,
                          mq_stream_on_new_fn on_new_stream, void *user);

/* Client: initiate a connection to `peer` using `alpn` and `settings`.
 * `owner` is opaque caller context (retrievable via mq_conn_user). Returns a
 * new mq_conn (state callbacks fire later) or NULL on failure. */
mq_conn_t *mq_conn_connect(mq_engine_t *eng, const struct sockaddr *peer,
                           socklen_t peerlen, const char *alpn,
                           const xqc_conn_settings_t *settings, void *owner);

/* Register the owner's state callback (established / closed). */
void mq_conn_set_on_state(mq_conn_t *c, mq_conn_on_state_fn fn, void *user);

/* Opaque owner context. For client conns this is the `owner` passed to
 * mq_conn_connect; for server conns it is initially NULL (settable via
 * mq_conn_set_user). */
void *mq_conn_user(const mq_conn_t *c);
void mq_conn_set_user(mq_conn_t *c, void *owner);

/* Client: open a new locally-initiated bidirectional stream. Returns a new
 * mq_stream or NULL on failure. */
mq_stream_t *mq_conn_open_stream(mq_conn_t *c);

/* Send CONNECTION_CLOSE. The mq_conn is freed later via conn_close_notify. */
void mq_conn_close(mq_conn_t *c);

#endif /* MQ_TRANSPORT_MQ_CONN_H */
