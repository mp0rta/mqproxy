/* mq_engine.h — xquic engine + libevent event loop (transport only).
 *
 * mq_engine owns an xqc_engine_t and a libevent event_base, wiring xquic's
 * set_event_timer callback to a libevent timer that drives
 * xqc_engine_main_logic, and routing xquic's multipath send callback
 * (write_socket_ex) to a per-path UDP fd.
 *
 * This module has NO TCP / stream / proxy knowledge. It only boots the
 * engine, runs the loop, and routes packet sends by path_id.
 */
#ifndef MQ_TRANSPORT_MQ_ENGINE_H
#define MQ_TRANSPORT_MQ_ENGINE_H

#include <stdint.h>

#include <xquic/xquic.h>

struct event_base;

typedef struct mq_engine_s mq_engine_t;

/* Create an engine in client (is_server==0) or server (is_server!=0) mode.
 *
 * If base is non-NULL it is borrowed (caller retains ownership and must
 * outlive the engine). If base is NULL, an event_base is created and owned
 * internally (freed by mq_engine_free).
 *
 * Returns NULL on failure (engine create / event_base alloc). */
mq_engine_t *mq_engine_new(int is_server, struct event_base *base);

/* Create a server-mode engine with a TLS certificate + private key (PEM
 * files). Required before a server engine can complete handshakes.
 *
 * cert_file / key_file are borrowed for the duration of this call only
 * (xquic copies the paths into its ssl config). base is borrowed/owned as
 * in mq_engine_new. Returns NULL on failure. */
mq_engine_t *mq_engine_new_server(struct event_base *base, const char *cert_file,
                                  const char *key_file);

/* Run the event loop (event_base_dispatch). Blocks until mq_engine_stop. */
void mq_engine_run(mq_engine_t *e);

/* Break out of the event loop (event_base_loopbreak). Safe from callbacks. */
void mq_engine_stop(mq_engine_t *e);

/* Accessors. */
xqc_engine_t *mq_engine_xqc(mq_engine_t *e);
struct event_base *mq_engine_base(mq_engine_t *e);

/* Path-id -> UDP fd routing map (consumed by the send callback).
 * Returns 0 on success, -1 if path_id is out of range. */
int mq_engine_register_path_fd(mq_engine_t *e, uint64_t path_id, int fd);
void mq_engine_unregister_path_fd(mq_engine_t *e, uint64_t path_id);

/* Multipath readiness hook. xquic fires ready_to_create_path_notify on a
 * connection once cids have been exchanged (the precondition for
 * xqc_conn_create_path). The engine routes that to `fn(scid, user)`. mq_conn
 * registers this to flip its per-conn mp_ready flag. One conn per client
 * engine in the proxy, so a single slot suffices. `scid` is the connection's
 * source cid (copied out by xquic; valid only for the callback duration). */
typedef void (*mq_engine_mp_ready_fn)(const xqc_cid_t *scid, void *user);
void mq_engine_set_mp_ready_cb(mq_engine_t *e, mq_engine_mp_ready_fn fn, void *user);

/* Destroy timer event, xqc engine, owned event_base (if any), and free. */
void mq_engine_free(mq_engine_t *e);

#endif /* MQ_TRANSPORT_MQ_ENGINE_H */
