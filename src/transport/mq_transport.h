// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_transport.h — sans-io transport core boundary (design §4).
 *
 * mq_transport is the I/O-free transport core: it owns the xqc_engine but no
 * socket and no event loop. The runtime injects received UDP packets via
 * on_udp_recv, drives the engine via tick (using next_timeout_ms to arm its
 * own timer), and receives outbound packets / path socket lifecycle requests
 * through the mq_transport_callbacks_t hooks.
 *
 * In Chunk 1 this is a thin shell that holds an mq_engine_t and delegates to
 * it; the callbacks are stored but not yet wired (Chunk 3/6). Later chunks
 * grow it into the real sans-io core. Nothing in production calls it yet.
 */
#ifndef MQ_TRANSPORT_MQ_TRANSPORT_H
#define MQ_TRANSPORT_MQ_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <xquic/xquic.h>

typedef struct mq_transport_s mq_transport_t;

/* send_udp return value: >=0 = bytes written, MQ_TX_AGAIN = would-block,
 * -1 = error. The core propagates MQ_TX_AGAIN to xquic as XQC_SOCKET_EAGAIN. */
#define MQ_TX_AGAIN (-2)

typedef struct {
    /* core -> caller: send one UDP packet. path is the xquic path-id. peer is
     * the destination address passed through from xquic. Returns the number of
     * bytes written (>=0, normally len for all-or-nothing UDP), MQ_TX_AGAIN on
     * would-block, or -1 on error. */
    int (*send_udp)(uint64_t path, const uint8_t *pkt, size_t len,
                    const struct sockaddr *peer, socklen_t peerlen, void *user);

    /* core -> caller: open a socket for an additional path. path is the
     * xquic-assigned path-id (passed in; the runtime does not mint ids). The
     * caller does socket()/bind()/getsockname(), arms recv, and registers
     * path->fd. Returns 0 on success, -1 on failure. */
    int (*open_path_socket)(uint64_t path, const char *local_ip, uint16_t port,
                            void *user);

    /* core -> caller: the additional path's socket may be closed. */
    void (*close_path_socket)(uint64_t path, void *user);
} mq_transport_callbacks_t;

/* Create a transport in client (is_server==0) or server (is_server!=0) mode.
 * cbs is copied (NULL tolerated == zeroed). user is stored opaquely. Returns
 * NULL on failure. */
mq_transport_t *mq_transport_new(int is_server, const mq_transport_callbacks_t *cbs,
                                 void *user);

/* Create a server-mode transport with a TLS certificate + private key (PEM
 * files, both required). cbs/user as in mq_transport_new. Returns NULL on
 * failure. */
mq_transport_t *mq_transport_new_server(const mq_transport_callbacks_t *cbs, void *user,
                                        const char *cert_file, const char *key_file);

void mq_transport_free(mq_transport_t *t);

/* Input: hand the core one UDP packet read from a path socket. path is the
 * receiving socket's xquic path-id (primary == 0). local is the receiving
 * socket's bind address; xquic identifies the path by the (local,peer) 4-tuple,
 * so both are required by xqc_engine_packet_process. */
int mq_transport_on_udp_recv(mq_transport_t *t, uint64_t path, const uint8_t *pkt,
                             size_t len, const struct sockaddr *local, socklen_t locallen,
                             const struct sockaddr *peer, socklen_t peerlen);

/* Advance the engine (= xqc_engine_main_logic). The runtime calls this after a
 * recv or when its timer fires. */
void mq_transport_tick(mq_transport_t *t);

/* Milliseconds until the core next wants to be ticked; -1 == not needed for
 * now. The runtime arms its own timer from this. */
int mq_transport_next_timeout_ms(mq_transport_t *t);

/* Accessor for the underlying xquic engine (used by mq_conn / cli). */
xqc_engine_t *mq_transport_xqc(mq_transport_t *t);

/* Multipath readiness hook: invoked once cids are exchanged on a connection
 * (the precondition for xqc_conn_create_path). scid is copied out by xquic and
 * valid only for the callback duration. */
typedef void (*mq_transport_mp_ready_fn)(const xqc_cid_t *scid, void *user);
void mq_transport_set_mp_ready_cb(mq_transport_t *t, mq_transport_mp_ready_fn fn,
                                  void *user);

/* Enable xquic's qlog sink, writing to "<dir>/<role>.qlog". Returns 0 on
 * success, -1 on bad args / open failure. *out_path (if non-NULL) receives the
 * opened path (borrowed, valid until mq_transport_free). */
int mq_transport_enable_qlog(mq_transport_t *t, const char *dir, const char **out_path);

#endif /* MQ_TRANSPORT_MQ_TRANSPORT_H */
