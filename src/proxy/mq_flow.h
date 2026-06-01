/* mq_flow.h — shared QUIC-stream ⇄ TCP-fd relay glue.
 *
 * A "flow" binds one bidirectional QUIC stream (the A side, driven via
 * mq_stream_recv/_send) to one TCP socket fd (the B side, driven via
 * recv()/send(MSG_NOSIGNAL)) through an mq_relay. It encapsulates the
 * hard-won completion / half-close / teardown logic that both the proxy
 * server (origin fd) and the proxy client (local app fd) need identically:
 *
 *   - graceful zero-length FIN on the QUIC stream when the fd hits EOF (so the
 *     peer observes a clean stream EOF with ALL bytes delivered — never a
 *     RESET that would truncate un-acked STREAM data);
 *   - event_del of the dead fd's read/write events on that direction's EOF, to
 *     kill the level-triggered busy-spin on a half-closed fd;
 *   - deferred reap (pending_reap + drain-after-edge) so the node is never
 *     freed underneath a relay/libevent callback still on the stack (no UAF);
 *   - per-flow teardown that closes stream + fd exactly once, frees events and
 *     the relay, and unlinks the node from its owner's active-flow list.
 *
 * The owner (server or client) handles the protocol-specific phases (decode the
 * CONNECT_TCP request/response, dial / open the fd) and then hands the flow a
 * connected fd plus the attached stream and calls mq_flow_begin_relay() to
 * enter the relaying phase.
 *
 * Ownership of an mq_flow node: the owner keeps an intrusive list head
 * (mq_flow_t*) and links/unlinks nodes via this module. On connection teardown
 * the owner reaps every node in its list (mq_flow_reap, idempotent).
 */
#ifndef MQ_PROXY_MQ_FLOW_H
#define MQ_PROXY_MQ_FLOW_H

#include <stddef.h>

#include "transport/mq_engine.h"
#include "transport/mq_stream.h"

typedef struct mq_flow_s mq_flow_t;

/* Allocate a flow node and link it at the head of *list_head. The stream is the
 * A side (already attached to the owning conn); fd is the B side TCP socket
 * (must be non-blocking) or -1 if not yet connected. base is the libevent base
 * used to register the fd read/write events when the relay starts. on_reap (may
 * be NULL) is invoked from mq_flow_reap AFTER the node has closed its stream/fd
 * and unlinked itself but BEFORE it is freed, so the owner can drop any back
 * pointer; user is passed through to on_reap.
 *
 * Returns NULL on OOM (caller still owns the stream/fd in that case). */
typedef void (*mq_flow_on_reap_fn)(mq_flow_t *flow, void *user);

mq_flow_t *mq_flow_new(mq_flow_t **list_head, struct event_base *base,
                       mq_stream_t *stream, int fd, mq_flow_on_reap_fn on_reap,
                       void *user);

/* Replace the flow's B-side fd (e.g. once a non-blocking connect completes).
 * The fd must be non-blocking. Only valid before mq_flow_begin_relay. */
void mq_flow_set_fd(mq_flow_t *flow, int fd);

/* The flow's current B-side fd, or -1. */
int mq_flow_fd(const mq_flow_t *flow);

/* The flow's A-side stream, or NULL once detached/reaped. */
mq_stream_t *mq_flow_stream(const mq_flow_t *flow);

/* Enter the relaying phase: build the relay, register a persistent EV_READ and
 * an on-demand EV_WRITE on the fd, re-wire the stream callbacks to drive the
 * relay edges, and pump both directions once (forwarding any bytes already
 * buffered on the stream or fd, and honoring an immediate EOF). The stream must
 * be set and the fd must be connected & non-blocking.
 *
 * Returns 0 on success. On failure (relay/event alloc) returns -1 and the flow
 * is left intact for the caller to fail+reap (mq_flow_mark_graceful + reap, or
 * its own error path); the caller decides how to notify the peer.
 *
 * After a successful return the flow drives itself to completion via libevent
 * and the stream callbacks; on completion it self-requests a deferred reap and
 * invokes on_reap. */
int mq_flow_begin_relay(mq_flow_t *flow);

/* Mark the flow graceful: its reap must NOT RESET the stream (used when the
 * stream already carries / will carry a FIN, e.g. the protocol error path sent
 * a response with fin=1). */
void mq_flow_mark_graceful(mq_flow_t *flow);

/* Reap the flow exactly once: detach stream callbacks, close stream (RESET only
 * if not graceful) + fd, free events + relay, run on_reap, unlink from the
 * list, and free the node. Safe from any phase and idempotent. */
void mq_flow_reap(mq_flow_t *flow);

#endif /* MQ_PROXY_MQ_FLOW_H */
