// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_runtime_libevent.h — Linux reference App-I/O runtime for mq_transport
 * (design §5).
 *
 * The runtime owns libevent + the UDP path sockets and implements the
 * mq_transport_callbacks_t hooks (send_udp / open_path_socket /
 * close_path_socket). It feeds received datagrams into the sans-io transport
 * core via mq_transport_on_udp_recv and drives the engine via a libevent timer
 * armed from mq_transport_next_timeout_ms. The transport itself stays
 * libevent-free; all OS I/O lives here.
 *
 * Construction order: caller builds the transport first, then the runtime,
 * which installs its callbacks (user == the runtime) onto the transport.
 */
#ifndef MQ_RUNTIME_MQ_RUNTIME_LIBEVENT_H
#define MQ_RUNTIME_MQ_RUNTIME_LIBEVENT_H

#include <stdint.h>

#include "transport/mq_transport.h"

struct event_base;

typedef struct mq_runtime_s mq_runtime_t;

/* Create a runtime bound to transport t. base==NULL -> the runtime creates and
 * owns an event_base; base!=NULL -> the base is borrowed (shared with
 * listeners / tests that drive a single loop). Installs the runtime's callbacks
 * onto t. Returns NULL on failure (frees everything it created). The transport
 * is borrowed, not owned. */
mq_runtime_t *mq_runtime_new(mq_transport_t *t, struct event_base *base);

/* The runtime's event_base (owned or borrowed), or NULL if r is NULL. */
struct event_base *mq_runtime_base(mq_runtime_t *r);

/* Open the primary path (path id 0): socket/bind/getsockname, arm EV_READ,
 * register path 0 -> fd + local addr. Call before connect. Returns 0/-1. */
int mq_runtime_open_udp_path(mq_runtime_t *r, const char *local_ip, uint16_t port);

void mq_runtime_run(mq_runtime_t *r);  /* event_base_dispatch */
void mq_runtime_stop(mq_runtime_t *r); /* event_base_loopbreak */

/* Free all path sockets/events + the timer, free the base if owned, free the
 * runtime. Does NOT free the transport (the caller owns it). Safe on NULL. */
void mq_runtime_free(mq_runtime_t *r);

#endif /* MQ_RUNTIME_MQ_RUNTIME_LIBEVENT_H */
