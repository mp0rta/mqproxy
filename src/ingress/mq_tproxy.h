// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#ifndef MQ_TPROXY_H
#define MQ_TPROXY_H

/* mq_tproxy.h — transparent-capture TCP listener (TPROXY / REDIRECT).
 *
 * Accepts kernel-redirected TCP connections, learns the original destination
 * from the kernel (via getsockname for TPROXY, SO_ORIGINAL_DST for REDIRECT),
 * and immediately hands the accepted fd to the proxy core via mq_tcp_open_fn.
 * No protocol is spoken toward the client; the relay is fully opaque.
 *
 * Capture modes:
 *   MQ_CAPTURE_REDIRECT — iptables nat REDIRECT (single-host OUTPUT or gateway
 *     PREROUTING); the original destination is recovered via SO_ORIGINAL_DST.
 *     Does NOT require IP_TRANSPARENT on the listen socket.
 *
 *   MQ_CAPTURE_TPROXY — iptables mangle TPROXY (router PREROUTING, foreign
 *     destinations); the listen socket must have IP_TRANSPARENT set BEFORE
 *     bind (requires CAP_NET_ADMIN).  The original destination is the local
 *     address reported by getsockname on the accepted fd.
 *
 * Because IP_TRANSPARENT requires CAP_NET_ADMIN there is no unprivileged unit
 * test for the listener constructor.  The pure orig-dst logic is tested by
 * test_origdst; the live end-to-end path is covered by the Task 9 NET_ADMIN
 * e2e suite.
 *
 * v1 is IPv4-only (AF_INET socket).
 */

#include <event2/event.h>
#include <stdint.h>

#include "ingress/mq_ingress.h" /* mq_tcp_open_fn */

typedef enum {
    MQ_CAPTURE_REDIRECT = 0, /* nat REDIRECT; orig-dst via SO_ORIGINAL_DST */
    MQ_CAPTURE_TPROXY = 1,   /* mangle TPROXY; orig-dst via getsockname */
} mq_capture_mode_t;

typedef struct mq_tproxy_listener mq_tproxy_listener_t;

/* Create a transparent-capture listener bound to bind_ip:port (port 0 =>
 * ephemeral; retrieve with mq_tproxy_listener_port).
 *
 * mode selects the kernel capture mechanism; in MQ_CAPTURE_TPROXY mode the
 * socket is given IP_TRANSPARENT before bind — this requires CAP_NET_ADMIN and
 * will return NULL with a logged error if the setsockopt fails.
 *
 * base is borrowed (must outlive the listener).  open_fn/core are the
 * proxy-core TCP boundary invoked for every successfully accepted connection.
 *
 * Returns NULL on bad args / privilege failure / bind / listen failure. */
mq_tproxy_listener_t *mq_tproxy_listener_new(struct event_base *base, const char *bind_ip,
                                             uint16_t port, mq_capture_mode_t mode,
                                             mq_tcp_open_fn open_fn, void *core);

/* The bound local TCP port in host byte order (ephemeral-bind support).
 * Returns 0 if unknown or l is NULL. */
uint16_t mq_tproxy_listener_port(const mq_tproxy_listener_t *l);

/* Stop accepting, close the listen socket, free the listener.
 * Safe on NULL. */
void mq_tproxy_listener_free(mq_tproxy_listener_t *l);

#endif /* MQ_TPROXY_H */
