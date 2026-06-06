// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_listener.h — ingress TCP accept listeners (SOCKS5 / HTTP CONNECT).
 *
 * A listener binds+listens a non-blocking TCP socket on bind_ip:port and runs
 * a libevent EV_READ accept loop. Each accepted connection gets a small
 * per-conn parse state that drives the protocol parser (SOCKS5 greeting/request
 * or HTTP CONNECT) until it has a target, then calls the supplied open_fn
 * (mq_tcp_open_fn) to hand the connection to the proxy core.
 *
 * Ownership of the accepted fd:
 *   - The listener OWNS the accepted fd from accept() until the moment it calls
 *     open_fn. On any pre-tcp_open failure (parse error, unsupported request,
 *     read error) the listener writes the appropriate reject reply (when the
 *     protocol defines one) and closes the accepted fd itself.
 *   - Once open_fn is called, the proxy core (mq_client) OWNS the fd and closes
 *     it on every terminal outcome. The listener MUST NOT close it afterwards.
 *     The open-result callback writes the protocol success/error reply to the
 *     (still-open) fd; the core closes it after the callback returns on error,
 *     and on relay completion on success.
 *   - SOCKS5 CMD UDP ASSOCIATE (0x03) is a third outcome: on MQ_SOCKS5_ASSOCIATE_DONE
 *     the accepted (control) fd is MOVED into a freshly created mq_udp_assoc, and
 *     the transient parse state is freed (without closing the fd). The assoc now
 *     owns the control fd (its EOF tears the association down) plus a bound UDP
 *     relay socket. The listener keeps an intrusive list of live assocs (see
 *     mq_udp_assoc.{c,h}) for: (1) self-removal on TCP-EOF teardown, (2)
 *     availability-sweep teardown when UDP becomes unavailable, (3) reaping any
 *     survivors at mq_listener_free. ASSOCIATE is admitted only when the
 *     udp_open quad is non-NULL AND availability != 0 (see set_udp_availability).
 *
 * This module knows nothing about xquic; it only speaks libevent + sockets and
 * the mq_tcp_open_fn / mq_udp_open_fn boundaries.
 */
#ifndef MQ_INGRESS_MQ_LISTENER_H
#define MQ_INGRESS_MQ_LISTENER_H

#include <stdint.h>

#include "ingress/mq_ingress.h"

struct event_base;

typedef struct mq_listener_s mq_listener_t;

/* Create a SOCKS5 ingress listener bound to bind_ip:port (port 0 => ephemeral).
 * base is borrowed (must outlive the listener). open_fn/core are the proxy-core
 * TCP boundary; they are invoked once per accepted connection that parses a valid
 * CONNECT target.
 *
 * udp_open/udp_send/udp_close are the UDP relay boundary (mq_udp_open_fn) used to
 * service CMD UDP ASSOCIATE. Passing them all NULL means "this ingress has no
 * local UDP relay support" => every ASSOCIATE is refused with REP 0x07. (This is
 * distinct from the remote-side availability tri-state — see
 * mq_listener_set_udp_availability — which governs an ingress that CAN relay but
 * whose server may not, yet.)
 *
 * udp_core is the `core` passed to udp_open (mq_ingress.h) — the concrete relay
 * table (mq_udp_cli_t*), which is DISTINCT from the TCP `core` (mq_client_t*), so
 * it is a separate parameter. NULL when udp_open is NULL.
 * Returns NULL on bad args / bind / listen failure. */
mq_listener_t *mq_socks5_listener_new(struct event_base *base, const char *bind_ip,
                                      uint16_t port, mq_tcp_open_fn open_fn, void *core,
                                      mq_udp_open_fn udp_open, mq_udp_send_fn udp_send,
                                      mq_udp_close_fn udp_close, void *udp_core);

/* Create an HTTP CONNECT ingress listener. Same shape as the SOCKS5 variant. The
 * HTTP listener does not speak SOCKS5, so the udp_open quad is accepted only for
 * ctor symmetry and is always forced NULL (no ASSOCIATE path exists here). */
mq_listener_t *mq_http_connect_listener_new(struct event_base *base, const char *bind_ip,
                                            uint16_t port, mq_tcp_open_fn open_fn,
                                            void *core, mq_udp_open_fn udp_open,
                                            mq_udp_send_fn udp_send,
                                            mq_udp_close_fn udp_close, void *udp_core);

/* Set the remote UDP-relay availability tri-state consulted at ASSOCIATE time:
 *    -1 = undetermined (pre-auth window): optimistically admit ASSOCIATE
 *     0 = unavailable: refuse ASSOCIATE with REP 0x07, AND immediately sweep —
 *         close every live assoc's TCP control connection (relay end, RFC 1928
 *         §7), including pre-auth assocs that have not sent UDP yet
 *     1 = available: admit ASSOCIATE
 * Initial value is -1. `l == NULL` is a no-op (public contract: an HTTP-only
 * client leaves socks5_l == NULL while the CLI glue still calls this). */
void mq_listener_set_udp_availability(mq_listener_t *l, int avail);

/* The bound local TCP port in host byte order (useful for ephemeral binds in
 * tests). Returns 0 if unknown. */
uint16_t mq_listener_local_port(const mq_listener_t *l);

/* Free the listener: stop accepting, close the listen socket, and close every
 * accepted fd still owned by the listener (i.e. those not yet handed to
 * open_fn). Safe on NULL. */
void mq_listener_free(mq_listener_t *l);

#endif /* MQ_INGRESS_MQ_LISTENER_H */
