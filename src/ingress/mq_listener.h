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
 *
 * This module knows nothing about xquic; it only speaks libevent + sockets and
 * the mq_tcp_open_fn boundary.
 */
#ifndef MQ_INGRESS_MQ_LISTENER_H
#define MQ_INGRESS_MQ_LISTENER_H

#include <stdint.h>

#include "ingress/mq_ingress.h"

struct event_base;

typedef struct mq_listener_s mq_listener_t;

/* Create a SOCKS5 ingress listener bound to bind_ip:port (port 0 => ephemeral).
 * base is borrowed (must outlive the listener). open_fn/core are the proxy-core
 * boundary; they are invoked once per accepted connection that parses a valid
 * CONNECT target. Returns NULL on bad args / bind / listen failure. */
mq_listener_t *mq_socks5_listener_new(struct event_base *base, const char *bind_ip,
                                      uint16_t port, mq_tcp_open_fn open_fn, void *core);

/* Create an HTTP CONNECT ingress listener. Same shape as the SOCKS5 variant. */
mq_listener_t *mq_http_connect_listener_new(struct event_base *base, const char *bind_ip,
                                            uint16_t port, mq_tcp_open_fn open_fn,
                                            void *core);

/* The bound local TCP port in host byte order (useful for ephemeral binds in
 * tests). Returns 0 if unknown. */
uint16_t mq_listener_local_port(const mq_listener_t *l);

/* Free the listener: stop accepting, close the listen socket, and close every
 * accepted fd still owned by the listener (i.e. those not yet handed to
 * open_fn). Safe on NULL. */
void mq_listener_free(mq_listener_t *l);

#endif /* MQ_INGRESS_MQ_LISTENER_H */
