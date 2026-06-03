// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_client.h — client-side bridge between the local fetch-API listener
 * (mq_fetch_listener) and an HTTP/3-over-MPQUIC tunnel to the gateway server
 * (mq_h3). Task 3.2 of the Phase 2 HTTP Gateway plan.
 *
 * One fetch request (POST /_mqproxy/fetch on the local listener) becomes one
 * H3 request on a single, eagerly-established gateway connection. The bridge:
 *
 *   - validates the X-Mq-* control headers (auth format, target, method, no
 *     duplicate control headers) and the tunnel's liveness, answering 4xx/502
 *     directly on the local connection on any failure;
 *   - on accept, opens an H3 request and forwards :method/:scheme/:authority/
 *     :path + x-mq-auth + x-mq-class + the remaining non-stripped request
 *     headers, then streams the upload body with backpressure in BOTH directions;
 *   - relays the H3 response back onto the local connection, framing the body as
 *     chunked when the response carries no content-length, and surfacing
 *     mid-stream truncation as an abort (never a fake clean finish).
 *
 * LAYERING: this module owns the proxy semantics; it speaks the mq_fetch_cbs_t
 * boundary (listener side) and the mq_h3 boundary (tunnel side) only. It never
 * touches sockets directly — the listener owns the local fd, the transport +
 * runtime own the UDP paths.
 *
 * OWNERSHIP / LIFETIME:
 *   - t / rt / h3 are BORROWED (the caller owns them).
 *   - SANCTIONED TEARDOWN ORDER (MANDATORY):
 *
 *         mq_gw_client_free(gw)  →  mq_h3_free(h3)  →  mq_transport_free(t)
 *
 *     gw_client MUST be freed FIRST, while the H3 engine is STILL LIVE. Doing so
 *     lets mq_gw_client_free detach each in-flight request's H3 callbacks
 *     (mq_h3_req_set_cbs(NULL,...)) and reset it against a live engine — safe,
 *     no UAF. If mq_h3_free ran first, the per-request wrappers would already be
 *     destroyed and any gw_client touch of r->req (set_cbs/reset) would be a UAF.
 *     mq_h3_free BEFORE mq_transport_free is the separate mq_h3.h contract.
 *   - Per-request state (mq_gw_req_t, internal) is owned by the bridge and freed
 *     exactly once on EVERY termination order — see mq_gw_client.c for the
 *     ownership rules across local-first / tunnel-first / racing teardown.
 */
#ifndef MQ_GATEWAY_MQ_GW_CLIENT_H
#define MQ_GATEWAY_MQ_GW_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "gateway/mq_fetch_listener.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h" /* mq_cc_t */
#include "transport/mq_h3.h"
#include "transport/mq_transport.h"

typedef struct mq_gw_client_s mq_gw_client_t;

/* Create a gateway client bridging fetch requests to an H3 tunnel.
 *
 *   t / rt : the sans-io transport + its runtime (BORROWED; must outlive the
 *            gw_client). rt owns the libevent base used for the mp-poll timer.
 *   h3     : the mq_h3 ctx for `t` (BORROWED). On a pure client the caller may
 *            pass NULL server hooks to mq_h3_init.
 *   server_ip / server_port : the tunnel peer (the gateway server).
 *   token  : the shared token EXPECTED in the X-Mq-Auth header. The bridge only
 *            FORMAT-checks the incoming header against "Bearer <token>"
 *            client-side; the server performs the authoritative verification.
 *            The string is copied.
 *   cc     : congestion control for the tunnel conn.
 *
 * Establishes the gateway H3 connection EAGERLY (mirrors mq_client's eager
 * connect). Returns NULL on bad args / OOM / connect failure. */
mq_gw_client_t *mq_gw_client_new(mq_transport_t *t, mq_runtime_t *rt, mq_h3_t *h3,
                                 const char *server_ip, uint16_t server_port,
                                 const char *token, mq_cc_t cc);

/* The mq_fetch_cbs_t implementation to wire into mq_fetch_listener_new. The
 * returned pointer is to a static, immutable vtable (valid for the program
 * lifetime). */
const mq_fetch_cbs_t *mq_gw_client_fetch_cbs(void);

/* The `user` pointer to pass alongside mq_gw_client_fetch_cbs() into
 * mq_fetch_listener_new (it is the mq_gw_client_t itself). */
void *mq_gw_client_fetch_user(mq_gw_client_t *c);

/* Register up to `n` extra local bind IPs to bring up as additional MPQUIC
 * paths on the tunnel conn once it becomes multipath-ready. Mirrors
 * mq_client_add_paths (deferred via a recurring mp-poll timer on rt's base).
 * The IP strings are copied. Returns the number accepted (clamped), or -1 on
 * bad args. */
int mq_gw_client_add_paths(mq_gw_client_t *c, const char *const *ips, size_t n);

/* Free the gateway client: tear down any in-flight requests (detaching their H3
 * callbacks, resetting their H3 requests, aborting their local handles, dropping
 * their per-request state) and the mp-poll timer. Does NOT free t / rt / h3.
 * Safe on NULL.
 *
 * MUST be called BEFORE mq_h3_free (see the SANCTIONED TEARDOWN ORDER above):
 * it touches r->req on live in-flight requests, which is only valid while the H3
 * engine still exists. */
void mq_gw_client_free(mq_gw_client_t *c);

#endif /* MQ_GATEWAY_MQ_GW_CLIENT_H */
