// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_server.h — server-side H3→origin execution bridge (Phase 2 Task 4.3).
 *
 * The mirror of mq_gw_client: where the client tunnels a local fetch request as
 * an H3 request to the gateway, the SERVER receives that H3 request, replays it
 * to the upstream origin via mq_origin_curl, and streams the origin's response
 * back over the SAME H3 request. One in-flight H3 request ⇄ one origin request.
 *
 * Per accepted H3 request (mq_h3 on_new_req):
 *   - recv the request headers; extract the :method/:scheme/:authority/:path
 *     pseudo-headers + x-mq-auth + x-mq-class.
 *   - AUTH: x-mq-auth must be "Bearer <token>", constant-time compared to the
 *     configured token (shared mq_ct_equal, util/mq_ct.h). Failure → synthesized
 *     403 + x-mq-error: auth-failed (no origin contact).
 *   - validate the pseudo-headers (scheme http|https); bad → 400 + x-mq-error.
 *   - build origin URL = scheme://authority + path, forward the request headers
 *     minus x-mq-* (mq_gw_strip_server) minus hop-by-hop (mq_gw_strip_hop), and
 *     start the origin request. Upload body (if any) is pulled from an H3-side
 *     recv spill; download body is streamed back, with backpressure in both
 *     directions. On origin error (before response headers are sent) the bridge
 *     synthesizes status = mq_gw_status_from_curl(result) + x-mq-error:curl:<n>;
 *     on an error AFTER headers are already on the wire it RESETS the H3 request
 *     (a truncation must be visible — never a fake clean fin).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * OWNERSHIP / LIFETIME / TEARDOWN ORDER (MANDATORY)
 * ─────────────────────────────────────────────────────────────────────────────
 *   - t / rt are BORROWED (the caller owns them).
 *   - mq_gw_server_new calls mq_h3_init ITSELF (the gw_server must be the hooks
 *     owner — a pre-inited mq_h3 would be circular, since the hooks need the
 *     gw_server). The created mq_h3 is exposed via mq_gw_server_h3() so the CLI
 *     and the test fixture can free it in the correct order.
 *
 *   - mq_gw_server_free does NOT free the mq_h3 it created. It tears down every
 *     in-flight request (aborts the origin, detaches the H3 req callbacks) and
 *     frees the origin client, then returns. The caller MUST then free the mq_h3
 *     and the transport. SANCTIONED TEARDOWN ORDER (consistent with gw_client):
 *
 *         mq_gw_server_free(s)  →  mq_h3_free(mq_gw_server_h3(s)…captured)  →
 *         mq_transport_free(t)
 *
 *     gw_server_free MUST run FIRST, while the H3 engine is STILL LIVE: it touches
 *     r->req on live in-flight requests (mq_h3_req_set_cbs(NULL,...)), which is
 *     only valid while the engine exists. If mq_h3_free ran first, the per-request
 *     wrappers would already be destroyed and any touch would be a UAF.
 *     NOTE: capture the h3 handle (mq_gw_server_h3(s)) BEFORE mq_gw_server_free —
 *     the handle accessor reads the gw_server struct, which free() releases.
 */
#ifndef MQ_GATEWAY_MQ_GW_SERVER_H
#define MQ_GATEWAY_MQ_GW_SERVER_H

#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_h3.h"
#include "transport/mq_transport.h"

typedef struct mq_gw_server_s mq_gw_server_t;

/* Create a gateway server.
 *
 *   t / rt : the sans-io server transport + its runtime (BORROWED; must outlive
 *            the gw_server). rt owns the libevent base used to drive mq_origin.
 *   token  : the shared token EXPECTED in each request's X-Mq-Auth header
 *            ("Bearer <token>"), verified by constant-time compare. Copied.
 *   ca_file: (nullable) CURLOPT_CAINFO for origin TLS verification (always on).
 *   connect_timeout_s : origin connect timeout, per request.
 *
 * Calls mq_h3_init(t, …its own hooks…) internally. Returns NULL on bad args /
 * OOM / mq_h3_init failure / mq_origin_new failure. */
mq_gw_server_t *mq_gw_server_new(mq_transport_t *t, mq_runtime_t *rt, const char *token,
                                 const char *ca_file, long connect_timeout_s);

/* The mq_h3 the gw_server created (for teardown ordering / CLI use). Borrowed —
 * do NOT free it before mq_gw_server_free. Returns NULL on a NULL arg. */
mq_h3_t *mq_gw_server_h3(const mq_gw_server_t *s);

/* Free the gateway server: abort every in-flight origin request, detach the H3
 * request callbacks, free the origin client and the gw_server. Does NOT free the
 * mq_h3 it created (see the SANCTIONED TEARDOWN ORDER above), nor t / rt. Safe on
 * NULL. MUST be called BEFORE mq_h3_free. */
void mq_gw_server_free(mq_gw_server_t *s);

/* Count of H3 requests the server has accepted (observability / test hook).
 * Bumped once per on_new_req (including auth-rejected requests — they are
 * accepted at the H3 layer before auth runs). 0 on a NULL arg. */
unsigned mq_gw_server_requests(const mq_gw_server_t *s);

#endif /* MQ_GATEWAY_MQ_GW_SERVER_H */
