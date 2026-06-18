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
 *   - Per-request state (mq_gw_xreq_t, internal) is owned by the bridge and freed
 *     exactly once on EVERY termination order — see mq_gw_client.c for the
 *     ownership rules across local-first / tunnel-first / racing teardown.
 */
#ifndef MQ_GATEWAY_MQ_GW_CLIENT_H
#define MQ_GATEWAY_MQ_GW_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "gateway/mq_fetch_listener.h"
#include "gateway/mq_gw_intake.h"
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
 *   keepalive_idle_ms : QUIC PING keepalive idle timeout for the tunnel conn
 *            (> 0 enables keepalive + sets the post-handshake idle timeout;
 *            0 disables). Mirrors mq_client_set_keepalive.
 *   reconnect_enabled : 1 re-establishes the tunnel conn on loss with an
 *            exponential backoff (mirrors mq_client); 0 keeps the legacy
 *            terminal-on-close behavior.
 *   reconnect_max_backoff_ms : backoff cap (floored to 1000 ms). Ignored when
 *            reconnect is disabled.
 *
 * Because the connection is established EAGERLY in the constructor (there is no
 * separate start), keepalive + reconnect are constructor args (not setters).
 *
 * Establishes the gateway H3 connection EAGERLY (mirrors mq_client's eager
 * connect). Returns NULL on bad args / OOM / connect failure. */
mq_gw_client_t *mq_gw_client_new(mq_transport_t *t, mq_runtime_t *rt, mq_h3_t *h3,
                                 const char *server_ip, uint16_t server_port,
                                 const char *token, mq_cc_t cc,
                                 uint64_t keepalive_idle_ms, int reconnect_enabled,
                                 uint64_t reconnect_max_backoff_ms);

/* Register up to `n` extra local bind IPs to bring up as additional MPQUIC
 * paths on the tunnel conn once it becomes multipath-ready. Mirrors
 * mq_client_add_paths (deferred via a recurring mp-poll timer on rt's base).
 * The IP strings are copied. Returns the number accepted (clamped), or -1 on
 * bad args. */
int mq_gw_client_add_paths(mq_gw_client_t *c, const char *const *ips, size_t n);

/* Snapshot + log the gateway tunnel conn's per-path byte counters (spec §23.1),
 * for e2e benchmarks that need to confirm both MPQUIC paths carried traffic on
 * the GATEWAY conn (the mq_client TCP-core conn is dumped separately via
 * mq_conn_dump_stats). Delegates to mq_h3_conn_dump_stats on the tunnel conn.
 * No-op if the conn is not (yet) up. Smoke-safe on NULL. */
void mq_gw_client_dump_stats(mq_gw_client_t *c);

/* Free the gateway client: tear down any in-flight requests (detaching their H3
 * callbacks, resetting their H3 requests, aborting their local handles, dropping
 * their per-request state) and the mp-poll timer. Does NOT free t / rt / h3.
 * Safe on NULL.
 *
 * MUST be called BEFORE mq_h3_free (see the SANCTIONED TEARDOWN ORDER above):
 * it touches r->req on live in-flight requests, which is only valid while the H3
 * engine still exists. */
void mq_gw_client_free(mq_gw_client_t *c);

/* ── Neutral intake boundary (Phase 7 MITM, Tasks 3–4) ──────────────────────
 *
 * Protocol-agnostic request boundary onto the gateway tunnel. Adapters (e.g.
 * mq_gw_fetch_adapter for H1, future H2/H3 MITM adapters) plug into this
 * boundary so the core tunnel-forwarding + response-relay logic is shared.
 *
 * Reject ORDER is observable (tests/e2e assert X-Mq-Error byte-for-byte) and is
 * split across two phases to preserve it:
 *   prevalidate  → dup-control-header, X-Mq-Auth (missing/format)
 *   [adapter parses the fetch envelope: X-Mq-Target/Method]
 *   req_begin    → X-Mq-Origin-Protocol, X-Mq-Cache, header-size, tunnel liveness
 */

/* Phase 1 of intake: header-only checks that, in the CURRENT code, run BEFORE the fetch
 * envelope's target/method parse — duplicate-control-header, then X-Mq-Auth format.
 * Returns MQ_GW_OK or the reject reason (+ *status). The adapter calls this FIRST so
 * observable reject ORDER is preserved: dup -> auth -> [adapter parses target/method] ->
 * req_begin. */
mq_gw_reject_reason_t mq_gw_client_prevalidate(mq_gw_client_t *c,
                                               const mq_h3_header_t *headers, size_t n,
                                               int *status);

/* Phase 2: begin a request (head already split + prevalidated). On acceptance returns the
 * handle. On rejection returns NULL and sets *err_status AND *reason. Core checks here IN
 * ORDER: X-Mq-Origin-Protocol(400), X-Mq-Cache(400), header-size(400), tunnel
 * liveness(502). */
mq_gw_xreq_t *mq_gw_client_req_begin(mq_gw_client_t *c, const mq_gw_req_head_t *head,
                                     const mq_gw_sink_ops_t *sink, void *sink_user,
                                     int *err_status, mq_gw_reject_reason_t *reason);
/* Return the RAW shared token stored at construction (the value EXPECTED in
 * X-Mq-Auth, WITHOUT the "Bearer " prefix). Borrowed, NUL-terminated, valid for
 * the client's lifetime. Used by the H2 MITM adapter's production submit vtable
 * (mq_gw_h2_submit_ops_gwc) to inject "Bearer <token>" on demuxed requests.
 * Safe on NULL (returns NULL). */
const char *mq_gw_client_token(const mq_gw_client_t *c);

int mq_gw_client_req_body(mq_gw_xreq_t *r, const uint8_t *p,
                          size_t len); /* 0 go, -1 pause (consumed) */
void mq_gw_client_req_body_done(mq_gw_xreq_t *r);
void mq_gw_client_req_aborted(mq_gw_xreq_t *r);
void mq_gw_client_req_drained(
    mq_gw_xreq_t *r); /* adapter output drained below low watermark */

#endif /* MQ_GATEWAY_MQ_GW_CLIENT_H */
