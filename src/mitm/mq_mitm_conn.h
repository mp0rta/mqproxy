// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_conn — Phase 7 Slice 3 LIVE per-connection MITM orchestrator.
//
// Installed as the tproxy/redirect open_fn under --mitm. For each captured TCP
// connection it:
//   1. DRAINS the (attacker-controlled) leading bytes off local_fd into a
//      bounded 8 KiB buffer, parsing them as a TLS ClientHello (mq_clienthello),
//      under a complete-ClientHello deadline timer (MQ_MITM_CH_DEADLINE_SEC).
//      Any non-TLS / malformed / no-SNI / deadline-exceeded input HARD-FAILS
//      (close the fd, no data forwarded) — this is the security boundary for
//      pre-handshake bytes.
//   2. NORMALIZES the SNI (mq_mitm_normalize_sni) and asks mq_ignore_hosts:
//        - HIT  → OPAQUE: replay the drained buffer (as prebuf) to the existing
//                 opaque entry (mq_client flow→MPQUIC), forwarding the ORIGINAL
//                 recovered orig-dst params UNCHANGED (host/atype/port). The SNI
//                 is NEVER substituted as the host.
//        - MISS → MITM: terminate TLS with a forged per-SNI leaf and bridge H2
//                 onto the gateway tunnel (Task 11 — currently a stub seam).
//
// fd OWNERSHIP: once mq_mitm_conn_open is invoked the orchestrator OWNS local_fd
// (tproxy contract). On the opaque path it transfers fd ownership to the opaque
// entry; on hard-fail it closes the fd; on the MITM path it retains it (Task 11).
//
// THREADING: single-threaded libevent data plane (1 client/process). All state
// is touched only from the event base's thread.
#ifndef MQ_MITM_CONN_H
#define MQ_MITM_CONN_H

#include <stddef.h>
#include <stdint.h>

#include "ingress/mq_ingress.h" /* mq_tcp_open_fn / mq_tcp_open_cb */
#include "mitm/mq_ignore_hosts.h"
#include "mitm/mq_mitm_core.h"
#include "wire/mq_wire.h" /* mq_addr_type_t */

struct event_base;
struct mq_gw_client_s;

typedef struct mq_mitm_ctx mq_mitm_ctx_t;

// Create the orchestrator context.
//   core        : MITM crypto core (CA + per-SNI leaf forge). BORROWED.
//   ign         : ignore-hosts list (opaque routing). BORROWED; may be NULL
//                 (then nothing is opaque — every TLS flow is MITM'd).
//   gwc         : gateway client tunnel for the MITM (H2→tunnel) path. BORROWED;
//                 consumed by Task 11.
//   opaque_open : the existing tproxy/relay entry (mq_client's mq_tcp_open_fn)
//                 used to splice ignore-hosts flows through untouched.
//   opaque_core : the void* core that opaque_open expects (mq_client).
//   base        : libevent base for the drain EV_READ + deadline timer. BORROWED.
// Returns NULL on bad args (base/opaque_open NULL) or OOM.
mq_mitm_ctx_t *mq_mitm_ctx_new(mq_mitm_core_t *core, mq_ignore_hosts_t *ign,
                               struct mq_gw_client_s *gwc, mq_tcp_open_fn opaque_open,
                               void *opaque_core, struct event_base *base);

// Tear down: drain the live-conn registry first (§5.1 — closes any conns still
// in the drain phase, freeing their events/timers/fds), then free ctx. Safe on
// NULL. Does NOT free core/ign/gwc/opaque_core (all BORROWED).
void mq_mitm_ctx_free(mq_mitm_ctx_t *ctx);

// mq_tcp_open_fn — invoked by the tproxy listener for each accepted fd. `ctx` is
// an mq_mitm_ctx_t*. prebuf is NULL/0 from tproxy (ClientHello still on the
// socket); the orchestrator drains it off local_fd itself. host/host_len/atype/
// port are the RECOVERED ORIGINAL destination and are forwarded UNCHANGED on the
// opaque path. cb is the listener's open-result callback (no-op for tproxy).
void mq_mitm_conn_open(void *ctx, const uint8_t *host, size_t host_len,
                       mq_addr_type_t atype, uint16_t port, int local_fd,
                       const uint8_t *prebuf, size_t prebuf_len, void *user,
                       mq_tcp_open_cb cb);

// ── Test seam (Task 4) ─────────────────────────────────────────────────────
// The decision logic is factored out of the libevent I/O so it can be unit
// tested without sockets/TLS. Given a ctx + a fully-drained ClientHello buffer +
// the original orig-dst params, decide opaque-vs-MITM and dispatch. Returns the
// branch taken (for tests). The buffer is borrowed.
//
// The MITM branch is reached via an injectable hook (mq_mitm_ctx_set_mitm_hook):
// in production it is the real handshake (Task 11); in tests it captures that the
// MITM branch was selected. When no hook is set the production stub runs.
typedef enum {
    MQ_MITM_ROUTE_OPAQUE = 0, // ignore-hosts hit → opaque entry
    MQ_MITM_ROUTE_MITM = 1,   // miss → terminate + forge (Task 11)
    MQ_MITM_ROUTE_FAIL = -1   // no/invalid SNI → hard-fail (caller closes fd)
} mq_mitm_route_t;

// Test-only MITM-start hook: invoked instead of the production mitm_start() body
// when the route is MITM, so a unit test can observe branch selection without the
// real TLS handshake. NULL restores the production path. The conn is identified
// by its local_fd + drained-buffer pointer (passed through `user`).
void mq_mitm_ctx_set_mitm_hook_for_test(mq_mitm_ctx_t *ctx,
                                        void (*hook)(void *hook_user, int local_fd,
                                                     const uint8_t *buf, size_t len,
                                                     const char *normalized_sni),
                                        void *hook_user);

#endif // MQ_MITM_CONN_H
