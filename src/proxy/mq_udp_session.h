// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_session.h — server-side UDP relay session table + OPEN handling;
 * the client role (mq_udp_cli_*, Task 6.2) lives in the same module.
 *
 * One mq_udp_srv_t is owned per accepted mqproxy connection (created in
 * mq_server's on_new_conn, freed in the conn-close teardown). It owns:
 *   - the session table (session_id → connected UDP socket + idle timer +
 *     defrag + per-session bookkeeping), capped at MQ_UDP_SRV_MAX_SESSIONS.
 *   - the per-session lifecycle: an 0x02 stream's OPEN is decoded, the target
 *     resolved (blocking getaddrinfo, SOCK_DGRAM), a connected UDP socket dialed,
 *     and a UDP_SESSION_RESP sent. The 0x02 stream stays open as the session's
 *     control handle — its close (client-initiated), an idle-timer expiry, or
 *     the conn closing all tear the session down (fd close + event free + defrag
 *     free), each path reaping exactly once.
 *
 * The datagram relay paths are fully delivered: mq_udp_srv_on_datagram provides
 * conn-level datagram dispatch with an auth gate (drops silently before
 * mq_udp_srv_set_authed), tunnel→target defrag+send, and a pre-OPEN buffer
 * (16 entries / 32 KiB per conn, 250 ms TTL) that buffers datagrams arriving
 * before the OPEN completes and flushes them at session creation.  The UDP
 * socket's EV_READ drives the target→tunnel path: split+send back to the
 * tunnel.  §9.2 drop/activity counters are maintained throughout; stats are
 * dumped to the log at conn close via mq_udp_srv_dump_stats.
 */
#ifndef MQ_PROXY_MQ_UDP_SESSION_H
#define MQ_PROXY_MQ_UDP_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include <event2/event.h>

#include "ingress/mq_ingress.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "wire/mq_wire.h"

/* Session table cap (design §6): small enough that a linear array + free list
 * beats a hash table (YAGNI). OPEN beyond the cap is rejected with
 * MQ_UDP_SESSION_LIMIT. */
#define MQ_UDP_SRV_MAX_SESSIONS 1024

typedef struct mq_udp_srv mq_udp_srv_t; /* per-connection (mq_srv_conn_t owns) */

/* Create the per-connection UDP relay state. `c` is the owning mqproxy conn,
 * `base` the libevent base for UDP-socket events + idle timers, idle_timeout_ms
 * the server's configured idle timeout (the per-session effective value is
 * min(client requested, this)), and `enabled` mirrors !--no-udp (when 0 every
 * OPEN is answered MQ_UDP_POLICY_DENIED). Returns NULL on OOM. */
mq_udp_srv_t *mq_udp_srv_new(mq_conn_t *c, struct event_base *base,
                             uint64_t idle_timeout_ms, int enabled);

/* Free all sessions (fd close + event free + defrag free) + pre-OPEN buffers,
 * then the struct. Safe on NULL. */
void mq_udp_srv_free(mq_udp_srv_t *u);

/* Attach a freshly-accepted 0x02 (UDP_SESSION) stream: buffer + decode OPEN,
 * resolve + dial the target, send UDP_SESSION_RESP, and either keep the stream
 * as a live session's control handle or reset it on error / duplicate SID.
 *
 * `carry` / `carry_len` are bytes the server's stream-type dispatch already
 * pulled off the stream that follow the 0x02 discriminator (the OPEN frame body
 * arrives in the same send as the discriminator — see mq_client — so the
 * dispatch's mq_framebuf_fill drains them out of the stream). They are seeded
 * into this module's OPEN framebuf so a single-send OPEN is not stalled. Pass
 * carry=NULL/carry_len=0 if nothing trailed the discriminator. */
void mq_udp_srv_attach_stream(mq_udp_srv_t *u, mq_stream_t *s, const uint8_t *carry,
                              size_t carry_len);

/* Connection-level datagram dispatch (from mq_server's on_datagram callback).
 * Routes tunnel→target: decode header → session lookup → defrag → send to UDP
 * socket; or pre-OPEN buffer on session-miss. Drops silently before auth
 * (`mq_udp_srv_set_authed` has not been called) or when UDP is disabled. */
void mq_udp_srv_on_datagram(mq_udp_srv_t *u, const uint8_t *data, size_t len);

/* Mark this connection as authenticated.  Call from the server's auth-success
 * path so the datagram entry path opens the auth gate.  Thread-safe note: both
 * the auth path and the datagram callback run on the same libevent loop —
 * no mutex needed. */
void mq_udp_srv_set_authed(mq_udp_srv_t *u, int authed);

/* Dump per-connection UDP relay stats to the log (INFO level).  Called once
 * from mq_udp_srv_free before teardown so the stats appear in the server log
 * that e2e captures. */
void mq_udp_srv_dump_stats(mq_udp_srv_t *u);

/* ── Observability: drop / activity counters (design §9.2) ───────────────────
 *
 * A by-value snapshot of the per-connection UDP relay counters. These mirror
 * the fields dumped by mq_udp_srv_dump_stats and are exposed for programmatic
 * observation (in-process integration tests, future metrics export) without
 * scraping the log line. Read on the libevent loop thread; no synchronisation
 * needed (single-threaded relay). */
typedef struct {
    uint32_t frags_sent;        /* frags emitted from multi-frag splits only */
    uint32_t frags_reassembled; /* completed multi-frag reassemblies */
    uint32_t drops_send_fail;   /* datagram_send -1, or split/socket send failed */
    uint32_t drops_oversize;    /* recv'd UDP payload too large to split (>255 frags) */
    uint32_t defrag_drops;      /* mq_defrag_feed returned -1 */
    uint32_t preopen_evictions; /* pre-OPEN buffer evictions (cap or byte overflow) */
    uint32_t drops_preauth;     /* datagrams dropped because !authed or !enabled */
} mq_udp_srv_counters_t;

/* Snapshot the current counters by value. Returns a zeroed struct if u is NULL. */
mq_udp_srv_counters_t mq_udp_srv_counters(const mq_udp_srv_t *u);

/* ═══════════════════════════════════════════════════════════════════════════
 *  client role  (mq_udp_cli_*)  — Task 6.2
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * One mq_udp_cli_t is owned per client mq_conn (created/owned by mq_client).
 * It is the proxy-core implementation behind the mq_udp_open_fn boundary
 * (mq_ingress.h): the ingress (mq_udp_assoc) opens UDP relay sessions through
 * it without touching xquic.
 *
 * Per-session lifecycle (mirrors the server role's table/mss-cache/defrag/
 * reap-once patterns):
 *   - open  = allocate a session (local, synchronous; NULL on cap / pre-auth
 *             queue full).  When authed it issues a 0x02 stream and sends OPEN
 *             optimistically (the user may send() immediately, before RESP).
 *             Pre-auth opens hold the session and defer stream issuance until
 *             auth succeeds (a small per-session send queue buffers payloads).
 *   - send  = cached mss → split → datagram_send (drop + counter on failure).
 *   - rx    = conn-level datagram dispatch → sid lookup → defrag → on_rx.
 *   - err   = remote-caused failure/termination → on_err (at most once) then
 *             the session is destroyed by the core.  err value: a decoded RESP
 *             error carries the wire code (1-4); idle timeout / normal stream
 *             close / conn close carry MQ_UDP_CLOSED (the assoc negative-cache
 *             decision in Task 6.3 keys off this distinction).  Auth failure is
 *             a policy-level denial → MQ_UDP_POLICY_DENIED.
 *
 * The negative cache is NOT held here (it is owned by the assoc's DST entry —
 * Task 6.3). 1024-session cap (open returns NULL beyond). */

typedef struct mq_udp_cli mq_udp_cli_t; /* per-connection (mq_client owns) */

/* Create the per-connection client UDP relay state. `c` is the client mqproxy
 * conn (must outlive the cli), `base` the libevent base. authed/available start
 * unset; mq_client drives them via the setters below. Returns NULL on OOM. */
mq_udp_cli_t *mq_udp_cli_new(mq_conn_t *c, struct event_base *base);

/* Free all sessions (on_err is NOT fired — this is core teardown, not a remote
 * failure; the owner is going away) and the struct. Safe on NULL. */
void mq_udp_cli_free(mq_udp_cli_t *u);

/* Open a UDP relay session (the mq_udp_open_fn boundary). See mq_ingress.h for
 * the full contract. Returns an opaque session handle, or NULL on immediate
 * failure (1024-session cap / pre-auth queue full / OOM). */
void *mq_udp_cli_open(void *core, const uint8_t *host, size_t host_len,
                      mq_addr_type_t atype, uint16_t port, mq_udp_rx_fn on_rx,
                      mq_udp_err_fn on_err, void *user);

/* Send one UDP payload on a session (the mq_udp_send_fn boundary). Split into
 * datagram frames per the cached mss; drops + counts on failure (UDP
 * semantics). Pre-stream-issuance (pre-auth) sends are buffered in a small
 * per-session queue (8 datagrams / 8 KiB) and flushed when the stream issues. */
void mq_udp_cli_send(void *session, const uint8_t *payload, size_t len);

/* Caller-initiated close of a session (the mq_udp_close_fn boundary). Detaches
 * callbacks synchronously (no further on_rx/on_err) and destroys the session. */
void mq_udp_cli_close(void *session);

/* Connection-level datagram dispatch (from mq_client's on_datagram callback).
 * Routes server→tunnel: decode header → session lookup → defrag → on_rx.
 * Unknown sid → silent drop (no client-side pre-OPEN buffer; design §6.2). */
void mq_udp_cli_on_datagram(mq_udp_cli_t *u, const uint8_t *data, size_t len);

/* Auth outcome glue (called by mq_client once AUTH_RESPONSE is known):
 *   ok!=0, available!=0 → drain pending sessions: issue 0x02 stream + OPEN, then
 *                         flush each session's buffered sends.
 *   ok!=0, available==0 → capability denied: fail all pending sessions with
 *                         on_err(MQ_UDP_POLICY_DENIED) and destroy them.
 *   ok==0               → auth failure: fail all pending with
 *                         on_err(MQ_UDP_POLICY_DENIED) and destroy them.
 * `available` reflects mq_client_udp_available()==1. Idempotent (settles once).*/
void mq_udp_cli_on_auth(mq_udp_cli_t *u, int ok, int available);

/* Conn-close glue (called by mq_client on MQ_CONN_CLOSED): fail every live and
 * pending session with on_err(MQ_UDP_CLOSED) and destroy them. After this the
 * cli holds no sessions; the conn pointer must not be used again. */
void mq_udp_cli_on_conn_close(mq_udp_cli_t *u);

#endif /* MQ_PROXY_MQ_UDP_SESSION_H */
