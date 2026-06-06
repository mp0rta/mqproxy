// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_session.h — server-side UDP relay session table + OPEN handling.
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

#include "transport/mq_conn.h"
#include "transport/mq_stream.h"

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

#endif /* MQ_PROXY_MQ_UDP_SESSION_H */
