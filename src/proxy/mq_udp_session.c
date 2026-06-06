// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_session.c — server-side UDP relay session table + OPEN handling.
 *
 * See mq_udp_session.h for the ownership / lifecycle contract.
 *
 * Task 5.1 delivered: session table, OPEN decode → resolve → dial → RESP, the
 * 0x02 stream lifecycle (stream-close ⇒ session teardown), the per-session idle
 * timer, and the three-way reap (stream close / idle expiry / conn close)
 * guarded so each session's fd / event / defrag are freed exactly once.
 *
 * Task 5.2 (this file): datagram relay paths (tunnel→target and
 * target→tunnel), pre-OPEN buffer, auth gate, MSS cache, drop counters, and
 * stats dump.
 *
 * ── MSS cache policy ────────────────────────────────────────────────────────
 * mq_conn_datagram_mss() does a calloc/free (xqc_conn_get_stats) per call, so
 * we MUST NOT call it per datagram or per frag emit.  We cache the mss on
 * mq_udp_srv (conn-level, not per session — one value per QUIC connection).
 * Cache refresh policy (cached_mss == 0 OR refresh_counter == 0):
 *   - initialised to 0 (unknown).
 *   - refreshed when: cached_mss == 0 (never fetched yet), or after each
 *     MQ_MSS_REFRESH_INTERVAL emits (64 emits), to pick up path changes.
 *   - if the refreshed value is still 0 (peer unsupported / conn gone) the
 *     datagram or split is skipped and drops_send_fail is incremented.
 *
 * ── frag counter semantics ──────────────────────────────────────────────────
 * frags_sent:        incremented by the number of frags emitted ONLY when
 *                    split produced >1 frag (frag_count>1).  Single-frag
 *                    passthrough does NOT count.  Proves the multi-frag emit
 *                    path ran.
 * frags_reassembled: incremented once per COMPLETED reassembly whose
 *                    frag_count>1 (i.e. a multi-frag packet was fully
 *                    reassembled from defrag).  Single-frag feed that returns 1
 *                    does NOT count.  Proves the defrag path ran end-to-end.
 *
 * ── pre-OPEN buffer ─────────────────────────────────────────────────────────
 * When a datagram arrives for a session_id that has no live session yet (the
 * OPEN is still in flight), we buffer the FULL datagram bytes (including the
 * 9-byte header) so flush can re-run the identical decode→defrag path.  Caps:
 * 16 entries AND 32 KiB total payload per connection.  Eviction: oldest first
 * (FIFO ring; preopen_evictions++).  TTL: 250 ms, swept lazily on each new
 * arrival and at flush time.
 *
 * ── target→tunnel recv loop ─────────────────────────────────────────────────
 * recv into a 65535-byte heap buffer; loop until EAGAIN, bounded to 16 packets
 * per wakeup.  Persistent EV_READ re-fires for leftovers.  Per-emit assembly
 * uses one scratch buffer (9 + 65535 = 65544 bytes) allocated once on
 * mq_udp_srv (NOT per packet, NOT on stack) to avoid per-frag heap churn.
 */
#include "proxy/mq_udp_session.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_defrag.h"
#include "proxy/mq_framebuf.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "util/mq_log.h"
#include "wire/mq_udp_msg.h"
#include "wire/mq_wire.h"

/* ── constants ─────────────────────────────────────────────────────────────── */

/* pre-OPEN buffer caps per connection */
#define MQ_PREOPEN_MAX_ENTRIES 16
#define MQ_PREOPEN_MAX_BYTES   (32 * 1024)
/* TTL for pre-OPEN entries in milliseconds */
#define MQ_PREOPEN_TTL_MS 250

/* recv loop: max packets per EV_READ wakeup */
#define MQ_UDP_RECV_LOOP_MAX 16

/* MSS cache refresh interval in emit-count units (carries per direction count) */
#define MQ_MSS_REFRESH_INTERVAL 64

/* ── monotonic milliseconds (local helper) ──────────────────────────────────
 *
 * No exported helper exists in this codebase for CLOCK_MONOTONIC-based ms.
 * Note: the transport layer uses gettimeofday for xquic timers (see
 * mq_transport.c comment) — that constraint only applies to xquic callbacks.
 * For our TTL/idle purposes CLOCK_MONOTONIC is correct and preferred. */
static uint64_t
srv_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* ── pre-OPEN buffer entry ──────────────────────────────────────────────────
 *
 * Stores the FULL datagram bytes (including 9-byte header) so flush re-runs
 * the identical decode→defrag path as a live hit. */
typedef struct {
    uint8_t *data;       /* malloc'd copy of full datagram (hdr + payload) */
    size_t len;          /* length of data */
    uint32_t session_id; /* decoded from the stored header (for sid-match lookup) */
    uint64_t arrived_ms; /* srv_mono_ms() at insertion time (for TTL) */
} mq_preopen_entry_t;

/* Fixed-array FIFO ring of MQ_PREOPEN_MAX_ENTRIES entries.  head is the
 * oldest entry index, count is the number of live entries.  Eviction removes
 * the entry at head (FIFO oldest-first). */
typedef struct {
    mq_preopen_entry_t entries[MQ_PREOPEN_MAX_ENTRIES];
    size_t head;        /* index of oldest entry */
    size_t count;       /* number of live entries (0..MQ_PREOPEN_MAX_ENTRIES) */
    size_t total_bytes; /* sum of all live entry data lengths */
} mq_preopen_buf_t;

/* ── per-session state ─────────────────────────────────────────────────────
 *
 * Lives in the parent's `sessions` array; `used` marks a slot live.
 * The 0x02 stream is the session's control handle: its close (or the conn
 * close, or an idle expiry) tears the session down. */
typedef struct {
    int used;
    uint32_t session_id;
    mq_stream_t *stream;     /* 0x02 control stream (NULL after close-notify) */
    int fd;                  /* connected UDP socket */
    struct event *rd_ev;     /* persistent EV_READ on fd */
    struct event *idle_ev;   /* idle evtimer (re-armed on bidirectional activity) */
    mq_defrag_t *defrag;     /* lazy: allocated on first fragmented inbound packet */
    uint16_t next_packet_id; /* server→client packet_id counter */
    int reaped;              /* reap-once guard (Known risk 7) */
    int graceful;            /* an arm-failure RESP(ERROR) was sent with FIN:
                              * reap must NOT RESET (RESET drops the un-acked RESP) */
    mq_udp_srv_t *owner;     /* back-pointer for callbacks */
} mq_udp_sess_t;

/* ── mq_udp_srv: per-connection UDP relay state ─────────────────────────── */

struct mq_udp_srv {
    mq_conn_t *conn;
    struct event_base *base;
    uint64_t idle_timeout_ms; /* server-configured idle timeout */
    int enabled;              /* mirrors !--no-udp */
    int authed;               /* set by mq_udp_srv_set_authed on auth success */

    /* Session table */
    mq_udp_sess_t sessions[MQ_UDP_SRV_MAX_SESSIONS];
    size_t live_count;

    /* Pre-OPEN buffer (one per conn, shared across all session_ids) */
    mq_preopen_buf_t preopen;

    /* MSS cache (conn-level; see file header for policy).
     * cached_mss: last fetched value from mq_conn_datagram_mss(); 0 = unknown.
     * mss_emit_countdown: counts down from MQ_MSS_REFRESH_INTERVAL; when it
     *   reaches 0 the cache is refreshed before the next emit.  Initialised to
     *   0 so the first emit always fetches. */
    size_t cached_mss;
    unsigned mss_emit_countdown;

    /* Per-conn scratch buffers (allocated once, reused per operation):
     *   recv_buf:    65535-byte buffer for recvfrom()
     *   emit_buf:    9+65535 bytes for assembling hdr+slice before datagram_send
     * Both allocated in mq_udp_srv_new; freed in mq_udp_srv_free. */
    uint8_t *recv_buf; /* 65535 bytes */
    uint8_t *emit_buf; /* MQ_UDP_MSG_HDR + 65535 bytes */

    /* Drop / activity counters (uint32_t, %u, design §9.2) */
    uint32_t drops_send_fail;   /* datagram_send returned -1, or split failed */
    uint32_t drops_oversize;    /* recv'd UDP payload > mss - MQ_UDP_MSG_HDR */
    uint32_t defrag_drops;      /* mq_defrag_feed returned -1 */
    uint32_t preopen_evictions; /* pre-OPEN buffer evictions (cap or byte overflow) */
    uint32_t drops_preauth;     /* datagrams dropped because !authed or !enabled */

    /* Observation counters (prove the frag path ran; see file header) */
    uint32_t frags_sent;        /* frags emitted from multi-frag splits only */
    uint32_t frags_reassembled; /* completed multi-frag reassemblies */
};

/* ── helpers ─────────────────────────────────────────────────────────────── */

static mq_udp_sess_t *
srv_find_session(mq_udp_srv_t *u, uint32_t sid)
{
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (u->sessions[i].used && u->sessions[i].session_id == sid) {
            return &u->sessions[i];
        }
    }
    return NULL;
}

static mq_udp_sess_t *
srv_alloc_session(mq_udp_srv_t *u)
{
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (!u->sessions[i].used) {
            return &u->sessions[i];
        }
    }
    return NULL;
}

/* Re-arm the session's idle timer.  Must be called on every bidirectional
 * activity (defrag-complete send AND target recv).  The timer is edge-triggered
 * (one-shot), so evtimer_add every time. */
static void
srv_idle_rearm(mq_udp_sess_t *sess)
{
    if (!sess->idle_ev) {
        return;
    }
    mq_udp_srv_t *u = sess->owner;
    struct timeval tv;
    tv.tv_sec = (time_t)(u->idle_timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((u->idle_timeout_ms % 1000) * 1000);
    /* evtimer_add on an already-pending timer re-arms it (libevent docs:
     * adding a pending event re-schedules it). */
    evtimer_add(sess->idle_ev, &tv);
}

/* ── MSS cache ──────────────────────────────────────────────────────────────
 *
 * Returns 0 if mss is not usable (peer unsupported / conn gone).  Otherwise
 * returns the payload bytes available per datagram frame (mss - MQ_UDP_MSG_HDR).
 * Updates u->cached_mss and u->mss_emit_countdown. */
static size_t
srv_get_mss_payload(mq_udp_srv_t *u)
{
    /* Refresh when cache is empty OR countdown expired */
    if (u->cached_mss == 0 || u->mss_emit_countdown == 0) {
        u->cached_mss = mq_conn_datagram_mss(u->conn);
        u->mss_emit_countdown = MQ_MSS_REFRESH_INTERVAL;
    }
    if (u->cached_mss <= MQ_UDP_MSG_HDR) {
        return 0; /* not usable */
    }
    return u->cached_mss - MQ_UDP_MSG_HDR;
}

/* ── pre-OPEN buffer operations ─────────────────────────────────────────── */

/* Sweep and drop entries older than MQ_PREOPEN_TTL_MS.  Called lazily on each
 * new arrival and at flush time (no timer needed — design §6.2). */
static void
srv_preopen_sweep_ttl(mq_preopen_buf_t *pb, uint64_t now_ms)
{
    while (pb->count > 0) {
        mq_preopen_entry_t *oldest = &pb->entries[pb->head];
        if (now_ms - oldest->arrived_ms <= MQ_PREOPEN_TTL_MS) {
            break; /* remaining entries are newer — FIFO order guarantees this */
        }
        free(oldest->data);
        oldest->data = NULL;
        pb->total_bytes -= oldest->len;
        pb->head = (pb->head + 1) % MQ_PREOPEN_MAX_ENTRIES;
        pb->count--;
    }
}

/* Insert a new pre-OPEN entry.  Evicts oldest if either cap is exceeded.
 * data/len are the FULL datagram bytes to copy.  session_id and arrived_ms
 * are pre-decoded/stamped by the caller. */
static void
srv_preopen_insert(mq_udp_srv_t *u, uint32_t sid, const uint8_t *data, size_t len,
                   uint64_t now_ms)
{
    mq_preopen_buf_t *pb = &u->preopen;

    /* Evict oldest entries until both caps are satisfied AFTER insertion. */
    while (pb->count > 0 && (pb->count >= MQ_PREOPEN_MAX_ENTRIES ||
                             pb->total_bytes + len > MQ_PREOPEN_MAX_BYTES)) {
        mq_preopen_entry_t *oldest = &pb->entries[pb->head];
        free(oldest->data);
        oldest->data = NULL;
        pb->total_bytes -= oldest->len;
        pb->head = (pb->head + 1) % MQ_PREOPEN_MAX_ENTRIES;
        pb->count--;
        u->preopen_evictions++;
    }

    /* Allocate and copy. */
    uint8_t *copy = malloc(len);
    if (!copy) {
        /* OOM: treat as eviction drop (silently skip insertion). */
        u->preopen_evictions++;
        return;
    }
    memcpy(copy, data, len);

    size_t slot = (pb->head + pb->count) % MQ_PREOPEN_MAX_ENTRIES;
    pb->entries[slot].data = copy;
    pb->entries[slot].len = len;
    pb->entries[slot].session_id = sid;
    pb->entries[slot].arrived_ms = now_ms;
    pb->total_bytes += len;
    pb->count++;
}

/* Free all entries in the pre-OPEN buffer (used at teardown). */
static void
srv_preopen_free_all(mq_preopen_buf_t *pb)
{
    for (size_t i = 0; i < MQ_PREOPEN_MAX_ENTRIES; i++) {
        if (pb->entries[i].data) {
            free(pb->entries[i].data);
            pb->entries[i].data = NULL;
        }
    }
    pb->head = 0;
    pb->count = 0;
    pb->total_bytes = 0;
}

/* ── defrag + send: shared by live-hit path and flush path ─────────────────
 *
 * Feeds one complete datagram (hdr + payload already decoded into hdr/payload/
 * plen) through defrag.  On reassembly completion, sends the reassembled UDP
 * packet to the session's fd.  Re-arms the idle timer on success. */
static void
srv_defrag_and_send(mq_udp_srv_t *u, mq_udp_sess_t *sess, const mq_udp_msg_hdr_t *hdr,
                    const uint8_t *payload, size_t plen)
{
    /* Lazy defrag allocation. */
    if (!sess->defrag) {
        sess->defrag = mq_defrag_new();
        if (!sess->defrag) {
            u->drops_send_fail++;
            return;
        }
    }

    uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = mq_defrag_feed(sess->defrag, hdr, payload, plen, &out, &out_len);

    if (rc < 0) {
        u->defrag_drops++;
        return;
    }
    if (rc == 0) {
        return; /* fragment accepted, packet not yet complete */
    }

    /* rc == 1: packet complete — out is malloc'd, caller must free. */

    /* Count completed multi-frag reassemblies (proves the defrag path ran). */
    if (hdr->frag_count > 1) {
        u->frags_reassembled++;
    }

    /* Send to target UDP socket. */
    ssize_t sent = send(sess->fd, out, out_len, 0);
    free(out);
    if (sent < 0) {
        u->drops_send_fail++;
        return;
    }

    /* Activity: re-arm idle timer. */
    srv_idle_rearm(sess);
}

/* ── pre-OPEN flush ─────────────────────────────────────────────────────── */

/* Called when a session transitions to OPEN-complete (see Task 5.1 flow).
 * Walks the pre-OPEN buffer for matching sid, applies TTL filter (250ms),
 * feeds live entries through the same decode→defrag path, then removes them
 * from the buffer. */
static void
srv_preopen_flush(mq_udp_srv_t *u, mq_udp_sess_t *sess)
{
    mq_preopen_buf_t *pb = &u->preopen;
    uint64_t now_ms = srv_mono_ms();

    /* Walk all live entries in FIFO order (head … head+count-1 mod MAX). */
    size_t i = 0;
    size_t remaining = pb->count;
    size_t new_head = pb->head;
    size_t new_count = 0;

    /* We compact the ring in place: entries we keep are shifted to the front. */
    mq_preopen_entry_t kept[MQ_PREOPEN_MAX_ENTRIES];
    size_t kept_count = 0;
    size_t kept_bytes = 0;

    for (i = 0; i < remaining; i++) {
        size_t idx = (pb->head + i) % MQ_PREOPEN_MAX_ENTRIES;
        mq_preopen_entry_t *e = &pb->entries[idx];

        if (e->session_id == sess->session_id) {
            /* Apply TTL filter before feeding. */
            if (now_ms - e->arrived_ms <= MQ_PREOPEN_TTL_MS) {
                /* Decode and feed. */
                mq_udp_msg_hdr_t hdr;
                if (e->len >= MQ_UDP_MSG_HDR &&
                    mq_udp_msg_decode_hdr(e->data, e->len, &hdr) == 0) {
                    const uint8_t *payload = e->data + MQ_UDP_MSG_HDR;
                    size_t plen = e->len - MQ_UDP_MSG_HDR;
                    srv_defrag_and_send(u, sess, &hdr, payload, plen);
                }
            }
            free(e->data);
            e->data = NULL;
            /* do not keep */
        } else {
            /* Keep this entry (different sid). */
            kept[kept_count] = *e;
            kept_count++;
            kept_bytes += e->len;
        }
    }

    /* Rebuild the ring from the kept entries. */
    for (i = 0; i < kept_count; i++) {
        pb->entries[i] = kept[i];
    }
    pb->head = 0;
    pb->count = kept_count;
    pb->total_bytes = kept_bytes;

    (void)new_head;
    (void)new_count;
}

/* ── Send a UDP_SESSION_RESP on the OPEN stream ─────────────────────────── */

/* Send a UDP_SESSION_RESP on the OPEN stream. On the error path the codec maps
 * MQ_STATUS_ERROR ⇔ codes 1-4; OK ⇔ MQ_UDP_OK. message is empty.
 *
 * fin selects the close semantics, mirroring mq_server.c srv_send_tcp_resp:
 *   fin=0 — success: keep the stream open as the session control handle.
 *   fin=1 — error: close the send direction so the RESP is the stream's final
 *           frame. The caller MUST NOT mq_stream_close() afterwards: a RESET
 *           (xqc_stream_close → xqc_send_queue_drop_stream_frame_packets) would
 *           DROP the not-yet-flushed RESP (engine flush is deferred inside a read
 *           callback), so the client would see only RESET, never the error code.
 *           The FIN terminates the stream; the peer's close completes teardown. */
static void
srv_send_udp_resp(mq_stream_t *s, mq_status_t status, mq_udp_err_t err,
                  uint64_t idle_timeout_ms, int fin)
{
    mq_udp_session_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.error_code = err;
    resp.message[0] = '\0';
    resp.message_len = 0;
    resp.idle_timeout_ms = idle_timeout_ms;

    uint8_t buf[512];
    int n = mq_encode_udp_session_resp(buf, sizeof(buf), &resp);
    if (n < 0) {
        MQ_LOGE("mq_udp_srv: encode UDP_SESSION_RESP failed");
        return;
    }
    long sent = mq_stream_send(s, buf, (size_t)n, fin);
    if (sent < 0 || (size_t)sent != (size_t)n) {
        MQ_LOGW("mq_udp_srv: UDP_SESSION_RESP send short/failed (%ld of %d)", sent, n);
    }
}

/* ── target resolution ───────────────────────────────────────────────────── */

/* Resolve the OPEN target into a connected-able sockaddr (SOCK_DGRAM). Mirrors
 * mq_server.c srv_resolve_target but tailored to UDP: it requests
 * hints.ai_socktype = SOCK_DGRAM and returns mq_udp_err_t. A minimal copy is
 * cleaner than exporting the TCP static (which returns mq_tcp_err_t and would
 * force an error-type translation + a new shared header dependency). */
static int
srv_resolve_udp_target(const mq_udp_session_open_t *open, struct sockaddr_storage *ss,
                       socklen_t *sslen, mq_udp_err_t *err)
{
    memset(ss, 0, sizeof(*ss));
    if (open->address_type == MQ_ADDR_IPV4) {
        if (open->host_len != 4) {
            *err = MQ_UDP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, open->host, 4);
        sin->sin_port = htons(open->port);
        *sslen = sizeof(*sin);
        return 0;
    }
    if (open->address_type == MQ_ADDR_IPV6) {
        if (open->host_len != 16) {
            *err = MQ_UDP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, open->host, 16);
        sin6->sin6_port = htons(open->port);
        *sslen = sizeof(*sin6);
        return 0;
    }
    /* DOMAIN: BLOCKING getaddrinfo (accepted debt, design §2). */
    char hostz[MQ_MAX_HOST + 1];
    if (open->host_len > MQ_MAX_HOST) {
        *err = MQ_UDP_DNS_FAILED;
        return -1;
    }
    memcpy(hostz, open->host, open->host_len);
    hostz[open->host_len] = '\0';
    char portz[8];
    snprintf(portz, sizeof(portz), "%u", (unsigned)open->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(hostz, portz, &hints, &res);
    if (gai != 0 || !res) {
        if (res) freeaddrinfo(res);
        *err = MQ_UDP_DNS_FAILED;
        return -1;
    }
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *sslen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* ── session teardown (reap-once, three callers) ─────────────────────────── */

/* Known risk 7: stream-close (client-initiated), idle-timer expiry, and conn
 * close all free the same session. The `reaped` guard makes this idempotent;
 * fd / events / defrag are freed exactly once. The stream is RESET here ONLY
 * when it is still live AND the teardown did not originate from the stream's own
 * close-notify (which nulls sess->stream first) AND it is not a graceful
 * teardown (an error RESP was already FIN'd — a RESET would drop it), mirroring
 * mq_server's flow / srv_data_reap pattern. In every case the callbacks are
 * detached first so the eventual close-notify cannot touch the freed slot. */
static void
srv_reap_session(mq_udp_sess_t *sess)
{
    if (!sess || !sess->used || sess->reaped) {
        return;
    }
    sess->reaped = 1;

    if (sess->idle_ev) {
        event_free(sess->idle_ev);
        sess->idle_ev = NULL;
    }
    if (sess->rd_ev) {
        event_free(sess->rd_ev);
        sess->rd_ev = NULL;
    }
    if (sess->fd >= 0) {
        close(sess->fd);
        sess->fd = -1;
    }
    if (sess->defrag) {
        mq_defrag_free(sess->defrag);
        sess->defrag = NULL;
    }
    if (sess->stream) {
        /* Still live (teardown came from idle expiry or conn close, NOT the
         * stream's own close-notify). Drop our callbacks so the eventual
         * close-notify (from the FIN / peer close, or conn teardown) cannot fire
         * on the freed slot. On the graceful path an error RESP was already sent
         * with FIN — a RESET would drop it, so leave the close to the FIN / peer
         * (the transport frees the stream at conn teardown either way). */
        mq_stream_set_cbs(sess->stream, NULL, NULL, NULL, NULL);
        if (!sess->graceful) {
            mq_stream_close(sess->stream);
        }
        sess->stream = NULL;
    }

    mq_udp_srv_t *u = sess->owner;
    if (u && u->live_count > 0) {
        u->live_count--;
    }
    /* Clear the slot (used=0 frees it for reuse). */
    memset(sess, 0, sizeof(*sess));
    sess->fd = -1;
}

/* Idle timer expiry: tear the session down. */
static void
srv_idle_expired_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_udp_sess_t *sess = (mq_udp_sess_t *)arg;
    MQ_LOGI("mq_udp_srv: session %u idle-expired", sess->session_id);
    srv_reap_session(sess);
}

/* ── target→tunnel: EV_READ callback ────────────────────────────────────── */

/* emit callback for mq_udp_msg_split: assemble hdr-bytes + slice into
 * u->emit_buf and send as one datagram frame.  user is mq_udp_srv_t*. */
typedef struct {
    mq_udp_srv_t *u;
    uint32_t frag_count; /* frag_count of this split operation (from first emit) */
    uint32_t frags_ok;   /* number of frags successfully sent in this split */
} emit_ctx_t;

static void
srv_split_emit_cb(const mq_udp_msg_hdr_t *h, const uint8_t *p, size_t len, void *user)
{
    emit_ctx_t *ctx = (emit_ctx_t *)user;
    mq_udp_srv_t *u = ctx->u;

    /* Assemble: encode header into emit_buf, then copy slice payload. */
    if (mq_udp_msg_encode_hdr(u->emit_buf, h) != 0) {
        u->drops_send_fail++;
        return;
    }
    memcpy(u->emit_buf + MQ_UDP_MSG_HDR, p, len);

    int rc = mq_conn_datagram_send(u->conn, u->emit_buf, MQ_UDP_MSG_HDR + len);
    if (rc != 0) {
        u->drops_send_fail++;
        /* Absolute rule: do NOT abort remaining frags — continue (design §8). */
        return;
    }

    ctx->frags_ok++;
    /* Decrement MSS countdown on each successful emit. */
    if (u->mss_emit_countdown > 0) {
        u->mss_emit_countdown--;
    }
}

/* Persistent EV_READ on a session's UDP socket: recv target→tunnel. */
static void
srv_udp_readable_cb(evutil_socket_t evfd, short what, void *arg)
{
    (void)what;
    mq_udp_sess_t *sess = (mq_udp_sess_t *)arg;
    mq_udp_srv_t *u = sess->owner;

    /* Loop up to MQ_UDP_RECV_LOOP_MAX packets per wakeup; EV_PERSIST re-fires
     * for any left in the socket buffer. */
    for (int pkts = 0; pkts < MQ_UDP_RECV_LOOP_MAX; pkts++) {
        ssize_t n = recv(evfd, u->recv_buf, 65535, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* socket drained */
            }
            /* Other error: count and continue; EV_PERSIST will retry. */
            u->drops_send_fail++;
            break;
        }
        if (n == 0) {
            break;
        }

        size_t plen = (size_t)n;

        /* Get (possibly cached) MSS payload capacity. */
        size_t mss_payload = srv_get_mss_payload(u);
        if (mss_payload == 0) {
            u->drops_send_fail++;
            continue;
        }

        /* Reject oversize: plen must fit in one or more fragments but the frag
         * count is u8 (max 255).  mq_udp_msg_split will guard this too, but we
         * also apply the "mss <= MQ_UDP_MSG_HDR" check here: if plen alone >
         * mss - MQ_UDP_MSG_HDR per frag the packet cannot be split into ≤255
         * frags.  We delegate the 255-frag overflow to mq_udp_msg_split (-1) and
         * count that as drops_oversize. */
        emit_ctx_t ctx;
        ctx.u = u;
        ctx.frag_count = 0;
        ctx.frags_ok = 0;

        int split_rc =
            mq_udp_msg_split(sess->session_id, sess->next_packet_id, u->recv_buf, plen,
                             mss_payload, srv_split_emit_cb, &ctx);
        if (split_rc != 0) {
            u->drops_oversize++;
            continue;
        }

        sess->next_packet_id++;

        /* Count frags_sent for multi-frag splits only (proves the path ran). */
        if (ctx.frags_ok > 1) {
            u->frags_sent += ctx.frags_ok;
        }

        /* Activity: re-arm idle timer on successful send. */
        if (ctx.frags_ok > 0) {
            srv_idle_rearm(sess);
        }
    }
}

/* The 0x02 stream's close-notify: the client closed/reset the session control
 * stream. Null our pointer (the transport frees the stream after this returns)
 * and reap the session. */
static void
srv_stream_closed_cb(mq_stream_t *s, void *user)
{
    (void)s;
    mq_udp_sess_t *sess = (mq_udp_sess_t *)user;
    sess->stream = NULL; /* transport frees it after this returns */
    srv_reap_session(sess);
}

/* The 0x02 stream readable after RESP: drain to avoid stalling it. */
static void
srv_stream_readable_cb(mq_stream_t *s, void *user)
{
    (void)user;
    uint8_t scratch[256];
    int fin = 0;
    while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
}

/* ── OPEN handling ──────────────────────────────────────────────────────── */

/* The 0x02 stream's readable callback during the OPEN phase: accumulate +
 * decode UDP_SESSION_OPEN (after the already-consumed 0x02 discriminator),
 * then resolve → dial → RESP. The pending-open state lives in a transient
 * heap struct hung off the stream's user pointer until the session is created
 * (or the stream errors). */
typedef struct {
    mq_udp_srv_t *u;
    mq_stream_t *stream;
    mq_framebuf_t rx;
    int settled; /* OPEN processed: ignore further reads */
} mq_udp_open_t;

static void
srv_open_free(mq_udp_open_t *op)
{
    free(op);
}

/* Pending-open stream close: the client gave up before OPEN completed. Free the
 * transient open state (no session was created yet). */
static void
srv_open_closed_cb(mq_stream_t *s, void *user)
{
    (void)s;
    mq_udp_open_t *op = (mq_udp_open_t *)user;
    srv_open_free(op);
}

/* Reject an OPEN before a session exists. Two shapes, mirroring the TCP path's
 * graceful-vs-RESET split (mq_server.c srv_data_fail / srv_data_reap):
 *
 *   send_resp != 0 (POLICY_DENIED / DNS_FAILED / SOCKET_FAILED / SESSION_LIMIT):
 *     send RESP(ERROR, err) with FIN, then detach callbacks and free the
 *     pending-open state. We do NOT mq_stream_close(): a RESET
 *     (xqc_send_queue_drop_stream_frame_packets) would drop the not-yet-flushed
 *     RESP — the engine flush is deferred inside this read callback — so the
 *     client would see only RESET, never the error code. The FIN terminates the
 *     send direction; the peer's close (or conn teardown) frees the stream.
 *     Because the callbacks are detached, the later close-notify cannot fire
 *     srv_open_closed_cb on the freed op (and the conn never frees op: it is a
 *     transient owned only here, freed exactly once below).
 *
 *   send_resp == 0 (duplicate-SID / malformed OPEN — no decodable session to
 *     RESP to): there is nothing to deliver, so RESET is correct and cheaper.
 *     Detach callbacks, mq_stream_close (RESET), free op. */
static void
srv_open_reject(mq_udp_open_t *op, int send_resp, mq_udp_err_t err)
{
    if (send_resp) {
        /* Graceful: FIN'd RESP, no RESET (would drop the un-acked RESP). */
        srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, err, 0, /*fin=*/1);
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
    } else {
        /* Silent reset: no RESP owed, RESET the stream. */
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
        mq_stream_close(op->stream);
    }
    srv_open_free(op);
}

/* Finalize a successful OPEN: create the session, send RESP(OK), hand the stream
 * over from the pending-open state to the session.
 *
 * After RESP is sent, flush any pre-OPEN buffered datagrams for this sid. */
static void
srv_open_success(mq_udp_open_t *op, const mq_udp_session_open_t *open,
                 struct sockaddr_storage *ss, socklen_t sslen, uint64_t eff_idle_ms)
{
    mq_udp_srv_t *u = op->u;

    int fd = socket(ss->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        MQ_LOGW("mq_udp_srv: socket: %s", strerror(errno));
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SOCKET_FAILED);
        return;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
        connect(fd, (struct sockaddr *)ss, sslen) != 0) {
        MQ_LOGW("mq_udp_srv: connect: %s", strerror(errno));
        close(fd);
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SOCKET_FAILED);
        return;
    }

    mq_udp_sess_t *sess = srv_alloc_session(u);
    if (!sess) {
        /* Lost the slot between the cap check and here (cannot happen single-
         * threaded, but fail closed). */
        close(fd);
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SESSION_LIMIT);
        return;
    }

    memset(sess, 0, sizeof(*sess));
    sess->used = 1;
    sess->session_id = open->session_id;
    sess->stream = op->stream;
    sess->fd = fd;
    sess->next_packet_id = 0;
    sess->owner = u;
    u->live_count++;

    /* Persistent EV_READ on the UDP socket (target→tunnel). */
    sess->rd_ev = event_new(u->base, fd, EV_READ | EV_PERSIST, srv_udp_readable_cb, sess);
    if (!sess->rd_ev || event_add(sess->rd_ev, NULL) != 0) {
        MQ_LOGE("mq_udp_srv: EV_READ arm failed");
        /* Graceful: FIN'd error RESP so the client learns SOCKET_FAILED, then
         * reap WITHOUT a RESET (which would drop the un-acked RESP). The stream
         * still carries the pending-open callbacks (user = op, freed below);
         * detach them before reap so the later close-notify cannot fire
         * srv_open_closed_cb on the freed op. sess->graceful makes reap skip the
         * RESET; reap still closes fd + frees rd_ev + decrements live_count +
         * nulls the stream + resets the slot. */
        srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, MQ_UDP_SOCKET_FAILED, 0,
                          /*fin=*/1);
        mq_stream_set_cbs(op->stream, NULL, NULL, NULL, NULL);
        sess->graceful = 1;
        srv_reap_session(sess);
        srv_open_free(op);
        return;
    }

    /* Re-point the stream callbacks at the live-session handlers. The session
     * now owns the stream; the pending-open state is freed. */
    mq_stream_set_cbs(op->stream, srv_stream_readable_cb, NULL, srv_stream_closed_cb,
                      sess);

    /* Arm the idle timer to the per-session effective (min) value.  Re-armed
     * on every bidirectional activity. */
    {
        struct timeval tv;
        tv.tv_sec = (time_t)(eff_idle_ms / 1000);
        tv.tv_usec = (suseconds_t)((eff_idle_ms % 1000) * 1000);
        sess->idle_ev = evtimer_new(u->base, srv_idle_expired_cb, sess);
        if (!sess->idle_ev || evtimer_add(sess->idle_ev, &tv) != 0) {
            MQ_LOGE("mq_udp_srv: idle timer arm failed");
            /* Graceful: FIN'd error RESP so the client learns SOCKET_FAILED, then
             * reap WITHOUT a RESET (which would drop the un-acked RESP).
             * Callbacks were just re-pointed at the live-session handlers (user =
             * sess); detach them before reap so the later close-notify cannot
             * fire srv_stream_closed_cb with a reaped sess. sess->graceful makes
             * reap skip the RESET and just null the stream. */
            srv_send_udp_resp(op->stream, MQ_STATUS_ERROR, MQ_UDP_SOCKET_FAILED, 0,
                              /*fin=*/1);
            mq_stream_set_cbs(sess->stream, NULL, NULL, NULL, NULL);
            sess->graceful = 1;
            srv_reap_session(sess);
            srv_open_free(op);
            return;
        }
    }

    srv_send_udp_resp(op->stream, MQ_STATUS_OK, MQ_UDP_OK, eff_idle_ms, /*fin=*/0);
    MQ_LOGI("mq_udp_srv: session %u OPEN ok (idle=%llums)", open->session_id,
            (unsigned long long)eff_idle_ms);

    srv_open_free(op);

    /* Flush any pre-OPEN buffered datagrams for this sid (FIFO, TTL-filtered). */
    srv_preopen_flush(u, sess);
}

static void
srv_open_readable_cb(mq_stream_t *s, void *user)
{
    mq_udp_open_t *op = (mq_udp_open_t *)user;
    if (op->settled) {
        /* Shouldn't fire (callbacks are re-pointed on success / freed on error),
         * but drain defensively. */
        uint8_t scratch[256];
        int fin = 0;
        while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
        return;
    }

    mq_framebuf_fill(s, &op->rx, NULL);

    mq_udp_session_open_t open;
    int consumed = mq_decode_udp_session_open(op->rx.buf, op->rx.len, &open);
    if (consumed < 0) {
        if (op->rx.len >= sizeof(op->rx.buf)) {
            MQ_LOGW("mq_udp_srv: UDP_SESSION_OPEN malformed/oversized, resetting");
            op->settled = 1;
            /* Malformed OPEN: silent reset (no decodable session to RESP to). */
            srv_open_reject(op, /*send_resp=*/0, MQ_UDP_OK);
        }
        return; /* need more bytes */
    }

    /* Invariant: the 0x02 control stream carries exactly ONE OPEN message.
     * After that single frame, this stream is a pure control handle — any
     * trailing or subsequent bytes are intentionally ignored.  UDP payload
     * rides DATAGRAM frames, not this stream; stream close signals session
     * close.  `consumed` therefore need not be acted upon. */
    (void)consumed;

    /* OPEN decoded — this stream is now settled regardless of outcome. */
    op->settled = 1;
    mq_udp_srv_t *u = op->u;

    /* Duplicate-SID detection (decode-direct, BEFORE socket creation): if the
     * session_id is already live, RESET the new stream with NO RESP and leave
     * the existing session entirely untouched. */
    if (srv_find_session(u, open.session_id) != NULL) {
        MQ_LOGW("mq_udp_srv: duplicate session_id %u, resetting new stream (no RESP)",
                open.session_id);
        srv_open_reject(op, /*send_resp=*/0, MQ_UDP_OK);
        return;
    }

    /* Policy gate: --no-udp ⇒ deny. */
    if (!u->enabled) {
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_POLICY_DENIED);
        return;
    }

    /* Session-table cap. */
    if (u->live_count >= MQ_UDP_SRV_MAX_SESSIONS) {
        srv_open_reject(op, /*send_resp=*/1, MQ_UDP_SESSION_LIMIT);
        return;
    }

    /* Resolve (blocking getaddrinfo for DOMAIN). */
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    mq_udp_err_t rerr = MQ_UDP_DNS_FAILED;
    if (srv_resolve_udp_target(&open, &ss, &sslen, &rerr) != 0) {
        srv_open_reject(op, /*send_resp=*/1, rerr);
        return;
    }

    /* Effective idle timeout = min(client requested or server default if 0,
     * server setting). */
    uint64_t requested = open.idle_timeout_ms ? open.idle_timeout_ms : u->idle_timeout_ms;
    uint64_t eff = requested < u->idle_timeout_ms ? requested : u->idle_timeout_ms;

    srv_open_success(op, &open, &ss, sslen, eff);
}

/* ── public API ─────────────────────────────────────────────────────────── */

mq_udp_srv_t *
mq_udp_srv_new(mq_conn_t *c, struct event_base *base, uint64_t idle_timeout_ms,
               int enabled)
{
    mq_udp_srv_t *u = calloc(1, sizeof(*u));
    if (!u) {
        return NULL;
    }
    u->conn = c;
    u->base = base;
    u->idle_timeout_ms = idle_timeout_ms;
    u->enabled = enabled;
    /* authed starts 0: the auth gate blocks datagrams until auth succeeds. */

    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        u->sessions[i].fd = -1;
    }

    /* MSS cache: initialised to 0 (unknown); mss_emit_countdown = 0 so the
     * first emit triggers a fetch. */
    u->cached_mss = 0;
    u->mss_emit_countdown = 0;

    /* Allocate scratch buffers (once per conn; reused per packet). */
    u->recv_buf = malloc(65535);
    if (!u->recv_buf) {
        free(u);
        return NULL;
    }
    u->emit_buf = malloc(MQ_UDP_MSG_HDR + 65535);
    if (!u->emit_buf) {
        free(u->recv_buf);
        free(u);
        return NULL;
    }

    return u;
}

void
mq_udp_srv_free(mq_udp_srv_t *u)
{
    if (!u) {
        return;
    }
    /* Dump stats before teardown (exactly once per conn). */
    mq_udp_srv_dump_stats(u);
    for (size_t i = 0; i < MQ_UDP_SRV_MAX_SESSIONS; i++) {
        if (u->sessions[i].used) {
            srv_reap_session(&u->sessions[i]);
        }
    }
    srv_preopen_free_all(&u->preopen);
    free(u->recv_buf);
    free(u->emit_buf);
    free(u);
}

void
mq_udp_srv_set_authed(mq_udp_srv_t *u, int authed)
{
    if (u) {
        u->authed = authed;
    }
}

void
mq_udp_srv_dump_stats(mq_udp_srv_t *u)
{
    if (!u) {
        return;
    }
    MQ_LOGI("mq_udp_srv: stats frags_sent=%u frags_reassembled=%u "
            "drops_send_fail=%u drops_oversize=%u defrag_drops=%u "
            "preopen_evictions=%u drops_preauth=%u",
            u->frags_sent, u->frags_reassembled, u->drops_send_fail, u->drops_oversize,
            u->defrag_drops, u->preopen_evictions, u->drops_preauth);
}

void
mq_udp_srv_attach_stream(mq_udp_srv_t *u, mq_stream_t *s, const uint8_t *carry,
                         size_t carry_len)
{
    mq_udp_open_t *op = calloc(1, sizeof(*op));
    if (!op) {
        MQ_LOGE("mq_udp_srv: OOM allocating pending-open state");
        mq_stream_close(s);
        return;
    }
    op->u = u;
    op->stream = s;
    op->settled = 0;

    /* Seed the OPEN framebuf with the carry-over bytes the server's stream-type
     * dispatch already pulled off the stream (the OPEN body that trailed the
     * 0x02 discriminator — client sends them in one send). Bounded by
     * MQ_FRAMEBUF_CAP; clamp defensively. */
    if (carry && carry_len > 0) {
        size_t n = carry_len > sizeof(op->rx.buf) ? sizeof(op->rx.buf) : carry_len;
        memcpy(op->rx.buf, carry, n);
        op->rx.len = n;
    }

    mq_stream_set_cbs(s, srv_open_readable_cb, NULL, srv_open_closed_cb, op);

    /* Try decoding immediately (carry-over may already hold the full OPEN);
     * else accumulate more from the stream on later readability. */
    srv_open_readable_cb(s, op);
}

/* ── tunnel→target datagram path ───────────────────────────────────────── */

void
mq_udp_srv_on_datagram(mq_udp_srv_t *u, const uint8_t *data, size_t len)
{
    if (!u) {
        return;
    }

    /* Auth gate: the 0x02 stream's pre-auth guard does NOT apply to DATAGRAM
     * frames (they arrive on the connection-level callback).  This is the sole
     * auth boundary for inbound datagrams.  Also gate on !enabled so pre-auth
     * datagrams on a --no-udp connection are counted separately (they never
     * should arrive, but fail closed). */
    if (!u->authed || !u->enabled) {
        u->drops_preauth++;
        return;
    }

    /* Decode the 9-byte header. */
    mq_udp_msg_hdr_t hdr;
    if (mq_udp_msg_decode_hdr(data, len, &hdr) != 0) {
        u->drops_preauth++; /* malformed — count as pre-auth since no sid */
        return;
    }

    const uint8_t *payload = data + MQ_UDP_MSG_HDR;
    size_t plen = len - MQ_UDP_MSG_HDR;

    /* Session lookup. */
    mq_udp_sess_t *sess = srv_find_session(u, hdr.session_id);
    if (sess) {
        /* Live session hit: defrag → send → re-arm idle. */
        srv_defrag_and_send(u, sess, &hdr, payload, plen);
    } else {
        /* No live session yet — OPEN may still be in flight.
         * Pre-OPEN buffer: sweep stale entries first, then insert (COPY). */
        uint64_t now_ms = srv_mono_ms();
        srv_preopen_sweep_ttl(&u->preopen, now_ms);
        srv_preopen_insert(u, hdr.session_id, data, len, now_ms);
    }
}
