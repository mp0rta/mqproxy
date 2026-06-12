// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_conn.c — raw MPQUIC connection wrapper + ALP callback tables.
 *
 * See mq_conn.h for the user_data scheme. In short:
 *   - transport user_data = mq_transport_t*  (transport recovers it for sends)
 *   - app-proto user_data = mq_conn_t*        (ALP callbacks recover the conn)
 *
 * The per-engine ALP registration context (mq_alpn_ctx_t) is stashed via
 * xqc_engine_set_priv_ctx so the ALP conn_create_notify can find the owner's
 * on_new_conn / on_new_stream hooks (xquic does not pass the registered
 * alp_ctx into the per-conn callbacks).
 */
#include "transport/mq_conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/mq_stream_internal.h"
#include "util/mq_log.h"

/* Max extra (non-primary) paths a single conn may add. The runtime's path
 * map is 8 slots wide (path_id 0 is the primary), so 7 extra paths max; cap
 * lower here — the proxy adds one secondary path in Phase 1. */
#define MQ_CONN_MAX_EXTRA_PATHS 7

/* Per-engine ALP registration context. Owns the new-conn / new-stream hooks
 * and is freed when the engine is destroyed (we keep it reachable via the
 * engine priv_ctx and free it lazily — see note in mq_conn_register_alpn). */
typedef struct mq_alpn_ctx_s {
    mq_conn_on_new_fn on_new_conn;
    mq_stream_on_new_fn on_new_stream;
    void *user;
    xqc_app_proto_callbacks_t ap_cbs; /* kept alive for the engine's lifetime */

    /* Set by mq_conn_connect immediately before xqc_connect so the very next
     * conn_create_notify (client side) adopts the caller's pre-allocated
     * mq_conn instead of creating a server-style one. xquic creates the
     * connection synchronously within xqc_connect on this single-threaded
     * engine, so this hand-off is race-free. Cleared on adoption. */
    mq_conn_t *pending_client_conn;

    /* The most-recently-serviced server mq_conn, used to attribute a
     * peer-initiated stream to its owning connection.
     *
     * The robust API for stream->conn is xqc_get_conn_alp_user_data_by_stream
     * (used by xquic's own hq/h3 demos), but the prebuilt *shared* libxquic
     * does not export it (only the static archive does, which we cannot link
     * alongside the shared lib without duplicate symbols). As a portable
     * substitute we record the conn in every server-side conn-level callback;
     * on this single-threaded engine a server conn's conn_create_notify runs
     * before any of that conn's stream_create_notify, so the first (control)
     * peer stream is attributed correctly. KNOWN LIMITATION (Phase 1): with
     * multiple clients whose handshakes interleave, the first stream of one
     * conn could in principle be misattributed; revisit once the shared lib
     * exports the alp accessor. */
    mq_conn_t *active_server_conn;
} mq_alpn_ctx_t;

struct mq_conn_s {
    mq_transport_t *transport;
    xqc_cid_t cid;
    int have_cid;
    int is_server;

    mq_conn_on_state_fn on_state;
    void *on_state_user;

    /* DATAGRAM receive hook (Phase 3 UDP relay). Set via
     * mq_conn_set_on_datagram; dispatched from the dgram_read_notify, which
     * recovers `this` from the dgram user_data (bound in conn_create_notify). */
    mq_conn_on_datagram_fn on_datagram;
    void *on_datagram_user;

    /* DATAGRAM loss/ack counters. UDP semantics: we never retransmit or reorder
     * — lost/acked notifies only bump these (+ DEBUG log). Observability only. */
    uint64_t dgram_lost;
    uint64_t dgram_acked;

    void *owner;

    /* Multipath: set once xquic fires ready_to_create_path_notify. */
    int mp_ready;

    /* Extra (non-primary) path-ids added via mq_conn_add_path. Their sockets
     * live in the runtime; they are torn down (mq_transport_close_path) on
     * conn teardown. */
    uint64_t extra_path_ids[MQ_CONN_MAX_EXTRA_PATHS];
    int n_extra_paths;
};

static mq_alpn_ctx_t *mq_conn_actx(void *conn_user_data);
/* Defined under "Multipath" below; forward-declared so mq_conn_close_notify can
 * unsubscribe this conn from the transport's mp-ready broadcast before free(c). */
static void mq_conn_on_mp_ready(const xqc_cid_t *scid, void *user);

/* ── ALP connection callbacks ───────────────────────────────────────────── */

/* conn_create_notify: conn_user_data is the transport (transport user_data);
 * conn_proto_data is the app-proto user_data — non-NULL for a client conn we
 * already created in mq_conn_connect, NULL for a server-accepted conn. */
static int
mq_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data,
                      void *conn_proto_data)
{
    (void)conn_proto_data;
    mq_transport_t *t = (mq_transport_t *)conn_user_data;
    mq_alpn_ctx_t *actx = (mq_alpn_ctx_t *)xqc_engine_get_priv_ctx(mq_transport_xqc(t));

    /* Client side: adopt the mq_conn the caller pre-allocated in
     * mq_conn_connect, binding it as the connection's alp user_data. */
    if (actx && actx->pending_client_conn) {
        mq_conn_t *c = actx->pending_client_conn;
        actx->pending_client_conn = NULL;
        c->transport = t;
        memcpy(&c->cid, (const void *)cid, sizeof(c->cid));
        c->have_cid = 1;
        xqc_conn_set_alp_user_data(conn, c);
        /* Bind the dgram user_data slot to the mq_conn so the dgram callbacks
         * recover it. Distinct from alp/transport user_data — does not clobber
         * either (Phase 2 H3 user_data trap). */
        xqc_datagram_set_user_data(conn, c);
        return 0;
    }

    /* Server side: build an mq_conn for the accepted connection. */
    mq_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return -1;
    }
    c->transport = t;
    c->is_server = 1;
    /* cid may be misaligned inside xquic internals; copy bytewise. */
    memcpy(&c->cid, (const void *)cid, sizeof(c->cid));
    c->have_cid = 1;

    xqc_conn_set_alp_user_data(conn, c);
    /* Bind the dgram user_data slot to the mq_conn (see client path above). */
    xqc_datagram_set_user_data(conn, c);
    if (actx) {
        actx->active_server_conn = c;
    }

    if (actx && actx->on_new_conn) {
        actx->on_new_conn(c, actx->user);
    }
    return 0;
}

/* Recover the per-engine ALP ctx from a conn-level callback (which receives the
 * transport as conn_user_data). */
static mq_alpn_ctx_t *
mq_conn_actx(void *conn_user_data)
{
    mq_transport_t *t = (mq_transport_t *)conn_user_data;
    if (!t) {
        return NULL;
    }
    return (mq_alpn_ctx_t *)xqc_engine_get_priv_ctx(mq_transport_xqc(t));
}

static int
mq_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data,
                     void *conn_proto_data)
{
    (void)conn;
    (void)cid;
    (void)conn_user_data;
    mq_conn_t *c = (mq_conn_t *)conn_proto_data;
    if (!c) {
        return 0;
    }
    /* NB: do NOT touch the ALP ctx (actx) here. During xqc_engine_destroy,
     * xquic frees the ALPN registration list (and thus actx) BEFORE destroying
     * connections, so xqc_engine_get_priv_ctx would return freed memory in the
     * teardown path. active_server_conn need not be cleared: it is only read to
     * attribute a *newly arriving* peer stream, and no new streams arrive on a
     * connection after it closes; any later stream belongs to another conn
     * whose create/handshake already refreshed the slot. */
    if (c->on_state) {
        c->on_state(c, MQ_CONN_CLOSED, c->on_state_user);
    }
    /* Unsubscribe from the transport's mp-ready broadcast BEFORE free(c).
     * mq_conn_connect registered mq_conn_on_mp_ready with `c` as the user
     * pointer; with multiple conns on one transport (Phase 2: tcp + h3) the
     * subscriber table outlives this conn, and a later readiness broadcast would
     * deref the freed `c` (use-after-free). A no-op for server conns, which never
     * subscribed (matched by fn+user, not found). */
    mq_transport_remove_mp_ready_cb(c->transport, mq_conn_on_mp_ready, c);
    /* Release any secondary paths this conn owns (the runtime frees the read
     * event + socket via close_path_socket). */
    for (int i = 0; i < c->n_extra_paths; i++) {
        mq_transport_close_path(c->transport, c->extra_path_ids[i]);
    }
    free(c);
    return 0;
}

static void
mq_conn_handshake_finished(xqc_connection_t *conn, void *conn_user_data,
                           void *conn_proto_data)
{
    (void)conn;
    mq_conn_t *c = (mq_conn_t *)conn_proto_data;
    /* For a server conn, refresh the active-conn slot so the imminent control
     * stream is attributed to this connection (see active_server_conn). */
    if (c && c->is_server) {
        mq_alpn_ctx_t *actx = mq_conn_actx(conn_user_data);
        if (actx) {
            actx->active_server_conn = c;
        }
    }
    if (c && c->on_state) {
        c->on_state(c, MQ_CONN_ESTABLISHED, c->on_state_user);
    }
}

/* ── ALP stream create (server / peer-initiated) ────────────────────────── */

static int
mq_conn_stream_create_notify(xqc_stream_t *stream, void *strm_user_data)
{
    /* Locally-initiated stream (mq_conn_open_stream): the wrapper was passed
     * as user_data to xqc_stream_create and arrives here pre-allocated. Bind
     * it to the xquic stream; do NOT fire the peer on_new_stream hook. */
    if (strm_user_data) {
        mq_stream_bind((mq_stream_t *)strm_user_data, stream);
        return 0;
    }

    /* Peer-initiated stream: wrap it and surface to the owner. The
     * connection's transport user_data is the mq_transport; from it we reach the
     * per-engine ALP registration ctx (and its on_new_stream hook). The owning
     * mq_conn is the transport's active server conn (see active_server_conn). */
    mq_transport_t *t = (mq_transport_t *)xqc_get_conn_user_data_by_stream(stream);
    mq_stream_t *s = mq_stream_wrap(stream);
    if (!s) {
        return -1;
    }
    if (t) {
        mq_alpn_ctx_t *actx =
            (mq_alpn_ctx_t *)xqc_engine_get_priv_ctx(mq_transport_xqc(t));
        if (actx) {
            mq_stream_set_conn(s, actx->active_server_conn);
        }
        if (actx && actx->on_new_stream) {
            actx->on_new_stream(s, actx->user);
        }
    }
    return 0;
}

/* ── ALP datagram callbacks (Phase 3 UDP relay) ─────────────────────────────
 *
 * The dgram callbacks receive `user_data` = the dgram_data slot, which is the
 * mq_conn_t* bound via xqc_datagram_set_user_data in conn_create_notify. This
 * is a DISTINCT slot from the transport user_data (mq_transport_t*) and the
 * app-proto user_data (also mq_conn_t* but a different slot) — so binding it
 * does NOT clobber either (cf. the Phase 2 H3 user_data trap). */

static void
mq_conn_datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data,
                             size_t data_len, uint64_t unix_ts)
{
    (void)conn;
    (void)unix_ts;
    mq_conn_t *c = (mq_conn_t *)user_data;
    if (c && c->on_datagram) {
        c->on_datagram(c, (const uint8_t *)data, data_len, c->on_datagram_user);
    }
}

/* No-op: the proxy never blocks on the dgram write path (a full send queue is
 * reported as EAGAIN-drop by mq_conn_datagram_send, and UDP semantics mean we
 * just drop rather than re-arm a write). */
static void
mq_conn_datagram_write_notify(xqc_connection_t *conn, void *user_data)
{
    (void)conn;
    (void)user_data;
}

/* UDP semantics: never retransmit. Returning 0 tells xquic NOT to retransmit
 * (XQC_DGRAM_RETX_ASKED_BY_APP would). Count + DEBUG-log only. */
static xqc_int_t
mq_conn_datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    (void)conn;
    mq_conn_t *c = (mq_conn_t *)user_data;
    if (c) {
        c->dgram_lost++;
        MQ_LOGD("mq_conn: dgram lost: id=%llu total=%llu", (unsigned long long)dgram_id,
                (unsigned long long)c->dgram_lost);
    }
    return 0;
}

static void
mq_conn_datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data)
{
    (void)conn;
    mq_conn_t *c = (mq_conn_t *)user_data;
    if (c) {
        c->dgram_acked++;
        MQ_LOGD("mq_conn: dgram acked: id=%llu total=%llu", (unsigned long long)dgram_id,
                (unsigned long long)c->dgram_acked);
    }
}

/* ── ALP registration ───────────────────────────────────────────────────── */

int
mq_conn_register_alpn(mq_transport_t *t, const char *alpn, mq_conn_on_new_fn on_new_conn,
                      mq_stream_on_new_fn on_new_stream, void *user)
{
    if (!t || !alpn) {
        return -1;
    }
    xqc_engine_t *xeng = mq_transport_xqc(t);
    if (!xeng) {
        return -1;
    }

    mq_alpn_ctx_t *actx = calloc(1, sizeof(*actx));
    if (!actx) {
        return -1;
    }
    actx->on_new_conn = on_new_conn;
    actx->on_new_stream = on_new_stream;
    actx->user = user;

    actx->ap_cbs.conn_cbs.conn_create_notify = mq_conn_create_notify;
    actx->ap_cbs.conn_cbs.conn_close_notify = mq_conn_close_notify;
    actx->ap_cbs.conn_cbs.conn_handshake_finished = mq_conn_handshake_finished;

    actx->ap_cbs.stream_cbs.stream_read_notify = mq_stream_read_notify;
    actx->ap_cbs.stream_cbs.stream_write_notify = mq_stream_write_notify;
    actx->ap_cbs.stream_cbs.stream_create_notify = mq_conn_stream_create_notify;
    actx->ap_cbs.stream_cbs.stream_close_notify = mq_stream_close_notify;

    /* DATAGRAM callbacks (Phase 3 UDP relay). Registered unconditionally; a conn
     * whose peer never negotiates max_datagram_frame_size simply never fires
     * them. The dgram user_data (mq_conn_t*) is bound per-conn in
     * conn_create_notify, NOT here. */
    actx->ap_cbs.dgram_cbs.datagram_read_notify = mq_conn_datagram_read_notify;
    actx->ap_cbs.dgram_cbs.datagram_write_notify = mq_conn_datagram_write_notify;
    actx->ap_cbs.dgram_cbs.datagram_lost_notify = mq_conn_datagram_lost_notify;
    actx->ap_cbs.dgram_cbs.datagram_acked_notify = mq_conn_datagram_acked_notify;

    if (xqc_engine_register_alpn(xeng, alpn, strlen(alpn), &actx->ap_cbs, actx) !=
        XQC_OK) {
        MQ_LOGE("mq_conn: register_alpn('%s') failed", alpn);
        free(actx);
        return -1;
    }

    /* Stash the registration ctx so conn_create_notify (which only receives
     * the engine + conn) can find the owner hooks. One ALPN per engine in the
     * proxy, so a single priv_ctx slot suffices. This is a non-owning alias:
     * xquic stores `actx` as the alpn registration's alp_ctx and frees it in
     * xqc_engine_destroy (xqc_engine_free_alpn_list), so we never free actx
     * ourselves. */
    xqc_engine_set_priv_ctx(xeng, actx);
    return 0;
}

/* ── Multipath ──────────────────────────────────────────────────────────── */

/* Engine mp-ready hook: xquic signalled that the conn identified by scid can
 * create a path. The user pointer is the client mq_conn registered in
 * mq_conn_connect. The notification is broadcast to every subscriber on the
 * transport, so filter by scid (cid_len + cid_buf) and only flip OUR conn.
 * scid points at an aligned copy made by the transport dispatch point (xquic
 * may hand it an unaligned cid pointer), so plain member access is safe here. */
static void
mq_conn_on_mp_ready(const xqc_cid_t *scid, void *user)
{
    mq_conn_t *c = (mq_conn_t *)user;
    if (!c || !c->have_cid || !scid) {
        return;
    }
    if (scid->cid_len == c->cid.cid_len &&
        memcmp(scid->cid_buf, c->cid.cid_buf, c->cid.cid_len) == 0) {
        c->mp_ready = 1;
    }
}

int
mq_conn_mp_ready(const mq_conn_t *c)
{
    return c ? c->mp_ready : 0;
}

int
mq_conn_add_path(mq_conn_t *c, const char *local_ip, uint16_t local_port)
{
    if (!c || !c->have_cid || !local_ip) {
        return -1;
    }
    if (c->n_extra_paths >= MQ_CONN_MAX_EXTRA_PATHS) {
        MQ_LOGW("mq_conn: add_path: extra-path slots exhausted");
        return -1;
    }
    xqc_engine_t *xeng = mq_transport_xqc(c->transport);
    if (!xeng) {
        return -1;
    }

    /* 1. Ask xquic to allocate a new path-id (needs a spare peer cid; that is
     *    the ready_to_create_path precondition). path_status 0 == AVAILABLE
     *    (xquic.h: 1==STANDBY, other==AVAILABLE). */
    uint64_t new_path_id = 0;
    xqc_int_t rc = xqc_conn_create_path(xeng, &c->cid, &new_path_id, /*AVAILABLE=*/0);
    if (rc != XQC_OK) {
        MQ_LOGW("mq_conn: xqc_conn_create_path failed: %d (mp_ready=%d)", (int)rc,
                c->mp_ready);
        return -1;
    }

    /* 2. Ask the runtime (via the transport) to open a UDP socket for the new
     *    path-id and arm its recv-drain so packets for it can be routed. */
    if (mq_transport_open_path(c->transport, new_path_id, local_ip, local_port) != 0) {
        MQ_LOGE("mq_conn: add_path: open_path_socket(path %llu) failed",
                (unsigned long long)new_path_id);
        /* Best-effort: tear the half-created xquic path back down so it does
         * not linger waiting on a socket that will never exist. */
        xqc_conn_close_path(xeng, &c->cid, new_path_id);
        return -1;
    }

    /* 3. Mark the path available so the peer may schedule traffic on it once
     *    validation completes. */
    if (xqc_conn_mark_path_available(xeng, &c->cid, new_path_id) != XQC_OK) {
        MQ_LOGW("mq_conn: mark_path_available(path %llu) failed",
                (unsigned long long)new_path_id);
        /* Non-fatal: the path was created + socket bound; validation may still
         * proceed. Keep the path so its socket stays alive. */
    }

    c->extra_path_ids[c->n_extra_paths++] = new_path_id;
    return (int)new_path_id;
}

/* ── Per-path stats (shared get_stats + free contract) ──────────────────────
 *
 * Fetch a connection-stats snapshot into *out. Returns 0 on success (and the
 * caller MUST free out->paths_info with libc free()), -1 if the conn/engine is
 * unknown (out is zeroed; nothing to free). Centralises the xqc_conn_get_stats
 * call + ownership contract so callers don't duplicate (or mis-free) it. */
static int
mq_conn_stats_snapshot(const mq_conn_t *c, xqc_conn_stats_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!c || !c->have_cid) {
        return -1;
    }
    xqc_engine_t *xeng = mq_transport_xqc(c->transport);
    if (!xeng) {
        return -1;
    }
    /* cid is const-correct read-only here; xqc_conn_get_stats takes a const
     * cid* and returns a snapshot with a heap-allocated paths_info. xquic
     * documents (xqc_conn_stats_t) that paths_info must be released with libc
     * free() — NOT xqc_free — and may be NULL with count 0 (no free needed,
     * free(NULL) is safe). */
    *out = xqc_conn_get_stats(xeng, &c->cid);
    return 0;
}

int
mq_conn_path_state(const mq_conn_t *c, uint64_t path_id)
{
    xqc_conn_stats_t st;
    if (mq_conn_stats_snapshot(c, &st) != 0) {
        return -1;
    }
    int state = -1;
    for (uint32_t i = 0; st.paths_info && i < st.paths_info_count; i++) {
        if (st.paths_info[i].path_id == path_id) {
            state = (int)st.paths_info[i].path_state;
            break;
        }
    }
    free(st.paths_info);
    return state;
}

int
mq_conn_path_bytes(const mq_conn_t *c, uint64_t path_id, uint64_t *sent, uint64_t *recv)
{
    xqc_conn_stats_t st;
    if (mq_conn_stats_snapshot(c, &st) != 0) {
        return -1;
    }
    int rc = -1;
    for (uint32_t i = 0; st.paths_info && i < st.paths_info_count; i++) {
        if (st.paths_info[i].path_id == path_id) {
            if (sent) {
                *sent = st.paths_info[i].path_send_bytes;
            }
            if (recv) {
                *recv = st.paths_info[i].path_recv_bytes;
            }
            rc = 0;
            break;
        }
    }
    free(st.paths_info);
    return rc;
}

int
mq_conn_format_path_line(char *buf, size_t cap, const xqc_path_metrics_t *p)
{
    if (!buf || !p) {
        return -1;
    }
    /* state raw int: 2 == XQC_PATH_STATE_ACTIVE (internal header; do not ref). */
    int n = snprintf(
        buf, cap,
        "mq.path id=%llu state=%u srtt_ms=%llu bw_Bps=%llu "
        "sent=%llu recv=%llu lost=%llu"
        " min_rtt_ms=%llu cwnd=%llu inflight=%llu",
        (unsigned long long)p->path_id, (unsigned)p->path_state,
        (unsigned long long)(p->path_srtt / 1000), /* usec -> ms */
        (unsigned long long)p->path_est_bw,        /* bytes/sec */
        (unsigned long long)p->path_send_bytes, (unsigned long long)p->path_recv_bytes,
        (unsigned long long)p->path_lost_count,
        (unsigned long long)(p->path_min_rtt / 1000), /* usec -> ms */
        (unsigned long long)p->path_cwnd, (unsigned long long)p->path_bytes_in_flight);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

int
mq_conn_format_conn_line(char *buf, size_t cap, const xqc_conn_stats_t *st)
{
    if (!buf || !st) {
        return -1;
    }
    int n = snprintf(buf, cap,
                     "mq.conn mp_state=%d paths=%u app_bytes=%llu standby_bytes=%llu",
                     st->mp_state, (unsigned)st->paths_info_count,
                     (unsigned long long)st->total_app_bytes,
                     (unsigned long long)st->standby_path_app_bytes);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

void
mq_conn_dump_stats_cid(mq_transport_t *t, const xqc_cid_t *cid)
{
    if (!t || !cid) {
        MQ_LOGI("mq_conn stats: no connection");
        return;
    }
    xqc_engine_t *xeng = mq_transport_xqc(t);
    if (!xeng) {
        MQ_LOGI("mq_conn stats: no connection");
        return;
    }
    /* xqc_conn_get_stats returns a snapshot whose heap-allocated paths_info MUST
     * be released with libc free() — NOT xqc_free — and may be NULL with count 0
     * (no free needed, free(NULL) is safe). Mirrors mq_conn_stats_snapshot's
     * ownership contract for the cid-keyed callers (mq_h3). */
    xqc_conn_stats_t st = xqc_conn_get_stats(xeng, cid);
    if (!st.paths_info || st.paths_info_count == 0) {
        MQ_LOGI("mq_conn stats: no path metrics");
        free(st.paths_info); /* free(NULL) is safe; count 0 may carry a buffer */
        return;
    }
    char line[MQ_METRICS_LINE_CAP];
    if (mq_conn_format_conn_line(line, sizeof(line), &st) > 0) {
        MQ_LOGI("%s", line);
    }
    for (uint32_t i = 0; i < st.paths_info_count; i++) {
        if (mq_conn_format_path_line(line, sizeof(line), &st.paths_info[i]) > 0) {
            MQ_LOGI("%s", line);
        }
    }
    free(st.paths_info);
}

void
mq_conn_dump_stats(mq_conn_t *c)
{
    if (!c || !c->have_cid) {
        MQ_LOGI("mq_conn stats: no connection");
        return;
    }
    mq_conn_dump_stats_cid(c->transport, &c->cid);
}

mq_cc_t
mq_cc_from_string(const char *name, int *ok)
{
    struct {
        const char *name;
        mq_cc_t cc;
    } table[] = {
        {"bbr2", MQ_CC_BBR2},
        {"bbr", MQ_CC_BBR},
        {"cubic", MQ_CC_CUBIC},
    };
    if (name) {
        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
            if (strcmp(name, table[i].name) == 0) {
                if (ok) {
                    *ok = 1;
                }
                return table[i].cc;
            }
        }
    }
    if (ok) {
        *ok = 0;
    }
    return MQ_CC_DEFAULT;
}

const char *
mq_cc_name(mq_cc_t cc)
{
    switch (cc) {
    case MQ_CC_BBR: return "bbr";
    case MQ_CC_CUBIC: return "cubic";
    case MQ_CC_BBR2:
    default: return "bbr2";
    }
}

static mq_sched_t g_mq_sched = MQ_SCHED_DEFAULT;

void
mq_conn_set_scheduler(mq_sched_t sched)
{
    g_mq_sched = sched;
}

mq_sched_t
mq_sched_from_string(const char *name, int *ok)
{
    struct {
        const char *name;
        mq_sched_t sched;
    } table[] = {
        {"minrtt", MQ_SCHED_MINRTT},
        {"backup", MQ_SCHED_BACKUP},
        {"wlb", MQ_SCHED_WLB},
    };
    if (name) {
        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
            if (strcmp(name, table[i].name) == 0) {
                if (ok) {
                    *ok = 1;
                }
                return table[i].sched;
            }
        }
    }
    if (ok) {
        *ok = 0;
    }
    return MQ_SCHED_DEFAULT;
}

const char *
mq_sched_name(mq_sched_t sched)
{
    switch (sched) {
    case MQ_SCHED_BACKUP: return "backup";
    case MQ_SCHED_WLB: return "wlb";
    case MQ_SCHED_MINRTT:
    default: return "minrtt";
    }
}

void
mq_conn_apply_mp_settings(xqc_conn_settings_t *s, int is_server, mq_cc_t cc)
{
    if (!s) {
        return;
    }
    /* Multipath (match mqvpn's recipe). enable_multipath + mp_ping_on on both
     * sides; init_max_path_id left at the xquic default (8). The server grants
     * a larger path-id ceiling on PATHS_BLOCKED since the client is the active
     * path creator (draft-21 §3.2.1 ¶7). */
    s->enable_multipath = 1;
    s->mp_ping_on = 1;
    if (is_server) {
        s->max_path_id_grant_max_value = 128;
    }

    /* Congestion control: always install a CC callback. Without this,
     * cong_ctrl_callback stays NULL and the sender is effectively un-throttled
     * — on a real rate-limited/lossy path that overflows the queue, triggers a
     * loss/PTO retransmit storm, and collapses throughput to ~KB/s. It is
     * INVISIBLE on clean loopback or under ASan (the sanitizer's slowdown keeps
     * the send rate below the link rate), which is why it only surfaced in the
     * shaped 1-B benchmark. Applies to both sides; the download sender (server)
     * needs it most. BBR is the default (MQ_CC_DEFAULT); --cc selects
     * bbr2/cubic for benchmarking. */
    switch (cc) {
    case MQ_CC_BBR: s->cong_ctrl_callback = xqc_bbr_cb; break;
    case MQ_CC_CUBIC: s->cong_ctrl_callback = xqc_cubic_cb; break;
    case MQ_CC_BBR2:
    default: s->cong_ctrl_callback = xqc_bbr2_cb; break;
    }

    /* Scheduler: minRTT. A single proxied flow is ONE QUIC stream, so we want
     * its packets spread across paths by RTT (within-stream multipath) to
     * aggregate bandwidth. minRTT does that; WLB (xqc_wlb_scheduler_cb) instead
     * PINS inner flows to paths — right for mqvpn's per-datagram flows, wrong
     * here (it would confine the single stream to one path = no aggregation).
     * minRTT is also xquic's current default, but pin it explicitly so a fork
     * default change can't silently regress 1-B aggregation.
     * --scheduler overrides this for A/B benchmarking (mq_conn_set_scheduler). */
    switch (g_mq_sched) {
    case MQ_SCHED_BACKUP: s->scheduler_callback = xqc_backup_scheduler_cb; break;
    case MQ_SCHED_WLB: s->scheduler_callback = xqc_wlb_scheduler_cb; break;
    case MQ_SCHED_MINRTT:
    default: s->scheduler_callback = xqc_minrtt_scheduler_cb; break;
    }

    /* Flow-control windows: rely on xquic's default (enable_stream_rate_limit
     * == 0) which advertises max_stream_data_bidi_local = XQC_MAX_RECV_WINDOW
     * = 16MB — larger than the 8MB aggregate-BDP target and consistent with
     * mqvpn. Setting enable_stream_rate_limit=1 would pin the initial window
     * to init_recv_window (8MB) for no benefit; recv_rate_bytes_per_sec stays
     * 0 so there is no rate throttle either way. The MQ_STREAM_WINDOW /
     * MQ_CONN_WINDOW constants are documentary and the static_asserts in
     * mq_conn.h guard the fork ceiling. */
}

/* ── Client connect ─────────────────────────────────────────────────────── */

mq_conn_t *
mq_conn_connect(mq_transport_t *t, const struct sockaddr *peer, socklen_t peerlen,
                const char *alpn, const xqc_conn_settings_t *settings, void *owner)
{
    if (!t || !peer || !alpn || !settings) {
        return NULL;
    }
    xqc_engine_t *xeng = mq_transport_xqc(t);
    if (!xeng) {
        return NULL;
    }

    mq_alpn_ctx_t *actx = (mq_alpn_ctx_t *)xqc_engine_get_priv_ctx(xeng);
    if (!actx) {
        MQ_LOGE("mq_conn: connect before mq_conn_register_alpn");
        return NULL;
    }

    mq_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->transport = t;
    c->is_server = 0;
    c->owner = owner;

    /* Subscribe to xquic's ready_to_create_path_notify (delivered to the
     * transport) so mq_conn_mp_ready flips once paths can be created. The
     * notification is broadcast to every subscriber on the transport (Phase 2:
     * a tcp conn and an h3 conn share one engine), so mq_conn_on_mp_ready
     * filters by scid to flip only THIS conn. */
    if (mq_transport_add_mp_ready_cb(t, mq_conn_on_mp_ready, c) != 0) {
        MQ_LOGE("mq_conn: mp-ready subscriber table full");
        free(c);
        return NULL;
    }

    xqc_conn_ssl_config_t conn_ssl;
    memset(&conn_ssl, 0, sizeof(conn_ssl));

    /* Hand the mq_conn to the imminent conn_create_notify (fired synchronously
     * inside xqc_connect) which binds it as the connection's alp user_data.
     * The transport user_data is the mq_transport so the send callback can
     * recover it. */
    actx->pending_client_conn = c;

    /* server_host is the TLS SNI; xquic dereferences it unconditionally
     * (strlen), so it must be non-NULL even on loopback. */
    const xqc_cid_t *cid =
        xqc_connect(xeng, settings, NULL, 0, "mqproxy", /*no_crypto_flag=*/0, &conn_ssl,
                    peer, peerlen, alpn, /*transport user_data=*/t);
    if (!cid) {
        MQ_LOGE("mq_conn: xqc_connect failed");
        actx->pending_client_conn = NULL;
        free(c);
        return NULL;
    }
    memcpy(&c->cid, cid, sizeof(c->cid));
    c->have_cid = 1;

    if (actx->pending_client_conn == c) {
        /* conn_create_notify did not fire synchronously; clear the hand-off
         * so a later unrelated conn_create can't adopt this conn. The alp
         * user_data binding will then be missing — treat as a hard error. */
        actx->pending_client_conn = NULL;
        MQ_LOGE("mq_conn: conn_create_notify did not fire during xqc_connect");
        free(c);
        return NULL;
    }
    return c;
}

void
mq_conn_set_on_state(mq_conn_t *c, mq_conn_on_state_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_state = fn;
    c->on_state_user = user;
}

void *
mq_conn_user(const mq_conn_t *c)
{
    return c ? c->owner : NULL;
}

void
mq_conn_set_user(mq_conn_t *c, void *owner)
{
    if (c) {
        c->owner = owner;
    }
}

mq_stream_t *
mq_conn_open_stream(mq_conn_t *c)
{
    if (!c || !c->have_cid) {
        return NULL;
    }
    /* Pre-allocate the wrapper and pass it as the stream user_data so the
     * stream_create_notify that xquic fires synchronously inside
     * xqc_stream_create binds this exact wrapper (no double-wrap). */
    mq_stream_t *s = mq_stream_alloc();
    if (!s) {
        return NULL;
    }
    xqc_stream_t *xs =
        xqc_stream_create(mq_transport_xqc(c->transport), &c->cid, NULL, s);
    if (!xs) {
        MQ_LOGW("mq_conn: xqc_stream_create failed");
        mq_stream_free(s);
        return NULL;
    }
    /* If stream_create_notify did not run (it should, synchronously), bind
     * defensively so the wrapper is usable and freed via close_notify. */
    mq_stream_bind(s, xs);
    return s;
}

/* ── QUIC DATAGRAM (Phase 3 UDP relay) ──────────────────────────────────────
 *
 * The send/mss wrappers recover the raw xqc_connection_t* afresh on every call
 * via xqc_engine_get_conn_by_scid (mq_conn keeps only transport + cid). After
 * the conn closes the lookup returns NULL and the wrappers fail naturally
 * (send=-1, mss=0) — we lean on that lifetime property rather than tracking
 * close state separately. */

void
mq_conn_set_on_datagram(mq_conn_t *c, mq_conn_on_datagram_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_datagram = fn;
    c->on_datagram_user = user;
}

/* Recover the raw xqc_connection_t* for this conn's scid, or NULL if unknown
 * (e.g. closed). Shared by the send/mss wrappers. */
static xqc_connection_t *
mq_conn_xqc(const mq_conn_t *c)
{
    if (!c || !c->have_cid) {
        return NULL;
    }
    xqc_engine_t *xeng = mq_transport_xqc(c->transport);
    if (!xeng) {
        return NULL;
    }
    return xqc_engine_get_conn_by_scid(xeng, &c->cid);
}

int
mq_conn_datagram_send(mq_conn_t *c, const uint8_t *data, size_t len)
{
    xqc_connection_t *conn = mq_conn_xqc(c);
    if (!conn) {
        return -1;
    }
    /* xqc_datagram_send takes void* (non-const) but does not mutate the buffer;
     * cast away const. qos NORMAL, no dgram_id needed (design §8). Any negative
     * return (EAGAIN / TOO_LARGE / NOT_SUPPORTED / CLOSING) collapses to -1: the
     * caller bumps a drop counter and continues (UDP semantics, design §9.2). */
    xqc_int_t rc =
        xqc_datagram_send(conn, (void *)(uintptr_t)data, len, NULL, XQC_DATA_QOS_NORMAL);
    return rc == XQC_OK ? 0 : -1;
}

size_t
mq_conn_datagram_mss(const mq_conn_t *c)
{
    xqc_connection_t *conn = mq_conn_xqc(c);
    if (!conn) {
        return 0;
    }
    /* xqc_datagram_get_mss returns the connection-level dgram_mss, computed from
     * conn->pkt_out_size (the default/primary path MTU) — it does NOT reflect a
     * per-path MTU min across active paths (xqc_datagram.c
     * xqc_datagram_record_mss). With multipath, a secondary path with a smaller
     * path_max_pkt_out_size would let an oversized datagram through the conn-level
     * check yet be too large for that path. So take the min over active paths via
     * xqc_datagram_get_mss_on_path; fall back to the conn-level mss if no path is
     * reported (single-path / pre-validation). */
    size_t conn_mss = xqc_datagram_get_mss(conn);
    if (conn_mss == 0) {
        return 0; /* peer does not support datagram */
    }

    /* Enumerate active paths via the stats snapshot (same ownership contract as
     * mq_conn_stats_snapshot). XQC_PATH_STATE_ACTIVE == 2 (mirrors mq_conn.h /
     * mqvpn; the enum lives in the private xqc_multipath.h). */
    xqc_conn_stats_t st;
    if (mq_conn_stats_snapshot(c, &st) != 0) {
        return conn_mss;
    }
    size_t min_mss = conn_mss;
    int saw_active = 0;
    for (uint32_t i = 0; st.paths_info && i < st.paths_info_count; i++) {
        if (st.paths_info[i].path_state != 2 /* XQC_PATH_STATE_ACTIVE */) {
            continue;
        }
        size_t path_mss = xqc_datagram_get_mss_on_path(conn, st.paths_info[i].path_id);
        if (path_mss == 0) {
            continue; /* path closing/unknown — skip, don't zero the result */
        }
        if (!saw_active || path_mss < min_mss) {
            min_mss = path_mss;
            saw_active = 1;
        }
    }
    free(st.paths_info);
    return min_mss;
}

void
mq_conn_close(mq_conn_t *c)
{
    if (!c || !c->have_cid) {
        return;
    }
    xqc_conn_close(mq_transport_xqc(c->transport), &c->cid);
}
