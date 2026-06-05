// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_h3.c — H3-over-MPQUIC wrapper over the sans-io transport core.
 *
 * See mq_h3.h for the user_data scheme and the ABSOLUTE RULES. In short:
 *   - the transport user_data slot (which xquic's internal H3 ALPN also makes
 *     the H3 conn's user_data) stays = mq_transport_t* forever, so our h3 conn
 *     callbacks receive the TRANSPORT, not our wrapper. We recover the
 *     mq_h3_conn from a small fixed table keyed by xqc_h3_conn_t*.
 *   - the h3 REQUEST user_data slot is independent and safe to own: it holds
 *     the mq_h3_req_t* (set at create on the client side, via
 *     xqc_h3_request_set_user_data on the server side).
 *
 * RECOVERING mq_h3 IN THE CALLBACKS: the H3 conn/request callbacks only receive
 * the transport (as h3c_user_data / via the request's conn user_data), and the
 * engine priv_ctx slot is already taken by mq_conn's ALPN — so we cannot stash
 * mq_h3 there. Instead a tiny file-scope transport->mq_h3 map (g_h3_by_transport)
 * lets every callback recover the owning mq_h3 from the transport. mq_h3_init
 * enforces one mq_h3 per transport, so the map is unambiguous. The engine is
 * single-threaded, so the map needs no locking.
 */
#include "transport/mq_h3.h"

#include <stdlib.h>
#include <string.h>

#include "transport/mq_conn.h" /* mq_conn_apply_mp_settings, mq_conn_dump_stats_cid */
#include "util/mq_log.h"

/* Max H3 conns tracked per transport. The proxy opens one H3 conn per upstream
 * (Phase 2 is a single client conn; servers accept a handful). The table is
 * small + fixed to mirror the transport's mp-ready table discipline; the insert
 * guard logs + drops on overflow rather than growing unboundedly. */
#define MQ_H3_MAX_CONNS 16

/* Max extra (non-primary) paths per H3 conn — mirrors MQ_CONN_MAX_EXTRA_PATHS
 * (the runtime path map is 8 slots wide, path_id 0 is primary). */
#define MQ_H3_MAX_EXTRA_PATHS 7

/* Transport -> mq_h3 map. mq_h3_init enforces one mq_h3 per transport, so this
 * tiny global table (engine priv_ctx is taken by mq_conn) lets the H3 conn
 * callbacks — which only receive the transport as h3c_user_data — recover the
 * owning mq_h3. Single-threaded engine, so no locking. */
#define MQ_H3_MAX_TRANSPORTS 8
static struct {
    mq_transport_t *t;
    mq_h3_t *h;
} g_h3_by_transport[MQ_H3_MAX_TRANSPORTS];

struct mq_h3_conn_s {
    mq_h3_t *owner;
    mq_transport_t *transport;
    xqc_h3_conn_t *h3c; /* table key; valid for the conn's lifetime */
    xqc_cid_t cid;
    int have_cid;
    int is_server;

    mq_h3_conn_state_fn on_state;
    void *on_state_user;

    /* Multipath: set once xquic fires ready_to_create_path_notify for our cid. */
    int mp_ready;

    uint64_t extra_path_ids[MQ_H3_MAX_EXTRA_PATHS];
    int n_extra_paths;
};

struct mq_h3_req_s {
    mq_h3_conn_t *conn;
    xqc_h3_request_t *r; /* xquic request handle */

    mq_h3_req_on_read_fn on_read;
    mq_h3_req_on_write_fn on_write;
    mq_h3_req_on_close_fn on_close;
    void *cb_user;
};

struct mq_h3_s {
    mq_transport_t *transport;
    int initialised; /* xqc_h3_ctx_init succeeded (so mq_h3_free must destroy) */

    mq_h3_on_new_conn_fn on_conn;
    mq_h3_on_new_req_fn on_req;
    void *user;

    /* Conn recovery table (xqc_h3_conn_t* -> mq_h3_conn_t*). INSERT in
     * h3_conn_create_notify, REMOVE + free in h3_conn_close_notify. */
    mq_h3_conn_t *conns[MQ_H3_MAX_CONNS];
    int n_conns;

    /* Hand-off for the client connect path: set immediately before
     * xqc_h3_connect so the synchronous create_notify adopts this wrapper
     * instead of building a server-style one. Cleared on adoption. */
    mq_h3_conn_t *pending_client_conn;

    /* Most-recently-serviced server conn, used to attribute a peer-initiated
     * request to its owning connection. Same pattern + limitation as
     * mq_conn's active_server_conn (no public request->h3_conn accessor in the
     * shared lib; on this single-threaded engine a conn's create/handshake runs
     * before its first request's create_notify).
     *
     * xqc_h3_get_conn_user_data_by_request exists but returns the TRANSPORT
     * user_data, not the mq_h3_conn wrapper — it is used below to recover the
     * mq_h3 from the transport map, not to recover the per-conn wrapper. A true
     * per-request h3-conn accessor would need a fork export (analogous to
     * mq_conn.c's xqc_get_conn_alp_user_data_by_stream note); absent that, this
     * windowed slot is the only safe recovery path. */
    mq_h3_conn_t *active_server_conn;
};

/* ── transport <-> mq_h3 map ────────────────────────────────────────────── */

static mq_h3_t *
mq_h3_for_transport(mq_transport_t *t)
{
    for (int i = 0; i < MQ_H3_MAX_TRANSPORTS; i++) {
        if (g_h3_by_transport[i].t == t) {
            return g_h3_by_transport[i].h;
        }
    }
    return NULL;
}

static int
mq_h3_map_insert(mq_transport_t *t, mq_h3_t *h)
{
    for (int i = 0; i < MQ_H3_MAX_TRANSPORTS; i++) {
        if (g_h3_by_transport[i].t == NULL) {
            g_h3_by_transport[i].t = t;
            g_h3_by_transport[i].h = h;
            return 0;
        }
    }
    return -1;
}

static void
mq_h3_map_remove(mq_transport_t *t)
{
    for (int i = 0; i < MQ_H3_MAX_TRANSPORTS; i++) {
        if (g_h3_by_transport[i].t == t) {
            g_h3_by_transport[i].t = NULL;
            g_h3_by_transport[i].h = NULL;
            return;
        }
    }
}

/* ── conn table ─────────────────────────────────────────────────────────── */

static mq_h3_conn_t *
mq_h3_conn_lookup(mq_h3_t *h, xqc_h3_conn_t *h3c)
{
    for (int i = 0; i < h->n_conns; i++) {
        if (h->conns[i]->h3c == h3c) {
            return h->conns[i];
        }
    }
    return NULL;
}

static int
mq_h3_conn_table_insert(mq_h3_t *h, mq_h3_conn_t *c)
{
    if (h->n_conns >= MQ_H3_MAX_CONNS) {
        MQ_LOGW("mq_h3: conn table full (%d slots)", MQ_H3_MAX_CONNS);
        return -1;
    }
    h->conns[h->n_conns++] = c;
    return 0;
}

static void
mq_h3_conn_table_remove(mq_h3_t *h, mq_h3_conn_t *c)
{
    for (int i = 0; i < h->n_conns; i++) {
        if (h->conns[i] == c) {
            /* Compact the tail down so the lookup loop never indexes a freed
             * slot (mirrors the transport's mp-ready table discipline). */
            for (int j = i; j < h->n_conns - 1; j++) {
                h->conns[j] = h->conns[j + 1];
            }
            h->n_conns--;
            h->conns[h->n_conns] = NULL;
            return;
        }
    }
}

/* ── multipath ──────────────────────────────────────────────────────────── */

/* Engine mp-ready hook: xquic signalled that the conn identified by scid can
 * create a path. Broadcast to every subscriber on the transport, so filter by
 * scid and only flip OUR conn. scid points at an aligned copy made by the
 * transport dispatch point, so plain member access is safe here. */
static void
mq_h3_conn_on_mp_ready(const xqc_cid_t *scid, void *user)
{
    mq_h3_conn_t *c = (mq_h3_conn_t *)user;
    if (!c || !c->have_cid || !scid) {
        return;
    }
    if (scid->cid_len == c->cid.cid_len &&
        memcmp(scid->cid_buf, c->cid.cid_buf, c->cid.cid_len) == 0) {
        c->mp_ready = 1;
    }
}

/* ── H3 connection callbacks ────────────────────────────────────────────── */

/* h3_conn_create_notify: h3c_user_data is the TRANSPORT (xquic's internal H3
 * ALPN copies the conn's transport user_data into the H3 conn's user_data).
 * cid is the conn's scid (owned by xquic). */
static int
mq_h3_conn_create_notify(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *h3c_user_data)
{
    mq_transport_t *t = (mq_transport_t *)h3c_user_data;
    mq_h3_t *h = mq_h3_for_transport(t);
    if (!h) {
        MQ_LOGE("mq_h3: conn_create_notify with no mq_h3 for transport");
        return -1;
    }

    /* Client side: adopt the wrapper the caller pre-allocated in mq_h3_connect.
     * Its cid was filled from xqc_h3_connect's return; bind the h3c handle. */
    if (h->pending_client_conn) {
        mq_h3_conn_t *c = h->pending_client_conn;
        h->pending_client_conn = NULL;
        c->h3c = h3c;
        /* cid may be misaligned inside xquic internals; copy bytewise. */
        memcpy(&c->cid, (const void *)cid, sizeof(c->cid));
        c->have_cid = 1;
        if (mq_h3_conn_table_insert(h, c) != 0) {
            return -1;
        }
        return 0;
    }

    /* Server side: build a wrapper for the accepted connection. */
    mq_h3_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return -1;
    }
    c->owner = h;
    c->transport = t;
    c->h3c = h3c;
    c->is_server = 1;
    memcpy(&c->cid, (const void *)cid, sizeof(c->cid));
    c->have_cid = 1;
    if (mq_h3_conn_table_insert(h, c) != 0) {
        free(c);
        return -1;
    }
    h->active_server_conn = c;

    if (h->on_conn) {
        h->on_conn(c, h->user);
    }
    return 0;
}

static int
mq_h3_conn_close_notify(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *h3c_user_data)
{
    (void)cid;
    mq_transport_t *t = (mq_transport_t *)h3c_user_data;
    mq_h3_t *h = mq_h3_for_transport(t);
    if (!h) {
        return 0;
    }
    mq_h3_conn_t *c = mq_h3_conn_lookup(h, h3c);
    if (!c) {
        return 0;
    }
    if (c->on_state) {
        c->on_state(c, /*established=*/0, c->on_state_user);
    }
    /* Unsubscribe from the transport's mp-ready broadcast BEFORE free(c): with
     * multiple conns on one transport the subscriber table outlives this conn,
     * and a later readiness broadcast would deref freed memory. A no-op for
     * server conns (never subscribed; matched by fn+user, not found). */
    mq_transport_remove_mp_ready_cb(t, mq_h3_conn_on_mp_ready, c);
    /* Release any secondary paths this conn owns. */
    for (int i = 0; i < c->n_extra_paths; i++) {
        mq_transport_close_path(t, c->extra_path_ids[i]);
    }
    if (h->active_server_conn == c) {
        h->active_server_conn = NULL;
    }
    mq_h3_conn_table_remove(h, c);
    free(c);
    return 0;
}

static void
mq_h3_conn_handshake_finished(xqc_h3_conn_t *h3c, void *h3c_user_data)
{
    mq_transport_t *t = (mq_transport_t *)h3c_user_data;
    mq_h3_t *h = mq_h3_for_transport(t);
    if (!h) {
        return;
    }
    mq_h3_conn_t *c = mq_h3_conn_lookup(h, h3c);
    if (!c) {
        return;
    }
    /* For a server conn, refresh the active-conn slot so the imminent first
     * request is attributed to this connection (see active_server_conn). */
    if (c->is_server) {
        h->active_server_conn = c;
    }
    if (c->on_state) {
        c->on_state(c, /*established=*/1, c->on_state_user);
    }
}

/* ── H3 request callbacks ───────────────────────────────────────────────── */

/* h3_request_create_notify: for a client request, h3s_user_data is the wrapper
 * passed to xqc_h3_request_create. For a server (peer-initiated) request,
 * h3s_user_data is NULL — wrap it and surface to the owner. */
static int
mq_h3_request_create_notify(xqc_h3_request_t *r, void *h3s_user_data)
{
    if (h3s_user_data) {
        /* Locally-initiated request (mq_h3_req_open): already bound. */
        return 0;
    }

    /* Peer-initiated request: recover the owning mq_h3 from the request's conn
     * user_data (the transport), then attribute it to the active server conn. */
    mq_transport_t *t = (mq_transport_t *)xqc_h3_get_conn_user_data_by_request(r);
    mq_h3_t *h = mq_h3_for_transport(t);
    if (!h) {
        return -1;
    }
    mq_h3_req_t *req = calloc(1, sizeof(*req));
    if (!req) {
        return -1;
    }
    req->r = r;
    /* active_server_conn can be NULL if the request's create_notify fires outside
     * the conn create/handshake window (attribution window edge case, e.g. a very
     * late peer-initiated stream after close_notify cleared the slot). Downstream
     * owners MUST guard against a NULL req->conn before dereferencing it. */
    req->conn = h->active_server_conn;
    /* Bind the wrapper as the request's user_data so subsequent read/write/close
     * notifies recover it directly (independent per-stream slot — safe). */
    xqc_h3_request_set_user_data(r, req);

    if (h->on_req) {
        h->on_req(req, h->user);
    }
    return 0;
}

static int
mq_h3_request_close_notify(xqc_h3_request_t *r, void *h3s_user_data)
{
    (void)r;
    mq_h3_req_t *req = (mq_h3_req_t *)h3s_user_data;
    if (!req) {
        return 0;
    }
    if (req->on_close) {
        req->on_close(req, req->cb_user);
    }
    free(req);
    return 0;
}

static int
mq_h3_request_read_notify(xqc_h3_request_t *r, xqc_request_notify_flag_t flag,
                          void *h3s_user_data)
{
    (void)r;
    mq_h3_req_t *req = (mq_h3_req_t *)h3s_user_data;
    if (req && req->on_read) {
        req->on_read(req, (int)flag, req->cb_user);
    }
    return 0;
}

static int
mq_h3_request_write_notify(xqc_h3_request_t *r, void *h3s_user_data)
{
    (void)r;
    mq_h3_req_t *req = (mq_h3_req_t *)h3s_user_data;
    if (req && req->on_write) {
        req->on_write(req, req->cb_user);
    }
    return 0;
}

/* ── init / free ────────────────────────────────────────────────────────── */

mq_h3_t *
mq_h3_init(mq_transport_t *t, mq_h3_on_new_conn_fn on_conn, mq_h3_on_new_req_fn on_req,
           void *user)
{
    if (!t) {
        return NULL;
    }
    xqc_engine_t *xeng = mq_transport_xqc(t);
    if (!xeng) {
        return NULL;
    }
    /* One mq_h3 per transport: xqc_h3_ctx_init re-registers the H3 ALPN (not
     * idempotent), so a second init would corrupt the engine's ALPN list. */
    if (mq_h3_for_transport(t)) {
        MQ_LOGE("mq_h3: transport already has an mq_h3 (init is one-per-transport)");
        return NULL;
    }

    mq_h3_t *h = calloc(1, sizeof(*h));
    if (!h) {
        return NULL;
    }
    h->transport = t;
    h->on_conn = on_conn;
    h->on_req = on_req;
    h->user = user;

    /* Register the transport->mq_h3 map entry BEFORE xqc_h3_ctx_init so a
     * synchronous create_notify (none expected here, but be safe) can find us. */
    if (mq_h3_map_insert(t, h) != 0) {
        MQ_LOGE("mq_h3: transport map full");
        free(h);
        return NULL;
    }

    xqc_h3_callbacks_t h3_cbs;
    memset(&h3_cbs, 0, sizeof(h3_cbs));
    h3_cbs.h3c_cbs.h3_conn_create_notify = mq_h3_conn_create_notify;
    h3_cbs.h3c_cbs.h3_conn_close_notify = mq_h3_conn_close_notify;
    h3_cbs.h3c_cbs.h3_conn_handshake_finished = mq_h3_conn_handshake_finished;
    h3_cbs.h3r_cbs.h3_request_create_notify = mq_h3_request_create_notify;
    h3_cbs.h3r_cbs.h3_request_close_notify = mq_h3_request_close_notify;
    h3_cbs.h3r_cbs.h3_request_read_notify = mq_h3_request_read_notify;
    h3_cbs.h3r_cbs.h3_request_write_notify = mq_h3_request_write_notify;

    if (xqc_h3_ctx_init(xeng, &h3_cbs) != XQC_OK) {
        MQ_LOGE("mq_h3: xqc_h3_ctx_init failed");
        mq_h3_map_remove(t);
        free(h);
        return NULL;
    }
    h->initialised = 1;
    return h;
}

void
mq_h3_free(mq_h3_t *h)
{
    if (!h) {
        return;
    }
    /* Destroy the H3 ctx BEFORE the engine is destroyed (mq_transport_free).
     * xqc_h3_ctx_destroy unregisters the H3 ALPNs and frees the H3 ctxs via the
     * still-live engine; if the engine were destroyed first it would already
     * have freed its ALPN list. Hence the contract: free the mq_h3 before
     * mq_transport_free.
     *
     * CONN-WRAPPER OWNERSHIP: unlike mq_conn (whose ALPN ctx stays registered
     * until xqc_engine_destroy, so the engine teardown fires conn_close_notify
     * and frees each wrapper), the H3 ALPN callbacks are unregistered HERE by
     * xqc_h3_ctx_destroy — strictly before the engine is destroyed in
     * mq_transport_free. So any conn still in the table will NEVER get a
     * subsequent h3_conn_close_notify (its callback is already gone), and the
     * wrapper would leak. We therefore free the remaining wrappers ourselves,
     * after the ctx is destroyed. (mq_h3_conn_close on a live conn defers its
     * close_notify to engine teardown, which no longer reaches us — so this is
     * the real single free point for any wrapper that outlived an explicit
     * close, as well as for conns never closed by the owner.) */
    if (h->initialised && h->transport) {
        xqc_h3_ctx_destroy(mq_transport_xqc(h->transport));
    }
    for (int i = 0; i < h->n_conns; i++) {
        /* Best-effort lifecycle signal so an owner watching state sees the conn
         * go away; then unsubscribe + free (mirrors h3_conn_close_notify, minus
         * the path teardown which the engine destroy below reclaims). */
        mq_h3_conn_t *c = h->conns[i];
        if (c->on_state) {
            c->on_state(c, /*established=*/0, c->on_state_user);
        }
        if (h->transport) {
            mq_transport_remove_mp_ready_cb(h->transport, mq_h3_conn_on_mp_ready, c);
        }
        free(c);
        h->conns[i] = NULL;
    }
    h->n_conns = 0;
    mq_h3_map_remove(h->transport);
    free(h);
}

/* ── client connect ─────────────────────────────────────────────────────── */

mq_h3_conn_t *
mq_h3_connect(mq_h3_t *h, const struct sockaddr *peer, socklen_t peerlen, mq_cc_t cc,
              mq_h3_conn_state_fn st, void *user)
{
    if (!h || !peer) {
        return NULL;
    }
    mq_transport_t *t = h->transport;
    xqc_engine_t *xeng = mq_transport_xqc(t);
    if (!xeng) {
        return NULL;
    }

    mq_h3_conn_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->owner = h;
    c->transport = t;
    c->is_server = 0;
    c->on_state = st;
    c->on_state_user = user;

    /* Subscribe to ready_to_create_path_notify (broadcast to every subscriber;
     * mq_h3_conn_on_mp_ready filters by scid to flip only THIS conn). */
    if (mq_transport_add_mp_ready_cb(t, mq_h3_conn_on_mp_ready, c) != 0) {
        MQ_LOGE("mq_h3: mp-ready subscriber table full");
        free(c);
        return NULL;
    }

    /* Same conn settings as the raw conn (multipath + CC + flow control).
     * proto_version MUST be set: xqc_h3_connect selects the H3 ALPN string via
     * xqc_h3_alpn[proto_version], and the default (XQC_IDRAFT_INIT_VER == 0) maps
     * to "" — an empty ALPN — which fails the client TLS handshake with
     * NO_APPLICATION_PROTOCOL. QUIC v1 maps to the "h3" ALPN. */
    xqc_conn_settings_t s;
    memset(&s, 0, sizeof(s));
    s.proto_version = XQC_VERSION_V1;
    mq_conn_apply_mp_settings(&s, /*is_server=*/0, cc);

    xqc_conn_ssl_config_t conn_ssl;
    memset(&conn_ssl, 0, sizeof(conn_ssl));

    /* Hand the wrapper to the imminent (synchronous) create_notify. */
    h->pending_client_conn = c;

    /* server_host is the TLS SNI; xquic dereferences it unconditionally, so it
     * must be non-NULL even on loopback. user_data MUST be the transport (RULE
     * #1): xquic makes it the H3 conn's user_data, which the send path casts to
     * mq_transport_t*. */
    const xqc_cid_t *cid = xqc_h3_connect(xeng, &s, NULL, 0, "mqproxy",
                                          /*no_crypto_flag=*/0, &conn_ssl, peer, peerlen,
                                          /*transport user_data=*/t);
    if (!cid) {
        MQ_LOGE("mq_h3: xqc_h3_connect failed");
        h->pending_client_conn = NULL;
        mq_transport_remove_mp_ready_cb(t, mq_h3_conn_on_mp_ready, c);
        free(c);
        return NULL;
    }
    memcpy(&c->cid, cid, sizeof(c->cid));
    c->have_cid = 1;

    if (h->pending_client_conn == c) {
        /* create_notify did not fire synchronously; the wrapper was never bound
         * to an h3c handle nor inserted into the table — treat as a hard error. */
        h->pending_client_conn = NULL;
        MQ_LOGE("mq_h3: h3_conn_create_notify did not fire during xqc_h3_connect");
        mq_transport_remove_mp_ready_cb(t, mq_h3_conn_on_mp_ready, c);
        free(c);
        return NULL;
    }
    return c;
}

int
mq_h3_conn_mp_ready(const mq_h3_conn_t *c)
{
    return c ? c->mp_ready : 0;
}

void
mq_h3_conn_set_state_cb(mq_h3_conn_t *c, mq_h3_conn_state_fn st, void *user)
{
    if (!c) {
        return;
    }
    c->on_state = st;
    c->on_state_user = user;
}

int
mq_h3_conn_add_path(mq_h3_conn_t *c, const char *local_ip, uint16_t port)
{
    if (!c || !c->have_cid || !local_ip) {
        return -1;
    }
    if (c->n_extra_paths >= MQ_H3_MAX_EXTRA_PATHS) {
        MQ_LOGW("mq_h3: add_path: extra-path slots exhausted");
        return -1;
    }
    xqc_engine_t *xeng = mq_transport_xqc(c->transport);
    if (!xeng) {
        return -1;
    }

    /* 1. Ask xquic to allocate a new path-id (needs a spare peer cid; that is
     *    the ready_to_create_path precondition). path_status 0 == AVAILABLE. */
    uint64_t new_path_id = 0;
    xqc_int_t rc = xqc_conn_create_path(xeng, &c->cid, &new_path_id, /*AVAILABLE=*/0);
    if (rc != XQC_OK) {
        MQ_LOGW("mq_h3: xqc_conn_create_path failed: %d (mp_ready=%d)", (int)rc,
                c->mp_ready);
        return -1;
    }

    /* 2. Ask the runtime (via the transport) to open a UDP socket for it. */
    if (mq_transport_open_path(c->transport, new_path_id, local_ip, port) != 0) {
        MQ_LOGE("mq_h3: add_path: open_path_socket(path %llu) failed",
                (unsigned long long)new_path_id);
        /* Tear the half-created xquic path back down so it does not linger
         * waiting on a socket that will never exist. */
        xqc_conn_close_path(xeng, &c->cid, new_path_id);
        return -1;
    }

    /* 3. Mark the path available so the peer may schedule traffic on it. */
    if (xqc_conn_mark_path_available(xeng, &c->cid, new_path_id) != XQC_OK) {
        MQ_LOGW("mq_h3: mark_path_available(path %llu) failed",
                (unsigned long long)new_path_id);
        /* Non-fatal: the path was created + socket bound; keep it alive. */
    }

    c->extra_path_ids[c->n_extra_paths++] = new_path_id;
    return (int)new_path_id;
}

void
mq_h3_conn_dump_stats(mq_h3_conn_t *c)
{
    if (!c || !c->have_cid) {
        return;
    }
    /* Both H3 and raw conns share ONE engine, so the cid alone selects the
     * connection; delegate to mq_conn's shared cid-keyed core. */
    mq_conn_dump_stats_cid(c->transport, &c->cid);
}

void
mq_h3_conn_close(mq_h3_conn_t *c)
{
    if (!c || !c->have_cid) {
        return;
    }
    /* Request close only; the wrapper is freed centrally in close_notify. */
    xqc_h3_conn_close(mq_transport_xqc(c->transport), &c->cid);
}

/* ── request ────────────────────────────────────────────────────────────── */

void
mq_h3_req_set_cbs(mq_h3_req_t *r, mq_h3_req_on_read_fn on_read,
                  mq_h3_req_on_write_fn on_write, mq_h3_req_on_close_fn on_close,
                  void *user)
{
    if (!r) {
        return;
    }
    r->on_read = on_read;
    r->on_write = on_write;
    r->on_close = on_close;
    r->cb_user = user;
}

mq_h3_req_t *
mq_h3_req_open(mq_h3_conn_t *c)
{
    if (!c || !c->have_cid) {
        return NULL;
    }
    mq_h3_req_t *req = calloc(1, sizeof(*req));
    if (!req) {
        return NULL;
    }
    req->conn = c;
    /* Pass the wrapper as the request user_data so the synchronous
     * create_notify (and later read/write/close notifies) recover it. This is
     * the independent per-stream slot — safe to own (unlike the conn slot).
     *
     * No defensive post-create bind (unlike mq_conn_open_stream) is needed here:
     * the request handle is only available as the return value of
     * xqc_h3_request_create, and no callback can fire on a brand-new
     * locally-initiated request before the caller has stored the return value. */
    xqc_h3_request_t *r =
        xqc_h3_request_create(mq_transport_xqc(c->transport), &c->cid, NULL, req);
    if (!r) {
        MQ_LOGW("mq_h3: xqc_h3_request_create failed");
        free(req);
        return NULL;
    }
    req->r = r;
    return req;
}

/* Normalise an xquic send return like mq_stream_send: -XQC_EAGAIN -> 0 (retry
 * after on_write), other negatives -> -1, else the byte/finish count. */
static long
mq_h3_norm_send(ssize_t rv, const char *what)
{
    if (rv == -XQC_EAGAIN) {
        return 0;
    }
    if (rv < 0) {
        MQ_LOGW("mq_h3: %s failed: %zd", what, rv);
        return -1;
    }
    return (long)rv;
}

long
mq_h3_req_send_headers(mq_h3_req_t *r, const mq_h3_header_t *hs, size_t n, int fin)
{
    if (!r || !r->r || (n && !hs)) {
        return -1;
    }
    if (n == 0 && !fin) {
        return 0;
    }

    /* Build the xqc_http_headers_t. Header name/value are NUL-terminated C
     * strings; frame each as an iovec (strlen). The header array is stack/heap
     * scratch consumed entirely by xqc_h3_request_send_headers. */
    xqc_http_header_t *arr = NULL;
    if (n) {
        arr = calloc(n, sizeof(*arr));
        if (!arr) {
            return -1;
        }
        for (size_t i = 0; i < n; i++) {
            const char *name = hs[i].name ? hs[i].name : "";
            const char *value = hs[i].value ? hs[i].value : "";
            arr[i].name.iov_base = (void *)name;
            arr[i].name.iov_len = strlen(name);
            arr[i].value.iov_base = (void *)value;
            arr[i].value.iov_len = strlen(value);
            arr[i].flags = XQC_HTTP_HEADER_FLAG_NONE;
        }
    }
    xqc_http_headers_t headers;
    memset(&headers, 0, sizeof(headers));
    headers.headers = arr;
    headers.count = n;
    headers.capacity = n;

    ssize_t rv = xqc_h3_request_send_headers(r->r, &headers, fin ? 1 : 0);
    free(arr);
    return mq_h3_norm_send(rv, "send_headers");
}

long
mq_h3_req_send_body(mq_h3_req_t *r, const uint8_t *p, size_t len, int fin)
{
    if (!r || !r->r) {
        return -1;
    }
    /* xqc_h3_request_send_body takes a non-const pointer but does not mutate the
     * buffer; cast away const. */
    union {
        const uint8_t *cp;
        unsigned char *p;
    } u = {.cp = p};
    ssize_t rv = xqc_h3_request_send_body(r->r, u.p, len, fin ? 1 : 0);
    return mq_h3_norm_send(rv, "send_body");
}

long
mq_h3_req_finish(mq_h3_req_t *r)
{
    if (!r || !r->r) {
        return -1;
    }
    ssize_t rv = xqc_h3_request_finish(r->r);
    return mq_h3_norm_send(rv, "finish");
}

int
mq_h3_req_recv_headers(mq_h3_req_t *r,
                       void (*each)(const char *n, size_t nl, const char *v, size_t vl,
                                    void *u),
                       void *u, int *fin)
{
    if (fin) {
        *fin = 0;
    }
    if (!r || !r->r) {
        return -1;
    }
    uint8_t xfin = 0;
    /* xquic OWNS the returned headers; they are valid only here (consumed
     * within this call) — copy out via `each` if the caller needs them later.
     * NULL is returned both on hard error AND when no header section is pending
     * (READ_HEADER/READ_TRAILER not set); callers must gate on the notify flag. */
    xqc_http_headers_t *hdrs = xqc_h3_request_recv_headers(r->r, &xfin);
    if (!hdrs) {
        return -1;
    }
    if (each) {
        for (size_t i = 0; i < hdrs->count; i++) {
            const xqc_http_header_t *hh = &hdrs->headers[i];
            each((const char *)hh->name.iov_base, hh->name.iov_len,
                 (const char *)hh->value.iov_base, hh->value.iov_len, u);
        }
    }
    if (fin) {
        *fin = xfin ? 1 : 0;
    }
    return (int)hdrs->count;
}

long
mq_h3_req_recv_body(mq_h3_req_t *r, uint8_t *buf, size_t cap, int *fin)
{
    if (fin) {
        *fin = 0;
    }
    if (!r || !r->r) {
        return -1;
    }
    uint8_t xfin = 0;
    ssize_t rv = xqc_h3_request_recv_body(r->r, (unsigned char *)buf, cap, &xfin);
    if (rv == -XQC_EAGAIN) {
        return 0;
    }
    if (rv < 0) {
        MQ_LOGW("mq_h3: recv_body failed: %zd", rv);
        return -1;
    }
    if (fin) {
        *fin = xfin ? 1 : 0;
    }
    return (long)rv;
}

void
mq_h3_req_reset(mq_h3_req_t *r)
{
    if (!r || !r->r) {
        return;
    }
    xqc_h3_request_close(r->r);
}
