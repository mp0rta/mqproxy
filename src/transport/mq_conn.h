// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_conn.h — wrapper around one raw MPQUIC (xqc_connection_t) connection.
 *
 * mq_conn ties an xquic connection (identified by its scid) to an owner. It
 * is the application-protocol layer for the "mqproxy-tcp/1" ALPN: the
 * connection and stream callback tables registered via mq_conn_register_alpn
 * recover the mq_conn from xquic's per-connection app-proto user_data and
 * surface lifecycle + new-stream events to the owner.
 *
 * USER_DATA SCHEME (see mq_transport's send callback):
 *   - transport user_data  = the mq_transport_t* (so write_socket[_ex] recovers
 *                            the transport by casting conn_user_data).
 *   - app-proto user_data  = the mq_conn_t* (so the ALP conn/stream callbacks
 *                            recover the mq_conn).
 * The transport pointer is also stashed via xqc_engine_set_priv_ctx so the ALP
 * conn_create_notify can locate the per-engine registration context.
 */
#ifndef MQ_TRANSPORT_MQ_CONN_H
#define MQ_TRANSPORT_MQ_CONN_H

#include <sys/socket.h>

#include <xquic/xquic.h>

#include "transport/mq_stream.h"
#include "transport/mq_transport.h"

/* ── Congestion control selection ───────────────────────────────────────────
 *
 * Which xquic congestion-control algorithm the proxy installs on its conn
 * settings. BBR is the default (MQ_CC_DEFAULT) — it gave the best single-path
 * throughput in the shaped 1-B benchmark; BBR2 / CUBIC are selectable (e.g. CLI
 * --cc) for benchmarking and A/B comparison. Maps to xqc_{bbr2,bbr,cubic}_cb in
 * mq_conn_apply_mp_settings. (reno/copa are #ifdef-gated out of this xquic
 * build, so not exposed.) */
typedef enum {
    MQ_CC_BBR2 = 0,
    MQ_CC_BBR = 1,
    MQ_CC_CUBIC = 2,
} mq_cc_t;

/* The policy default CC used when none is explicitly selected (CLI --cc unset).
 * The enum numeric values are independent of this. */
#define MQ_CC_DEFAULT MQ_CC_BBR

/* Parse a CC name ("bbr2"/"bbr"/"cubic") into mq_cc_t. On an unknown name
 * returns MQ_CC_DEFAULT and sets *ok=0 (if ok!=NULL); on a known name *ok=1. */
mq_cc_t mq_cc_from_string(const char *name, int *ok);

/* Human-readable name for logging ("bbr2"/"bbr"/"cubic"). */
const char *mq_cc_name(mq_cc_t cc);

/* ── Flow-control window sizing (aggregate-BDP target) ──────────────────────
 *
 * The proxy aggregates throughput across multiple paths, so the receive
 * windows must cover the sum-of-paths bandwidth-delay product, not a single
 * path's. Targets: ≥8MB advertised per-stream, ≤16MB per-connection.
 *
 * xquic's HARD ceiling is XQC_MAX_RECV_WINDOW = 16MB (internal
 * src/transport/xqc_conn.h, not on the public include path). Raising the
 * window above it requires a fork patch — the static_assert below guards that.
 *
 * HOW THESE MAP ONTO xquic (see xqc_conn.c xqc_conn_create_settings /
 * local_settings derivation, the `else`/`if (enable_stream_rate_limit)`
 * blocks):
 *   - max_stream_data_bidi_remote / _uni are ALWAYS XQC_MAX_RECV_WINDOW (16MB).
 *   - max_stream_data_bidi_local (the window WE advertise to the peer for the
 *     streams the peer opens to us — i.e. what gates inbound stream data) is:
 *         enable_stream_rate_limit == 0  ->  XQC_MAX_RECV_WINDOW (16MB)  [DEFAULT]
 *         enable_stream_rate_limit == 1  ->  init_recv_window
 *   - conn-level max_data (when not interop / no recv_rate cap) is derived as
 *     max_streams * per-stream-window, i.e. far above 16MB; there is no public
 *     knob to pin it to exactly 16MB without recv_rate_bytes_per_sec, so
 *     MQ_CONN_WINDOW documents intent and bounds the static-assert ceiling.
 *
 * We rely on xquic's DEFAULT (enable_stream_rate_limit == 0) which advertises
 * max_stream_data_bidi_local = XQC_MAX_RECV_WINDOW = 16MB. This is ≥ the 8MB
 * aggregate-BDP target and matches mqvpn's recipe (no rate-limit knob set).
 * MQ_STREAM_WINDOW / MQ_CONN_WINDOW are documentary constants; the
 * static_asserts guard that they stay within the xquic fork ceiling. */
#define MQ_STREAM_WINDOW (8 * 1024 * 1024)
#define MQ_CONN_WINDOW   (16 * 1024 * 1024)
/* Mirrors XQC_MAX_RECV_WINDOW (internal xqc_conn.h). Keep in sync. */
#define MQ_XQUIC_MAX_RECV_WINDOW (16 * 1024 * 1024)
_Static_assert(MQ_CONN_WINDOW <= MQ_XQUIC_MAX_RECV_WINDOW,
               "window exceeds xquic ceiling; raising it needs a fork patch");
_Static_assert(MQ_STREAM_WINDOW <= MQ_XQUIC_MAX_RECV_WINDOW,
               "stream window exceeds xquic ceiling; raising it needs a fork patch");

/* Apply the proxy's multipath + flow-control window settings to a freshly
 * memset() xqc_conn_settings_t. `is_server` selects the server-only
 * PATHS_BLOCKED auto-grant (max_path_id_grant_max_value). Call after setting
 * proto_version / cc / pacing etc. */
void mq_conn_apply_mp_settings(xqc_conn_settings_t *s, int is_server, mq_cc_t cc);

typedef struct mq_conn_s mq_conn_t;

/* Connection lifecycle state reported to the owner. */
typedef enum {
    MQ_CONN_ESTABLISHED = 1, /* handshake finished */
    MQ_CONN_CLOSED = 2,      /* connection closed (mq_conn freed right after) */
} mq_conn_state_t;

typedef void (*mq_conn_on_state_fn)(mq_conn_t *c, mq_conn_state_t st, void *user);

/* Server-side hooks: invoked when xquic accepts a connection / creates a peer
 * stream for the registered ALPN. on_new_conn yields a freshly-created
 * mq_conn (owner may attach its own context via mq_conn_set_on_state / the
 * stream's mq_stream_set_cbs). on_new_stream yields a freshly-created
 * mq_stream. Either may be NULL (e.g. on a client engine). */
typedef void (*mq_conn_on_new_fn)(mq_conn_t *c, void *user);
typedef void (*mq_stream_on_new_fn)(mq_stream_t *s, void *user);

/* Register the ALP callback tables for `alpn` on `eng`. Both client and
 * server engines must register before connecting / accepting. on_new_conn /
 * on_new_stream / user describe how accepted connections and peer-initiated
 * streams are surfaced (server side); pass NULL on a pure client.
 * Returns 0 on success, -1 on failure. */
int mq_conn_register_alpn(mq_transport_t *t, const char *alpn,
                          mq_conn_on_new_fn on_new_conn,
                          mq_stream_on_new_fn on_new_stream, void *user);

/* Client: initiate a connection to `peer` using `alpn` and `settings`.
 * `owner` is opaque caller context (retrievable via mq_conn_user). Returns a
 * new mq_conn (state callbacks fire later) or NULL on failure. */
mq_conn_t *mq_conn_connect(mq_transport_t *t, const struct sockaddr *peer,
                           socklen_t peerlen, const char *alpn,
                           const xqc_conn_settings_t *settings, void *owner);

/* Register the owner's state callback (established / closed). */
void mq_conn_set_on_state(mq_conn_t *c, mq_conn_on_state_fn fn, void *user);

/* Opaque owner context. For client conns this is the `owner` passed to
 * mq_conn_connect; for server conns it is initially NULL (settable via
 * mq_conn_set_user). */
void *mq_conn_user(const mq_conn_t *c);
void mq_conn_set_user(mq_conn_t *c, void *owner);

/* Client: open a new locally-initiated bidirectional stream. Returns a new
 * mq_stream or NULL on failure. */
mq_stream_t *mq_conn_open_stream(mq_conn_t *c);

/* ── Multipath: add a second (or further) path ──────────────────────────────
 *
 * mq_conn_mp_ready: 1 once xquic has fired ready_to_create_path_notify for
 * this connection (cids exchanged) — i.e. mq_conn_add_path can now succeed.
 * Returns 0 before that (or on NULL). Client conns only. */
int mq_conn_mp_ready(const mq_conn_t *c);

/* Create a NEW MPQUIC path bound to local_ip:local_port (port 0 == ephemeral),
 * open its UDP socket via the transport's open_path_socket callback, and mark it
 * available so the peer may schedule traffic on it. The new path-id is recorded
 * by the conn and torn down (close_path_socket) on conn teardown.
 *
 * MUST be called after mq_conn_mp_ready(c) returns 1 (otherwise xquic has no
 * available path-id and the call fails). Returns the new path_id (> 0) on
 * success, or -1 on failure (not ready / out of path slots / bind failure).
 * Client conns only. */
int mq_conn_add_path(mq_conn_t *c, const char *local_ip, uint16_t local_port);

/* Current xquic path-state for path_id, by polling xqc_conn_get_stats.
 *   2 == XQC_PATH_STATE_ACTIVE (validated, usable) — the value of interest.
 * Returns -1 if the conn/path is unknown. (XQC_PATH_STATE_ACTIVE lives in the
 * private xqc_multipath.h, so the literal 2 mirrors mqvpn's usage.) */
int mq_conn_path_state(const mq_conn_t *c, uint64_t path_id);

/* ── Per-path observability (spec §23.1) ────────────────────────────────────
 *
 * mq_conn_dump_stats: snapshot per-path byte counters via xqc_conn_get_stats
 * and log each path's id / send-bytes / recv-bytes at INFO. If xquic reports no
 * path metrics (paths_info == NULL or count == 0) it logs "no path metrics".
 * The heap-allocated paths_info buffer is freed with libc free() (the xquic
 * ownership contract — see xqc_conn_stats_t doc). Smoke-safe on any conn. */
void mq_conn_dump_stats(mq_conn_t *c);

/* mq_conn_dump_stats_cid: the cid-keyed core of mq_conn_dump_stats, shared with
 * mq_h3 (whose conn wrapper is keyed by an h3 cid, not an mq_conn). Snapshots
 * per-path byte counters via xqc_conn_get_stats(transport-engine, cid) and logs
 * each path's id / send-bytes / recv-bytes at INFO; logs "no path metrics" if
 * xquic reports none. The heap-allocated paths_info buffer is freed with libc
 * free() (the xquic ownership contract — see xqc_conn_stats_t doc). A no-op if
 * t/cid is NULL. Both H3 and raw conns share ONE engine, so the cid alone
 * selects the connection. */
void mq_conn_dump_stats_cid(mq_transport_t *t, const xqc_cid_t *cid);

/* mq_conn_path_bytes: read path_id's cumulative send/recv byte counters from
 * the same stats snapshot. On success writes *sent / *recv and returns 0; if
 * the conn is unknown or path_id has no metrics, returns -1 and leaves *sent /
 * *recv untouched. sent / recv may be NULL (then only existence is checked). */
int mq_conn_path_bytes(const mq_conn_t *c, uint64_t path_id, uint64_t *sent,
                       uint64_t *recv);

/* ── QUIC DATAGRAM (Phase 3: UDP relay) ─────────────────────────────────────
 *
 * Thin wrappers over xquic's DATAGRAM API for the UDP-relay carrier. UDP
 * semantics: no retransmission, no ordering recovery — a lost/dropped datagram
 * is simply counted and the caller moves on (design §8/§9.2).
 *
 * Enabled by settings.max_datagram_frame_size on the mqproxy-tcp/1 conn (both
 * client and server). The gateway h3 conn does NOT set it and so reports mss==0
 * (peer-unsupported), which the wrappers below fail closed on. */

/* Receive notification for a DATAGRAM frame. data is owned by xquic and is
 * valid only for the duration of the callback — copy if needed. */
typedef void (*mq_conn_on_datagram_fn)(mq_conn_t *c, const uint8_t *data, size_t len,
                                       void *user);
void mq_conn_set_on_datagram(mq_conn_t *c, mq_conn_on_datagram_fn fn, void *user);

/* Send a DATAGRAM frame. Returns 0 on acceptance, -1 on a drop-equivalent
 * error (EAGAIN / TOO_LARGE / NOT_SUPPORTED / CLOSING are all collapsed into
 * -1 — the caller increments its counter and moves on. design §9.2). */
int mq_conn_datagram_send(mq_conn_t *c, const uint8_t *data, size_t len);

/* Current datagram payload ceiling at the QUIC layer. 0 = peer does not
 * support datagrams or the MSS is unknown. Subtract MQ_UDP_MSG_HDR to get the
 * effective UDP payload limit.
 *
 * Multipath note: xqc_datagram_get_mss returns only the connection-level
 * dgram_mss (based on conn->pkt_out_size) and does not reflect per-path MTU
 * differences (xqc_datagram.c xqc_datagram_record_mss). This wrapper therefore
 * enumerates active paths and takes the minimum of xqc_datagram_get_mss_on_path
 * across them, falling back to the connection-level value if no paths are
 * listed. */
size_t mq_conn_datagram_mss(const mq_conn_t *c);

/* Send CONNECTION_CLOSE. The mq_conn is freed later via conn_close_notify. */
void mq_conn_close(mq_conn_t *c);

#endif /* MQ_TRANSPORT_MQ_CONN_H */
