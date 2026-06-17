// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_server.c — proxy server + control-stream AUTH handshake.
 *
 * Per accepted connection: an mq_srv_conn state struct is allocated in
 * on_new_conn and hung off the mq_conn owner slot (mq_conn_set_user). It is
 * freed when the connection closes (state callback MQ_CONN_CLOSED).
 *
 * The FIRST bidi stream on a connection is the control stream: we accumulate
 * its bytes, decode AUTH_REQUEST, constant-time-compare the token to the
 * configured one, reply AUTH_RESPONSE, and on failure close the connection.
 * Later (non-control) streams are left unhandled here — Task 12 wires data
 * streams. The auth-attempt counter is bumped exactly once per control stream.
 */
#include "proxy/mq_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>

#include "proxy/mq_flow.h"
#include "proxy/mq_framebuf.h"
#include "proxy/mq_udp_session.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "transport/mq_transport.h"
#include "util/mq_ct.h"
#include "util/mq_log.h"
#include "wire/mq_varint.h"
#include "wire/mq_wire.h"

#define MQ_SERVER_ALPN "mqproxy-tcp/1"
#define MQ_SERVER_ID   "mqproxy-server"

/* Origin connect deadline. A non-blocking connect to a blackholed target would
 * otherwise pin an fd + QUIC stream + data node until the kernel TCP timeout
 * (~2 min). Cap it so a captured client cannot exhaust resources by dialing dead
 * hosts. Internal backstop (not operator-tuned); 15 s is well under the kernel
 * default and above any healthy origin's connect latency. */
#define MQ_SRV_CONNECT_TIMEOUT_MS 15000

/* The buffered AUTH_REQUEST / CONNECT_TCP_REQUEST is bounded by MQ_FRAMEBUF_CAP
 * (512): the full frame is at most version + client_id(<=64) + auth_token(<=256)
 * + host/port + small fields, comfortably under that. Exceeding the bound without
 * a decode is malformed. */

typedef struct mq_srv_conn_s mq_srv_conn_t;
typedef struct mq_srv_data_s mq_srv_data_t;

/* Per-connection state, hung off mq_conn's owner slot. */
struct mq_srv_conn_s {
    mq_server_t *server;
    int authed;
    int control_stream_seen; /* the first bidi stream was claimed as control */
    int auth_done;           /* AUTH_RESPONSE sent (control stream settled) */
    mq_stream_t *ctrl;

    mq_framebuf_t rx;

    /* Intrusive singly-linked list of active data streams / relays. */
    mq_srv_data_t *data_head;

    /* Per-connection UDP relay state (Chunk 5). Created in on_new_conn from the
     * server's udp settings; owns the session table + 0x02 OPEN handling. */
    mq_udp_srv_t *udp;
};

/* Per-data-stream state: one CONNECT_TCP request + its origin fd + relay.
 *
 * The stream⇄fd relay machinery (I/O adapters, fd events, completion/FIN/
 * half-close/deferred-reap) lives in the shared mq_flow module; this node owns
 * the protocol-specific phases on top of it.
 *
 * Lifecycle phases:
 *   1. Header accumulation: buffer bytes until CONNECT_TCP_REQUEST decodes.
 *   2. Connecting: non-blocking connect() in flight; a one-shot EV_WRITE event
 *      on the origin fd fires when the connect completes (or errors).
 *   3. Relaying: mq_flow drives the relay (mq_flow_begin_relay).
 *   4. Reaped: flow reaped (closes stream + fd once), node unlinked + freed.
 */
struct mq_srv_data_s {
    mq_srv_conn_t *sc;
    mq_flow_t *flow;          /* shared stream⇄fd relay node (owns stream + fd) */
    mq_stream_t *stream;      /* header phase: the data stream (also held by flow) */
    int fd;                   /* origin socket during connect; handed to flow on relay */
    struct event *connect_ev; /* one-shot EV_WRITE to detect connect completion */
    int reaped;
    int graceful; /* pre-relay error path sent a FIN'd response: do NOT RESET */

    mq_framebuf_t rx;
    size_t hdr_consumed; /* bytes of rx.buf the CONNECT_TCP_REQUEST occupied */

    mq_srv_data_t *next;
};

struct mq_server_s {
    mq_transport_t *transport;
    mq_runtime_t *rt;
    char auth_token[256];
    size_t auth_token_len;
    unsigned auth_attempts;
    uint64_t udp_idle_timeout_ms; /* idle timeout for UDP relay sessions (Chunk 5) */
    int udp_enabled;              /* whether to advertise MQ_FEAT_UDP_RELAY */
    /* Observability: the UDP relay state of the most-recently-accepted conn.
     * Set in on_new_conn, cleared when that conn closes. Single-conn observation
     * hook (see mq_server_last_udp_srv). */
    mq_udp_srv_t *last_udp;
    mq_conn_t *last_conn; /* most-recent accepted conn (Phase 5c observability) */
};


static void
srv_send_resp(mq_stream_t *s, mq_status_t status, mq_auth_err_t err, uint64_t features)
{
    mq_auth_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.error_code = err;
    resp.features = features;
    snprintf(resp.server_id, sizeof(resp.server_id), "%s", MQ_SERVER_ID);

    uint8_t buf[512];
    int n = mq_encode_auth_resp(buf, sizeof(buf), &resp);
    if (n < 0) {
        MQ_LOGE("mq_server: encode AUTH_RESPONSE failed");
        return;
    }
    /* No FIN: keep the control stream open (reused by later capabilities). */
    long sent = mq_stream_send(s, buf, (size_t)n, /*fin=*/0);
    if (sent < 0 || (size_t)sent != (size_t)n) {
        MQ_LOGW("mq_server: AUTH_RESPONSE send short/failed (%ld of %d)", sent, n);
    }
}

/* Control stream readable: accumulate, decode AUTH_REQUEST, authenticate. */
static void
srv_ctrl_readable(mq_stream_t *s, void *user)
{
    mq_srv_conn_t *sc = (mq_srv_conn_t *)user;
    mq_server_t *srv = sc->server;

    if (sc->auth_done) {
        /* Already settled; drain to avoid stalling the stream. */
        uint8_t scratch[256];
        int fin = 0;
        while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
        return;
    }

    mq_framebuf_fill(s, &sc->rx, NULL);

    mq_auth_req_t req;
    memset(&req, 0, sizeof(req));
    int consumed = mq_decode_auth_req(sc->rx.buf, sc->rx.len, &req);
    if (consumed < 0) {
        if (sc->rx.len >= sizeof(sc->rx.buf)) {
            /* Malformed / oversized: count the attempt, reject, close. */
            srv->auth_attempts++;
            sc->auth_done = 1;
            MQ_LOGW("mq_server: AUTH_REQUEST malformed/oversized, rejecting");
            srv_send_resp(s, MQ_STATUS_ERROR, MQ_AUTH_FAILED, 0);
            mq_conn_close((mq_conn_t *)mq_stream_conn(s));
        }
        return; /* otherwise: need more bytes */
    }

    /* A full AUTH_REQUEST decoded — this is the (single) auth attempt. */
    srv->auth_attempts++;
    sc->auth_done = 1;

    /* Constant-time token compare. auth_token is a fixed-size field; compare
     * over its NUL-terminated content length. */
    size_t tok_len = strnlen(req.auth_token, sizeof(req.auth_token));
    int ok = mq_ct_equal(req.auth_token, tok_len, srv->auth_token, srv->auth_token_len);

    if (ok) {
        sc->authed = 1;
        /* Open the datagram auth gate so mq_udp_srv_on_datagram accepts frames
         * for this connection (DATAGRAM frames bypass the 0x02 stream pre-auth
         * guard — this is the sole auth boundary for inbound datagrams). */
        mq_udp_srv_set_authed(sc->udp, 1);
        uint64_t feat = srv->udp_enabled ? MQ_FEAT_UDP_RELAY : 0;
        srv_send_resp(s, MQ_STATUS_OK, MQ_AUTH_OK, feat);
        MQ_LOGI("mq_server: auth OK for client_id='%s'", req.client_id);
    } else {
        srv_send_resp(s, MQ_STATUS_ERROR, MQ_AUTH_FAILED, 0);
        MQ_LOGW("mq_server: auth FAILED for client_id='%s'", req.client_id);
        mq_conn_close((mq_conn_t *)mq_stream_conn(s));
    }
}

/* ── data streams: CONNECT_TCP → origin dial → relay ─────────────────────── */

/* Send a CONNECT_TCP_RESPONSE on the data stream. fin!=0 closes the send
 * direction after the response (used on the error path so the response is not
 * abandoned by a RESET_STREAM — RESET discards un-acked stream data). */
static void
srv_send_tcp_resp(mq_stream_t *s, mq_status_t status, mq_tcp_err_t err, int fin)
{
    mq_connect_tcp_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.error_code = err;
    resp.message[0] = '\0';

    uint8_t buf[512];
    int n = mq_encode_connect_tcp_resp(buf, sizeof(buf), &resp);
    if (n < 0) {
        MQ_LOGE("mq_server: encode CONNECT_TCP_RESPONSE failed");
        return;
    }
    long sent = mq_stream_send(s, buf, (size_t)n, fin);
    if (sent < 0 || (size_t)sent != (size_t)n) {
        MQ_LOGW("mq_server: CONNECT_TCP_RESPONSE send short/failed (%ld of %d)", sent, n);
    }
}

/* Map a connect()/getaddrinfo errno to a CONNECT_TCP error code. */
static mq_tcp_err_t
srv_map_errno(int e)
{
    switch (e) {
    case ECONNREFUSED: return MQ_TCP_CONN_REFUSED;
    case ETIMEDOUT: return MQ_TCP_TIMEOUT;
    default: return MQ_TCP_CONN_REFUSED;
    }
}

/* Unlink a data-stream node from its conn's list. */
static void
srv_data_unlink(mq_srv_data_t *d)
{
    mq_srv_conn_t *sc = d->sc;
    mq_srv_data_t **pp = &sc->data_head;
    while (*pp) {
        if (*pp == d) {
            *pp = d->next;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Reap a data stream exactly once: reap its flow (which closes stream + fd,
 * frees events + relay), free the connect event, unlink and free the node. Safe
 * from any phase. Re-entrancy: reaping the flow may invoke srv_flow_on_reap
 * (which sets d->flow = NULL); the d->reaped guard makes the whole thing
 * idempotent. */
static void
srv_data_reap(mq_srv_data_t *d)
{
    if (!d || d->reaped) {
        return;
    }
    d->reaped = 1;

    if (d->connect_ev) {
        event_free(d->connect_ev);
        d->connect_ev = NULL;
    }
    if (d->flow) {
        /* Relay phase: the flow owns the stream + fd; reaping it closes both. */
        mq_flow_t *fl = d->flow;
        d->flow = NULL;
        d->stream = NULL;
        d->fd = -1;
        mq_flow_reap(fl);
    } else {
        /* Pre-relay (header / connect phase): no flow yet. Close the stream/fd
         * directly. On the graceful error path the FIN'd response was already
         * sent — do NOT RESET (RESET would discard the un-acked response). */
        if (d->stream) {
            mq_stream_set_cbs(d->stream, NULL, NULL, NULL, NULL);
            if (!d->graceful) {
                mq_stream_close(d->stream);
            }
            d->stream = NULL;
        }
        if (d->fd >= 0) {
            close(d->fd);
            d->fd = -1;
        }
    }
    srv_data_unlink(d);
    free(d);
}

/* Flow reap callback: the shared relay node has closed stream + fd and is about
 * to free itself. Drop our pointer and reap the protocol node. Guarded by
 * d->reaped so a reap initiated from srv_data_reap (which nulls d->flow first)
 * does not recurse. */
static void
srv_flow_on_reap(mq_flow_t *fl, void *user)
{
    (void)fl;
    mq_srv_data_t *d = (mq_srv_data_t *)user;
    d->flow = NULL;
    d->stream = NULL;
    d->fd = -1;
    srv_data_reap(d);
}

/* Error path (pre-relay only): send CONNECT_TCP_RESPONSE(ERROR, err) with FIN,
 * then reap the node gracefully (no RESET). The stream finishes naturally,
 * delivering the response to the client before close. */
static void
srv_data_fail(mq_srv_data_t *d, mq_tcp_err_t err)
{
    if (d->stream) {
        srv_send_tcp_resp(d->stream, MQ_STATUS_ERROR, err, /*fin=*/1);
        d->graceful = 1;
    }
    srv_data_reap(d);
}

/* Transition a connected fd into the relay phase: create the shared flow (taking
 * ownership of the stream + fd), send CONNECT_TCP_RESPONSE(OK), and start
 * relaying. The flow re-wires the stream callbacks and pumps both directions
 * once (forwarding any bytes the client sent past the CONNECT_TCP_REQUEST). */
static void
srv_data_begin_relay(mq_srv_data_t *d)
{
    mq_server_t *srv = d->sc->server;
    struct event_base *base = mq_runtime_base(srv->rt);

    d->flow = mq_flow_new(&d->flow, base, d->stream, d->fd, srv_flow_on_reap, d);
    if (!d->flow) {
        MQ_LOGE("mq_server: flow alloc failed");
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    /* The flow owns the stream + fd now; clear our pre-relay handles so reap
     * goes through the flow. */
    d->fd = -1;

    /* Hand any client bytes that trailed the CONNECT_TCP_REQUEST (already pulled
     * into rx.buf during header buffering) to the flow's prebuffer so they reach
     * the origin and are not lost. */
    if (d->rx.len > d->hdr_consumed) {
        if (mq_flow_prebuffer(d->flow, d->rx.buf + d->hdr_consumed,
                              d->rx.len - d->hdr_consumed) != 0) {
            MQ_LOGE("mq_server: prebuffer failed");
            srv_data_reap(d);
            return;
        }
    }

    /* Send the success response BEFORE starting the relay so it precedes any
     * relayed origin bytes on the stream. */
    srv_send_tcp_resp(d->stream, MQ_STATUS_OK, MQ_TCP_OK, /*fin=*/0);

    if (mq_flow_begin_relay(d->flow) != 0) {
        MQ_LOGE("mq_server: begin relay failed");
        srv_data_reap(d);
    }
}

/* Origin connect-completion one-shot: check SO_ERROR. */
static void
srv_connect_done_cb(evutil_socket_t fd, short what, void *arg)
{
    mq_srv_data_t *d = (mq_srv_data_t *)arg;

    /* The one-shot connect_ev has fired; it is no longer pending. */
    if (d->connect_ev) {
        event_free(d->connect_ev);
        d->connect_ev = NULL;
    }

    /* Deadline hit before the connect completed: fail the open with TIMEOUT so
     * the origin fd + stream + node are released instead of pinned until the
     * kernel TCP timeout. */
    if (what & EV_TIMEOUT) {
        MQ_LOGW("mq_server: origin connect timed out");
        srv_data_fail(d, MQ_TCP_TIMEOUT);
        return;
    }

    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0) {
        soerr = errno ? errno : ECONNREFUSED;
    }
    if (soerr != 0) {
        MQ_LOGW("mq_server: connect failed: %s", strerror(soerr));
        srv_data_fail(d, srv_map_errno(soerr));
        return;
    }
    if (!d->stream) {
        /* Stream went away while connecting. */
        srv_data_reap(d);
        return;
    }
    srv_data_begin_relay(d);
}

/* Resolve the CONNECT_TCP target into a sockaddr. Returns 0 on success and
 * fills *ss / *sslen; on failure returns -1 and sets *err. */
static int
srv_resolve_target(const mq_connect_tcp_req_t *req, struct sockaddr_storage *ss,
                   socklen_t *sslen, mq_tcp_err_t *err)
{
    memset(ss, 0, sizeof(*ss));
    if (req->address_type == MQ_ADDR_IPV4) {
        if (req->host_len != 4) {
            *err = MQ_TCP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, req->host, 4);
        sin->sin_port = htons(req->port);
        *sslen = sizeof(*sin);
        return 0;
    }
    if (req->address_type == MQ_ADDR_IPV6) {
        if (req->host_len != 16) {
            *err = MQ_TCP_DNS_FAILED;
            return -1;
        }
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, req->host, 16);
        sin6->sin6_port = htons(req->port);
        *sslen = sizeof(*sin6);
        return 0;
    }
    /* DOMAIN: Phase 1 uses BLOCKING getaddrinfo (acceptable for now; Phase 2
     * moves DNS off the event loop). */
    char hostz[MQ_MAX_HOST + 1];
    if (req->host_len > MQ_MAX_HOST) {
        *err = MQ_TCP_DNS_FAILED;
        return -1;
    }
    memcpy(hostz, req->host, req->host_len);
    hostz[req->host_len] = '\0';
    char portz[8];
    snprintf(portz, sizeof(portz), "%u", (unsigned)req->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(hostz, portz, &hints, &res);
    if (gai != 0 || !res) {
        if (res) freeaddrinfo(res);
        *err = MQ_TCP_DNS_FAILED;
        return -1;
    }
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *sslen = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* Begin dialing the origin for a decoded CONNECT_TCP request. */
static void
srv_data_dial(mq_srv_data_t *d, const mq_connect_tcp_req_t *req)
{
    struct sockaddr_storage ss;
    socklen_t sslen = 0;
    mq_tcp_err_t rerr = MQ_TCP_DNS_FAILED;
    if (srv_resolve_target(req, &ss, &sslen, &rerr) != 0) {
        srv_data_fail(d, rerr);
        return;
    }

    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(fd);
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    d->fd = fd;

    int rc = connect(fd, (struct sockaddr *)&ss, sslen);
    if (rc == 0) {
        /* Immediate connect (loopback may complete synchronously). */
        srv_data_begin_relay(d);
        return;
    }
    if (errno != EINPROGRESS) {
        int e = errno;
        MQ_LOGW("mq_server: connect: %s", strerror(e));
        srv_data_fail(d, srv_map_errno(e));
        return;
    }
    /* In progress: watch for writability to learn the outcome. */
    struct event_base *base = mq_runtime_base(d->sc->server->rt);
    d->connect_ev = event_new(base, fd, EV_WRITE, srv_connect_done_cb, d);
    if (!d->connect_ev) {
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    /* Arm with a deadline: fires on writable (connect done) OR timeout, once. */
    struct timeval tv = {.tv_sec = MQ_SRV_CONNECT_TIMEOUT_MS / 1000,
                         .tv_usec = (MQ_SRV_CONNECT_TIMEOUT_MS % 1000) * 1000};
    event_add(d->connect_ev, &tv);
}

/* Data stream readable while still buffering the CONNECT_TCP_REQUEST header.
 *
 * Wire layout (design §5.2):
 *   [discriminator varint] [request frame...]
 *
 * The discriminator is decoded on every retry together with the request frame
 * (cheap: always 1 byte for currently-defined values).  This avoids any extra
 * per-stream state to track "discriminator already consumed". */
static void
srv_data_header_readable(mq_stream_t *s, void *user)
{
    mq_srv_data_t *d = (mq_srv_data_t *)user;

    mq_framebuf_fill(s, &d->rx, NULL);

    /* Step 1: decode the stream-type discriminator. */
    uint64_t stream_type = 0;
    int disc_len = mq_varint_decode(d->rx.buf, d->rx.len, &stream_type);
    if (disc_len < 0) {
        /* Not even 1 byte yet (or buffer overflow without a discriminator). */
        if (d->rx.len >= sizeof(d->rx.buf)) {
            MQ_LOGW("mq_server: data stream header malformed/oversized, resetting");
            srv_data_reap(d);
        }
        return; /* need more bytes */
    }

    /* Step 2: dispatch on stream type. */
    if (stream_type == MQ_STREAM_TYPE_CONNECT_TCP) {
        mq_connect_tcp_req_t req;
        int consumed = mq_decode_connect_tcp_req(d->rx.buf + disc_len,
                                                 d->rx.len - (size_t)disc_len, &req);
        if (consumed < 0) {
            if (d->rx.len >= sizeof(d->rx.buf)) {
                MQ_LOGW("mq_server: CONNECT_TCP_REQUEST malformed/oversized, resetting");
                srv_data_reap(d);
            }
            return; /* need more bytes */
        }

        /* Header complete. hdr_consumed accounts for discriminator + request. */
        d->hdr_consumed = (size_t)disc_len + (size_t)consumed;
        srv_data_dial(d, &req);

    } else if (stream_type == MQ_STREAM_TYPE_UDP_SESSION) {
        /* UDP_SESSION (0x02): hand the stream to the per-conn UDP relay, which
         * decodes OPEN → resolves → dials → sends RESP. The client sends the
         * discriminator + OPEN in one send (mq_client), so mq_framebuf_fill
         * above already drained the OPEN body out of the stream into d->rx; it
         * now sits at d->rx.buf + disc_len. Forward it as carry-over so the
         * relay's framebuf is seeded and a single-send OPEN is not stalled. */
        mq_srv_conn_t *sc = d->sc;
        const uint8_t *carry = d->rx.buf + disc_len;
        size_t carry_len = d->rx.len - (size_t)disc_len;

        /* Detach this node from the data-stream machinery: the UDP relay takes
         * ownership of the stream. Drop our header callbacks, mark reaped, and
         * unlink + free the node WITHOUT closing the stream (the relay owns it
         * now). */
        mq_stream_set_cbs(s, NULL, NULL, NULL, NULL);
        d->stream = NULL;
        d->reaped = 1;
        srv_data_unlink(d);

        if (sc->udp) {
            mq_udp_srv_attach_stream(sc->udp, s, carry, carry_len);
        } else {
            MQ_LOGW("mq_server: UDP relay disabled (no udp state), resetting");
            mq_stream_close(s);
        }
        free(d);

    } else {
        MQ_LOGW("mq_server: unknown stream type 0x%02x, resetting",
                (unsigned)stream_type);
        mq_stream_close(s);
    }
}

/* Header-phase stream close: the stream closed before the relay started (no
 * flow yet). Drop our pointer and reap. (Once the relay starts, the flow owns
 * the stream-close callback.) */
static void
srv_data_header_closed(mq_stream_t *s, void *user)
{
    (void)s;
    mq_srv_data_t *d = (mq_srv_data_t *)user;
    d->stream = NULL; /* the transport frees it after this returns */
    srv_data_reap(d);
}

/* Attach a new data stream: allocate state, link it, start header buffering. */
static void
srv_attach_data_stream(mq_srv_conn_t *sc, mq_stream_t *s)
{
    mq_srv_data_t *d = calloc(1, sizeof(*d));
    if (!d) {
        MQ_LOGE("mq_server: OOM allocating data-stream state");
        mq_stream_close(s);
        return;
    }
    d->sc = sc;
    d->stream = s;
    d->fd = -1;
    d->next = sc->data_head;
    sc->data_head = d;

    mq_stream_set_cbs(s, srv_data_header_readable, NULL, srv_data_header_closed, d);

    /* Bytes may already be buffered in the stream; try decoding immediately. */
    srv_data_header_readable(s, d);
}

/* Connection-state hook installed on each accepted conn: reaps active data
 * relays then frees per-conn state on close. */
static void
srv_conn_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    if (st == MQ_CONN_CLOSED) {
        mq_srv_conn_t *sc = (mq_srv_conn_t *)user;
        /* Reap every active relay (each closes its stream+fd once, frees
         * events/relay, unlinks itself). Iterate defensively against the
         * self-unlink. */
        while (sc->data_head) {
            srv_data_reap(sc->data_head);
        }
        /* Tear down all UDP sessions (fd close + event free + defrag free) and
         * free the per-conn UDP relay state. Sessions hold 0x02 stream pointers;
         * the conn is closing so those streams are gone — mq_udp_srv_free reaps
         * each session's resources (it does NOT touch the dead streams beyond a
         * RESET that the closing conn drops). */
        if (sc->server->last_udp == sc->udp) {
            sc->server->last_udp = NULL;
        }
        if (sc->server->last_conn == c) {
            sc->server->last_conn = NULL;
        }
        mq_udp_srv_free(sc->udp);
        sc->udp = NULL;
        free(sc);
    }
}

/* Datagram callback trampoline: adapts mq_conn_on_datagram_fn (which carries
 * the mq_conn_t* and a void* user) to mq_udp_srv_on_datagram (which takes the
 * mq_udp_srv_t* as its first arg and has no conn pointer). */
static void
srv_on_datagram_cb(mq_conn_t *c, const uint8_t *data, size_t len, void *user)
{
    (void)c;
    mq_udp_srv_on_datagram((mq_udp_srv_t *)user, data, len);
}

/* on_new_conn: allocate per-conn state, attach it to the conn owner slot. */
static void
srv_on_new_conn(mq_conn_t *c, void *user)
{
    mq_server_t *srv = (mq_server_t *)user;
    mq_srv_conn_t *sc = calloc(1, sizeof(*sc));
    if (!sc) {
        MQ_LOGE("mq_server: OOM allocating per-conn state");
        mq_conn_close(c);
        return;
    }
    sc->server = srv;
    /* Per-conn UDP relay state (Chunk 5). enabled mirrors !--no-udp; the idle
     * timeout is the server-configured value (per-session effective = min with
     * the client's OPEN request). Allocation failure just disables UDP for this
     * conn (sc->udp stays NULL ⇒ 0x02 streams get reset). */
    sc->udp = mq_udp_srv_new(c, mq_runtime_base(srv->rt), srv->udp_idle_timeout_ms,
                             srv->udp_enabled);
    srv->last_udp = sc->udp; /* observability: most-recent conn's UDP relay state */
    srv->last_conn = c;      /* observability: most-recent accepted conn */
    mq_conn_set_user(c, sc);
    mq_conn_set_on_state(c, srv_conn_state, sc);
    /* Wire the connection-level DATAGRAM callback so tunnel→target datagrams
     * are dispatched to the UDP relay.  The auth gate inside
     * mq_udp_srv_on_datagram drops all frames until mq_udp_srv_set_authed(1).
     * If sc->udp is NULL (OOM) the callback is not registered (safe no-op). */
    if (sc->udp) {
        mq_conn_set_on_datagram(c, srv_on_datagram_cb, sc->udp);
    }
}

/* on_new_stream: the FIRST stream on a connection is the control stream. */
static void
srv_on_new_stream(mq_stream_t *s, void *user)
{
    (void)user;
    mq_conn_t *c = (mq_conn_t *)mq_stream_conn(s);
    if (!c) {
        MQ_LOGW("mq_server: stream with no owning conn; ignoring");
        return;
    }
    mq_srv_conn_t *sc = (mq_srv_conn_t *)mq_conn_user(c);
    if (!sc) {
        MQ_LOGW("mq_server: stream on conn with no state; ignoring");
        return;
    }

    if (!sc->control_stream_seen) {
        sc->control_stream_seen = 1;
        sc->ctrl = s;
        mq_stream_set_cbs(s, srv_ctrl_readable, NULL, NULL, sc);
        return;
    }

    /* Non-control (data) stream. Pre-auth guard: a data stream may only be
     * served on an authenticated connection (design §4.2/4.3). If auth has not
     * succeeded yet, RESET the stream rather than buffer indefinitely or dial. */
    if (!sc->authed) {
        MQ_LOGW("mq_server: data stream %llu before auth; resetting",
                (unsigned long long)mq_stream_id(s));
        mq_stream_close(s);
        return;
    }

    srv_attach_data_stream(sc, s);
}

mq_server_t *
mq_server_new(mq_transport_t *t, mq_runtime_t *rt, const char *auth_token, mq_cc_t cc,
              uint64_t udp_idle_timeout_ms, int udp_enabled)
{
    if (!t || !rt || !auth_token) {
        return NULL;
    }
    mq_server_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->transport = t;
    s->rt = rt;
    snprintf(s->auth_token, sizeof(s->auth_token), "%s", auth_token);
    s->auth_token_len = strnlen(s->auth_token, sizeof(s->auth_token));
    s->udp_idle_timeout_ms = udp_idle_timeout_ms;
    s->udp_enabled = udp_enabled;

    if (mq_conn_register_alpn(t, MQ_SERVER_ALPN, srv_on_new_conn, srv_on_new_stream, s) !=
        0) {
        MQ_LOGE("mq_server: register_alpn failed");
        free(s);
        return NULL;
    }

    /* Apply multipath + aggregate-BDP flow-control windows to every accepted
     * connection. The server is a pure responder (the client creates paths),
     * but it must advertise enable_multipath + the larger path-id grant so the
     * client's paths can be created and validated. */
    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    /* Enable QUIC DATAGRAM (Phase 3 UDP relay carrier) — symmetric with the
     * client. u16 field (xquic.h). */
    settings.max_datagram_frame_size = 65535;
    mq_conn_apply_mp_settings(&settings, /*is_server=*/1, cc);
    xqc_server_set_conn_settings(mq_transport_xqc(t), &settings);

    return s;
}

unsigned
mq_server_auth_attempts(const mq_server_t *s)
{
    return s ? s->auth_attempts : 0;
}

mq_udp_srv_t *
mq_server_last_udp_srv(const mq_server_t *s)
{
    return s ? s->last_udp : NULL;
}

mq_conn_t *
mq_server_active_conn(const mq_server_t *s)
{
    return s ? s->last_conn : NULL;
}

void
mq_server_free(mq_server_t *s)
{
    free(s);
}
