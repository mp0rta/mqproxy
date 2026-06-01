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

#include "proxy/mq_relay.h"
#include "transport/mq_conn.h"
#include "transport/mq_engine.h"
#include "transport/mq_stream.h"
#include "util/mq_log.h"
#include "wire/mq_wire.h"

#define MQ_SERVER_ALPN "mqproxy-tcp/1"
#define MQ_SERVER_ID   "mqproxy-server"

/* Upper bound on the buffered AUTH_REQUEST before we declare it malformed.
 * The full frame is at most version + client_id(<=64) + auth_token(<=256) +
 * features + padding, comfortably under 512. */
#define MQ_SERVER_REQ_MAX 512

typedef struct mq_srv_conn_s mq_srv_conn_t;
typedef struct mq_srv_data_s mq_srv_data_t;

/* Per-connection state, hung off mq_conn's owner slot. */
struct mq_srv_conn_s {
    mq_server_t *server;
    int authed;
    int control_stream_seen; /* the first bidi stream was claimed as control */
    int auth_done;           /* AUTH_RESPONSE sent (control stream settled) */
    mq_stream_t *ctrl;

    uint8_t rxbuf[MQ_SERVER_REQ_MAX];
    size_t rxlen;

    /* Intrusive singly-linked list of active data streams / relays. */
    mq_srv_data_t *data_head;
};

/* Per-data-stream state: one CONNECT_TCP request + its origin fd + relay.
 *
 * Lifecycle phases:
 *   1. Header accumulation: buffer bytes until CONNECT_TCP_REQUEST decodes.
 *   2. Connecting: non-blocking connect() in flight; a one-shot EV_WRITE event
 *      on the origin fd fires when the connect completes (or errors).
 *   3. Relaying: relay is live; persistent EV_READ/EV_WRITE events on the fd and
 *      the stream's read/write callbacks drive the relay edges.
 *   4. Reaped: stream closed, fd closed, events freed, relay freed, unlinked.
 */
struct mq_srv_data_s {
    mq_srv_conn_t *sc;
    mq_stream_t *stream;      /* NULL'd by the stream on_close callback */
    int fd;                   /* origin socket, -1 once closed */
    struct event *connect_ev; /* one-shot EV_WRITE to detect connect completion */
    struct event *rd_ev;      /* persistent EV_READ on fd (relay phase) */
    struct event *wr_ev;      /* persistent EV_WRITE on fd, added on demand */
    mq_relay_t *relay;
    int reaped;
    int graceful; /* error response sent with FIN: do NOT RESET on reap */

    uint8_t rxbuf[MQ_SERVER_REQ_MAX];
    size_t rxlen;

    mq_srv_data_t *next;
};

struct mq_server_s {
    mq_engine_t *eng;
    char auth_token[256];
    size_t auth_token_len;
    unsigned auth_attempts;
};

/* Constant-time comparison of two byte ranges. Returns 1 if equal (same length
 * AND same bytes), 0 otherwise. Length-independent over the compared bytes via
 * a volatile accumulator so the compiler cannot short-circuit. */
static int
ct_equal(const void *a, size_t alen, const void *b, size_t blen)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    volatile unsigned char acc = 0;
    /* Fold the length difference into the accumulator so a mismatching length
     * cannot pass even if the shorter is a prefix of the longer. */
    acc |= (unsigned char)((alen ^ blen) | ((alen ^ blen) >> 8) | ((alen ^ blen) >> 16) |
                           ((alen ^ blen) >> 24));
    size_t n = alen < blen ? alen : blen;
    for (size_t i = 0; i < n; i++) {
        acc |= (unsigned char)(pa[i] ^ pb[i]);
    }
    return acc == 0;
}

static void
srv_send_resp(mq_stream_t *s, mq_status_t status, mq_auth_err_t err)
{
    mq_auth_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    resp.error_code = err;
    resp.features = 0;
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

    for (;;) {
        if (sc->rxlen >= sizeof(sc->rxbuf)) {
            break;
        }
        int fin = 0;
        long n =
            mq_stream_recv(s, sc->rxbuf + sc->rxlen, sizeof(sc->rxbuf) - sc->rxlen, &fin);
        if (n <= 0) {
            break;
        }
        sc->rxlen += (size_t)n;
    }

    mq_auth_req_t req;
    memset(&req, 0, sizeof(req));
    int consumed = mq_decode_auth_req(sc->rxbuf, sc->rxlen, &req);
    if (consumed < 0) {
        if (sc->rxlen >= MQ_SERVER_REQ_MAX) {
            /* Malformed / oversized: count the attempt, reject, close. */
            srv->auth_attempts++;
            sc->auth_done = 1;
            MQ_LOGW("mq_server: AUTH_REQUEST malformed/oversized, rejecting");
            srv_send_resp(s, MQ_STATUS_ERROR, MQ_AUTH_FAILED);
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
    int ok = ct_equal(req.auth_token, tok_len, srv->auth_token, srv->auth_token_len);

    if (ok) {
        sc->authed = 1;
        srv_send_resp(s, MQ_STATUS_OK, MQ_AUTH_OK);
        MQ_LOGI("mq_server: auth OK for client_id='%s'", req.client_id);
    } else {
        srv_send_resp(s, MQ_STATUS_ERROR, MQ_AUTH_FAILED);
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

/* Reap a data stream exactly once: close stream + fd, free events + relay,
 * unlink and free the node. Safe to call from any phase. */
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
    if (d->rd_ev) {
        event_free(d->rd_ev);
        d->rd_ev = NULL;
    }
    if (d->wr_ev) {
        event_free(d->wr_ev);
        d->wr_ev = NULL;
    }
    if (d->fd >= 0) {
        close(d->fd);
        d->fd = -1;
    }
    if (d->stream) {
        /* Detach our callbacks so the imminent stream close_notify does not
         * call back into a freed node. On the graceful error path the response
         * was already sent with FIN — do NOT RESET (RESET would discard the
         * un-acked response). Otherwise abort the stream with RESET_STREAM. The
         * mq_stream is freed by the transport's stream_close_notify. */
        mq_stream_set_cbs(d->stream, NULL, NULL, NULL, NULL);
        if (!d->graceful) {
            mq_stream_close(d->stream);
        }
        d->stream = NULL;
    }
    if (d->relay) {
        mq_relay_free(d->relay);
        d->relay = NULL;
    }
    srv_data_unlink(d);
    free(d);
}

/* Error path: send CONNECT_TCP_RESPONSE(ERROR, err) with FIN, then reap the
 * node gracefully (no RESET). The stream finishes naturally, delivering the
 * response to the client before close. */
static void
srv_data_fail(mq_srv_data_t *d, mq_tcp_err_t err)
{
    if (d->stream) {
        srv_send_tcp_resp(d->stream, MQ_STATUS_ERROR, err, /*fin=*/1);
        d->graceful = 1;
    }
    srv_data_reap(d);
}

/* relay on_done: both directions finished or a hard error — reap once. */
static void
srv_relay_done(mq_relay_t *r, void *user)
{
    (void)r;
    srv_data_reap((mq_srv_data_t *)user);
}

/* ── relay I/O adapters ──────────────────────────────────────────────────── */
/* A side = QUIC stream. */
static long
srv_a_read(void *io, unsigned char *buf, size_t cap, int *eof, int *wb)
{
    mq_srv_data_t *d = (mq_srv_data_t *)io;
    if (!d->stream) {
        *eof = 1;
        return 0;
    }
    int fin = 0;
    long n = mq_stream_recv(d->stream, buf, cap, &fin);
    if (n < 0) {
        return -1;
    }
    if (fin) {
        *eof = 1;
    }
    if (n == 0 && !fin) {
        *wb = 1;
    }
    return n;
}

static long
srv_a_write(void *io, const unsigned char *buf, size_t len, int *wb)
{
    mq_srv_data_t *d = (mq_srv_data_t *)io;
    if (!d->stream) {
        return -1;
    }
    long n = mq_stream_send(d->stream, buf, len, 0);
    if (n < 0) {
        return -1;
    }
    if (n == 0 && len > 0) {
        *wb = 1; /* flow-control blocked; resumes on stream on_writable */
    }
    return n;
}

/* B side = origin TCP fd. */
static long
srv_b_read(void *io, unsigned char *buf, size_t cap, int *eof, int *wb)
{
    mq_srv_data_t *d = (mq_srv_data_t *)io;
    if (d->fd < 0) {
        *eof = 1;
        return 0;
    }
    ssize_t n = recv(d->fd, buf, cap, 0);
    if (n == 0) {
        *eof = 1;
        return 0;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *wb = 1;
            return 0;
        }
        return -1;
    }
    return (long)n;
}

static long
srv_b_write(void *io, const unsigned char *buf, size_t len, int *wb)
{
    mq_srv_data_t *d = (mq_srv_data_t *)io;
    if (d->fd < 0) {
        return -1;
    }
    ssize_t n = send(d->fd, buf, len, MSG_NOSIGNAL);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *wb = 1;
            /* Ensure we get a writable edge to resume. */
            if (d->wr_ev) {
                event_add(d->wr_ev, NULL);
            }
            return 0;
        }
        return -1;
    }
    return (long)n;
}

/* ── relay edge wiring ───────────────────────────────────────────────────── */
/* Stream readable → A is the source for A->B. */
static void
srv_data_stream_readable(mq_stream_t *s, void *user)
{
    (void)s;
    mq_srv_data_t *d = (mq_srv_data_t *)user;
    if (d->relay) {
        mq_relay_on_a_readable(d->relay);
    }
}

/* Stream writable → A is the destination for B->A. */
static void
srv_data_stream_writable(mq_stream_t *s, void *user)
{
    (void)s;
    mq_srv_data_t *d = (mq_srv_data_t *)user;
    if (d->relay) {
        mq_relay_on_a_writable(d->relay);
    }
}

/* Stream closed by the transport: drop our pointer, then reap. */
static void
srv_data_stream_closed(mq_stream_t *s, void *user)
{
    (void)s;
    mq_srv_data_t *d = (mq_srv_data_t *)user;
    d->stream = NULL; /* the transport frees it after this returns */
    srv_data_reap(d);
}

/* Origin fd readable → B is the source for B->A. */
static void
srv_fd_readable_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_srv_data_t *d = (mq_srv_data_t *)arg;
    if (d->relay) {
        mq_relay_on_b_readable(d->relay);
    }
}

/* Origin fd writable → B is the destination for A->B. One-shot per add. */
static void
srv_fd_writable_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mq_srv_data_t *d = (mq_srv_data_t *)arg;
    if (d->relay) {
        mq_relay_on_b_writable(d->relay);
    }
}

/* Transition a connected fd into the relay phase: build the relay, register
 * persistent read + on-demand write events, send CONNECT_TCP_RESPONSE(OK), and
 * pump once. */
static void
srv_data_begin_relay(mq_srv_data_t *d)
{
    mq_server_t *srv = d->sc->server;
    struct event_base *base = mq_engine_base(srv->eng);

    mq_relay_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.a_io = d;
    cfg.b_io = d;
    cfg.a_read = srv_a_read;
    cfg.a_write = srv_a_write;
    cfg.b_read = srv_b_read;
    cfg.b_write = srv_b_write;
    cfg.on_done = srv_relay_done;
    cfg.user = d;

    d->relay = mq_relay_new(&cfg);
    if (!d->relay) {
        MQ_LOGE("mq_server: relay alloc failed");
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }

    d->rd_ev = event_new(base, d->fd, EV_READ | EV_PERSIST, srv_fd_readable_cb, d);
    d->wr_ev = event_new(base, d->fd, EV_WRITE, srv_fd_writable_cb, d);
    if (!d->rd_ev || !d->wr_ev) {
        MQ_LOGE("mq_server: fd event alloc failed");
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    event_add(d->rd_ev, NULL);

    /* Re-wire the stream callbacks for the relay phase (readable/writable). */
    mq_stream_set_cbs(d->stream, srv_data_stream_readable, srv_data_stream_writable,
                      srv_data_stream_closed, d);

    srv_send_tcp_resp(d->stream, MQ_STATUS_OK, MQ_TCP_OK, /*fin=*/0);

    /* Pump both directions once: any bytes the client already sent past the
     * CONNECT_TCP_REQUEST, plus to register interest. */
    mq_relay_on_a_readable(d->relay);
    mq_relay_on_b_readable(d->relay);
}

/* Origin connect-completion one-shot: check SO_ERROR. */
static void
srv_connect_done_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    mq_srv_data_t *d = (mq_srv_data_t *)arg;

    /* The one-shot connect_ev has fired; it is no longer pending. */
    if (d->connect_ev) {
        event_free(d->connect_ev);
        d->connect_ev = NULL;
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
 * fills *ss/*sslen; on failure returns -1 and sets *err. */
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
    struct event_base *base = mq_engine_base(d->sc->server->eng);
    d->connect_ev = event_new(base, fd, EV_WRITE, srv_connect_done_cb, d);
    if (!d->connect_ev) {
        srv_data_fail(d, MQ_TCP_CONN_REFUSED);
        return;
    }
    event_add(d->connect_ev, NULL);
}

/* Data stream readable while still buffering the CONNECT_TCP_REQUEST header. */
static void
srv_data_header_readable(mq_stream_t *s, void *user)
{
    mq_srv_data_t *d = (mq_srv_data_t *)user;

    for (;;) {
        if (d->rxlen >= sizeof(d->rxbuf)) {
            break;
        }
        int fin = 0;
        long n =
            mq_stream_recv(s, d->rxbuf + d->rxlen, sizeof(d->rxbuf) - d->rxlen, &fin);
        if (n <= 0) {
            break;
        }
        d->rxlen += (size_t)n;
    }

    mq_connect_tcp_req_t req;
    int consumed = mq_decode_connect_tcp_req(d->rxbuf, d->rxlen, &req);
    if (consumed < 0) {
        if (d->rxlen >= sizeof(d->rxbuf)) {
            MQ_LOGW("mq_server: CONNECT_TCP_REQUEST malformed/oversized, resetting");
            srv_data_reap(d);
        }
        return; /* otherwise need more bytes */
    }

    /* Header complete. Stop header-buffering callbacks (re-wired in relay phase)
     * and dial the origin. Any bytes past the header stay readable on the stream
     * and are pumped once the relay starts. */
    srv_data_dial(d, &req);
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

    mq_stream_set_cbs(s, srv_data_header_readable, NULL, srv_data_stream_closed, d);

    /* Bytes may already be buffered in the stream; try decoding immediately. */
    srv_data_header_readable(s, d);
}

/* Connection-state hook installed on each accepted conn: reaps active data
 * relays then frees per-conn state on close. */
static void
srv_conn_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    if (st == MQ_CONN_CLOSED) {
        mq_srv_conn_t *sc = (mq_srv_conn_t *)user;
        /* Reap every active relay (each closes its stream+fd once, frees
         * events/relay, unlinks itself). Iterate defensively against the
         * self-unlink. */
        while (sc->data_head) {
            srv_data_reap(sc->data_head);
        }
        free(sc);
    }
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
    mq_conn_set_user(c, sc);
    mq_conn_set_on_state(c, srv_conn_state, sc);
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
mq_server_new(mq_engine_t *eng, const char *auth_token)
{
    if (!eng || !auth_token) {
        return NULL;
    }
    mq_server_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->eng = eng;
    snprintf(s->auth_token, sizeof(s->auth_token), "%s", auth_token);
    s->auth_token_len = strnlen(s->auth_token, sizeof(s->auth_token));

    if (mq_conn_register_alpn(eng, MQ_SERVER_ALPN, srv_on_new_conn, srv_on_new_stream,
                              s) != 0) {
        MQ_LOGE("mq_server: register_alpn failed");
        free(s);
        return NULL;
    }
    return s;
}

unsigned
mq_server_auth_attempts(const mq_server_t *s)
{
    return s ? s->auth_attempts : 0;
}

void
mq_server_free(mq_server_t *s)
{
    free(s);
}
