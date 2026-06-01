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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/mq_conn.h"
#include "transport/mq_stream.h"
#include "util/mq_log.h"
#include "wire/mq_wire.h"

#define MQ_SERVER_ALPN "mqproxy-tcp/1"
#define MQ_SERVER_ID   "mqproxy-server"

/* Upper bound on the buffered AUTH_REQUEST before we declare it malformed.
 * The full frame is at most version + client_id(<=64) + auth_token(<=256) +
 * features + padding, comfortably under 512. */
#define MQ_SERVER_REQ_MAX 512

/* Per-connection state, hung off mq_conn's owner slot. */
typedef struct {
    mq_server_t *server;
    int authed;
    int control_stream_seen; /* the first bidi stream was claimed as control */
    int auth_done;           /* AUTH_RESPONSE sent (control stream settled) */
    mq_stream_t *ctrl;

    uint8_t rxbuf[MQ_SERVER_REQ_MAX];
    size_t rxlen;
} mq_srv_conn_t;

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

/* Connection-state hook installed on each accepted conn: frees per-conn state
 * on close. */
static void
srv_conn_state(mq_conn_t *c, mq_conn_state_t st, void *user)
{
    (void)c;
    if (st == MQ_CONN_CLOSED) {
        mq_srv_conn_t *sc = (mq_srv_conn_t *)user;
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

    /* Non-control (data) stream: not handled in Task 11. Leave it unhandled;
     * Task 12 wires TCP data streams here. */
    MQ_LOGD("mq_server: non-control stream %llu ignored (Task 12)",
            (unsigned long long)mq_stream_id(s));
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
