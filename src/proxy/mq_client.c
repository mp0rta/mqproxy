/* mq_client.c — proxy client + control-stream AUTH handshake.
 *
 * Flow:
 *   mq_client_start -> mq_conn_connect (ALPN "mqproxy-tcp/1")
 *   on ESTABLISHED  -> open control stream, send AUTH_REQUEST (no FIN)
 *   on control stream readable -> accumulate bytes, retry mq_decode_auth_resp
 *                                 until it succeeds; report via on_auth.
 *
 * The control stream stays open after auth so Tasks 12/13 can reuse it.
 */
#include "proxy/mq_client.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/mq_stream.h"
#include "util/mq_log.h"
#include "wire/mq_wire.h"

#define MQ_CLIENT_ALPN "mqproxy-tcp/1"

/* Upper bound on the AUTH_RESPONSE frame; beyond this without a valid decode we
 * treat the stream as malformed (Phase 1: fail closed). The encoded response is
 * tiny (status+error+server_id+features+padding), well under this. */
#define MQ_CLIENT_RESP_MAX 512

struct mq_client_s {
    mq_engine_t *eng;
    char server_ip[64];
    uint16_t server_port;

    mq_auth_req_t req; /* prebuilt AUTH_REQUEST fields */

    mq_conn_t *conn;
    mq_stream_t *ctrl; /* control stream */

    mq_client_on_auth_fn on_auth;
    void *on_auth_user;
    mq_conn_on_state_fn on_state;
    void *on_state_user;

    /* AUTH_RESPONSE accumulation buffer. */
    uint8_t rxbuf[MQ_CLIENT_RESP_MAX];
    size_t rxlen;

    int authed;
    int auth_reported; /* on_auth fired exactly once */
};

static void
client_report_auth(mq_client_t *c, int ok, mq_auth_err_t err)
{
    if (c->auth_reported) {
        return;
    }
    c->auth_reported = 1;
    c->authed = ok ? 1 : 0;
    if (c->on_auth) {
        c->on_auth(ok, err, c->on_auth_user);
    }
}

/* Control-stream readable: pull bytes, retry decode. */
static void
client_ctrl_readable(mq_stream_t *s, void *user)
{
    mq_client_t *c = (mq_client_t *)user;
    if (c->auth_reported) {
        /* Auth already settled; drain to keep the stream from stalling. */
        uint8_t scratch[256];
        int fin = 0;
        while (mq_stream_recv(s, scratch, sizeof(scratch), &fin) > 0) {}
        return;
    }

    for (;;) {
        if (c->rxlen >= sizeof(c->rxbuf)) {
            break; /* buffer full, handled as malformed below */
        }
        int fin = 0;
        long n =
            mq_stream_recv(s, c->rxbuf + c->rxlen, sizeof(c->rxbuf) - c->rxlen, &fin);
        if (n <= 0) {
            break; /* no more data right now */
        }
        c->rxlen += (size_t)n;
    }

    mq_auth_resp_t resp;
    memset(&resp, 0, sizeof(resp));
    int consumed = mq_decode_auth_resp(c->rxbuf, c->rxlen, &resp);
    if (consumed >= 0) {
        int ok = (resp.status == MQ_STATUS_OK);
        client_report_auth(c, ok, resp.error_code);
        return;
    }

    /* decode failed: could be "need more" or malformed. Phase 1: once we have
     * accumulated past a sane bound without a valid frame, treat as malformed. */
    if (c->rxlen >= MQ_CLIENT_RESP_MAX) {
        MQ_LOGW("mq_client: AUTH_RESPONSE exceeded %d bytes, treating as malformed",
                MQ_CLIENT_RESP_MAX);
        client_report_auth(c, 0, MQ_AUTH_FAILED);
    }
}

/* Connection state: on ESTABLISHED, open control stream + send AUTH_REQUEST. */
static void
client_on_state(mq_conn_t *conn, mq_conn_state_t st, void *user)
{
    mq_client_t *c = (mq_client_t *)user;

    if (st == MQ_CONN_ESTABLISHED) {
        c->ctrl = mq_conn_open_stream(conn);
        if (!c->ctrl) {
            MQ_LOGE("mq_client: failed to open control stream");
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }
        mq_stream_set_cbs(c->ctrl, client_ctrl_readable, NULL, NULL, c);

        uint8_t buf[512];
        int n = mq_encode_auth_req(buf, sizeof(buf), &c->req);
        if (n < 0) {
            MQ_LOGE("mq_client: encode AUTH_REQUEST failed");
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }
        /* No FIN: keep the control stream open for the response. */
        long sent = mq_stream_send(c->ctrl, buf, (size_t)n, /*fin=*/0);
        if (sent < 0 || (size_t)sent != (size_t)n) {
            MQ_LOGE("mq_client: send AUTH_REQUEST short/failed (%ld of %d)", sent, n);
            client_report_auth(c, 0, MQ_AUTH_FAILED);
            goto forward;
        }
    } else if (st == MQ_CONN_CLOSED) {
        c->conn = NULL;
        c->ctrl = NULL;
        /* If the connection died before auth settled, report failure. */
        client_report_auth(c, 0, MQ_AUTH_FAILED);
    }

forward:
    if (c->on_state) {
        c->on_state(conn, st, c->on_state_user);
    }
}

mq_client_t *
mq_client_new(mq_engine_t *eng, const char *server_ip, uint16_t server_port,
              const char *client_id, const char *auth_token)
{
    if (!eng || !server_ip || !client_id || !auth_token) {
        return NULL;
    }
    mq_client_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->eng = eng;
    c->server_port = server_port;
    snprintf(c->server_ip, sizeof(c->server_ip), "%s", server_ip);

    c->req.version = 1;
    c->req.features = 0;
    snprintf(c->req.client_id, sizeof(c->req.client_id), "%s", client_id);
    /* auth_token is not NUL-guaranteed-meaningful but encoded as a string field;
     * use the NUL-terminated length. */
    snprintf(c->req.auth_token, sizeof(c->req.auth_token), "%s", auth_token);
    return c;
}

void
mq_client_set_on_auth(mq_client_t *c, mq_client_on_auth_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_auth = fn;
    c->on_auth_user = user;
}

void
mq_client_set_on_state(mq_client_t *c, mq_conn_on_state_fn fn, void *user)
{
    if (!c) {
        return;
    }
    c->on_state = fn;
    c->on_state_user = user;
}

int
mq_client_start(mq_client_t *c)
{
    if (!c) {
        return -1;
    }

    /* Register the client ALPN (no server-side hooks). Idempotency: registering
     * twice on one engine is not supported, so this assumes one client per
     * engine, which matches the proxy's usage. */
    if (mq_conn_register_alpn(c->eng, MQ_CLIENT_ALPN, NULL, NULL, NULL) != 0) {
        MQ_LOGE("mq_client: register_alpn failed");
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c->server_port);
    if (inet_pton(AF_INET, c->server_ip, &sa.sin_addr) != 1) {
        MQ_LOGE("mq_client: bad server ip '%s'", c->server_ip);
        return -1;
    }

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.pacing_on = 1;
    settings.max_pkt_out_size = 1200;

    c->conn = mq_conn_connect(c->eng, (struct sockaddr *)&sa, sizeof(sa), MQ_CLIENT_ALPN,
                              &settings, c);
    if (!c->conn) {
        MQ_LOGE("mq_client: connect failed");
        return -1;
    }
    mq_conn_set_on_state(c->conn, client_on_state, c);
    return 0;
}

int
mq_client_is_authed(const mq_client_t *c)
{
    return c ? c->authed : 0;
}

mq_conn_t *
mq_client_conn(const mq_client_t *c)
{
    return c ? c->conn : NULL;
}

void
mq_client_free(mq_client_t *c)
{
    free(c);
}
