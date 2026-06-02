// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_transport.c — Chunk 1 shell.
 *
 * mq_transport currently wraps an mq_engine_t and delegates to it. The stored
 * callbacks are not yet wired (Chunk 3/6 invert mq_conn's direct socket I/O
 * onto them); on_udp_recv / next_timeout_ms are minimal stubs (Chunk 4/5).
 * Nothing in production calls this module yet — it is a pure addition.
 */
#include "transport/mq_transport.h"

#include <stdlib.h>
#include <string.h>

#include "transport/mq_engine.h"

struct mq_transport_s {
    mq_engine_t *eng;
    mq_transport_callbacks_t cbs;
    void *user;
};

mq_transport_t *
mq_transport_new(int is_server, const mq_transport_callbacks_t *cbs, void *user)
{
    mq_transport_t *t = calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    if (cbs) {
        t->cbs = *cbs;
    } else {
        memset(&t->cbs, 0, sizeof(t->cbs));
    }
    t->user = user;
    t->eng = mq_engine_new(is_server, NULL);
    if (!t->eng) {
        free(t);
        return NULL;
    }
    return t;
}

mq_transport_t *
mq_transport_new_server(const mq_transport_callbacks_t *cbs, void *user,
                        const char *cert_file, const char *key_file)
{
    mq_transport_t *t = calloc(1, sizeof(*t));
    if (!t) {
        return NULL;
    }
    if (cbs) {
        t->cbs = *cbs;
    } else {
        memset(&t->cbs, 0, sizeof(t->cbs));
    }
    t->user = user;
    t->eng = mq_engine_new_server(NULL, cert_file, key_file);
    if (!t->eng) {
        free(t);
        return NULL;
    }
    return t;
}

void
mq_transport_free(mq_transport_t *t)
{
    if (!t) {
        return;
    }
    mq_engine_free(t->eng);
    free(t);
}

int
mq_transport_on_udp_recv(mq_transport_t *t, uint64_t path, const uint8_t *pkt, size_t len,
                         const struct sockaddr *peer, socklen_t peerlen)
{
    /* Chunk 5 wires this to xqc_engine_packet_process; minimal stub for now. */
    (void)t;
    (void)path;
    (void)pkt;
    (void)len;
    (void)peer;
    (void)peerlen;
    return 0;
}

void
mq_transport_tick(mq_transport_t *t)
{
    xqc_engine_main_logic(mq_engine_xqc(t->eng));
}

int
mq_transport_next_timeout_ms(mq_transport_t *t)
{
    /* Real deadline tracking lands in Chunk 4. */
    (void)t;
    return -1;
}

xqc_engine_t *
mq_transport_xqc(mq_transport_t *t)
{
    return mq_engine_xqc(t->eng);
}

void
mq_transport_set_mp_ready_cb(mq_transport_t *t, mq_transport_mp_ready_fn fn, void *user)
{
    mq_engine_set_mp_ready_cb(t->eng, (mq_engine_mp_ready_fn)fn, user);
}

int
mq_transport_enable_qlog(mq_transport_t *t, const char *dir, const char **out_path)
{
    return mq_engine_enable_qlog(t->eng, dir, out_path);
}
