// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_gw_h2_adapter.c — HTTP/2 (nghttp2) server adapter over the neutral
 * mq_gw_client intake boundary. See mq_gw_h2_adapter.h.
 *
 * SKELETON SCOPE (Task 5): create the nghttp2 SERVER session, submit the §5.2
 * SETTINGS, and plumb recv / want_write to the byte transport. No request
 * demux, header policy, response path or body handling yet (Tasks 6/7/8).
 *
 * The production wrapper mq_gw_h2_submit_ops_gwc() is NOT defined here — it is
 * built in Task 11 (its first live use), because it needs mq_gw_client_token()
 * which Task 6 adds. Declaring it in the header keeps the API complete without a
 * forward reference to a not-yet-existing symbol. */
#include "gateway/mq_gw_h2_adapter.h"

#include <nghttp2/nghttp2.h>
#include <stdlib.h>

/* ── §5.2 resource limits (NORMATIVE) ──────────────────────────────────────── */

/* Cap concurrent streams to bound per-connection state / stream-flood DoS. */
#define MQ_H2_MAX_CONCURRENT_STREAMS 128
/* HTTP/2 default frame size; do NOT advertise larger (smaller read amplification
 * surface). 16384 = the protocol minimum/default. */
#define MQ_H2_MAX_FRAME_SIZE 16384
/* Bound the HPACK dynamic table (4 KiB) so a decoder-state-bloat attack is
 * capped. */
#define MQ_H2_HEADER_TABLE_SIZE 4096
/* Cumulative (name+value+per-field-overhead) cap for a single inbound header
 * block (16 KiB), advertised as SETTINGS_MAX_HEADER_LIST_SIZE.
 *
 * This SETTINGS entry is a COOPERATIVE HINT to the peer only: nghttp2 1.59.0
 * does NOT auto-enforce it on inbound header blocks (the recv/HPACK-inflate path
 * never compares decoded header-list size against local_settings; the inflater
 * caps only the HPACK dynamic table). The symbol that would enforce it,
 * nghttp2_option_set_max_header_list_size, is absent from 1.59.0.
 *
 * Therefore inbound header-bomb rejection is NOT provided by advertising this
 * setting — it must be enforced by application-side cumulative header-size
 * accounting in the on_header callback. That accounting is added in Task 6. */
#define MQ_H2_MAX_HEADER_LIST_SIZE 16384

/* ── adapter struct ─────────────────────────────────────────────────────────── */

struct mq_gw_h2_adapter {
    nghttp2_session *session; /* server session */

    /* Submission boundary (BORROWED). Stored for Tasks 6/7/8; unused by the
     * skeleton beyond holding the references. */
    const mq_gw_submit_ops_t *submit;
    void *submit_user;

    /* Plaintext writer (BORROWED). */
    ssize_t (*send_cb)(void *io, const uint8_t *p, size_t n);
    void *io;
};

/* ── public API ────────────────────────────────────────────────────────────── */

mq_gw_h2_adapter_t *
mq_gw_h2_adapter_new(const mq_gw_submit_ops_t *submit, void *submit_user,
                     ssize_t (*send_cb)(void *io, const uint8_t *p, size_t n), void *io)
{
    if (!submit || !send_cb) return NULL;

    mq_gw_h2_adapter_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->submit = submit;
    a->submit_user = submit_user;
    a->send_cb = send_cb;
    a->io = io;

    /* Session callbacks. The skeleton registers none of the request-handling
     * callbacks (Tasks 6/7/8 add on_begin_headers / on_header / on_data_chunk /
     * on_frame_recv / on_stream_close); an empty callbacks object is sufficient
     * for the SETTINGS handshake and to ignore unsupported frames safely. */
    nghttp2_session_callbacks *cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        free(a);
        return NULL;
    }

    int rc = nghttp2_session_server_new(&a->session, cbs, a);
    nghttp2_session_callbacks_del(cbs);
    if (rc != 0) {
        free(a);
        return NULL;
    }

    /* Submit the §5.2 SETTINGS. MAX_FRAME_SIZE is the default; advertising it
     * explicitly documents intent and locks the value. MAX_HEADER_LIST_SIZE is
     * the header-bomb guard (see the #define). */
    const nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MQ_H2_MAX_CONCURRENT_STREAMS},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, MQ_H2_MAX_FRAME_SIZE},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, MQ_H2_HEADER_TABLE_SIZE},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, MQ_H2_MAX_HEADER_LIST_SIZE},
    };
    if (nghttp2_submit_settings(a->session, NGHTTP2_FLAG_NONE, iv,
                                sizeof(iv) / sizeof(iv[0])) != 0) {
        nghttp2_session_del(a->session);
        free(a);
        return NULL;
    }

    return a;
}

int
mq_gw_h2_adapter_recv(mq_gw_h2_adapter_t *a, const uint8_t *p, size_t n)
{
    if (!a) return -1;
    ssize_t r = nghttp2_session_mem_recv(a->session, p, n);
    if (r < 0) return -1;
    /* nghttp2 consumes the whole buffer or signals a fatal error; a partial
     * positive return is not expected from mem_recv, but treat any shortfall as
     * fatal to be safe. */
    if ((size_t)r != n) return -1;
    return 0;
}

int
mq_gw_h2_adapter_want_write(mq_gw_h2_adapter_t *a)
{
    if (!a) return -1;
    for (;;) {
        const uint8_t *data = NULL;
        ssize_t n = nghttp2_session_mem_send(a->session, &data);
        if (n < 0) return -1; /* fatal */
        if (n == 0) return 0; /* nothing more to write */
        ssize_t w = a->send_cb(a->io, data, (size_t)n);
        if (w < 0 || (size_t)w != (size_t)n) return -1; /* writer failed/partial */
    }
}

void
mq_gw_h2_adapter_free(mq_gw_h2_adapter_t *a)
{
    if (!a) return;
    nghttp2_session_del(a->session);
    free(a);
}
