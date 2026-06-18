// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#ifndef MQ_CLIENTHELLO_H
#define MQ_CLIENTHELLO_H
#include <stddef.h>
#include <stdint.h>

/* Result of peeking at an (possibly partial) TLS ClientHello byte stream.
 *   MQ_CH_OK        sni (may be empty) + alpn flags extracted.
 *   MQ_CH_NEED_MORE record/handshake incomplete — caller should read more bytes.
 *   MQ_CH_NOT_TLS   first byte is not a TLS handshake record (e.g. plaintext
 *                   HTTP, SSLv2). HARD-FAIL: this is not a TLS flow.
 *   MQ_CH_INVALID   structurally malformed TLS (impossible field, overrun of a
 *                   COMPLETE enclosing field, or 8 KiB cap exceeded). HARD-FAIL. */
typedef enum {
    MQ_CH_OK = 0,
    MQ_CH_NEED_MORE = 1,
    MQ_CH_NOT_TLS = -1,
    MQ_CH_INVALID = -2
} mq_ch_result_t;

typedef struct {
    char sni[256]; /* NUL-terminated server_name (host_name type 0); empty if absent */
    int has_h2;    /* 1 if the ALPN offer list contains the exact token "h2" */
    int has_alpn;  /* 1 if an ALPN extension was present at all */
} mq_clienthello_t;

/* Parse a (possibly partial) TLS plaintext byte stream. buf/len = the bytes
 * accumulated from the client so far. Pure function: no allocation, never reads
 * past `len`, never blocks. `out` is fully populated only on MQ_CH_OK (and is
 * always zero-initialised first, so it is safe to read after any result). The
 * raw host_name bytes are copied verbatim (NOT lowercased/normalised — the
 * caller normalises via mq_mitm_normalize_sni). An over-long host_name (>253)
 * is skipped, leaving sni empty. */
mq_ch_result_t mq_clienthello_parse(const uint8_t *buf, size_t len,
                                    mq_clienthello_t *out);

#endif
