// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_clienthello_parse — bounds-checked TLS ClientHello SNI/ALPN peek.
//
// SECURITY: `buf`/`len` is attacker-controlled network input. Every length and
// offset read is guarded against `len`; the parser NEVER reads past `len` and
// NEVER allocates. A claimed inner length that runs past `len` while the
// enclosing record is itself incomplete => NEED_MORE (read more). A length that
// overruns a COMPLETE enclosing field (record fragment / handshake body) is a
// structural impossibility => INVALID. The parser only inspects a single TLS
// record: a ClientHello fits one record in practice, so we do not reassemble
// across records — but a fragment claiming more than `len` => NEED_MORE.
#include "ingress/mq_clienthello.h"
#include <string.h>

#define MQ_CH_CAP             8192u /* hard upper bound on accumulated bytes */
#define MQ_CH_SNI_MAX         253u  /* DNS hostname max; +1 NUL must fit sni[256] */
#define TLS_CONTENT_HANDSHAKE 22
#define TLS_HS_CLIENT_HELLO   1
#define TLS_EXT_SERVER_NAME   0x0000
#define TLS_EXT_ALPN          0x0010
#define TLS_SNI_HOST_NAME     0x00

/* A bounds-checked cursor over [base, base+limit). Every read advances `pos`
 * only after confirming `limit` covers it; reads never touch base+limit or
 * beyond. `limit` is the count of bytes KNOWN to be present (<= len). */
typedef struct {
    const uint8_t *base;
    size_t limit;
    size_t pos;
} cur_t;

/* True iff `n` more bytes are available from the current position. */
static int
cur_have(const cur_t *c, size_t n)
{
    return n <= c->limit - c->pos; /* c->pos <= c->limit always holds */
}

static uint8_t
cur_u8(cur_t *c)
{
    return c->base[c->pos++];
}

static uint16_t
cur_u16(cur_t *c)
{
    uint16_t v = (uint16_t)((c->base[c->pos] << 8) | c->base[c->pos + 1]);
    c->pos += 2;
    return v;
}

mq_ch_result_t
mq_clienthello_parse(const uint8_t *buf, size_t len, mq_clienthello_t *out)
{
    /* `out` is always zeroed first so callers may read it after any result. */
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (buf == NULL || out == NULL) {
        return MQ_CH_INVALID;
    }
    /* DoS / runaway guard: if we have accumulated more than the cap and still
     * cannot complete, refuse rather than loop. */
    if (len > MQ_CH_CAP) {
        return MQ_CH_INVALID;
    }

    /* ---- TLS record layer ---- */
    /* Need 5-byte record header: content_type(1) version(2) length(2). */
    if (len < 5) {
        /* A handshake record begins with 0x16; if the first byte is present
         * and not 0x16 this is not a TLS handshake flow at all. */
        if (len >= 1 && buf[0] != TLS_CONTENT_HANDSHAKE) {
            return MQ_CH_NOT_TLS;
        }
        return MQ_CH_NEED_MORE;
    }
    if (buf[0] != TLS_CONTENT_HANDSHAKE) {
        return MQ_CH_NOT_TLS;
    }
    /* buf[1..2] legacy_version — not validated (TLS 1.3 keeps it at 0x0301). */
    size_t frag_len = ((size_t)buf[3] << 8) | buf[4];
    if (frag_len == 0) {
        return MQ_CH_INVALID;
    }
    /* The record fragment is the enclosing field for the handshake. If fewer
     * than frag_len bytes are present, the record is incomplete => NEED_MORE
     * (never read past what we have). The total record size cannot exceed the
     * cap either. */
    if (5 + frag_len > MQ_CH_CAP) {
        return MQ_CH_INVALID;
    }
    if (len < 5 + frag_len) {
        return MQ_CH_NEED_MORE;
    }

    /* From here on, the record fragment is COMPLETE: overruns of it => INVALID.
     * Bound the cursor to exactly the fragment so inner overruns are caught as
     * structural errors, not as NEED_MORE. */
    cur_t c = {.base = buf + 5, .limit = frag_len, .pos = 0};

    /* ---- Handshake layer ---- */
    if (!cur_have(&c, 4)) {
        return MQ_CH_INVALID; /* fragment too small to hold a handshake header */
    }
    uint8_t msg_type = cur_u8(&c);
    if (msg_type != TLS_HS_CLIENT_HELLO) {
        return MQ_CH_INVALID; /* valid TLS record but not a ClientHello */
    }
    size_t hs_len = ((size_t)cur_u8(&c) << 16);
    hs_len |= ((size_t)cur_u8(&c) << 8);
    hs_len |= (size_t)cur_u8(&c);
    if (!cur_have(&c, hs_len)) {
        /* Handshake claims more than the (complete) record fragment carries. */
        return MQ_CH_INVALID;
    }
    /* Bound the cursor to the handshake body — its enclosing field is complete. */
    c.limit = c.pos + hs_len;

    /* ---- ClientHello body ---- */
    /* legacy_version(2) + random(32) */
    if (!cur_have(&c, 2 + 32)) {
        return MQ_CH_INVALID;
    }
    c.pos += 2 + 32;
    /* session_id: u8 length + bytes */
    if (!cur_have(&c, 1)) {
        return MQ_CH_INVALID;
    }
    {
        uint8_t sid = cur_u8(&c);
        if (!cur_have(&c, sid)) {
            return MQ_CH_INVALID;
        }
        c.pos += sid;
    }
    /* cipher_suites: u16 length + bytes */
    if (!cur_have(&c, 2)) {
        return MQ_CH_INVALID;
    }
    {
        uint16_t cs = cur_u16(&c);
        if (!cur_have(&c, cs)) {
            return MQ_CH_INVALID;
        }
        c.pos += cs;
    }
    /* compression_methods: u8 length + bytes */
    if (!cur_have(&c, 1)) {
        return MQ_CH_INVALID;
    }
    {
        uint8_t cm = cur_u8(&c);
        if (!cur_have(&c, cm)) {
            return MQ_CH_INVALID;
        }
        c.pos += cm;
    }
    /* extensions: optional. TLS <1.2 ClientHello may legally omit the block.
     * If nothing follows compression, there are simply no extensions => OK with
     * empty sni / no alpn. */
    if (!cur_have(&c, 2)) {
        if (c.pos == c.limit) {
            return MQ_CH_OK; /* well-formed body, no extensions */
        }
        return MQ_CH_INVALID; /* trailing byte(s) too short to be a length */
    }
    uint16_t ext_total = cur_u16(&c);
    if (!cur_have(&c, ext_total)) {
        return MQ_CH_INVALID; /* extensions block overruns the handshake body */
    }
    /* Bound the cursor to exactly the extensions block. */
    c.limit = c.pos + ext_total;

    /* ---- iterate extensions ---- */
    while (c.pos < c.limit) {
        if (!cur_have(&c, 4)) {
            return MQ_CH_INVALID; /* dangling bytes too short for ext header */
        }
        uint16_t ext_type = cur_u16(&c);
        uint16_t ext_len = cur_u16(&c);
        if (!cur_have(&c, ext_len)) {
            return MQ_CH_INVALID; /* extension data overruns the ext block */
        }
        /* Sub-cursor scoped to this extension's data. */
        size_t ext_start = c.pos;
        size_t ext_end = c.pos + ext_len;

        if (ext_type == TLS_EXT_SERVER_NAME && ext_len > 0) {
            cur_t e = {.base = c.base, .limit = ext_end, .pos = ext_start};
            /* ServerNameList: u16 list length, then entries. */
            if (cur_have(&e, 2)) {
                uint16_t list_len = cur_u16(&e);
                size_t list_end = e.pos + list_len;
                if (list_end <= ext_end) {
                    e.limit = list_end;
                    /* Take the first host_name (type 0) entry. */
                    while (e.pos < e.limit) {
                        if (!cur_have(&e, 1)) {
                            break;
                        }
                        uint8_t name_type = cur_u8(&e);
                        if (!cur_have(&e, 2)) {
                            break;
                        }
                        uint16_t name_len = cur_u16(&e);
                        if (!cur_have(&e, name_len)) {
                            break;
                        }
                        if (name_type == TLS_SNI_HOST_NAME) {
                            if (name_len > 0 && name_len <= MQ_CH_SNI_MAX) {
                                memcpy(out->sni, e.base + e.pos, name_len);
                                out->sni[name_len] = '\0';
                            }
                            /* else: over-long / empty host_name → leave sni
                             * empty (skip), per the >253 reject rule. */
                            break; /* first host_name wins */
                        }
                        e.pos += name_len;
                    }
                }
            }
        } else if (ext_type == TLS_EXT_ALPN) {
            out->has_alpn = 1;
            cur_t e = {.base = c.base, .limit = ext_end, .pos = ext_start};
            /* ProtocolNameList: u16 list length, then length-prefixed names. */
            if (cur_have(&e, 2)) {
                uint16_t list_len = cur_u16(&e);
                size_t list_end = e.pos + list_len;
                if (list_end <= ext_end) {
                    e.limit = list_end;
                    while (e.pos < e.limit) {
                        if (!cur_have(&e, 1)) {
                            break;
                        }
                        uint8_t pn_len = cur_u8(&e);
                        if (!cur_have(&e, pn_len)) {
                            break;
                        }
                        /* Exact 2-byte "h2" — length-prefixed, so no substring
                         * confusion with "h2c"/"h3". */
                        if (pn_len == 2 && e.base[e.pos] == 'h' &&
                            e.base[e.pos + 1] == '2') {
                            out->has_h2 = 1;
                        }
                        e.pos += pn_len;
                    }
                }
            }
        }

        /* Advance to the next extension regardless of inner parse outcome. */
        c.pos = ext_end;
    }

    return MQ_CH_OK;
}
