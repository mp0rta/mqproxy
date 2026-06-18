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
// structural impossibility => INVALID.
//
// REASSEMBLY (RFC 8446 §5.1): a single handshake message (the ClientHello) MAY
// be fragmented across multiple consecutive TLS handshake records
// (content_type==22). We therefore present the handshake to the parser as a
// LOGICAL byte stream spanning all such records IN PLACE — no allocation: the
// cursor walks records and transparently skips each 5-byte record header when a
// read crosses a fragment boundary. The caller accumulates raw bytes into its
// own bounded (8 KiB) buffer and re-calls us on the growing buffer, so a
// handshake that is not yet fully present across the buffered records => NEED_MORE.
// A non-handshake record (content_type != 22) appearing while the ClientHello is
// still incomplete is a protocol violation => INVALID.
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
 * beyond. `limit` is the count of bytes KNOWN to be present (<= len). Used for
 * the inner sub-parses (extensions, SNI/ALPN entries) that operate over a single
 * already-validated contiguous span. */
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

/* ---- record-spanning handshake reader ----
 *
 * `hs_t` presents the handshake-record fragments of `buf` as one logical byte
 * stream, copying needed bytes into a small fixed scratch as it reads so that a
 * field straddling a record boundary is read seamlessly. It NEVER reads past
 * `len` and NEVER allocates. State machine results are encoded by the readers:
 * a short read returns an error code via the caller's bounds checks.
 *
 *   buf,len         the full raw accumulated buffer (hard bound).
 *   rec_off         offset in buf of the CURRENT record header (content_type).
 *   frag_pos        bytes of the current record's fragment already consumed.
 *   frag_len        the current record's declared fragment length.
 *   incomplete      set when more raw bytes are needed to satisfy a read
 *                   (record header or fragment not fully present) => NEED_MORE.
 *   bad             set when a structural impossibility is hit (non-handshake
 *                   record mid-message, zero-length fragment) => INVALID. */
typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t rec_off;
    size_t frag_pos;
    size_t frag_len;
    int incomplete;
    int bad;
} hs_t;

/* Position the reader at the first handshake record. The first record header is
 * validated by the caller before this is invoked, so here we only seed state. */
static void
hs_init(hs_t *h, const uint8_t *buf, size_t len, size_t rec_off, size_t frag_len)
{
    h->buf = buf;
    h->len = len;
    h->rec_off = rec_off;
    h->frag_len = frag_len;
    h->frag_pos = 0;
    h->incomplete = 0;
    h->bad = 0;
}

/* Ensure the current record has at least one unconsumed fragment byte. If the
 * current fragment is exhausted, advance to the NEXT record: parse its 5-byte
 * header, require content_type==22, and require its declared fragment to be
 * present in `buf`. Sets h->incomplete (need more bytes) or h->bad (protocol
 * violation) on failure. Returns 1 if a fragment byte is available, else 0. */
static int
hs_ensure(hs_t *h)
{
    if (h->bad || h->incomplete) {
        return 0;
    }
    while (h->frag_pos == h->frag_len) {
        /* Current fragment drained — try to enter the next record. */
        size_t next = h->rec_off + 5 + h->frag_len;
        /* next == h->len means the buffered records ended exactly on a fragment
         * boundary with the handshake still unsatisfied => need more records. */
        if (next + 5 > h->len) {
            h->incomplete = 1; /* next record header not fully present yet */
            return 0;
        }
        if (h->buf[next] != TLS_CONTENT_HANDSHAKE) {
            h->bad = 1; /* non-handshake record mid-ClientHello => INVALID */
            return 0;
        }
        size_t flen = ((size_t)h->buf[next + 3] << 8) | h->buf[next + 4];
        if (flen == 0) {
            h->bad = 1; /* zero-length record fragment is structurally invalid */
            return 0;
        }
        if (next + 5 + flen > MQ_CH_CAP) {
            h->bad = 1; /* record layer would exceed the hard cap */
            return 0;
        }
        if (next + 5 + flen > h->len) {
            h->incomplete = 1; /* fragment not fully present yet => need more */
            return 0;
        }
        h->rec_off = next;
        h->frag_len = flen;
        h->frag_pos = 0;
    }
    return 1;
}

/* Read `n` logical handshake bytes into `dst` (which must hold `n`).
 * Returns 1 on success; on failure returns 0 with h->incomplete or h->bad set.
 * Spans record boundaries transparently — used both for the small fixed-size
 * header/length reads and for copying the whole handshake body out. */
static int
hs_read(hs_t *h, uint8_t *dst, size_t n)
{
    size_t got = 0;
    while (got < n) {
        if (!hs_ensure(h)) {
            return 0;
        }
        size_t avail = h->frag_len - h->frag_pos;
        size_t take = n - got < avail ? n - got : avail;
        memcpy(dst + got, h->buf + h->rec_off + 5 + h->frag_pos, take);
        h->frag_pos += take;
        got += take;
    }
    return 1;
}

static int
hs_u8(hs_t *h, uint8_t *out)
{
    return hs_read(h, out, 1);
}

static int
hs_u24(hs_t *h, size_t *out)
{
    uint8_t b[3];
    if (!hs_read(h, b, 3)) {
        return 0;
    }
    *out = ((size_t)b[0] << 16) | ((size_t)b[1] << 8) | (size_t)b[2];
    return 1;
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

    /* ---- Handshake layer (reassembled across handshake records) ----
     * The handshake message MAY span several content_type==22 records. Walk the
     * logical handshake byte stream via `hs_t`, which transparently skips record
     * headers and surfaces "need more bytes" vs "structurally invalid". */
    hs_t h;
    hs_init(&h, buf, len, /*rec_off=*/0, frag_len);

    uint8_t msg_type;
    if (!hs_u8(&h, &msg_type)) {
        if (h.bad) return MQ_CH_INVALID;
        return MQ_CH_NEED_MORE; /* header straddles into a not-yet-present record */
    }
    if (msg_type != TLS_HS_CLIENT_HELLO) {
        return MQ_CH_INVALID; /* valid TLS record but not a ClientHello */
    }
    size_t hs_len;
    if (!hs_u24(&h, &hs_len)) {
        if (h.bad) return MQ_CH_INVALID;
        return MQ_CH_NEED_MORE;
    }
    /* LOAD-BEARING bound for the body[MQ_CH_CAP] copy below: hs_len is a 24-bit
     * field (up to ~16M), so reject any declared handshake body that cannot fit
     * the fixed scratch BEFORE copying. A body structurally too large to ever fit
     * is INVALID; one merely not fully buffered yet is NEED_MORE (distinguished by
     * walking the records). On a 64-bit target 4+hs_len cannot wrap. */
    if (4 + hs_len > MQ_CH_CAP) {
        return MQ_CH_INVALID;
    }
    /* Copy the (possibly record-spanning) handshake body into a fixed scratch so
     * the contiguous extension parser below is unchanged. Allocation-free: the
     * body is bounded by MQ_CH_CAP (checked just above). */
    uint8_t body[MQ_CH_CAP];
    if (!hs_read(&h, body, hs_len)) {
        if (h.bad) return MQ_CH_INVALID;
        return MQ_CH_NEED_MORE; /* body not yet fully present across records */
    }

    /* The reassembled body is now a complete, contiguous enclosing field: inner
     * overruns of it are structural impossibilities => INVALID. */
    cur_t c = {.base = body, .limit = hs_len, .pos = 0};

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
                    /* Take the first host_name (type 0) entry. Inner
                     * malformations here are NON-FATAL: the enclosing
                     * server_name extension framing is already length-validated
                     * (ext_len / list_end bounded above), so a truncated sub-
                     * field degrades to empty-SNI rather than rejecting the
                     * whole flow. Hence `break` (leave sni empty), not return. */
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
                    /* As with SNI above, inner malformations are NON-FATAL: the
                     * ALPN extension framing is already length-validated, so a
                     * truncated protocol-name sub-field degrades to no-h2 rather
                     * than rejecting the whole flow. Hence `break`, not return. */
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
