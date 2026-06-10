#include "gateway/mq_gw_metrics.h"
#include <stdio.h>
#include <string.h>

/* Append a logfmt quoted field: key="value" with capping + quote-escaping.
 * Writes into buf[off..cap). Returns new offset, or -1 on overflow. cap_value
 * bounds the value length (excluding escapes); on cap an ellipsis marker "…"
 * is appended before the closing quote so truncation is visible. */
static int
append_quoted(char *buf, size_t cap, int off, const char *key, const char *val,
              size_t cap_value)
{
    if (off < 0) return -1;
    int n = snprintf(buf + off, (off < (int)cap) ? cap - off : 0, " %s=\"", key);
    if (n < 0 || off + n >= (int)cap) return -1;
    off += n;
    size_t written = 0;
    int capped = 0;
    for (const char *p = val; *p; p++) {
        if (written >= cap_value) {
            capped = 1;
            break;
        }
        char esc[3];
        int el;
        if (*p == '"' || *p == '\\') {
            esc[0] = '\\';
            esc[1] = *p;
            el = 2;
        } else {
            esc[0] = *p;
            el = 1;
        }
        if (off + el >= (int)cap) return -1;
        memcpy(buf + off, esc, el);
        off += el;
        written++;
    }
    if (capped) {
        const char *ell = "\xE2\x80\xA6"; /* U+2026 … */
        int el = 3;
        if (off + el >= (int)cap) return -1;
        memcpy(buf + off, ell, el);
        off += el;
    }
    if (off + 1 >= (int)cap) return -1;
    buf[off++] = '"';
    return off;
}

int
mq_gw_format_req_line(char *buf, size_t cap, const char *cid_hex, uint64_t sid,
                      const mq_gw_req_metrics_t *m)
{
    if (!buf || !cid_hex || !m) return -1;
    int off = snprintf(buf, cap, "mq.req cid=%s sid=%llu method=%s status=%d", cid_hex,
                       (unsigned long long)sid, m->method, m->status);
    if (off < 0 || off >= (int)cap) return -1;

    off =
        append_quoted(buf, cap, off, "authority", m->authority, MQ_GW_REQ_AUTHORITY_CAP);
    off = append_quoted(buf, cap, off, "path", m->path, MQ_GW_REQ_PATH_CAP);
    if (off < 0) return -1;

    int n =
        snprintf(buf + off, cap - off,
                 " req_bytes=%llu resp_bytes=%llu ttfb_ms=%d duration_ms=%d"
                 " origin_protocol=%s origin_tls=%s cache=%s origin_reuse=%d"
                 " origin_connect_ms=%d mp_state=%d completion_ms=%d",
                 (unsigned long long)m->req_bytes, (unsigned long long)m->resp_bytes,
                 m->ttfb_ms, m->duration_ms, m->origin_protocol, m->origin_tls, m->cache,
                 m->origin_reuse, m->origin_connect_ms, m->mp_state, m->completion_ms);
    if (n < 0 || off + n >= (int)cap) return -1;
    off += n;

    off = append_quoted(buf, cap, off, "reset", m->reset_reason, MQ_GW_REQ_RESET_CAP);
    if (off < 0) return -1;
    if (off < (int)cap) buf[off] = '\0';
    return off;
}
