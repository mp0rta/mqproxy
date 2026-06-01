#include "ingress/mq_http_connect.h"
#include <arpa/inet.h>
#include <string.h>

/* Find the end (one past the last byte) of the first "\r\n\r\n" terminator in
   buf[0..len). Returns 0 if not found. */
static size_t
find_header_end(const uint8_t *buf, size_t len)
{
    if (len < 4) return 0;
    for (size_t i = 0; i + 4 <= len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return 0;
}

/* Parse a decimal port from text[0..len). Returns 0 on any error (0 is never a
   valid CONNECT port). */
static uint16_t
parse_port(const char *text, size_t len)
{
    if (len == 0 || len > 5) return 0;
    uint32_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        if (c < '0' || c > '9') return 0;
        v = v * 10 + (uint32_t)(c - '0');
    }
    if (v < 1 || v > 65535) return 0;
    return (uint16_t)v;
}

mq_http_status_t
mq_http_connect_parse(const uint8_t *buf, size_t len, mq_http_target_t *out,
                      size_t *header_len)
{
    size_t hend = find_header_end(buf, len);
    if (hend == 0) return MQ_HTTP_NEED_MORE;

    /* The request line ends at the first CRLF within [0, hend). */
    size_t line_end = 0; /* index of '\r' ending the request line */
    for (size_t i = 0; i + 1 < hend; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            line_end = i;
            break;
        }
    }
    /* hend always contains a CRLF, so line_end is valid (could be 0 only for an
       empty first line, which has no method => BAD). */

    const char *line = (const char *)buf;
    size_t llen = line_end;

    /* METHOD SP TARGET SP HTTP/x.y */
    /* find first space (end of method) */
    size_t m_end = 0;
    while (m_end < llen && line[m_end] != ' ')
        m_end++;
    if (m_end == 0 || m_end >= llen) return MQ_HTTP_BAD; /* no method or no target */

    /* method check */
    if (m_end != 7 || memcmp(line, "CONNECT", 7) != 0) return MQ_HTTP_UNSUPPORTED;

    /* target starts after the space */
    size_t t_start = m_end + 1;
    /* find next space (end of target / start of version) */
    size_t t_end = t_start;
    while (t_end < llen && line[t_end] != ' ')
        t_end++;
    if (t_end >= llen) return MQ_HTTP_BAD;    /* no version field => malformed line */
    if (t_end == t_start) return MQ_HTTP_BAD; /* empty target */

    /* version field must be non-empty and look like HTTP/ */
    size_t v_start = t_end + 1;
    if (v_start >= llen) return MQ_HTTP_BAD;
    if (llen - v_start < 5 || memcmp(line + v_start, "HTTP/", 5) != 0) return MQ_HTTP_BAD;

    /* target = host:port (authority-form). Split on the LAST colon. */
    const char *target = line + t_start;
    size_t tlen = t_end - t_start;

    size_t colon = tlen; /* index of last colon within target, or tlen if none */
    for (size_t i = tlen; i > 0; i--) {
        if (target[i - 1] == ':') {
            colon = i - 1;
            break;
        }
    }
    if (colon == tlen) return MQ_HTTP_BAD; /* no port */

    const char *host = target;
    size_t host_len = colon;
    const char *port_text = target + colon + 1;
    size_t port_len = tlen - colon - 1;

    uint16_t port = parse_port(port_text, port_len);
    if (port == 0) return MQ_HTTP_BAD;

    if (host_len == 0) return MQ_HTTP_BAD;

    /* Bracketed IPv6 literal: [ ... ] */
    if (host[0] == '[' && host[host_len - 1] == ']') {
        size_t inner_len = host_len - 2;
        if (inner_len == 0 || inner_len > 45) return MQ_HTTP_BAD;
        char tmp[46];
        memcpy(tmp, host + 1, inner_len);
        tmp[inner_len] = '\0';
        uint8_t raw[16];
        if (inet_pton(AF_INET6, tmp, raw) != 1) return MQ_HTTP_BAD;
        out->atype = MQ_ADDR_IPV6;
        memcpy(out->host, raw, 16);
        out->host_len = 16;
        out->port = port;
        *header_len = hend;
        return MQ_HTTP_CONNECT_DONE;
    }

    if (host_len > MQ_MAX_HOST) return MQ_HTTP_BAD;

    /* Try dotted-quad IPv4. inet_pton needs a NUL-terminated string; an IPv4
       literal is at most 15 chars. */
    if (host_len <= 15) {
        char tmp[16];
        memcpy(tmp, host, host_len);
        tmp[host_len] = '\0';
        uint8_t raw[4];
        if (inet_pton(AF_INET, tmp, raw) == 1) {
            out->atype = MQ_ADDR_IPV4;
            memcpy(out->host, raw, 4);
            out->host_len = 4;
            out->port = port;
            *header_len = hend;
            return MQ_HTTP_CONNECT_DONE;
        }
    }

    /* Otherwise: domain name text. */
    out->atype = MQ_ADDR_DOMAIN;
    memcpy(out->host, host, host_len);
    out->host_len = host_len;
    out->port = port;
    *header_len = hend;
    return MQ_HTTP_CONNECT_DONE;
}

size_t
mq_http_build_200(char *out, size_t cap)
{
    static const char msg[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    size_t n = sizeof(msg) - 1;
    if (cap < n) return 0;
    memcpy(out, msg, n);
    return n;
}

const char *
mq_http_status_line(mq_tcp_err_t err)
{
    switch (err) {
    case MQ_TCP_TIMEOUT: return "HTTP/1.1 504 Gateway Timeout\r\n\r\n";
    case MQ_TCP_POLICY_DENIED: return "HTTP/1.1 403 Forbidden\r\n\r\n";
    case MQ_TCP_DNS_FAILED:
    case MQ_TCP_CONN_REFUSED:
    case MQ_TCP_OK:
    default: return "HTTP/1.1 502 Bad Gateway\r\n\r\n";
    }
}
