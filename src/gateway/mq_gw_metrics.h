#ifndef MQ_GW_METRICS_H
#define MQ_GW_METRICS_H

#include <stddef.h>
#include <stdint.h>

/* mq.req line buffer cap. Holds the fixed keys plus the capped authority/path
 * (see *_CAP below). 1024 is comfortable. Note: each *_CAP bounds INPUT
 * characters; a quoted field can emit up to ~2x its cap in bytes when every
 * character needs escaping (e.g. all-quotes value). A -1 (caller drops the
 * line) is therefore reachable on adversarial input; expected-rare for normal
 * URL authority/path. */
#define MQ_GW_REQ_LINE_CAP      1024
#define MQ_GW_REQ_AUTHORITY_CAP 128
#define MQ_GW_REQ_PATH_CAP      256
#define MQ_GW_REQ_RESET_CAP     64 /* max input chars for reset_reason field */

/* All values are already gathered by the caller; no xquic/libcurl/libevent
 * dependency, so this is a pure-unit test target. String fields must be
 * non-NULL ("-" / "" for absent). Numeric -1 denotes "unknown". */
typedef struct {
    const char *method;          /* "GET"/"POST"/... or "-" */
    int status;                  /* HTTP status sent to client; 0 if none */
    const char *authority;       /* target host[:port] or "-" */
    const char *path;            /* target path, query already stripped, or "-" */
    uint64_t req_bytes;          /* request body bytes received from client */
    uint64_t resp_bytes;         /* response body bytes sent to client */
    int ttfb_ms;                 /* -1 if unknown */
    int duration_ms;             /* -1 if unknown */
    const char *origin_protocol; /* "h3"/"h2"/"h1"/"none" */
    const char *origin_tls;      /* "ok"/"verify_fail"/"connect_fail"/"na" */
    const char *cache;           /* "bypass" now; "hit"/"miss" in Phase 6 */
    int origin_reuse;            /* 1 when the origin connection was reused, else 0 */
    int origin_connect_ms;       /* origin TCP+TLS setup ms; 0 on reuse; -1 unknown */
    int mp_state;                /* xqc_request_stats_t.mp_state 0..3 */
    int completion_ms;           /* -1 if unknown */
    const char *reset_reason;    /* "" if clean close */
} mq_gw_req_metrics_t;

/* Render a logfmt "mq.req ..." line into buf. cid_hex is the connection cid as
 * a string — callers pass "-" today (5c log lines carry no cid, so there is
 * nothing to correlate a hex cid against yet); the param is retained so Phase 6
 * can wire a real cid without a signature change. sid is the request's MPQUIC
 * stream id (the live within-conn correlation key). authority/path/reset_reason
 * are quoted and capped; embedded quotes are escaped. Returns bytes written
 * (>0) or -1 on truncation. */
int mq_gw_format_req_line(char *buf, size_t cap, const char *cid_hex, uint64_t sid,
                          const mq_gw_req_metrics_t *m);

#endif /* MQ_GW_METRICS_H */
