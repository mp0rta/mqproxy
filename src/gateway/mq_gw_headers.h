// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_GW_HEADERS_H
#define MQ_GW_HEADERS_H
#include <stddef.h>

#include "gateway/mq_http1.h"

/* Pure, allocation-free header-policy / target-parsing / error-mapping helpers
 * shared by the gateway CLIENT (it tunnels a local fetch request) and the
 * gateway SERVER (it replays that request to an origin). Nothing here touches
 * sockets, libcurl, or the transport; every function is a deterministic
 * function of its inputs so it can be exhaustively unit-tested.
 *
 * Design references: spec §14.2 / §14.5 (strip rules), §18.3 (error mapping),
 * design doc §7 (header policy) / §10 (curl error → HTTP status).
 */

/* ---------------------------------------------------------------------------
 * Target parsing  (X-Mq-Target → scheme / authority / path+query)
 * ------------------------------------------------------------------------- */
typedef struct {
    char scheme[8];      /* "http" | "https" (NUL-terminated) */
    char authority[256]; /* host[:port], non-empty (NUL-terminated) */
    char path[1024];     /* path + query; "/" if empty (NUL-terminated) */
} mq_gw_target_t;

/* Parse the X-Mq-Target value into scheme / authority / path+query.
 * Returns 0 on success (filling *out), -1 on any rejection.
 *
 * Accepted form:  ("http://" | "https://") authority [ path ] [ "?" query ]
 *
 * Deliberately strict (this value crosses the local trust boundary and is
 * turned into an outbound fetch URL — a lenient parser here is an SSRF /
 * credential-injection / request-smuggling surface):
 *
 *   - scheme: lowercase "http://" or "https://" ONLY. Mixed/upper case
 *     ("HTTPS://") is REJECTED — callers emit the target, so requiring the
 *     canonical lowercase form keeps the contract unambiguous and avoids
 *     scheme-confusion games.
 *   - authority: bytes up to the first '/' or '?' (or end). Must be non-empty
 *     and <= 255 bytes. NO '@' anywhere (userinfo is rejected outright — it is
 *     a credential-injection surface and we never want to carry creds in the
 *     URL). No control bytes (<0x20 or 0x7f) and no space. If a port is
 *     present it must be digits-only and non-empty; the host:port split is on
 *     the LAST ':' UNLESS the host is a bracketed IPv6 literal "[....]", in
 *     which case the colon scan starts after the closing ']'.
 *   - path+query: everything after the authority. If empty → "/". If it starts
 *     with '?' (no path segment) → "/" + query. <= 1023 bytes. No control
 *     bytes (<0x20 or 0x7f) and no space.
 *   - fragment ("#..."): REJECTED. A fetch target carrying a fragment is a
 *     caller bug (fragments are client-side only and never sent on the wire);
 *     rejecting it surfaces the bug instead of silently forwarding it.
 */
int mq_gw_parse_target(const char *s, size_t len, mq_gw_target_t *out);

/* ---------------------------------------------------------------------------
 * Method parsing
 * ------------------------------------------------------------------------- */

/* Validate and canonicalise an HTTP method. RFC 7230 token chars only;
 * ASCII-lowercased letters are uppercased; result must be 1..15 chars.
 * Writes a NUL-terminated method into out[16] and returns 0, or returns -1
 * (leaving out unspecified) on empty / too-long / non-token input. */
int mq_gw_parse_method(const char *s, size_t len, char out[16]);

/* ---------------------------------------------------------------------------
 * Strip predicates  (case-insensitive header-name match; 1 = strip the header)
 *
 *   hop-by-hop (RFC 7230 §6.1, stripped in BOTH directions):
 *     Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE,
 *     Trailer, Transfer-Encoding, Upgrade
 *   client → tunnel  (mq_gw_strip_client): hop-by-hop + X-Mq-* (any) + Host +
 *     Content-Length + Cookie
 *   server → origin  (mq_gw_strip_server): hop-by-hop + X-Mq-* (any)
 *
 * NOTE: Authorization is intentionally NOT in any set — it is default-forwarded
 * to the origin so the caller can authenticate to the target. Cookie is
 * stripped client-side only (not server-side); Content-Length is stripped
 * client-side but is NOT hop-by-hop.
 * ------------------------------------------------------------------------- */
int mq_gw_strip_client(const char *n, size_t nl);
int mq_gw_strip_server(const char *n, size_t nl);
int mq_gw_strip_hop(const char *n, size_t nl);

/* Returns 1 if the parsed request carries the same X-Mq-* header name two or
 * more times (a duplicate control header → caller should answer 400). Only
 * X-Mq-* names are considered; ordinary duplicate headers (e.g. two Accept)
 * are legal and ignored here. Name comparison is case-insensitive. */
int mq_gw_has_dup_xmq(const mq_http1_req_t *req);

/* ---------------------------------------------------------------------------
 * libcurl result code → HTTP status  (design §10.1)
 *
 * Mirrored constants so this translation unit compiles WITHOUT libcurl. The
 * curl client (Chunk 4) adds _Static_asserts that each mirror equals the real
 * CURLE_* value, so any future divergence is caught at compile time.
 * ------------------------------------------------------------------------- */
#define MQ_GW_CURL_RESOLVE     6  /* mirrors CURLE_COULDNT_RESOLVE_HOST     */
#define MQ_GW_CURL_CONNECT     7  /* mirrors CURLE_COULDNT_CONNECT          */
#define MQ_GW_CURL_TIMEDOUT    28 /* mirrors CURLE_OPERATION_TIMEDOUT       */
#define MQ_GW_CURL_PEER_VERIFY 60 /* mirrors CURLE_PEER_FAILED_VERIFICATION */

/* Map a curl result code to an HTTP status for the synthesized error response:
 *   RESOLVE(6)->502, CONNECT(7)->502, TIMEDOUT(28)->504, PEER_VERIFY(60)->502,
 *   anything else -> 502.
 * This must NOT be called with 0 (CURLE_OK) — success has no error status; if
 * it is, the defensive result is 502. */
int mq_gw_status_from_curl(int curl_code);

#endif
