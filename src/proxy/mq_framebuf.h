/* mq_framebuf.h — bounded frame-accumulation buffer for control/header decode.
 *
 * The proxy client and server each need to pull bytes off a freshly-opened
 * QUIC stream into a small fixed buffer and retry decoding a single
 * length-prefixed frame (AUTH_REQUEST/RESPONSE, CONNECT_TCP_REQUEST/RESPONSE)
 * as more bytes arrive, treating a full buffer without a valid frame as
 * malformed. This value-type helper owns only the buffer + length + the fill
 * loop; the caller still performs the decode, the overflow⇒malformed decision,
 * and (on success) computes the trailing-byte offset for mq_flow_prebuffer.
 */
#ifndef MQ_FRAMEBUF_H
#define MQ_FRAMEBUF_H

#include <stddef.h>
#include <stdint.h>

#include "transport/mq_stream.h"

/* Bound for an accumulated control/header frame. AUTH and CONNECT_TCP frames
 * (client id + token / host + port + small fields) sit comfortably under this;
 * exceeding it without a decode is treated by the caller as malformed. */
#define MQ_FRAMEBUF_CAP 512

/* A zero-initialized mq_framebuf_t (e.g. via calloc) is already empty. */
typedef struct {
    uint8_t buf[MQ_FRAMEBUF_CAP];
    size_t len;
} mq_framebuf_t;

/* Drain currently-available stream bytes into fb (up to MQ_FRAMEBUF_CAP),
 * looping while the stream keeps returning data. The caller then attempts a
 * decode on fb->buf / fb->len and, on success, may consume + reset.
 *
 * If non-NULL, *fin is set to 1 (and never cleared) when a stream FIN is
 * observed during the fill; the caller may treat a FIN-without-decode as
 * malformed.
 *
 * Returns:
 *   >0  new total fb->len (bytes are available to attempt a decode);
 *    0  no new bytes right now (EAGAIN) — caller still re-attempts decode on
 *       whatever is already buffered, exactly as before;
 *   -1  hard stream error (e.g. RESET) before a frame. Callers that fail hard
 *       on a pre-frame error act on this; callers that historically retried the
 *       decode regardless may ignore the distinction and still decode fb.
 *
 * Note the buffer-full case is NOT reported here: when fb is full the helper
 * simply stops reading and returns fb->len (>0); the caller owns the
 * "full without a valid frame ⇒ malformed" decision after its decode attempt,
 * preserving each call site's exact policy. */
int mq_framebuf_fill(mq_stream_t *s, mq_framebuf_t *fb, int *fin);

#endif /* MQ_FRAMEBUF_H */
