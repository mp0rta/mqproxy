/* mq_stream.h — wrapper around one raw MPQUIC (xqc_stream_t) stream.
 *
 * An mq_stream owns the application-side view of a single bidirectional QUIC
 * stream: it stores the xqc_stream_t, registers itself as the stream's
 * user_data so xquic's read/write/close notifications recover it, and
 * forwards those notifications to an owner via mq_stream_set_cbs.
 *
 * Lifetime: an mq_stream is created either by mq_conn_open_stream (client,
 * locally initiated) or by xquic's stream_create_notify (server, peer
 * initiated). It is freed from the stream_close_notify path.
 */
#ifndef MQ_TRANSPORT_MQ_STREAM_H
#define MQ_TRANSPORT_MQ_STREAM_H

#include <stddef.h>
#include <stdint.h>

#include <xquic/xquic.h>

typedef struct mq_stream_s mq_stream_t;

/* Owner callbacks. on_readable fires when stream data is ready to read;
 * on_writable fires when a previously-blocked send can resume; on_close fires
 * once, just before the mq_stream is freed (the owner must drop its pointer
 * and must not call mq_stream_* afterwards). user is the value passed to
 * mq_stream_set_cbs. */
typedef void (*mq_stream_on_readable_fn)(mq_stream_t *s, void *user);
typedef void (*mq_stream_on_writable_fn)(mq_stream_t *s, void *user);
typedef void (*mq_stream_on_close_fn)(mq_stream_t *s, void *user);

/* Register owner callbacks (any may be NULL). */
void mq_stream_set_cbs(mq_stream_t *s, mq_stream_on_readable_fn on_readable,
                       mq_stream_on_writable_fn on_writable,
                       mq_stream_on_close_fn on_close, void *user);

/* Send up to len bytes; fin!=0 closes the send direction after this write.
 * Returns bytes accepted (>=0), or -1 on a hard error. A return of 0 with a
 * non-empty buffer means flow control is blocked (was -XQC_EAGAIN) — retry
 * after the on_writable callback. */
long mq_stream_send(mq_stream_t *s, const void *buf, size_t len, int fin);

/* Recv up to cap bytes. *fin is set to 1 if the peer closed the stream.
 * Returns bytes read (>=0), or -1 on error. 0 with *fin==0 means no data
 * available right now (was -XQC_EAGAIN). */
long mq_stream_recv(mq_stream_t *s, void *buf, size_t cap, int *fin);

/* Send RESET_STREAM. The mq_stream is freed later via stream_close_notify. */
void mq_stream_close(mq_stream_t *s);

/* The underlying xquic stream id. */
uint64_t mq_stream_id(const mq_stream_t *s);

/* The mq_conn_t* that owns this stream, or NULL. Set by the transport when a
 * peer-initiated stream is surfaced, so the owner can recover the connection
 * (e.g. to attach/look up per-conn state). Returned as void* to avoid a header
 * cycle; callers cast to mq_conn_t*. */
void *mq_stream_conn(const mq_stream_t *s);

#endif /* MQ_TRANSPORT_MQ_STREAM_H */
