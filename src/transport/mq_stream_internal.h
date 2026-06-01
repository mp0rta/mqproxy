/* mq_stream_internal.h — definitions shared between mq_stream.c and mq_conn.c.
 *
 * Not part of the public transport API. mq_conn needs to construct/wrap
 * mq_streams and reference the xquic stream notify callbacks when building
 * the ALP callback tables.
 */
#ifndef MQ_TRANSPORT_MQ_STREAM_INTERNAL_H
#define MQ_TRANSPORT_MQ_STREAM_INTERNAL_H

#include <xquic/xquic.h>

#include "transport/mq_stream.h"

struct mq_stream_s {
    xqc_stream_t *xs;
    void *conn; /* owning mq_conn_t* (set by mq_conn for peer streams) */

    mq_stream_on_readable_fn on_readable;
    mq_stream_on_writable_fn on_writable;
    mq_stream_on_close_fn on_close;
    void *cb_user;
};

/* Set/get the owning mq_conn_t* (opaque void* to avoid a header cycle). */
void mq_stream_set_conn(mq_stream_t *s, void *conn);

/* Allocate an mq_stream around an existing xqc_stream_t and register it as
 * the stream's user_data. Returns NULL on alloc failure. */
mq_stream_t *mq_stream_wrap(xqc_stream_t *xs);

/* Allocate an unbound mq_stream (no xqc_stream_t yet). Used by the client
 * stream-open path so the wrapper can be handed to xqc_stream_create as
 * user_data and bound from stream_create_notify, avoiding a double-wrap. */
mq_stream_t *mq_stream_alloc(void);

/* Bind a previously-allocated mq_stream to an xqc_stream_t and register it as
 * the stream's user_data. */
void mq_stream_bind(mq_stream_t *s, xqc_stream_t *xs);

/* Free the mq_stream struct (does not touch xquic state). */
void mq_stream_free(mq_stream_t *s);

/* xquic stream notify callbacks, wired into the ALP stream callback table. */
xqc_int_t mq_stream_read_notify(xqc_stream_t *stream, void *strm_user_data);
xqc_int_t mq_stream_write_notify(xqc_stream_t *stream, void *strm_user_data);
xqc_int_t mq_stream_close_notify(xqc_stream_t *stream, void *strm_user_data);

#endif /* MQ_TRANSPORT_MQ_STREAM_INTERNAL_H */
