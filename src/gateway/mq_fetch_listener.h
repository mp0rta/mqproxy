// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_fetch_listener.h — local fetch-API listener (POST /_mqproxy/fetch).
 *
 * A loopback HTTP/1.1 accept loop that the gateway client uses to receive
 * fetch requests from a local-but-untrusted peer (the app / SDK). It binds and
 * listens a non-blocking TCP socket on ip:port and runs a libevent EV_READ
 * accept loop, mirroring mq_listener's socket/accept machinery.
 *
 * Unlike mq_listener (1 connection = a long-lived CONNECT tunnel), here ONE
 * connection = ONE request: every response carries `Connection: close` and
 * keep-alive is NOT supported in the MVP. After the request head parses, the
 * BODY is streamed to the gateway client through callbacks, with backpressure
 * in BOTH directions.
 *
 * Request lifecycle:
 *   1. Accumulate bytes into a head buffer until mq_http1_parse_req returns
 *      DONE/BAD (capped at MQ_HTTP1_MAX_HEAD).
 *   2. Listener-owned direct error replies (the cbs are NEVER invoked):
 *        - parse BAD                              -> 400 Bad Request
 *        - method+path not "POST /_mqproxy/fetch" -> 404 Not Found
 *        - Transfer-Encoding lists chunked        -> 411 Length Required
 *      Each reply is "<status>\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
 *      flushed, then the connection is closed.
 *   3. Valid request -> cbs->on_request(req, handle, user, &req_ctx).
 *        - return -1 => the handler already wrote its own error reply via the
 *          handle ops; the listener just flushes and closes (no body streamed).
 *        - return 0  => the listener streams exactly content_length body bytes
 *          to cbs->on_body, then cbs->on_body_done. content_length <= 0 calls
 *          on_body_done immediately after on_request returns.
 *   4. cbs->on_body returning -1 => the listener pauses reading (backpressure);
 *      the gateway resumes it via mq_fetch_conn_resume_read(handle).
 *   5. Peer EOF/error BEFORE content_length bytes are delivered => on_aborted
 *      (NOT on_body_done). After on_body_done, peer EOF is normal: the listener
 *      waits for the gateway to write the response via the handle ops.
 *   6. Body bytes exceeding content_length are a peer protocol violation, but
 *      the body is fully received: on_body_done has already fired and the
 *      gateway owns the write side. The listener does NOT fire on_aborted and
 *      does NOT tear the connection down from the read path; it just stops
 *      reading and leaves teardown to the gateway's finish()/abort() (so a
 *      response the gateway is mid-flushing is not discarded).
 *
 * DESIGN NOTE — handle vs fd: the converged plan's on_request signature passes
 * an `int fd`, but the per-connection handle ops below need the listener's
 * per-conn object, not a raw fd. Per the sanctioned plan-review interpretation,
 * on_request receives a `void *handle` (the opaque per-conn handle) instead;
 * the accepted fd stays internal to the listener. The gateway drives the
 * connection ONLY through the handle ops.
 *
 * Ownership of the accepted fd / handle:
 *   - The listener OWNS the accepted fd for the connection's whole life and is
 *     the only party that ever closes it. The gateway never sees the fd.
 *   - The `handle` is valid from the on_request call until the gateway calls
 *     mq_fetch_conn_finish() or mq_fetch_conn_abort(), OR until on_aborted
 *     fires. After ANY of those, the handle is DEAD: the gateway MUST drop it
 *     and never call a handle op again. The listener guarantees that NO cbs
 *     fire after finish()/abort() (it sets a 'detached' flag), so finish/abort
 *     are the gateway's clean hand-back of the connection.
 *   - on_aborted is the listener telling the gateway the peer died mid-body;
 *     the gateway must drop the handle (it is already being torn down) and MUST
 *     NOT call finish/abort on it.
 *
 * This module knows nothing about xquic; it speaks libevent + sockets and the
 * mq_fetch_cbs_t boundary only.
 *
 * KNOWN LIMITATION — per-request vs per-process memory: each request's buffers
 * are individually bounded (the request head is capped at MQ_HTTP1_MAX_HEAD, the
 * download spill buffer at 256 KiB, and the per-connection output queue at the
 * 4 MiB hard ceiling above), so no single request can grow memory without limit.
 * The per-PROCESS SUM of those buffers across many concurrent requests is NOT
 * bounded, however. This is acceptable for the Phase 2 single-trusted-client
 * scope (one local app drives a small number of in-flight fetches); a global
 * memory budget / concurrency cap is deferred to the multi-client hardening work
 * (Phase 5).
 */
#ifndef MQ_GATEWAY_MQ_FETCH_LISTENER_H
#define MQ_GATEWAY_MQ_FETCH_LISTENER_H

#include <stddef.h>
#include <stdint.h>

#include "gateway/mq_http1.h"

struct event_base;

typedef struct mq_fetch_listener_s mq_fetch_listener_t;

/* Gateway-supplied callbacks. All are invoked from the event loop. None may
 * free the listener.
 *
 * ── HANDLE-OP RE-ENTRANCY CONTRACT (which ops are safe from which callback) ──
 * The listener touches the connection object AFTER on_request and on_body
 * return (drive_head reads c->body_total + calls deliver_body after on_request;
 * deliver_body does `c->body_delivered += take` immediately after on_body
 * returns — see mq_fetch_listener.c). finish()/abort() DETACH and may DESTROY
 * the connection, so calling them from inside on_request or on_body would make
 * those post-return touches a use-after-free. Therefore:
 *
 *   - mq_fetch_conn_finish / mq_fetch_conn_abort MUST NOT be called from within
 *     on_request or on_body. Use the RETURN VALUES instead: return -1 from
 *     on_request = "I already replied via the handle ops" (listener flushes +
 *     closes); return -1 from on_body = "consumed, but pause reading".
 *   - finish/abort ARE safe from on_body_done and from any later (RESP-phase)
 *     point, and from OUTSIDE any callback (the normal hand-back). on_body_done
 *     is the listener's LAST touch of the connection on the read path: it sets
 *     the *done out-param (deliver_body, drive_head) BEFORE invoking on_body_done
 *     and does not touch `c` afterward, so finish/abort there is safe — this is
 *     the normal echo path (reply + finish from on_body_done).
 *   - mq_fetch_conn_pause_read / resume_read / write / set_drain_cb are safe
 *     ANYWHERE (they early-return when the handle is detached; resume_read
 *     defers its read kick, so it is even safe from inside on_body).
 *   - on_aborted is terminal: the handle is already being torn down — drop it
 *     and call NO handle op (not even finish/abort). */
typedef struct {
    /* The request head parsed (valid POST /_mqproxy/fetch). The listener will
     * then stream body bytes to on_body. Return 0 = accepted (listener
     * proceeds to stream the body); return -1 = the handler already wrote its
     * own error reply (the listener just flushes and closes). *req_ctx is the
     * handler's per-request context, threaded into the later callbacks.
     *
     * MUST NOT call finish/abort (the listener touches the conn after this
     * returns — UAF); reply-and-close is signalled by returning -1 after
     * writing via the handle ops. write/pause_read/resume_read/set_drain_cb are
     * safe here.
     *
     * `req`'s header slices point into the listener's read buffer and are valid
     * only for the duration of this call — copy anything you need to keep. */
    int (*on_request)(const mq_http1_req_t *req, void *handle, void *user,
                      void **req_ctx);

    /* A chunk of body bytes [p, p+len). The chunk is ALWAYS consumed by this
     * call (the listener never re-delivers it). Return value signals only
     * backpressure: 0 = keep streaming; -1 = consumed-but-now-full, so the
     * listener stops reading further body until the gateway calls
     * mq_fetch_conn_resume_read(). p is valid only for this call.
     *
     * MUST NOT call finish/abort (the listener touches the conn after this
     * returns — UAF); use the -1 return to pause. write/pause_read/resume_read/
     * set_drain_cb are safe here. */
    int (*on_body)(void *req_ctx, const uint8_t *p, size_t len);

    /* Exactly content_length body bytes have been delivered to on_body. The
     * listener will not touch the connection on the read path after this returns
     * (the read path's *done discipline guarantees it), so finish/abort ARE safe
     * here — this is the normal response-phase hand-back. */
    void (*on_body_done)(void *req_ctx);

    /* The local peer died (EOF/error) before content_length bytes arrived. The
     * handle is being torn down: drop it, do not call any handle op. */
    void (*on_aborted)(void *req_ctx);
} mq_fetch_cbs_t;

/* Create a fetch-API listener bound to ip:port (port 0 => ephemeral). `base`
 * is borrowed (must outlive the listener). `cbs` is copied; `user` is opaque
 * and threaded into on_request. Returns NULL on bad args / bind / listen
 * failure. */
mq_fetch_listener_t *mq_fetch_listener_new(struct event_base *base, const char *ip,
                                           uint16_t port, const mq_fetch_cbs_t *cbs,
                                           void *user);

/* The bound local TCP port in host byte order (useful for ephemeral binds in
 * tests). Returns 0 if unknown. */
uint16_t mq_fetch_listener_port(const mq_fetch_listener_t *l);

/* Free the listener: stop accepting, close the listen socket, and tear down
 * every live connection (closing its fd). Safe on NULL. */
void mq_fetch_listener_free(mq_fetch_listener_t *l);

/* ── per-connection handle ops (called by the gateway client) ─────────────────
 *
 * `handle` is the opaque per-conn handle delivered to on_request. All ops are
 * no-ops (or return an error) once the connection is detached (after
 * finish/abort/on_aborted) — but the gateway MUST treat the handle as dead and
 * stop using it after finish/abort/on_aborted regardless. */

/* Stop reading body bytes from the peer (backpressure from the gateway). */
void mq_fetch_conn_pause_read(void *handle);

/* Resume reading body bytes after a pause. The read kick is DEFERRED to the
 * next event-loop turn (it does not re-enter the read path synchronously), so
 * it is safe to call this from within on_body — there is no recursion into the
 * read loop and no use-after-free window if a later callback tears the conn
 * down. */
void mq_fetch_conn_resume_read(void *handle);

/* Append response bytes to the connection's output. Returns:
 *   >0  accepted (queued/sent),
 *    0  high-watermark hit — the output buffer is full; STOP feeding and wait
 *       for the drain callback (set via mq_fetch_conn_set_drain_cb) to fire,
 *   -1  error (handle dead / write failure / the write would push the queued
 *       output above the internal hard ceiling, currently 4 MiB).
 *
 * A gateway that honors the 0 (high-watermark) return never reaches the hard
 * ceiling; the ceiling only bounds memory for a misbehaving caller. */
int mq_fetch_conn_write(void *handle, const void *p, size_t len);

/* Register a callback fired when the output buffer drains below the low
 * watermark after a high-watermark hit (the gateway may resume writing). */
void mq_fetch_conn_set_drain_cb(void *handle, void (*fn)(void *), void *u);

/* Flush any queued output, then close the connection. After this the handle is
 * dead. No cbs fire afterward. */
void mq_fetch_conn_finish(void *handle);

/* Immediately close the connection (mid-body error path), discarding queued
 * output. After this the handle is dead. No cbs fire afterward. */
void mq_fetch_conn_abort(void *handle);

#endif /* MQ_GATEWAY_MQ_FETCH_LISTENER_H */
