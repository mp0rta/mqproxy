// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_conn — LIVE per-connection MITM orchestrator (Phase 7 Slice 3).
// See mq_mitm_conn.h for the contract.
//
// LIFECYCLE of a captured TCP connection:
//   1. DRAIN: read attacker-controlled leading bytes off local_fd into a bounded
//      8 KiB buffer, parse as a TLS ClientHello (mq_clienthello), under a
//      complete-ClientHello deadline. Any malformed/oversized/slow input
//      HARD-FAILS closed. (Task 10.)
//   2. DECIDE: normalize the SNI, ask mq_ignore_hosts.
//        HIT  → OPAQUE: hand the drained bytes + ORIGINAL orig-dst to the relay.
//        MISS → MITM: terminate TLS with a forged per-SNI leaf, bridge H2 onto
//               the gateway tunnel (this file, Task 11).
//
// ── MITM HANDSHAKE / BIO DESIGN (Task 11, chosen + documented) ───────────────
// The orchestrator OWNS local_fd and does raw recv()/send() on it. The SSL talks
// to a MEMORY BIO PAIR (BIO_new_bio_pair): SSL_set_bio gives the SSL its end
// (`ssl_bio`); the orchestrator holds the other end (`app_bio`) and shuttles
// bytes both ways. This matches the existing codebase (test_mitm_core.c) and the
// adapter's send_cb/recv byte model, and — crucially — means NO BIO ever owns the
// fd, so the BIO_NOCLOSE concern is moot: the orchestrator closes the fd itself.
//
// Encrypted-byte flow:
//   fd → recv() → BIO_write(app_bio)  → SSL sees ciphertext to read
//   SSL writes ciphertext → BIO_read(app_bio) → send() → fd
// The drained ClientHello (c->buf) is BIO_write'n into app_bio BEFORE the first
// SSL_accept so the handshake sees those bytes first; subsequent ciphertext comes
// from recv(fd). Plaintext H2 frames are pumped via SSL_read → adapter recv, and
// the adapter's send_cb does SSL_write → drain app_bio → send(fd).
//
// ── TEARDOWN ORDER (§5.1, codex H8) ──────────────────────────────────────────
//   drive req_aborted per in-flight stream  (via mq_gw_h2_adapter_free, which
//        already iterates its live-stream list and calls submit->req_aborted on
//        each xreq — the adapter→core "local gone" signal, NO sink callback) →
//   free the H2 adapter (nghttp2 session) →
//   SSL_free(ssl) (frees ssl_bio) → BIO_free(app_bio) →
//   close(local_fd) → unlink from registry → free conn ctx → free submit wrapper.
//
// ── RE-ENTRANCY MODEL ────────────────────────────────────────────────────────
// A teardown can be triggered from inside a libevent callback (e.g. SSL_read
// error during the read pump, or send() failure during the write pump). Freeing
// the conn ctx right there would free state whose stack frame is still running
// (the event callback, the adapter, the SSL). So conn_close() is SPLIT:
//   - it sets c->dying (idempotent: a second trigger is a no-op),
//   - unlinks the conn from the live registry,
//   - frees the read event so no further callback can re-enter,
//   - moves the conn onto ctx->pending_free,
//   - and activates ctx->free_ev (a zero-timeout libevent event).
// ctx->free_ev's callback runs at the NEXT loop iteration (libevent never runs an
// active event re-entrantly inside the callback that activated it), AFTER every
// in-flight stack frame has unwound, and only THEN performs the real teardown
// (adapter_free → SSL_free → close → free). mq_mitm_ctx_free drains both the live
// registry AND the pending-free list synchronously (it runs outside the loop).
//
// THREADING: single-threaded libevent data plane (1 client/process).

#include "mitm/mq_mitm_conn.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/event.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "gateway/mq_gw_h2_adapter.h"
#include "ingress/mq_clienthello.h"
#include "util/mq_log.h"

// Bounded per-conn drain buffer. Mirrors mq_clienthello's own 8 KiB cap: a real
// ClientHello (with SNI + a few extensions) is well under this; the parser
// itself reports MQ_CH_INVALID past 8 KiB, so this is the hard ceiling.
#define MQ_MITM_CH_BUF_MAX 8192

// Complete-ClientHello deadline. A genuine ClientHello arrives within one
// round-trip of the TCP handshake; 5s is generous for high-latency/lossy links
// yet bounds a slow-loris that dribbles bytes (or sends none) to keep the fd +
// its event/timer pinned forever.
#define MQ_MITM_CH_DEADLINE_SEC 5

// Mem-BIO-pair ring size. 64 KiB matches test_mitm_core.c and comfortably holds a
// full TLS flight (ClientHello + the server's Certificate/CertVerify/Finished).
#define MQ_MITM_BIO_RING 65536

// Scratch sizes for the per-pump ciphertext/plaintext transfers.
#define MQ_MITM_PUMP_CHUNK 16384

// ── Context ────────────────────────────────────────────────────────────────

struct mq_mitm_ctx {
    mq_mitm_core_t *core;       // BORROWED — MITM crypto core
    mq_ignore_hosts_t *ign;     // BORROWED — opaque-routing list (may be NULL)
    struct mq_gw_client_s *gwc; // BORROWED — gateway tunnel (MITM→H2 path)
    mq_tcp_open_fn opaque_open; // existing relay entry (mq_client)
    void *opaque_core;          // mq_client core for opaque_open
    struct event_base *base;    // BORROWED — libevent base

    // Live conn registry (singly linked). A conn stays registered through its
    // WHOLE life: drain phase AND post-handshake live MITM. Opaque/hard-fail
    // conns are removed when they leave this orchestrator. On ctx_free, every
    // conn still here is torn down (§5.1).
    struct mq_mitm_conn *conns;

    // Deferred-free queue (re-entrancy safety — see the file header). Conns whose
    // teardown was requested from inside a callback land here and are reaped by
    // free_ev at the next loop iteration.
    struct mq_mitm_conn *pending_free;
    struct event *free_ev; // zero-timeout event that drains pending_free

    // Test-only MITM-start hook (see header). NULL → production handshake.
    void (*mitm_hook)(void *, int, const uint8_t *, size_t, const char *);
    void *mitm_hook_user;
};

// ── Per-connection state ─────────────────────────────────────────────────────

typedef enum {
    MQ_MITM_PHASE_DRAIN = 0,     // accumulating the ClientHello
    MQ_MITM_PHASE_HANDSHAKE = 1, // SSL_accept in progress
    MQ_MITM_PHASE_LIVE = 2,      // handshake done; pumping TLS↔adapter
} mq_mitm_phase_t;

struct mq_mitm_conn {
    mq_mitm_ctx_t *ctx;
    struct mq_mitm_conn *next; // registry / pending_free link

    mq_mitm_phase_t phase;
    int dying; // teardown requested; idempotent guard (re-entrancy)

    int local_fd;              // OWNED (closed on teardown)
    struct event *read_ev;     // EV_READ|EV_PERSIST on local_fd
    struct event *write_ev;    // EV_WRITE (one-shot, re-armed when send() blocks)
    struct event *deadline_ev; // one-shot complete-ClientHello timer

    // Original recovered orig-dst params (forwarded UNCHANGED on the opaque path).
    uint8_t orig_host[16];
    size_t orig_host_len;
    mq_addr_type_t orig_atype;
    uint16_t orig_port;

    uint8_t buf[MQ_MITM_CH_BUF_MAX]; // accumulated ClientHello bytes
    size_t buf_len;

    // ── TLS termination state (handshake + live) ────────────────────────────
    SSL *ssl;     // OWNED (SSL_free in teardown; frees ssl_bio)
    BIO *app_bio; // OWNED — the orchestrator's end of the mem-BIO pair

    // Ciphertext write-holdover. flush_ciphertext() pulls ciphertext out of
    // app_bio and send()s it; on a partial/blocked send the UNSENT tail is parked
    // here (BIO_read is destructive, so the bytes cannot go back into the BIO) and
    // retried on EV_WRITE. wbuf is sized to one pump chunk; flush stops pulling
    // from the BIO while a holdover is pending, so it never overflows.
    uint8_t wbuf[MQ_MITM_PUMP_CHUNK];
    size_t wbuf_off; // next unsent byte
    size_t wbuf_len; // total parked bytes (unsent = [wbuf_off, wbuf_len))

    // ── adapter bridge (live phase) ─────────────────────────────────────────
    mq_gw_h2_adapter_t *adapter;     // OWNED (freed FIRST in teardown)
    mq_gw_h2_submit_gwc_t *submit_w; // OWNED — production submit wrapper
};

// ── registry helpers ─────────────────────────────────────────────────────────

static void
registry_add(mq_mitm_ctx_t *ctx, struct mq_mitm_conn *c)
{
    c->next = ctx->conns;
    ctx->conns = c;
}

static void
registry_remove(mq_mitm_ctx_t *ctx, struct mq_mitm_conn *c)
{
    struct mq_mitm_conn **pp = &ctx->conns;
    while (*pp) {
        if (*pp == c) {
            *pp = c->next;
            c->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

// Free all of a conn's libevent objects. Idempotent (NULLs as it goes).
static void
conn_free_events(struct mq_mitm_conn *c)
{
    if (c->read_ev) {
        event_free(c->read_ev); // del + free in one
        c->read_ev = NULL;
    }
    if (c->write_ev) {
        event_free(c->write_ev);
        c->write_ev = NULL;
    }
    if (c->deadline_ev) {
        event_free(c->deadline_ev); // cancels the pending one-shot timer
        c->deadline_ev = NULL;
    }
}

// REAL teardown — runs OUTSIDE any in-flight callback (from free_ev or from
// mq_mitm_ctx_free). Performs the §5.1 ordered teardown. The conn is assumed
// already unlinked from the live registry (conn_close does that) and its events
// freed (conn_close frees them too, so no callback re-enters); here we finish.
static void
conn_destroy(struct mq_mitm_conn *c)
{
    conn_free_events(c); // belt-and-suspenders (already done in conn_close)

    // 1. Drive req_aborted per in-flight stream + free the H2 adapter. The
    //    adapter's free path iterates its own live-stream list and calls
    //    submit->req_aborted(xreq) on each (adapter→core "local gone"; NO sink
    //    callback) then RSTs/frees them — exactly the codex-H8 direction.
    if (c->adapter) {
        mq_gw_h2_adapter_free(c->adapter);
        c->adapter = NULL;
    }
    // 2. SSL_free frees the SSL's end of the BIO pair (ssl_bio); our end
    //    (app_bio) is freed separately.
    if (c->ssl) {
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
    if (c->app_bio) {
        BIO_free(c->app_bio);
        c->app_bio = NULL;
    }
    // 3. Close the orchestrator-owned fd (never a BIO's job here).
    if (c->local_fd >= 0) {
        close(c->local_fd);
        c->local_fd = -1;
    }
    // 4. Free the production submit wrapper (borrows the shared gwc; gwc not
    //    freed here).
    if (c->submit_w) {
        mq_gw_h2_submit_gwc_free(c->submit_w);
        c->submit_w = NULL;
    }
    free(c);
}

// Request teardown. RE-ENTRANCY-SAFE: callable from inside a libevent/SSL/adapter
// callback. Sets dying (idempotent), unlinks from the live registry, frees the
// I/O events immediately (so no further callback can fire into this conn), then
// DEFERS the real teardown to the next loop iteration via free_ev. The deferred
// reap (conn_destroy) runs after the current stack unwinds — never freeing state
// still on the stack.
static void
conn_close(struct mq_mitm_conn *c)
{
    if (c->dying) return; // already queued
    c->dying = 1;

    mq_mitm_ctx_t *ctx = c->ctx;
    registry_remove(ctx, c);

    // Cancel ALL I/O events NOW so neither the read pump, write pump nor the
    // deadline can re-enter this (about-to-be-freed) conn. (codex M-5: the
    // deadline timer is cancelled on every teardown path.)
    conn_free_events(c);

    // Queue for deferred reap.
    c->next = ctx->pending_free;
    ctx->pending_free = c;
    if (ctx->free_ev) event_active(ctx->free_ev, 0, 0);
}

// free_ev callback — drains the pending-free queue at a safe point (next loop
// iteration, after every callback that requested a teardown has returned).
static void
on_free_pending(evutil_socket_t fd, short what, void *user)
{
    (void)fd;
    (void)what;
    mq_mitm_ctx_t *ctx = (mq_mitm_ctx_t *)user;
    while (ctx->pending_free) {
        struct mq_mitm_conn *c = ctx->pending_free;
        ctx->pending_free = c->next;
        conn_destroy(c);
    }
}

// ── live MITM: TLS pumps ↔ H2 adapter ─────────────────────────────────────────
//
// Encrypted-byte plumbing. The orchestrator owns local_fd; the SSL talks to a
// mem-BIO pair whose application end is c->app_bio (see the file header).

// Forward decls (the pumps reference each other / teardown).
static int flush_ciphertext(struct mq_mitm_conn *c);
static int pump_outbound(struct mq_mitm_conn *c);
static void on_local_io(evutil_socket_t fd, short what, void *user);
static ssize_t adapter_ssl_send(void *io, const uint8_t *p, size_t n);

// Arm the one-shot EV_WRITE event so flush_ciphertext is retried when the socket
// becomes writable again. Safe to call repeatedly (event_add on an armed one-shot
// is idempotent).
static void
arm_write(struct mq_mitm_conn *c)
{
    if (c->write_ev) event_add(c->write_ev, NULL);
}

// Drain ciphertext from app_bio to local_fd. Lossless under partial sends: a send
// that blocks parks the UNSENT tail in c->wbuf (BIO_read is destructive, so the
// bytes can't go back) and arms EV_WRITE. While a holdover is pending we do NOT
// pull more from the BIO. Returns 0 on progress/would-block, -1 on a hard error.
static int
flush_ciphertext(struct mq_mitm_conn *c)
{
    for (;;) {
        // 1. Flush any parked holdover first.
        while (c->wbuf_off < c->wbuf_len) {
            ssize_t w = send(c->local_fd, c->wbuf + c->wbuf_off,
                             c->wbuf_len - c->wbuf_off, MSG_NOSIGNAL);
            if (w > 0) {
                c->wbuf_off += (size_t)w;
                continue;
            }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                arm_write(c);
                return 0; // still blocked; retry on EV_WRITE
            }
            if (w < 0 && errno == EINTR) continue;
            return -1; // hard send error
        }
        c->wbuf_off = c->wbuf_len = 0;

        // 2. Pull the next ciphertext chunk out of the BIO.
        int pend = BIO_read(c->app_bio, c->wbuf, (int)sizeof(c->wbuf));
        if (pend <= 0)
            return 0; // nothing buffered (BIO_should_retry on a pair BIO
                      // just means empty here; SSL refills it)
        c->wbuf_off = 0;
        c->wbuf_len = (size_t)pend;
        // loop: the holdover-flush at the top now sends [0, pend).
    }
}

// Run SSL_accept until it completes, blocks, or fails. Feeds the read BIO from
// recv() as needed and drains the write BIO to send(). Transitions to LIVE on
// success (asserting ALPN=h2). Returns 0 to stay (handshake or live), -1 to tear
// down.
static int
drive_handshake(struct mq_mitm_conn *c)
{
    for (;;) {
        int r = SSL_accept(c->ssl);
        // Always push out any handshake ciphertext the SSL produced.
        if (flush_ciphertext(c) != 0) return -1;
        if (r == 1) break; // handshake complete

        int e = SSL_get_error(c->ssl, r);
        if (e == SSL_ERROR_WANT_READ) {
            // SSL needs more ciphertext; it will arrive via on_local_io's recv→BIO
            // feed. Return and wait for EV_READ.
            return 0;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            // The write BIO is full (we just flushed); wait for writability.
            arm_write(c);
            return 0;
        }
        MQ_LOGD("mq_mitm_conn: SSL_accept failed (err=%d) — hard-fail close", e);
        return -1;
    }

    // Handshake complete — REQUIRE ALPN h2 (browser must speak h2 for this slice).
    const uint8_t *alpn = NULL;
    unsigned alpn_len = 0;
    SSL_get0_alpn_selected(c->ssl, &alpn, &alpn_len);
    if (alpn_len != 2 || memcmp(alpn, "h2", 2) != 0) {
        MQ_LOGD("mq_mitm_conn: negotiated ALPN is not h2 — hard-fail close");
        return -1;
    }

    // Cancel the ClientHello deadline (M-5): the handshake is done.
    if (c->deadline_ev) {
        event_free(c->deadline_ev);
        c->deadline_ev = NULL;
    }

    // Build the production submit wrapper (binds the static gwc vtable to the
    // shared gwc) + the H2 adapter. send_cb = adapter_ssl_send (SSL_write + flush).
    c->submit_w = mq_gw_h2_submit_gwc_new(c->ctx->gwc);
    if (!c->submit_w) {
        MQ_LOGW("mq_mitm_conn: submit-wrapper alloc failed — hard-fail close");
        return -1;
    }
    c->adapter =
        mq_gw_h2_adapter_new(mq_gw_h2_submit_ops_gwc(), c->submit_w, adapter_ssl_send, c);
    if (!c->adapter) {
        MQ_LOGW("mq_mitm_conn: H2 adapter alloc failed — hard-fail close");
        return -1;
    }

    c->phase = MQ_MITM_PHASE_LIVE;
    MQ_LOGD("mq_mitm_conn: handshake complete (ALPN=h2) — live MITM bridge up");

    // Drain the adapter's initial SETTINGS frame out to the browser.
    if (pump_outbound(c) != 0) return -1;
    return 0;
}

// adapter send_cb: write plaintext H2 bytes into the SSL, then drain the resulting
// ciphertext to the fd. Returns `n` on full acceptance, -1 on a hard error.
// SSL_write here is all-or-nothing for the byte count we hand it (mem BIO never
// short-writes plaintext); WANT_WRITE means the ciphertext BIO is momentarily full
// — we flush and report acceptance (the plaintext is buffered inside the SSL).
static ssize_t
adapter_ssl_send(void *io, const uint8_t *p, size_t n)
{
    struct mq_mitm_conn *c = (struct mq_mitm_conn *)io;
    if (n == 0) return 0;
    int w = SSL_write(c->ssl, p, (int)n);
    if (w <= 0) {
        int e = SSL_get_error(c->ssl, w);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            // Could not take the plaintext right now; flush what ciphertext exists.
            // The send_cb contract has no "partial" return (only n or -1); a 0 would
            // be read as a fatal short-write. With a 64 KiB BIO vs 16 KiB frames this
            // is unreachable, so we fail closed on WANT_*.
            (void)flush_ciphertext(c);
        }
        return -1;
    }
    if (flush_ciphertext(c) != 0) return -1;
    return (ssize_t)w;
}

// Push any pending adapter output (and resume download backpressure), then flush
// the resulting ciphertext. Returns 0 / -1.
static int
pump_outbound(struct mq_mitm_conn *c)
{
    if (!c->adapter) return 0;
    if (mq_gw_h2_adapter_want_write(c->adapter) != 0) return -1;
    return flush_ciphertext(c);
}

// Read ciphertext off the fd → BIO, then SSL_read plaintext → adapter. Loops until
// the socket would block. Returns 0 (stay) / -1 (tear down) / 1 (peer EOF).
static int
pump_inbound(struct mq_mitm_conn *c)
{
    uint8_t cipher[MQ_MITM_PUMP_CHUNK];
    for (;;) {
        ssize_t n = recv(c->local_fd, cipher, sizeof(cipher), 0);
        if (n > 0) {
            // Feed ALL received ciphertext into the SSL's read BIO. A pair BIO can
            // momentarily be full if the SSL hasn't consumed prior bytes; with a
            // 64 KiB ring and 16 KiB reads + an immediate SSL_read drain below this
            // does not happen in practice — treat a short BIO_write as fatal.
            int wb = BIO_write(c->app_bio, cipher, (int)n);
            if (wb != (int)n) {
                MQ_LOGD("mq_mitm_conn: read-BIO full — hard-fail");
                return -1;
            }
        } else if (n == 0) {
            return 1; // peer closed
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            MQ_LOGD("mq_mitm_conn: recv error: %s — hard-fail", strerror(errno));
            return -1;
        }

        // Drain plaintext H2 frames out of the SSL into the adapter.
        for (;;) {
            uint8_t plain[MQ_MITM_PUMP_CHUNK];
            int pr = SSL_read(c->ssl, plain, (int)sizeof(plain));
            if (pr > 0) {
                if (mq_gw_h2_adapter_recv(c->adapter, plain, (size_t)pr) != 0) {
                    MQ_LOGD("mq_mitm_conn: H2 adapter recv fatal — hard-fail");
                    return -1;
                }
                continue;
            }
            int e = SSL_get_error(c->ssl, pr);
            if (e == SSL_ERROR_WANT_READ) break; // need more ciphertext
            if (e == SSL_ERROR_WANT_WRITE) {
                // A renegotiation-style write need; flush and continue.
                if (flush_ciphertext(c) != 0) return -1;
                break;
            }
            // TLS close_notify. A peer half-close (FIN/close_notify) is
            // deliberately treated as a full-close here (acceptable for the
            // h2/browser MITM case), like the WANT_WRITE-fatal choice above.
            if (e == SSL_ERROR_ZERO_RETURN) return 1;
            MQ_LOGD("mq_mitm_conn: SSL_read error (err=%d) — hard-fail", e);
            return -1;
        }

        // The adapter may have produced output (WINDOW_UPDATE / responses).
        if (pump_outbound(c) != 0) return -1;
    }
    // Flush anything still queued and return.
    if (pump_outbound(c) != 0) return -1;
    return 0;
}

// Unified local-fd event callback (drain phase uses on_readable below; the LIVE
// phase + handshake use this one). EV_READ feeds the inbound pump; EV_WRITE
// retries the ciphertext flush. Teardown is deferred (conn_close), so it is safe
// to call here even though we are inside a libevent callback.
static void
on_local_io(evutil_socket_t fd, short what, void *user)
{
    (void)fd;
    struct mq_mitm_conn *c = (struct mq_mitm_conn *)user;
    if (c->dying) return;

    if (what & EV_WRITE) {
        if (flush_ciphertext(c) != 0) {
            conn_close(c);
            return;
        }
        // If the handshake was waiting on writability, advance it.
        if (c->phase == MQ_MITM_PHASE_HANDSHAKE) {
            if (drive_handshake(c) != 0) {
                conn_close(c);
                return;
            }
        } else if (c->phase == MQ_MITM_PHASE_LIVE) {
            // Draining the socket holdover may have re-opened headroom for a
            // download that was deferred under backpressure (Task 7). Re-pump the
            // adapter so want_write clears sq_deferred and fires req_drained,
            // resuming the gateway pump — mirroring the pump_inbound tail. Without
            // this the download stalls until the next inbound packet re-enters.
            if (pump_outbound(c) != 0) {
                conn_close(c);
                return;
            }
        }
    }

    if (what & EV_READ) {
        if (c->phase == MQ_MITM_PHASE_HANDSHAKE) {
            // Pull ciphertext into the read BIO, then advance the handshake.
            uint8_t cipher[MQ_MITM_PUMP_CHUNK];
            for (;;) {
                ssize_t n = recv(c->local_fd, cipher, sizeof(cipher), 0);
                if (n > 0) {
                    if (BIO_write(c->app_bio, cipher, (int)n) != (int)n) {
                        conn_close(c);
                        return;
                    }
                    continue;
                }
                if (n == 0) {
                    MQ_LOGD("mq_mitm_conn: peer closed during handshake — hard-fail");
                    conn_close(c);
                    return;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                MQ_LOGD("mq_mitm_conn: recv error in handshake — hard-fail");
                conn_close(c);
                return;
            }
            if (drive_handshake(c) != 0) {
                conn_close(c);
                return;
            }
        } else if (c->phase == MQ_MITM_PHASE_LIVE) {
            int r = pump_inbound(c);
            if (r != 0) { // -1 fatal or 1 peer EOF → tear down
                conn_close(c);
                return;
            }
        }
    }
}

// Begin the live MITM handshake: build the SSL + mem-BIO pair, seed the drained
// ClientHello into the read BIO, install the unified EV_READ|EV_WRITE callback,
// and kick off SSL_accept. The drain-phase read_ev/deadline are still valid here
// (the deadline is cancelled when the handshake completes). Returns 0 on success
// (conn becomes HANDSHAKE/LIVE) or -1 (caller hard-fails). On -1 the SSL/BIO are
// freed by the caller's conn_close path.
static int
mitm_handshake_begin(struct mq_mitm_conn *c)
{
    mq_mitm_ctx_t *ctx = c->ctx;

    c->ssl = mq_mitm_core_new_ssl(ctx->core);
    if (!c->ssl) {
        MQ_LOGW("mq_mitm_conn: mq_mitm_core_new_ssl failed — hard-fail");
        return -1;
    }

    BIO *ssl_bio = NULL, *app_bio = NULL;
    if (BIO_new_bio_pair(&ssl_bio, MQ_MITM_BIO_RING, &app_bio, MQ_MITM_BIO_RING) != 1) {
        MQ_LOGW("mq_mitm_conn: BIO_new_bio_pair failed — hard-fail");
        return -1; // c->ssl freed by conn_close
    }
    // SSL takes ownership of ssl_bio (freed by SSL_free); we own app_bio.
    SSL_set_bio(c->ssl, ssl_bio, ssl_bio);
    c->app_bio = app_bio;

    // Seed the drained ClientHello so SSL_accept sees it before any recv().
    if (c->buf_len) {
        if (BIO_write(c->app_bio, c->buf, (int)c->buf_len) != (int)c->buf_len) {
            MQ_LOGW("mq_mitm_conn: failed to seed ClientHello into BIO — hard-fail");
            return -1;
        }
    }

    // Swap the drain-phase read event for the unified handshake/live callback.
    if (c->read_ev) {
        event_free(c->read_ev);
        c->read_ev = NULL;
    }
    c->read_ev = event_new(ctx->base, c->local_fd, EV_READ | EV_PERSIST, on_local_io, c);
    c->write_ev = event_new(ctx->base, c->local_fd, EV_WRITE, on_local_io, c);
    if (!c->read_ev || !c->write_ev || event_add(c->read_ev, NULL) != 0) {
        MQ_LOGW("mq_mitm_conn: handshake event setup failed — hard-fail");
        return -1;
    }

    c->phase = MQ_MITM_PHASE_HANDSHAKE;
    return drive_handshake(c);
}

// ── MITM start seam ──────────────────────────────────────────────────────────
//
// Production: terminate TLS + bridge H2 onto the gateway tunnel. A test may
// inject mitm_hook to observe branch selection without the real handshake.
static void
mitm_start(struct mq_mitm_conn *c, const char *normalized_sni)
{
    mq_mitm_ctx_t *ctx = c->ctx;
    if (ctx->mitm_hook) {
        ctx->mitm_hook(ctx->mitm_hook_user, c->local_fd, c->buf, c->buf_len,
                       normalized_sni);
        // The hook observes selection; it does not take fd ownership. Tear the
        // conn down (close fd) so the test path leaves no dangling resources.
        conn_close(c);
        return;
    }

    // No core (mis-config) → cannot forge. Fail closed.
    if (!ctx->core || !ctx->gwc) {
        MQ_LOGW("mq_mitm_conn: MITM selected but core/gwc unavailable — hard-fail");
        conn_close(c);
        return;
    }

    MQ_LOGD("mq_mitm_conn: MITM terminate for SNI '%s'",
            normalized_sni ? normalized_sni : "?");
    if (mitm_handshake_begin(c) != 0) {
        conn_close(c);
        return;
    }
    // conn stays registered + alive (HANDSHAKE/LIVE); do NOT touch it further here.
}

// ── decision seam (Task 4 unit-testable) ────────────────────────────────────
//
// Given a conn with a COMPLETE, parsed ClientHello buffered, decide opaque vs
// MITM and dispatch. Consumes the conn on the FAIL/OPAQUE paths (and the MITM
// HARD-FAIL paths); on a successful MITM start the conn lives on. The caller must
// not touch `c` after a FAIL/OPAQUE return. Returns the route taken.
static mq_mitm_route_t
mitm_conn_decide(struct mq_mitm_conn *c, const mq_clienthello_t *ch)
{
    mq_mitm_ctx_t *ctx = c->ctx;

    // No SNI → cannot key a forged leaf; hard-fail (see header rationale).
    if (ch->sni[0] == '\0') {
        MQ_LOGD("mq_mitm_conn: ClientHello has no SNI — hard-fail close");
        conn_close(c);
        return MQ_MITM_ROUTE_FAIL;
    }

    // Normalize the SNI. Rejects IP literals / wildcards / empty labels.
    char norm[256];
    if (mq_mitm_normalize_sni(ch->sni, strlen(ch->sni), norm) != 0) {
        MQ_LOGD("mq_mitm_conn: SNI '%s' failed normalization — hard-fail close", ch->sni);
        conn_close(c);
        return MQ_MITM_ROUTE_FAIL;
    }

    // Ignore-hosts hit → OPAQUE. Replay the drained ClientHello as prebuf to the
    // existing relay, forwarding the ORIGINAL orig-dst params UNCHANGED (codex H6).
    // fd ownership transfers to the opaque entry.
    if (mq_ignore_hosts_match(ctx->ign, norm)) {
        MQ_LOGD("mq_mitm_conn: SNI '%s' in ignore-hosts → opaque relay", norm);
        int fd = c->local_fd;
        // Detach fd + cancel events/timer + unlink, but keep `c` alive across the
        // opaque_open call so its drained buffer can be borrowed for the call.
        registry_remove(ctx, c);
        conn_free_events(c);
        c->local_fd = -1; // ownership transfers to the opaque entry
        ctx->opaque_open(ctx->opaque_core, c->orig_host, c->orig_host_len, c->orig_atype,
                         c->orig_port, fd, c->buf, c->buf_len, NULL, NULL);
        free(c); // never entered the deferred path; no events armed
        return MQ_MITM_ROUTE_OPAQUE;
    }

    // Miss → MITM (terminate + forge). mitm_start either advances to HANDSHAKE/LIVE
    // (conn lives) or hard-fails (conn_close).
    mitm_start(c, norm);
    return MQ_MITM_ROUTE_MITM;
}

// TEST-ONLY entry into the decision seam without sockets (see header).
mq_mitm_route_t
mq_mitm_conn_decide_for_test(mq_mitm_ctx_t *ctx, const uint8_t *buf, size_t len,
                             const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                             uint16_t port, int local_fd)
{
    struct mq_mitm_conn *c = calloc(1, sizeof(*c));
    if (!c) return MQ_MITM_ROUTE_FAIL;
    c->ctx = ctx;
    c->local_fd = local_fd;
    c->orig_atype = atype;
    c->orig_port = port;
    c->orig_host_len = host_len <= sizeof(c->orig_host) ? host_len : sizeof(c->orig_host);
    if (host && c->orig_host_len) memcpy(c->orig_host, host, c->orig_host_len);
    c->buf_len = len <= sizeof(c->buf) ? len : sizeof(c->buf);
    if (buf && c->buf_len) memcpy(c->buf, buf, c->buf_len);
    registry_add(ctx, c);

    mq_clienthello_t ch;
    mq_ch_result_t r = mq_clienthello_parse(c->buf, c->buf_len, &ch);
    if (r != MQ_CH_OK) {
        conn_close(c);
        return MQ_MITM_ROUTE_FAIL;
    }
    return mitm_conn_decide(c, &ch);
}

// ── deadline timer ───────────────────────────────────────────────────────────

static void
on_deadline(evutil_socket_t fd, short what, void *user)
{
    (void)fd;
    (void)what;
    struct mq_mitm_conn *c = (struct mq_mitm_conn *)user;
    MQ_LOGD("mq_mitm_conn: ClientHello deadline (%ds) exceeded — hard-fail close",
            MQ_MITM_CH_DEADLINE_SEC);
    conn_close(c);
}

// ── drain read event ─────────────────────────────────────────────────────────

static void
on_readable(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    struct mq_mitm_conn *c = (struct mq_mitm_conn *)user;
    if (c->dying) return;

    for (;;) {
        if (c->buf_len >= sizeof(c->buf)) {
            MQ_LOGD("mq_mitm_conn: ClientHello exceeded %d-byte cap — hard-fail",
                    MQ_MITM_CH_BUF_MAX);
            conn_close(c);
            return;
        }
        ssize_t n = recv(fd, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len, 0);
        if (n > 0) {
            c->buf_len += (size_t)n;
            mq_clienthello_t ch;
            mq_ch_result_t r = mq_clienthello_parse(c->buf, c->buf_len, &ch);
            if (r == MQ_CH_NEED_MORE) continue; // keep reading
            if (r != MQ_CH_OK) {
                MQ_LOGD("mq_mitm_conn: ClientHello parse rejected (%d) — hard-fail",
                        (int)r);
                conn_close(c);
                return;
            }
            // Complete ClientHello — decide + dispatch. On FAIL/OPAQUE the conn is
            // consumed; on MITM it advances to HANDSHAKE/LIVE (still registered).
            // Either way, do NOT touch `c` or `fd` afterwards.
            (void)mitm_conn_decide(c, &ch);
            return;
        }
        if (n == 0) {
            MQ_LOGD("mq_mitm_conn: peer closed mid-ClientHello — hard-fail");
            conn_close(c);
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return; // wait for more
        if (errno == EINTR) continue;
        MQ_LOGD("mq_mitm_conn: recv error: %s — hard-fail", strerror(errno));
        conn_close(c);
        return;
    }
}

// ── public API ───────────────────────────────────────────────────────────────

mq_mitm_ctx_t *
mq_mitm_ctx_new(mq_mitm_core_t *core, mq_ignore_hosts_t *ign, struct mq_gw_client_s *gwc,
                mq_tcp_open_fn opaque_open, void *opaque_core, struct event_base *base)
{
    if (!opaque_open || !base) return NULL;
    mq_mitm_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->core = core;
    ctx->ign = ign;
    ctx->gwc = gwc;
    ctx->opaque_open = opaque_open;
    ctx->opaque_core = opaque_core;
    ctx->base = base;
    // Deferred-free event: zero-timeout, fires at the next loop iteration to reap
    // conns whose teardown was requested inside a callback (re-entrancy safety).
    ctx->free_ev = event_new(base, -1, 0, on_free_pending, ctx);
    if (!ctx->free_ev) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void
mq_mitm_ctx_free(mq_mitm_ctx_t *ctx)
{
    if (!ctx) return;
    // §5.1: drain the live registry first. Each conn (drain-phase OR live MITM) is
    // torn down in order. We run OUTSIDE the event loop here, so conn_close queues
    // onto pending_free; drain that synchronously after. (conn_destroy runs the
    // adapter_free→SSL_free→close→free order.)
    while (ctx->conns) {
        conn_close(ctx->conns);
    }
    // Reap everything conn_close queued (free_ev will never fire — the loop is
    // done — so drain by hand).
    while (ctx->pending_free) {
        struct mq_mitm_conn *c = ctx->pending_free;
        ctx->pending_free = c->next;
        conn_destroy(c);
    }
    if (ctx->free_ev) event_free(ctx->free_ev);
    free(ctx);
}

void
mq_mitm_conn_open(void *ctx_v, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                  uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
                  void *user, mq_tcp_open_cb cb)
{
    mq_mitm_ctx_t *ctx = (mq_mitm_ctx_t *)ctx_v;

    // We OWN local_fd from here (tproxy contract). On any setup failure we close
    // it and report via cb where provided. MQ_TCP_TIMEOUT is used as a stand-in
    // for "local setup failure" — the mq_tcp_status_t enum has no dedicated
    // resource/internal code, and the tproxy open-result cb is a no-op anyway.
    struct mq_mitm_conn *c = calloc(1, sizeof(*c));
    if (!c) {
        if (local_fd >= 0) close(local_fd);
        if (cb) cb(0, MQ_TCP_TIMEOUT, user); // stand-in: local setup failure
        return;
    }
    c->ctx = ctx;
    c->local_fd = local_fd;
    c->orig_atype = atype;
    c->orig_port = port;
    c->orig_host_len = host_len <= sizeof(c->orig_host) ? host_len : sizeof(c->orig_host);
    if (host && c->orig_host_len) memcpy(c->orig_host, host, c->orig_host_len);

    if (prebuf && prebuf_len) {
        c->buf_len = prebuf_len <= sizeof(c->buf) ? prebuf_len : sizeof(c->buf);
        memcpy(c->buf, prebuf, c->buf_len);
    }

    c->read_ev = event_new(ctx->base, local_fd, EV_READ | EV_PERSIST, on_readable, c);
    c->deadline_ev = evtimer_new(ctx->base, on_deadline, c);
    if (!c->read_ev || !c->deadline_ev) {
        MQ_LOGW("mq_mitm_conn: event allocation failed — closing");
        conn_free_events(c);
        if (local_fd >= 0) close(local_fd);
        free(c);
        if (cb) cb(0, MQ_TCP_TIMEOUT, user); // stand-in: local setup failure
        return;
    }

    struct timeval dl = {.tv_sec = MQ_MITM_CH_DEADLINE_SEC, .tv_usec = 0};
    if (event_add(c->read_ev, NULL) != 0 || evtimer_add(c->deadline_ev, &dl) != 0) {
        MQ_LOGW("mq_mitm_conn: event_add failed — closing");
        conn_free_events(c);
        if (local_fd >= 0) close(local_fd);
        free(c);
        if (cb) cb(0, MQ_TCP_TIMEOUT, user); // stand-in: local setup failure
        return;
    }

    registry_add(ctx, c);
    (void)cb; // success path: draining continues in on_readable / on_deadline
}

void
mq_mitm_ctx_set_mitm_hook_for_test(mq_mitm_ctx_t *ctx,
                                   void (*hook)(void *, int, const uint8_t *, size_t,
                                                const char *),
                                   void *hook_user)
{
    if (!ctx) return;
    ctx->mitm_hook = hook;
    ctx->mitm_hook_user = hook_user;
}

int
mq_mitm_conn_make_live_for_test(mq_mitm_ctx_t *ctx, struct mq_gw_h2_adapter *adapter,
                                struct ssl_st *ssl, int local_fd)
{
    if (!ctx) return -1;
    struct mq_mitm_conn *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->ctx = ctx;
    c->phase = MQ_MITM_PHASE_LIVE;
    c->local_fd = local_fd;
    c->ssl = (SSL *)ssl;
    c->adapter = (mq_gw_h2_adapter_t *)adapter;
    // No submit wrapper / app_bio in this seam — the test owns adapter construction
    // (it binds its own stub submit vtable) and may pass a NULL/real SSL. Teardown
    // exercises adapter_free (→ req_aborted per stream) → SSL_free → close → free.
    registry_add(ctx, c);
    return 0;
}
