// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_mitm_conn — LIVE per-connection MITM orchestrator (Phase 7 Slice 3 Task 10).
// See mq_mitm_conn.h for the contract. This file implements the DRAIN→decide→
// opaque-dispatch half. The MITM TLS handshake + adapter bridge + teardown is
// Task 11; the mitm_start() seam below is a clearly-marked stub.
//
// SECURITY: the drain phase consumes ATTACKER-CONTROLLED bytes before any TLS
// handshake. It is bounded in BYTES (8 KiB) and in TIME (a per-conn deadline) so
// a slow/oversized/non-TLS peer cannot pin resources. Every malformed/ambiguous
// input HARD-FAILS closed; nothing is forwarded until the SNI is known.

#include "mitm/mq_mitm_conn.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>

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

// ── Context ────────────────────────────────────────────────────────────────

struct mq_mitm_ctx {
    mq_mitm_core_t *core;       // BORROWED — MITM crypto core (Task 11)
    mq_ignore_hosts_t *ign;     // BORROWED — opaque-routing list (may be NULL)
    struct mq_gw_client_s *gwc; // BORROWED — gateway tunnel (Task 11)
    mq_tcp_open_fn opaque_open; // existing relay entry (mq_client)
    void *opaque_core;          // mq_client core for opaque_open
    struct event_base *base;    // BORROWED — libevent base

    // Live drain-phase conn registry (singly linked). Conns are removed on every
    // exit from the drain phase (opaque handoff / MITM start / hard-fail). On
    // ctx_free, any conns still here are torn down (§5.1).
    struct mq_mitm_conn *conns;

    // Test-only MITM-start hook (see header). NULL → production stub.
    void (*mitm_hook)(void *, int, const uint8_t *, size_t, const char *);
    void *mitm_hook_user;
};

// ── Per-connection drain state ───────────────────────────────────────────────

struct mq_mitm_conn {
    mq_mitm_ctx_t *ctx;
    struct mq_mitm_conn *next; // registry link

    int local_fd;              // OWNED during drain (closed on hard-fail)
    struct event *read_ev;     // EV_READ|EV_PERSIST on local_fd
    struct event *deadline_ev; // one-shot complete-ClientHello timer

    // Original recovered orig-dst params (forwarded UNCHANGED on the opaque
    // path — the SNI is NEVER substituted as the host).
    uint8_t orig_host[16];
    size_t orig_host_len;
    mq_addr_type_t orig_atype;
    uint16_t orig_port;

    uint8_t buf[MQ_MITM_CH_BUF_MAX]; // accumulated ClientHello bytes
    size_t buf_len;
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

// Free the conn's events + timer. Caller decides fd disposition (close vs handed
// off) BEFORE calling, and must have removed it from the registry.
//
// (codex M-5) Both the read event AND the deadline timer are freed here, so the
// timer can never fire into a freed conn ctx. Every exit from the drain phase
// routes through conn_drop, so the deadline is cancelled on EVERY path.
static void
conn_free_events(struct mq_mitm_conn *c)
{
    if (c->read_ev) {
        event_free(c->read_ev); // del + free in one
        c->read_ev = NULL;
    }
    if (c->deadline_ev) {
        event_free(c->deadline_ev); // cancels the pending one-shot timer
        c->deadline_ev = NULL;
    }
}

// Remove from registry, free events/timer, optionally close the fd, free the
// conn. `close_fd`=1 for hard-fail (we still own the fd); =0 when ownership was
// transferred away (opaque handoff) or retained elsewhere (MITM — Task 11).
static void
conn_drop(struct mq_mitm_conn *c, int close_fd)
{
    registry_remove(c->ctx, c);
    conn_free_events(c);
    if (close_fd && c->local_fd >= 0) {
        close(c->local_fd);
    }
    c->local_fd = -1;
    free(c);
}

// ── MITM start seam (Task 11) ────────────────────────────────────────────────
//
// PRODUCTION STUB — Task 11 replaces this body with the real per-SNI leaf
// handshake + H2/nghttp2 adapter + gateway bridge + teardown. For Task 10 the
// MITM branch is fully SELECTED and reachable; it just does not yet terminate
// TLS. Until Task 11 lands, selecting MITM hard-fails closed (safe default: no
// attacker bytes forwarded, fd closed) so a half-wired build cannot leak a flow.
//
// A test may inject mitm_hook to observe that the MITM branch was chosen without
// the real handshake.
static void
mitm_start(struct mq_mitm_conn *c, const char *normalized_sni)
{
    mq_mitm_ctx_t *ctx = c->ctx;
    if (ctx->mitm_hook) {
        ctx->mitm_hook(ctx->mitm_hook_user, c->local_fd, c->buf, c->buf_len,
                       normalized_sni);
        // The hook observes selection; it does not take fd ownership. Drop the
        // conn (close fd) so the test path leaves no dangling resources.
        conn_drop(c, /*close_fd=*/1);
        return;
    }

    // TODO(Task 11): mq_mitm_core_new_ssl + SSL_set_fd + handshake pump + H2
    // adapter onto ctx->gwc. For now: hard-fail closed.
    MQ_LOGD("mq_mitm_conn: MITM selected for SNI '%s' (Task 11 not yet wired) — "
            "closing",
            normalized_sni ? normalized_sni : "?");
    conn_drop(c, /*close_fd=*/1);
}

// ── decision seam (Task 4 unit-testable) ────────────────────────────────────
//
// Given a conn with a COMPLETE, parsed ClientHello buffered, decide opaque vs
// MITM and dispatch. Consumes the conn on EVERY path (hard-fail close, opaque
// handoff, MITM start) — the caller must not touch `c` afterwards. Returns the
// route taken (for tests/diagnostics).
//
// Cancels the deadline timer on every exit (it is freed inside conn_drop /
// conn_free_events, both of which run before any return path here).
static mq_mitm_route_t
mitm_conn_decide(struct mq_mitm_conn *c, const mq_clienthello_t *ch)
{
    mq_mitm_ctx_t *ctx = c->ctx;

    // No SNI → we cannot key a forged leaf and have no opaque destination basis
    // beyond the orig-dst. Per spec this hard-fails (a TLS flow with no SNI is
    // not something we MITM; the orig-dst relay is the opaque entry, but routing
    // there requires an explicit ignore-hosts decision which needs the SNI).
    if (ch->sni[0] == '\0') {
        MQ_LOGD("mq_mitm_conn: ClientHello has no SNI — hard-fail close");
        conn_drop(c, /*close_fd=*/1);
        return MQ_MITM_ROUTE_FAIL;
    }

    // Normalize the SNI (lowercase, no leading/trailing dot). Rejects IP
    // literals / wildcards / empty labels — all hard-fail.
    char norm[256];
    if (mq_mitm_normalize_sni(ch->sni, strlen(ch->sni), norm) != 0) {
        MQ_LOGD("mq_mitm_conn: SNI '%s' failed normalization — hard-fail close", ch->sni);
        conn_drop(c, /*close_fd=*/1);
        return MQ_MITM_ROUTE_FAIL;
    }

    // Ignore-hosts hit → OPAQUE. Replay the drained ClientHello as prebuf to the
    // existing relay, forwarding the ORIGINAL orig-dst params UNCHANGED (codex
    // H6 — do NOT substitute the SNI as the host). The relay replays the bytes
    // toward the origin over MPQUIC. fd ownership transfers to the opaque entry.
    if (mq_ignore_hosts_match(ctx->ign, norm)) {
        MQ_LOGD("mq_mitm_conn: SNI '%s' in ignore-hosts → opaque relay", norm);
        int fd = c->local_fd;
        // Cancel the deadline timer + read event FIRST (so neither can fire into
        // freed state) and detach the fd from this conn — but keep `c` alive so
        // its drained buffer can be borrowed for the duration of opaque_open
        // (prebuf is borrowed only for the call; the relay copies what it needs).
        registry_remove(ctx, c);
        conn_free_events(c);
        c->local_fd = -1; // ownership transfers to the opaque entry below

        // Forward the ORIGINAL orig-dst params UNCHANGED (codex H6 — do NOT
        // substitute the SNI as the host). The relay replays the drained
        // ClientHello toward the origin over MPQUIC.
        ctx->opaque_open(ctx->opaque_core, c->orig_host, c->orig_host_len, c->orig_atype,
                         c->orig_port, fd, c->buf, c->buf_len, NULL, NULL);
        free(c);
        return MQ_MITM_ROUTE_OPAQUE;
    }

    // Miss → MITM (terminate + forge). mitm_start consumes the conn.
    mitm_start(c, norm);
    return MQ_MITM_ROUTE_MITM;
}

// TEST-ONLY entry into the decision seam without sockets. Declared extern (no
// header) and used by tests/test_mitm_conn.c. Builds a transient conn around a
// caller-supplied fd + drained buffer + orig-dst, parses, and dispatches.
// Returns the route. On the FAIL/MITM-stub paths the fd is closed by conn_drop;
// on OPAQUE it is handed to opaque_open. The test passes fd=-1 (no real socket)
// and a stub opaque_open that does not touch the fd.
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
        conn_drop(c, /*close_fd=*/local_fd >= 0 ? 1 : 0);
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
    conn_drop(c, /*close_fd=*/1);
}

// ── drain read event ─────────────────────────────────────────────────────────

static void
on_readable(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    struct mq_mitm_conn *c = (struct mq_mitm_conn *)user;

    for (;;) {
        if (c->buf_len >= sizeof(c->buf)) {
            // 8 KiB cap reached without a complete ClientHello → hard-fail.
            MQ_LOGD("mq_mitm_conn: ClientHello exceeded %d-byte cap — hard-fail",
                    MQ_MITM_CH_BUF_MAX);
            conn_drop(c, /*close_fd=*/1);
            return;
        }
        ssize_t n = recv(fd, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len, 0);
        if (n > 0) {
            c->buf_len += (size_t)n;
            mq_clienthello_t ch;
            mq_ch_result_t r = mq_clienthello_parse(c->buf, c->buf_len, &ch);
            if (r == MQ_CH_NEED_MORE) {
                continue; // keep reading until complete or the deadline fires
            }
            if (r != MQ_CH_OK) {
                // NOT_TLS / INVALID → hard-fail close.
                MQ_LOGD("mq_mitm_conn: ClientHello parse rejected (%d) — hard-fail",
                        (int)r);
                conn_drop(c, /*close_fd=*/1);
                return;
            }
            // Complete ClientHello — decide + dispatch. mitm_conn_decide consumes
            // the conn on every path (and cancels the deadline timer); do NOT
            // touch `c` or `fd` afterwards.
            (void)mitm_conn_decide(c, &ch);
            return;
        }
        if (n == 0) {
            // Peer closed before completing the ClientHello.
            MQ_LOGD("mq_mitm_conn: peer closed mid-ClientHello — hard-fail");
            conn_drop(c, /*close_fd=*/1);
            return;
        }
        // n < 0
        if (errno == EAGAIN || errno == EWOULDBLOCK) return; // wait for more
        if (errno == EINTR) continue;
        MQ_LOGD("mq_mitm_conn: recv error: %s — hard-fail", strerror(errno));
        conn_drop(c, /*close_fd=*/1);
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
    return ctx;
}

void
mq_mitm_ctx_free(mq_mitm_ctx_t *ctx)
{
    if (!ctx) return;
    // §5.1: drain the registry first. Any conn still in the drain phase has live
    // events/timer + an owned fd → tear it down (close fd) so nothing fires into
    // freed state after ctx is gone.
    while (ctx->conns) {
        conn_drop(ctx->conns, /*close_fd=*/1);
    }
    free(ctx);
}

void
mq_mitm_conn_open(void *ctx_v, const uint8_t *host, size_t host_len, mq_addr_type_t atype,
                  uint16_t port, int local_fd, const uint8_t *prebuf, size_t prebuf_len,
                  void *user, mq_tcp_open_cb cb)
{
    (void)user;
    mq_mitm_ctx_t *ctx = (mq_mitm_ctx_t *)ctx_v;

    // We OWN local_fd from here (tproxy contract). On any setup failure we close
    // it ourselves and report the result. tproxy passes cb=tproxy_open_result
    // (a no-op on fd ownership) but other callers may differ; signal failure via
    // cb where provided.
    struct mq_mitm_conn *c = calloc(1, sizeof(*c));
    if (!c) {
        if (local_fd >= 0) close(local_fd);
        if (cb) cb(0, MQ_TCP_TIMEOUT, user);
        return;
    }
    c->ctx = ctx;
    c->local_fd = local_fd;
    c->orig_atype = atype;
    c->orig_port = port;
    c->orig_host_len = host_len <= sizeof(c->orig_host) ? host_len : sizeof(c->orig_host);
    if (host && c->orig_host_len) memcpy(c->orig_host, host, c->orig_host_len);

    // tproxy passes prebuf=NULL/0 (the ClientHello is still on the socket). If a
    // caller DID pre-read bytes, seed them so we don't lose them.
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
        if (cb) cb(0, MQ_TCP_TIMEOUT, user);
        return;
    }

    struct timeval dl = {.tv_sec = MQ_MITM_CH_DEADLINE_SEC, .tv_usec = 0};
    if (event_add(c->read_ev, NULL) != 0 || evtimer_add(c->deadline_ev, &dl) != 0) {
        MQ_LOGW("mq_mitm_conn: event_add failed — closing");
        conn_free_events(c);
        if (local_fd >= 0) close(local_fd);
        free(c);
        if (cb) cb(0, MQ_TCP_TIMEOUT, user);
        return;
    }

    registry_add(ctx, c);

    // The relay is established only after we drain + route. tproxy's open-result
    // cb is a no-op (no in-band reply), so do not invoke cb here on the success
    // path — draining continues in on_readable / on_deadline callbacks.
    (void)cb;
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
