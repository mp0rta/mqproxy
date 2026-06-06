// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_assoc.c — SOCKS5 UDP ASSOCIATE edge. See mq_udp_assoc.h. */
#include "ingress/mq_udp_assoc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <event2/event.h>

#include "ingress/mq_socks5.h"
#include "util/mq_log.h"

/* Per-assoc DST session map: fixed linear table. A single association's set of
 * distinct destinations is small (one client app), so 64 entries with a linear
 * scan is ample; full => drop the datagram (it retries naturally). */
#define MQ_UDP_ASSOC_MAX_DST 64

/* Negative cache window: suppress re-OPEN of a DST that failed (remote OPEN
 * error) for this many milliseconds. */
#define MQ_UDP_ASSOC_NEGCACHE_MS 2000

/* Largest datagram we accept/relay (encap header + payload). MTU-ish; the relay
 * itself fragments nothing. */
#define MQ_UDP_ASSOC_DGRAM_CAP 65535

struct mq_dst_entry {
    int used;
    /* DST key: atyp + raw host bytes (host_len) + port. */
    mq_addr_type_t atype;
    uint8_t host[MQ_MAX_HOST];
    size_t host_len;
    uint16_t port;
    /* Relay session handle from open_fn (NULL while none / after death). */
    void *session;
    int dead;           /* on_err received: handle invalid, never close it. */
    uint64_t failed_at; /* monotonic ms of last remote OPEN failure (neg cache);
                           0 = no negative cache active. */
};

/* Per-DST `user` carried across the open_fn boundary into on_rx/on_err. One per
 * slot, kept parallel to the DST table so the pointer stays valid for the whole
 * session lifetime and is freed with the assoc. */
struct rx_ctx {
    struct mq_udp_assoc *a;
    mq_addr_type_t atype;
    uint8_t host[MQ_MAX_HOST];
    size_t host_len;
    uint16_t port;
};

struct mq_udp_assoc {
    struct event_base *base;
    int tcp_fd; /* SOCKS5 control connection; EOF/error => teardown. */
    struct event *tcp_ev;
    int udp_fd; /* relay socket bound bind_ip:ephemeral. */
    struct event *udp_ev;
    uint16_t udp_port; /* host order */

    /* boundary */
    mq_udp_open_fn open_fn;
    mq_udp_send_fn send_fn;
    mq_udp_close_fn close_fn;
    void *core;

    /* Source learning (RFC 1928 §7): locked after the first datagram from the
     * TCP peer's IP. */
    struct sockaddr_in tcp_peer; /* learned at ctor (getpeername); IP filter. */
    int client_locked;
    struct sockaddr_in client_addr; /* exact IP:port the client sends from. */

    struct mq_dst_entry dst[MQ_UDP_ASSOC_MAX_DST];
    struct rx_ctx rxslot[MQ_UDP_ASSOC_MAX_DST]; /* parallel to dst[] */

    /* intrusive list owned by the listener (head lives on mq_listener_s). */
    mq_udp_assoc_t **list_head; /* &listener->assocs (for self-removal) */
    mq_udp_assoc_t *prev;
    mq_udp_assoc_t *next;
    int tearing_down; /* re-entrancy guard for teardown */
};

void
mq_udp_assoc_list_push(mq_udp_assoc_t **head, mq_udp_assoc_t *a)
{
    if (!head || !a) return;
    a->list_head = head;
    a->prev = NULL;
    a->next = *head;
    if (*head) (*head)->prev = a;
    *head = a;
}

mq_udp_assoc_t *
mq_udp_assoc_list_next(mq_udp_assoc_t *a)
{
    return a ? a->next : NULL;
}

/* Unlink `a` from its list (if linked). Safe to call repeatedly. */
static void
list_unlink(mq_udp_assoc_t *a)
{
    if (!a->list_head) return; /* not linked */
    if (a->prev) {
        a->prev->next = a->next;
    } else if (*a->list_head == a) {
        *a->list_head = a->next;
    }
    if (a->next) a->next->prev = a->prev;
    a->prev = NULL;
    a->next = NULL;
    a->list_head = NULL;
}

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int
set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ── DST map ────────────────────────────────────────────────────────────── */

static int
dst_key_eq(const struct mq_dst_entry *e, const mq_socks5_req_t *dst)
{
    return e->used && e->atype == dst->atype && e->host_len == dst->host_len &&
           e->port == dst->port &&
           (dst->host_len == 0 || memcmp(e->host, dst->host, dst->host_len) == 0);
}

static struct mq_dst_entry *
dst_find(mq_udp_assoc_t *a, const mq_socks5_req_t *dst)
{
    for (size_t i = 0; i < MQ_UDP_ASSOC_MAX_DST; i++) {
        if (dst_key_eq(&a->dst[i], dst)) return &a->dst[i];
    }
    return NULL;
}

static struct mq_dst_entry *
dst_alloc(mq_udp_assoc_t *a, const mq_socks5_req_t *dst)
{
    for (size_t i = 0; i < MQ_UDP_ASSOC_MAX_DST; i++) {
        if (!a->dst[i].used) {
            struct mq_dst_entry *e = &a->dst[i];
            memset(e, 0, sizeof(*e));
            e->used = 1;
            e->atype = dst->atype;
            e->host_len = dst->host_len;
            if (dst->host_len) memcpy(e->host, dst->host, dst->host_len);
            e->port = dst->port;
            return e;
        }
    }
    return NULL; /* table full => caller drops the datagram */
}

/* Map a relay session handle back to its DST entry (for on_rx/on_err). */
static struct mq_dst_entry *
dst_by_session(mq_udp_assoc_t *a, void *session)
{
    if (!session) return NULL;
    for (size_t i = 0; i < MQ_UDP_ASSOC_MAX_DST; i++) {
        if (a->dst[i].used && !a->dst[i].dead && a->dst[i].session == session) {
            return &a->dst[i];
        }
    }
    return NULL;
}

/* ── reverse direction (relay → client) ─────────────────────────────────── */

static void
on_rx(const uint8_t *payload, size_t len, void *user)
{
    struct rx_ctx *rc = (struct rx_ctx *)user;
    mq_udp_assoc_t *a = rc->a;
    if (!a->client_locked) return; /* no client to send to yet */

    /* Build encap header with the DST as the source address, then payload. */
    mq_socks5_req_t src;
    memset(&src, 0, sizeof(src));
    src.atype = rc->atype;
    src.host_len = rc->host_len;
    if (rc->host_len) memcpy(src.host, rc->host, rc->host_len);
    src.port = rc->port;

    uint8_t out[MQ_UDP_ASSOC_DGRAM_CAP];
    int hlen = mq_socks5_build_udp_hdr(out, sizeof(out), &src);
    if (hlen < 0) return;
    if ((size_t)hlen + len > sizeof(out)) return; /* oversized; drop */
    if (len) memcpy(out + hlen, payload, len);

    (void)sendto(a->udp_fd, out, (size_t)hlen + len, MSG_NOSIGNAL,
                 (struct sockaddr *)&a->client_addr, sizeof(a->client_addr));
}

static void
on_err(void *session, mq_udp_err_t err, void *user)
{
    struct rx_ctx *rc = (struct rx_ctx *)user;
    mq_udp_assoc_t *a = rc->a;
    struct mq_dst_entry *e = dst_by_session(a, session);
    if (!e) return; /* already reaped / unknown — late event, ignore */

    /* Negative cache only for remote OPEN failures (RESP error decode). A
     * normal close / idle timeout (MQ_UDP_CLOSED) just retires the entry so a
     * future datagram re-opens immediately. */
    if (err != MQ_UDP_CLOSED) {
        e->failed_at = now_ms();
    }
    /* Contract: handle invalid after on_err; never call close_fn on it. Mark
     * dead and detach the session pointer. The rx_ctx stays attached to the
     * entry (freed when the entry is reused or the assoc dies). */
    e->dead = 1;
    e->session = NULL;
}

/* ── datagram receive (client → relay) ──────────────────────────────────── */

static void handle_client_datagram(mq_udp_assoc_t *a, const uint8_t *buf, size_t len,
                                   const struct sockaddr_in *from);

static void
on_udp_readable(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    mq_udp_assoc_t *a = (mq_udp_assoc_t *)user;
    for (;;) {
        uint8_t buf[MQ_UDP_ASSOC_DGRAM_CAP];
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        if (flen < (socklen_t)sizeof(from) || from.sin_family != AF_INET) {
            continue; /* IPv4 only on this socket */
        }
        handle_client_datagram(a, buf, (size_t)n, &from);
    }
}

static void
handle_client_datagram(mq_udp_assoc_t *a, const uint8_t *buf, size_t len,
                       const struct sockaddr_in *from)
{
    /* Source learning + filter. */
    if (!a->client_locked) {
        /* First datagram must come from the TCP peer's IP (any port). */
        if (from->sin_addr.s_addr != a->tcp_peer.sin_addr.s_addr) {
            return; /* spoofed source; drop */
        }
        a->client_addr = *from;
        a->client_locked = 1;
    } else {
        /* Exact IP:port match only. */
        if (from->sin_addr.s_addr != a->client_addr.sin_addr.s_addr ||
            from->sin_port != a->client_addr.sin_port) {
            return; /* drop */
        }
    }

    /* Parse the SOCKS5 UDP encapsulation header. */
    mq_socks5_udp_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    int r = mq_socks5_parse_udp_hdr(buf, len, &hdr);
    if (r < 0) return; /* malformed (-1) or FRAG != 0 (-2): drop */

    const uint8_t *payload = buf + hdr.hdr_len;
    size_t payload_len = len - hdr.hdr_len;

    struct mq_dst_entry *e = dst_find(a, &hdr.dst);
    if (e) {
        if (e->dead) {
            /* Negative cache: suppress re-open within the window. */
            if (e->failed_at != 0 && now_ms() - e->failed_at < MQ_UDP_ASSOC_NEGCACHE_MS) {
                return; /* drop */
            }
            /* Window expired (or close, no neg cache): retire and re-open. */
            e->used = 0;
            e->session = NULL;
            e->dead = 0;
            e->failed_at = 0;
            e = NULL;
        } else if (e->session) {
            /* Live session: optimistic send. */
            a->send_fn(e->session, payload, payload_len);
            return;
        } else {
            /* Used but no live session and not dead: shouldn't happen; reset. */
            e->used = 0;
            e = NULL;
        }
    }

    /* No (live) entry: allocate one and open a session. */
    if (!e) {
        e = dst_alloc(a, &hdr.dst);
        if (!e) return; /* table full: drop, no cache */
    }

    /* Stash the DST in the rx_ctx kept parallel to this slot. */
    size_t idx = (size_t)(e - a->dst);
    struct rx_ctx *rc = &a->rxslot[idx];
    rc->a = a;
    rc->atype = hdr.dst.atype;
    rc->host_len = hdr.dst.host_len;
    if (hdr.dst.host_len) memcpy(rc->host, hdr.dst.host, hdr.dst.host_len);
    rc->port = hdr.dst.port;

    void *session = a->open_fn(a->core, hdr.dst.host, hdr.dst.host_len, hdr.dst.atype,
                               hdr.dst.port, on_rx, on_err, rc);
    if (!session) {
        /* NULL = transient (session limit / pre-auth queue full / availability
         * undetermined): drop this datagram only, do NOT cache. Retire the
         * just-allocated entry so the next datagram retries. */
        e->used = 0;
        return;
    }
    e->session = session;
    e->dead = 0;
    e->failed_at = 0;

    /* Optimistic send right away. */
    a->send_fn(session, payload, payload_len);
}

/* ── TCP control connection (EOF watch) ─────────────────────────────────── */

static void
assoc_teardown(mq_udp_assoc_t *a)
{
    if (!a) return;
    if (a->tearing_down) return;
    a->tearing_down = 1;

    /* Close every live relay session (caller-initiated terminate). Dead entries
     * (on_err already fired) must NOT be closed — boundary contract. */
    for (size_t i = 0; i < MQ_UDP_ASSOC_MAX_DST; i++) {
        struct mq_dst_entry *e = &a->dst[i];
        if (e->used && !e->dead && e->session) {
            a->close_fn(e->session);
        }
        e->session = NULL;
        e->used = 0;
    }

    /* Self-remove from the listener's active list. */
    list_unlink(a);
}

static void
on_tcp_event(evutil_socket_t fd, short what, void *user)
{
    (void)what;
    mq_udp_assoc_t *a = (mq_udp_assoc_t *)user;
    /* The control connection carries no application data after ASSOCIATE; any
     * readable event is EOF or an error => tear the whole association down
     * (RFC 1928 §7). Drain to confirm. */
    uint8_t scratch[256];
    ssize_t n = recv(fd, scratch, sizeof(scratch), 0);
    if (n > 0) {
        /* Unexpected data on the control channel; the client should not send
         * anything. Ignore it but keep the assoc alive (be permissive). */
        return;
    }
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        /* mq_udp_assoc_free runs assoc_teardown (close live sessions + unlink
         * from the listener list) then frees the shell. */
        mq_udp_assoc_free(a);
        return;
    }
    /* EAGAIN/EINTR: spurious wakeup; ignore. */
}

/* ── construction / teardown ────────────────────────────────────────────── */

mq_udp_assoc_t *
mq_udp_assoc_new(struct event_base *base, int tcp_fd, const char *bind_ip,
                 mq_udp_open_fn open_fn, mq_udp_send_fn send_fn, mq_udp_close_fn close_fn,
                 void *core)
{
    if (!base || tcp_fd < 0 || !bind_ip || !open_fn || !send_fn || !close_fn) {
        return NULL;
    }

    mq_udp_assoc_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->base = base;
    a->tcp_fd = tcp_fd;
    a->udp_fd = -1;
    a->open_fn = open_fn;
    a->send_fn = send_fn;
    a->close_fn = close_fn;
    a->core = core;

    /* Learn the TCP peer's IP for source filtering. */
    socklen_t plen = sizeof(a->tcp_peer);
    if (getpeername(tcp_fd, (struct sockaddr *)&a->tcp_peer, &plen) != 0 ||
        a->tcp_peer.sin_family != AF_INET) {
        free(a);
        return NULL;
    }

    /* Bind the UDP relay socket on bind_ip:ephemeral. */
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ufd < 0) {
        free(a);
        return NULL;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = 0; /* ephemeral */
    if (inet_pton(AF_INET, bind_ip, &sa.sin_addr) != 1) {
        close(ufd);
        free(a);
        return NULL;
    }
    if (bind(ufd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || set_nonblock(ufd) != 0) {
        close(ufd);
        free(a);
        return NULL;
    }
    a->udp_fd = ufd;

    /* Determine the UDP port and the BND.ADDR we advertise. */
    struct sockaddr_in ubound;
    socklen_t ulen = sizeof(ubound);
    if (getsockname(ufd, (struct sockaddr *)&ubound, &ulen) == 0) {
        a->udp_port = ntohs(ubound.sin_port);
    }

    /* BND.ADDR: the IP the client can reach the UDP socket at. If bind_ip is a
     * concrete address, use it; if it is the wildcard 0.0.0.0, the standard
     * approach is the TCP socket's local address (the interface the client
     * already reached us on). BND.PORT is always the UDP socket's port. */
    uint32_t bnd_ip_be = ubound.sin_addr.s_addr; /* = bind_ip (network order) */
    if (bnd_ip_be == htonl(INADDR_ANY)) {
        struct sockaddr_in local;
        socklen_t llen = sizeof(local);
        if (getsockname(tcp_fd, (struct sockaddr *)&local, &llen) == 0 &&
            local.sin_family == AF_INET) {
            bnd_ip_be = local.sin_addr.s_addr;
        }
    }

    /* Write the ASSOCIATE success reply on the control connection. */
    uint8_t rep[10];
    size_t rn = mq_socks5_build_associate_reply(rep, ntohl(bnd_ip_be), a->udp_port);
    if (send(tcp_fd, rep, rn, MSG_NOSIGNAL) != (ssize_t)rn) {
        close(ufd);
        a->udp_fd = -1;
        free(a);
        return NULL;
    }

    /* Wire events: UDP readable (relay) + TCP readable (EOF watch). */
    a->udp_ev = event_new(base, ufd, EV_READ | EV_PERSIST, on_udp_readable, a);
    a->tcp_ev = event_new(base, tcp_fd, EV_READ | EV_PERSIST, on_tcp_event, a);
    if (!a->udp_ev || !a->tcp_ev) {
        if (a->udp_ev) event_free(a->udp_ev);
        if (a->tcp_ev) event_free(a->tcp_ev);
        close(ufd);
        free(a);
        return NULL;
    }
    event_add(a->udp_ev, NULL);
    event_add(a->tcp_ev, NULL);

    return a;
}

void
mq_udp_assoc_free(mq_udp_assoc_t *a)
{
    if (!a) return;
    /* Close any sessions still live (e.g. listener-free path where TCP-EOF
     * never ran). assoc_teardown is idempotent. */
    assoc_teardown(a);

    if (a->udp_ev) event_free(a->udp_ev);
    if (a->tcp_ev) event_free(a->tcp_ev);
    if (a->udp_fd >= 0) close(a->udp_fd);
    if (a->tcp_fd >= 0) close(a->tcp_fd);
    free(a);
}

uint16_t
mq_udp_assoc_udp_port(const mq_udp_assoc_t *a)
{
    return a ? a->udp_port : 0;
}
