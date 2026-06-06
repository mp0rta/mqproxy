// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_udp_assoc.h — SOCKS5 UDP ASSOCIATE edge (RFC 1928 §7).
 *
 * One mq_udp_assoc_t backs a single accepted SOCKS5 control connection that
 * issued CMD UDP ASSOCIATE (0x03). The listener hands it the TCP control fd
 * (whose EOF/error tears the whole association down) and a freshly bound UDP
 * socket on bind_ip:ephemeral; the assoc writes the ASSOCIATE success reply
 * (REP=0, BND.ADDR:BND.PORT = the address the client can reach the UDP socket
 * at) onto the TCP fd.
 *
 * On a client datagram (UDP readable):
 *   - source learning: the first datagram from the TCP peer's IP (any port)
 *     locks IP:port; afterwards only an exact IP:port match is accepted, all
 *     others are silently dropped (RFC 1928 §7 source filtering).
 *   - parse the encapsulation header (mq_socks5_parse_udp_hdr): FRAG != 0 or
 *     malformed => drop.
 *   - look up / create a per-DST relay session (open_fn boundary, mq_ingress.h).
 *     open returns a handle synchronously or NULL; optimistic send is allowed
 *     immediately after open. on_rx for the reverse direction re-encapsulates
 *     (mq_socks5_build_udp_hdr with the DST as source) and sendto()s the
 *     learned client addr.
 *
 * The open_fn/send_fn/close_fn/core quad is the mq_udp_open_fn boundary; the
 * assoc never touches xquic. See mq_ingress.h for the at-most-once on_err and
 * callback-suppression-after-close contract this module relies on.
 */
#ifndef MQ_INGRESS_MQ_UDP_ASSOC_H
#define MQ_INGRESS_MQ_UDP_ASSOC_H

#include <stdint.h>

#include "ingress/mq_ingress.h"

struct event_base;

typedef struct mq_udp_assoc mq_udp_assoc_t;

/* Accept an ASSOCIATE: take ownership of tcp_fd (EV_READ EOF watch), bind a UDP
 * socket on bind_ip:ephemeral, and write the SOCKS5 success reply onto tcp_fd.
 * open_fn/send_fn/close_fn/core are the mq_udp_open_fn boundary. base is
 * borrowed (must outlive the assoc). Returns NULL on bad args / socket / bind
 * failure (caller then closes tcp_fd and rejects). */
mq_udp_assoc_t *mq_udp_assoc_new(struct event_base *base, int tcp_fd, const char *bind_ip,
                                 mq_udp_open_fn open_fn, mq_udp_send_fn send_fn,
                                 mq_udp_close_fn close_fn, void *core);

/* Tear down: close every live relay session (close_fn), free the UDP socket,
 * the TCP control fd, and all events. Idempotent-safe via the listener path.
 * Safe on NULL. */
void mq_udp_assoc_free(mq_udp_assoc_t *a);

/* ── intrusive list (owned by the listener) ──────────────────────────────────
 * The listener keeps the head; the assoc owns the prev/next links and a
 * back-pointer to the head so it can self-remove on TCP-EOF teardown. */

/* Link `a` at the head of *head (the listener's active-assoc list). */
void mq_udp_assoc_list_push(mq_udp_assoc_t **head, mq_udp_assoc_t *a);
/* The next assoc in the list (for iteration). NULL at the tail. */
mq_udp_assoc_t *mq_udp_assoc_list_next(mq_udp_assoc_t *a);

#endif /* MQ_INGRESS_MQ_UDP_ASSOC_H */
