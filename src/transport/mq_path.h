// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_path.h — one UDP socket bound to a local address, registered as one
 * MPQUIC path.
 *
 * An mq_path owns a non-blocking UDP socket, registers its fd in the engine's
 * path-id -> fd map (so the engine's send callback can route by path_id), and
 * installs a libevent EV_READ|EV_PERSIST event that drains incoming datagrams
 * and feeds them to xqc_engine_packet_process / xqc_engine_finish_recv.
 *
 * This module has NO TCP / stream / proxy knowledge.
 */
#ifndef MQ_TRANSPORT_MQ_PATH_H
#define MQ_TRANSPORT_MQ_PATH_H

#include <stdint.h>
#include <sys/socket.h>

#include "transport/mq_engine.h"

typedef struct mq_path mq_path_t;

/* Open a non-blocking UDP socket bound to local_ip:local_port.
 *
 * - local_port == 0 requests an ephemeral port; the actual bound address is
 *   read back via getsockname and cached.
 * - The address family is inferred from local_ip (AF_INET vs AF_INET6).
 * - The path is associated with `eng` (for send routing) and registered under
 *   `path_id` (XQC_INITIAL_PATH_ID == 0 for the primary path) in the engine's
 *   path-id -> fd map.
 * - A libevent read event is installed on the engine's event_base.
 *
 * Returns NULL on failure (no fd / event leaked). */
mq_path_t *mq_path_open(mq_engine_t *eng, uint64_t path_id, const char *local_ip,
                        uint16_t local_port);

/* The underlying UDP socket fd (>= 0), or -1 if p is NULL. */
int mq_path_fd(const mq_path_t *p);

/* Copy the cached bound local address into *out (capacity sizeof storage).
 * Writes the length into *out_len. Returns 0 on success, -1 on bad args. */
int mq_path_local_addr(const mq_path_t *p, struct sockaddr_storage *out,
                       socklen_t *out_len);

/* The path_id this path was registered under. */
uint64_t mq_path_id(const mq_path_t *p);

/* Unregister from the engine map, free the libevent read event, close the fd,
 * and free the struct. Safe on NULL. */
void mq_path_close(mq_path_t *p);

#endif /* MQ_TRANSPORT_MQ_PATH_H */
