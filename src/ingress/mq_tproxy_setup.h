// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#ifndef MQ_TPROXY_SETUP_H
#define MQ_TPROXY_SETUP_H

/* mq_tproxy_setup.h — optional kernel firewall helper for transparent capture.
 *
 * Installs / uninstalls the nftables + ip-rule/ip-route rules needed to
 * redirect TCP traffic into the mq_tproxy_listener.  Requires root or
 * CAP_NET_ADMIN + CAP_NET_RAW.  Use is OPTIONAL — operators who manage their
 * own firewall rules can skip this entirely and just wire --tproxy.
 *
 * REDIRECT mode:
 *   nft: output-hook nat REDIRECT → listener-port (skip owner UID)
 *
 * TPROXY mode:
 *   ip rule + ip route: mark-based local routing
 *   nft: prerouting-hook filter TPROXY → listener-port (mark set, skip UID)
 *
 * All state (table name, mark, etc.) is owned by the mq_tproxy_setup_t
 * handle.  install / uninstall are idempotent at the nft/ip level (nft
 * delete-table is silent if the table does not exist; ip rule/route del
 * errors are logged and tolerated).
 */

#include <stdint.h>
#include <sys/types.h>

#include "ingress/mq_tproxy.h" /* mq_capture_mode_t */

typedef struct mq_tproxy_setup mq_tproxy_setup_t;

/* Allocate a setup handle.
 *   mode          — capture mode (REDIRECT or TPROXY)
 *   bind_ip       — listener bind address (informational; used in log only)
 *   listener_port — TCP port the mq_tproxy_listener is bound to
 *   dport         — destination port to capture (e.g. 443)
 *   skip_uid      — UID whose outbound traffic is NOT redirected (the proxy
 *                   process itself); pass (uid_t)-1 to use geteuid()
 *   fwmark        — packet mark for TPROXY routing (ignored in REDIRECT mode)
 *   table         — ip routing table for TPROXY (ignored in REDIRECT mode)
 *
 * Returns NULL on allocation failure. */
mq_tproxy_setup_t *mq_tproxy_setup_new(mq_capture_mode_t mode, const char *bind_ip,
                                       uint16_t listener_port, uint16_t dport,
                                       uid_t skip_uid, int fwmark, int table);

/* Run the install commands.
 * Returns 0 if all commands succeeded, -1 if any failed (errors logged). */
int mq_tproxy_setup_install(mq_tproxy_setup_t *s);

/* Run the uninstall/cleanup commands (idempotent; errors are logged, not
 * propagated — teardown must not prevent process exit). Safe on NULL. */
void mq_tproxy_setup_uninstall(mq_tproxy_setup_t *s);

/* Free the handle.  Does NOT run uninstall — call mq_tproxy_setup_uninstall
 * first if rules were installed.  Safe on NULL. */
void mq_tproxy_setup_free(mq_tproxy_setup_t *s);

#endif /* MQ_TPROXY_SETUP_H */
