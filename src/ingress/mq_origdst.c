// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
#include "ingress/mq_origdst.h"
#include <netinet/in.h>
#include <linux/netfilter_ipv4.h> /* SO_ORIGINAL_DST */
#include <string.h>
#include <sys/socket.h>

int
mq_origdst_to_target(const struct sockaddr_storage *ss, uint8_t *host, size_t cap,
                     size_t *host_len, int *atype, uint16_t *port)
{
    if (ss->ss_family == AF_INET) {
        if (cap < 4) return -1;
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        memcpy(host, &s4->sin_addr, 4);
        *host_len = 4;
        *atype = MQ_ADDR_IPV4;
        *port = ntohs(s4->sin_port);
        return 0;
    }
    if (ss->ss_family == AF_INET6) {
        if (cap < 16) return -1;
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        memcpy(host, &s6->sin6_addr, 16);
        *host_len = 16;
        *atype = MQ_ADDR_IPV6;
        *port = ntohs(s6->sin6_port);
        return 0;
    }
    return -1;
}

int
mq_origdst_from_fd_tproxy(int fd, struct sockaddr_storage *out)
{
    socklen_t len = sizeof(*out);
    if (getsockname(fd, (struct sockaddr *)out, &len) < 0) return -1;
    return 0;
}

int
mq_origdst_from_fd_redirect(int fd, struct sockaddr_storage *out)
{
    struct sockaddr_in s4;
    socklen_t len = sizeof(s4);
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &s4, &len) < 0) return -1;
    memset(out, 0, sizeof(*out));
    memcpy(out, &s4, sizeof(s4));
    return 0;
}
