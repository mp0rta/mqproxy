// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// Unit tests for mq_origdst_to_target. The syscall wrappers (tproxy/redirect)
// need a live socket and are covered by Task 9 e2e — not tested here.
#include "mqtest.h"
#include "ingress/mq_origdst.h"
#include "wire/mq_wire.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

static void
test_ipv4(void)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(443);
    inet_pton(AF_INET, "93.184.216.34", &s4->sin_addr);

    uint8_t host[16];
    size_t host_len = 0;
    int atype = -1;
    uint16_t port = 0;
    int rc = mq_origdst_to_target(&ss, host, sizeof(host), &host_len, &atype, &port);

    MQ_CHECK_EQ_INT(rc, 0);
    MQ_CHECK_EQ_INT(atype, MQ_ADDR_IPV4);
    MQ_CHECK_EQ_INT((int)port, 443);
    MQ_CHECK_EQ_INT((int)host_len, 4);
    const uint8_t want[4] = {93, 184, 216, 34};
    MQ_CHECK_MEM(host, want, 4);
}

static void
test_ipv6(void)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(8080);
    inet_pton(AF_INET6, "2001:db8::1", &s6->sin6_addr);

    uint8_t host[16];
    size_t host_len = 0;
    int atype = -1;
    uint16_t port = 0;
    int rc = mq_origdst_to_target(&ss, host, sizeof(host), &host_len, &atype, &port);

    MQ_CHECK_EQ_INT(rc, 0);
    MQ_CHECK_EQ_INT(atype, MQ_ADDR_IPV6);
    MQ_CHECK_EQ_INT((int)port, 8080);
    MQ_CHECK_EQ_INT((int)host_len, 16);
    uint8_t want[16];
    inet_pton(AF_INET6, "2001:db8::1", want);
    MQ_CHECK_MEM(host, want, 16);
}

static void
test_short_buffer(void)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(80);
    inet_pton(AF_INET, "1.2.3.4", &s4->sin_addr);

    uint8_t host[4];
    size_t host_len = 0;
    int atype = 0;
    uint16_t port = 0;
    int rc = mq_origdst_to_target(&ss, host, 3, &host_len, &atype, &port);
    MQ_CHECK_EQ_INT(rc, -1);
}

static void
test_unsupported_family(void)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_family = AF_UNIX;

    uint8_t host[16];
    size_t host_len = 0;
    int atype = 0;
    uint16_t port = 0;
    int rc = mq_origdst_to_target(&ss, host, sizeof(host), &host_len, &atype, &port);
    MQ_CHECK_EQ_INT(rc, -1);
}

MQ_TEST_MAIN(test_ipv4(); test_ipv6(); test_short_buffer(); test_unsupported_family();)
