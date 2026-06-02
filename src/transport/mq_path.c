// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_path.c — per-path UDP socket bound to a local address (one MPQUIC path).
 *
 * Recv path mirrors mqvpn's single-threaded libevent integration of the same
 * xquic fork (mqvpn_client_on_socket_recv): drain datagrams with recvfrom,
 * feed each into xqc_engine_packet_process with this path's cached local addr
 * and the recvfrom peer addr, then call xqc_engine_finish_recv once.
 */
#include "transport/mq_path.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <event2/event.h>

#include "util/mq_log.h"

/* Max UDP datagram we read into a stack buffer per recvfrom. */
#define MQ_PATH_RECV_BUF 65536

struct mq_path {
    mq_engine_t *eng;
    uint64_t path_id;
    int fd;
    struct event *ev_read;

    struct sockaddr_storage local_addr; /* cached getsockname() value */
    socklen_t local_addrlen;

    void *user; /* conn_user_data handed to packet_process (Task 10: mq_conn) */
};

/* Receive timestamp in microseconds (matches xquic's internal xqc_now, which
 * is gettimeofday-based). */
static xqc_usec_t
mq_path_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + (xqc_usec_t)tv.tv_usec;
}

/* libevent EV_READ handler: drain all pending datagrams, feed each to the
 * engine, then finish_recv once. */
static void
mq_path_read_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    mq_path_t *p = (mq_path_t *)arg;
    xqc_engine_t *xeng = mq_engine_xqc(p->eng);

    unsigned char buf[MQ_PATH_RECV_BUF];
    int processed = 0;

    for (;;) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        memset(&peer, 0, sizeof(peer));

        ssize_t n =
            recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            MQ_LOGW("mq_path: recvfrom(path %llu) failed: %s",
                    (unsigned long long)p->path_id, strerror(errno));
            break;
        }
        if (n == 0) {
            /* Empty datagram; nothing to process. */
            continue;
        }

        xqc_usec_t recv_time = mq_path_now_us();
        xqc_engine_packet_process(xeng, buf, (size_t)n, (struct sockaddr *)&p->local_addr,
                                  p->local_addrlen, (struct sockaddr *)&peer, peer_len,
                                  recv_time, p->user);
        processed = 1;
    }

    if (processed) {
        xqc_engine_finish_recv(xeng);
    }
}

/* Parse local_ip into a sockaddr; sets *af. Returns 0 on success. */
static int
mq_path_build_addr(const char *local_ip, uint16_t local_port,
                   struct sockaddr_storage *out, socklen_t *out_len, int *af)
{
    memset(out, 0, sizeof(*out));

    struct in6_addr a6;
    struct in_addr a4;

    if (inet_pton(AF_INET, local_ip, &a4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_addr = a4;
        sin->sin_port = htons(local_port);
        *out_len = sizeof(*sin);
        *af = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, local_ip, &a6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = a6;
        sin6->sin6_port = htons(local_port);
        *out_len = sizeof(*sin6);
        *af = AF_INET6;
        return 0;
    }
    return -1;
}

mq_path_t *
mq_path_open(mq_engine_t *eng, uint64_t path_id, const char *local_ip,
             uint16_t local_port)
{
    if (!eng || !local_ip) {
        return NULL;
    }
    if (!mq_engine_base(eng) || !mq_engine_xqc(eng)) {
        return NULL;
    }

    struct sockaddr_storage bind_addr;
    socklen_t bind_len = 0;
    int af = 0;
    if (mq_path_build_addr(local_ip, local_port, &bind_addr, &bind_len, &af) != 0) {
        MQ_LOGE("mq_path: invalid local_ip '%s'", local_ip);
        return NULL;
    }

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        MQ_LOGE("mq_path: socket(af=%d) failed: %s", af, strerror(errno));
        return NULL;
    }

    /* Non-blocking. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        MQ_LOGE("mq_path: set O_NONBLOCK failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        MQ_LOGW("mq_path: SO_REUSEADDR failed: %s", strerror(errno));
        /* non-fatal */
    }

    if (bind(fd, (struct sockaddr *)&bind_addr, bind_len) < 0) {
        MQ_LOGE("mq_path: bind(%s:%u) failed: %s", local_ip, local_port, strerror(errno));
        close(fd);
        return NULL;
    }

    mq_path_t *p = calloc(1, sizeof(*p));
    if (!p) {
        close(fd);
        return NULL;
    }
    p->eng = eng;
    p->path_id = path_id;
    p->fd = fd;
    /* Default the packet_process user_data to the engine. xquic hands this
     * value to the server "before accept" send callback (and server_accept)
     * as conn_user_data, and mq_engine's send callback recovers the engine
     * by casting conn_user_data -> mq_engine_t*. The value must remain
     * engine-recoverable. */
    p->user = eng;

    /* Read back the actual bound address (resolves ephemeral port). */
    p->local_addrlen = sizeof(p->local_addr);
    if (getsockname(fd, (struct sockaddr *)&p->local_addr, &p->local_addrlen) < 0) {
        MQ_LOGE("mq_path: getsockname failed: %s", strerror(errno));
        close(fd);
        free(p);
        return NULL;
    }

    /* Register fd in the engine's path-id -> fd map for send routing. */
    if (mq_engine_register_path_fd(eng, path_id, fd) != 0) {
        MQ_LOGE("mq_path: register_path_fd(path %llu) failed (out of range)",
                (unsigned long long)path_id);
        close(fd);
        free(p);
        return NULL;
    }

    /* Install the persistent read event. */
    p->ev_read =
        event_new(mq_engine_base(eng), fd, EV_READ | EV_PERSIST, mq_path_read_cb, p);
    if (!p->ev_read || event_add(p->ev_read, NULL) < 0) {
        MQ_LOGE("mq_path: event_new/event_add failed");
        if (p->ev_read) {
            event_free(p->ev_read);
        }
        mq_engine_unregister_path_fd(eng, path_id);
        close(fd);
        free(p);
        return NULL;
    }

    return p;
}

int
mq_path_fd(const mq_path_t *p)
{
    return p ? p->fd : -1;
}

int
mq_path_local_addr(const mq_path_t *p, struct sockaddr_storage *out, socklen_t *out_len)
{
    if (!p || !out || !out_len) {
        return -1;
    }
    memcpy(out, &p->local_addr, p->local_addrlen);
    *out_len = p->local_addrlen;
    return 0;
}

uint64_t
mq_path_id(const mq_path_t *p)
{
    return p ? p->path_id : 0;
}

void
mq_path_close(mq_path_t *p)
{
    if (!p) {
        return;
    }
    if (p->ev_read) {
        event_del(p->ev_read);
        event_free(p->ev_read);
    }
    mq_engine_unregister_path_fd(p->eng, p->path_id);
    if (p->fd >= 0) {
        close(p->fd);
    }
    free(p);
}
