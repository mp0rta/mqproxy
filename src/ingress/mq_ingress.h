#ifndef MQ_INGRESS_H
#define MQ_INGRESS_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>
/* delivered asynchronously when the proxy core has a result for a tcp_open */
typedef void (*mq_tcp_open_cb)(int ok, mq_tcp_err_t err, void *user);
/* implemented later by mq_client; ingress calls this and never touches xquic */
typedef void (*mq_tcp_open_fn)(void *core, const uint8_t *host, size_t host_len,
                               mq_addr_type_t atype, uint16_t port, int local_fd,
                               void *user, mq_tcp_open_cb cb);
#endif
