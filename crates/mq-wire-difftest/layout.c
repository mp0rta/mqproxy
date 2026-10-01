// spec §8.2: sizeof/offsetof of the mq_wire.h structs, checked against the
// #[repr(C)] mirrors in src/lib.rs (rust_layout()).
#include <stddef.h>

#include "wire/mq_wire.h"

static const size_t layout[] = {
    sizeof(mq_auth_req_t),
    offsetof(mq_auth_req_t, version),
    offsetof(mq_auth_req_t, client_id),
    offsetof(mq_auth_req_t, auth_token),
    offsetof(mq_auth_req_t, features),
    sizeof(mq_auth_resp_t),
    offsetof(mq_auth_resp_t, status),
    offsetof(mq_auth_resp_t, error_code),
    offsetof(mq_auth_resp_t, server_id),
    offsetof(mq_auth_resp_t, features),
    sizeof(mq_connect_tcp_req_t),
    offsetof(mq_connect_tcp_req_t, flags),
    offsetof(mq_connect_tcp_req_t, address_type),
    offsetof(mq_connect_tcp_req_t, host),
    offsetof(mq_connect_tcp_req_t, host_len),
    offsetof(mq_connect_tcp_req_t, port),
    sizeof(mq_connect_tcp_resp_t),
    offsetof(mq_connect_tcp_resp_t, status),
    offsetof(mq_connect_tcp_resp_t, error_code),
    offsetof(mq_connect_tcp_resp_t, message),
    offsetof(mq_connect_tcp_resp_t, message_len),
    sizeof(mq_status_t),
    sizeof(mq_addr_type_t),
};

const size_t *
mq_difftest_layout(size_t *n)
{
    *n = sizeof layout / sizeof layout[0];
    return layout;
}
