#ifndef MQ_WIRE_H
#define MQ_WIRE_H
#include <stdint.h>
#include <stddef.h>

typedef enum { MQ_STATUS_OK = 0, MQ_STATUS_ERROR = 1 } mq_status_t;
typedef enum {
    MQ_AUTH_OK = 0,
    MQ_AUTH_FAILED = 1,
    MQ_AUTH_TOKEN_EXPIRED = 2,
    MQ_AUTH_POLICY_DENIED = 3
} mq_auth_err_t;
typedef enum {
    MQ_TCP_OK = 0,
    MQ_TCP_DNS_FAILED = 1,
    MQ_TCP_CONN_REFUSED = 2,
    MQ_TCP_TIMEOUT = 3,
    MQ_TCP_POLICY_DENIED = 4
} mq_tcp_err_t;
typedef enum {
    MQ_ADDR_IPV4 = 0x01,
    MQ_ADDR_DOMAIN = 0x03,
    MQ_ADDR_IPV6 = 0x04
} mq_addr_type_t;

#define MQ_MAX_HOST 255

typedef struct {
    uint64_t version;
    char client_id[64];
    char auth_token[256];
    uint64_t features;
} mq_auth_req_t;
typedef struct {
    mq_status_t status;
    mq_auth_err_t error_code;
    char server_id[64];
    uint64_t features;
} mq_auth_resp_t;
typedef struct {
    uint64_t flags;
    mq_addr_type_t address_type;
    uint8_t host[MQ_MAX_HOST];
    size_t host_len;
    uint16_t port;
} mq_connect_tcp_req_t;
typedef struct {
    mq_status_t status;
    mq_tcp_err_t error_code;
    char message[256];
    size_t message_len;
} mq_connect_tcp_resp_t;

/* Each returns bytes written (encode) / consumed (decode), or -1 on error.
   Decoders are strict: reject truncation and over-long string fields.
   Encoders write padding_length = 0 (no padding emitted); decoders MUST read
   padding_length and skip that many bytes (bounds-checked) for forward compat. */
int mq_encode_auth_req(uint8_t *buf, size_t cap, const mq_auth_req_t *f);
int mq_decode_auth_req(const uint8_t *buf, size_t len, mq_auth_req_t *out);
int mq_encode_auth_resp(uint8_t *buf, size_t cap, const mq_auth_resp_t *f);
int mq_decode_auth_resp(const uint8_t *buf, size_t len, mq_auth_resp_t *out);
int mq_encode_connect_tcp_req(uint8_t *buf, size_t cap, const mq_connect_tcp_req_t *f);
int mq_decode_connect_tcp_req(const uint8_t *buf, size_t len, mq_connect_tcp_req_t *out);
int mq_encode_connect_tcp_resp(uint8_t *buf, size_t cap, const mq_connect_tcp_resp_t *f);
int mq_decode_connect_tcp_resp(const uint8_t *buf, size_t len,
                               mq_connect_tcp_resp_t *out);
#endif
