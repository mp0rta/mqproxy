// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
//
// NOT part of the CMake build. Regenerate wire seeds (run from repo ROOT):
//   clang -g -O1 -Isrc fuzz/scripts/gen_wire_seeds.c \
//     src/wire/mq_wire.c src/wire/mq_varint.c src/wire/mq_udp_msg.c -o
//     /tmp/gen_wire_seeds
//   for d in wire_auth_req wire_auth_resp wire_connect_tcp_req wire_connect_tcp_resp \
//            wire_udp_session_open wire_udp_session_resp udp_msg_hdr; do mkdir -p
//            fuzz/corpus/$d; done
//   /tmp/gen_wire_seeds
//
// Emits a minimal valid frame + one boundary frame per wire type, by running the
// real encoders. Seeds only bootstrap libFuzzer coverage; they are not golden
// fixtures (the fuzzer mutates them), so a stale seed at worst loses a little
// coverage and never breaks the gate.
#include "wire/mq_udp_msg.h"
#include "wire/mq_wire.h"
#include <stdio.h>
#include <string.h>

static void
dump(const char *path, const uint8_t *b, int n)
{
    if (n < 0) {
        fprintf(stderr, "encode failed: %s\n", path);
        return;
    }
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return;
    }
    fwrite(b, 1, (size_t)n, f);
    fclose(f);
}

int
main(void)
{
    uint8_t buf[1024];

    /* --- AUTH_REQUEST --- */
    mq_auth_req_t ar = {.version = 1, .features = 0};
    strcpy(ar.client_id, "c1");
    strcpy(ar.auth_token, "t1");
    dump("fuzz/corpus/wire_auth_req/min", buf, mq_encode_auth_req(buf, sizeof buf, &ar));
    mq_auth_req_t ar2 = {.version = 0xFFFFFFFF, .features = 0xDEADBEEF};
    memset(ar2.client_id, 'A', sizeof ar2.client_id - 1);
    memset(ar2.auth_token, 'B', sizeof ar2.auth_token - 1);
    dump("fuzz/corpus/wire_auth_req/maxlen", buf,
         mq_encode_auth_req(buf, sizeof buf, &ar2));

    /* --- AUTH_RESPONSE --- */
    mq_auth_resp_t aresp = {
        .status = MQ_STATUS_OK, .error_code = MQ_AUTH_OK, .features = MQ_FEAT_UDP_RELAY};
    strcpy(aresp.server_id, "s1");
    dump("fuzz/corpus/wire_auth_resp/ok", buf,
         mq_encode_auth_resp(buf, sizeof buf, &aresp));
    mq_auth_resp_t aresp_err = {
        .status = MQ_STATUS_ERROR, .error_code = MQ_AUTH_TOKEN_EXPIRED, .features = 0};
    strcpy(aresp_err.server_id, "s1");
    dump("fuzz/corpus/wire_auth_resp/err", buf,
         mq_encode_auth_resp(buf, sizeof buf, &aresp_err));

    /* --- CONNECT_TCP_REQUEST --- */
    mq_connect_tcp_req_t creq = {
        .flags = 0, .address_type = MQ_ADDR_IPV4, .host_len = 4, .port = 80};
    memcpy(creq.host, (uint8_t[]){127, 0, 0, 1}, 4);
    dump("fuzz/corpus/wire_connect_tcp_req/ipv4", buf,
         mq_encode_connect_tcp_req(buf, sizeof buf, &creq));
    mq_connect_tcp_req_t creq_dom = {
        .flags = 0, .address_type = MQ_ADDR_DOMAIN, .port = 443};
    const char *dom = "example.com";
    creq_dom.host_len = strlen(dom);
    memcpy(creq_dom.host, dom, creq_dom.host_len);
    dump("fuzz/corpus/wire_connect_tcp_req/domain", buf,
         mq_encode_connect_tcp_req(buf, sizeof buf, &creq_dom));

    /* --- CONNECT_TCP_RESPONSE --- */
    mq_connect_tcp_resp_t cresp = {
        .status = MQ_STATUS_OK, .error_code = MQ_TCP_OK, .message_len = 0};
    dump("fuzz/corpus/wire_connect_tcp_resp/ok", buf,
         mq_encode_connect_tcp_resp(buf, sizeof buf, &cresp));
    mq_connect_tcp_resp_t cresp_err = {.status = MQ_STATUS_ERROR,
                                       .error_code = MQ_TCP_CONN_REFUSED};
    const char *msg = "connection refused";
    cresp_err.message_len = strlen(msg);
    memcpy(cresp_err.message, msg, cresp_err.message_len);
    dump("fuzz/corpus/wire_connect_tcp_resp/err", buf,
         mq_encode_connect_tcp_resp(buf, sizeof buf, &cresp_err));

    /* --- UDP_SESSION_OPEN --- */
    mq_udp_session_open_t uopen = {.session_id = 1,
                                   .flags = 0,
                                   .address_type = MQ_ADDR_IPV4,
                                   .host_len = 4,
                                   .port = 53,
                                   .idle_timeout_ms = 0};
    memcpy(uopen.host, (uint8_t[]){8, 8, 8, 8}, 4);
    dump("fuzz/corpus/wire_udp_session_open/ipv4", buf,
         mq_encode_udp_session_open(buf, sizeof buf, &uopen));

    /* --- UDP_SESSION_RESPONSE --- */
    mq_udp_session_resp_t uresp = {.status = MQ_STATUS_OK,
                                   .error_code = MQ_UDP_OK,
                                   .message_len = 0,
                                   .idle_timeout_ms = 30000};
    dump("fuzz/corpus/wire_udp_session_resp/ok", buf,
         mq_encode_udp_session_resp(buf, sizeof buf, &uresp));

    /* --- UDP_MSG_HDR (fixed 9-byte header) --- */
    mq_udp_msg_hdr_t h = {
        .session_id = 1, .packet_id = 1, .flags = 0, .frag_id = 0, .frag_count = 1};
    uint8_t hbuf[MQ_UDP_MSG_HDR];
    int hn = mq_udp_msg_encode_hdr(hbuf, &h);
    dump("fuzz/corpus/udp_msg_hdr/min", hbuf, hn == 0 ? (int)MQ_UDP_MSG_HDR : -1);

    return 0;
}
