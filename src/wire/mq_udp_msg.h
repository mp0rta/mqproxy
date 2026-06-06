// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_UDP_MSG_H
#define MQ_UDP_MSG_H
#include <stdint.h>
#include <stddef.h>

/* Fixed 9-byte header that prefixes every UDP payload carried in a QUIC
 * DATAGRAM frame.  Wire layout (all big-endian):
 *   session_id  u32 BE | packet_id u16 BE | flags u8 | frag_id u8 | frag_count u8
 * = 9 bytes total.  §5.4 of the Phase-3 design doc. */
#define MQ_UDP_MSG_HDR 9

typedef struct {
    uint32_t session_id;
    uint16_t packet_id;
    uint8_t flags; /* transmit: set to 0; receive: ignore (forward compat) */
    uint8_t frag_id;
    uint8_t frag_count; /* 1 = unfragmented */
} mq_udp_msg_hdr_t;

/* Encode hdr into buf[MQ_UDP_MSG_HDR].  Returns 0 on success, -1 on error. */
int mq_udp_msg_encode_hdr(uint8_t buf[MQ_UDP_MSG_HDR], const mq_udp_msg_hdr_t *h);

/* Decode hdr from buf[0..len).  Returns 0 on success, -1 if len < MQ_UDP_MSG_HDR. */
int mq_udp_msg_decode_hdr(const uint8_t *buf, size_t len, mq_udp_msg_hdr_t *out);

/* Fragment callback: called once per fragment with the per-fragment header,
 * a pointer into the *original* payload buffer (zero-copy slice), and the
 * slice length. */
typedef void (*mq_udp_frag_emit_fn)(const mq_udp_msg_hdr_t *h, const uint8_t *p,
                                    size_t len, void *user);

/* Split payload of `len` bytes into fragments of at most `mss_payload` bytes
 * each, calling emit() for every fragment.  Pure function: no allocation, no
 * I/O.  Slices point directly into the caller's payload buffer.
 *
 * Returns 0 on success, -1 (without calling emit) if:
 *   - mss_payload == 0
 *   - the required fragment count exceeds 255 (frag_count is u8)
 *
 * len == 0: emits exactly 1 fragment of length 0 (frag_count = 1). */
int mq_udp_msg_split(uint32_t sid, uint16_t packet_id, const uint8_t *payload, size_t len,
                     size_t mss_payload, mq_udp_frag_emit_fn emit, void *user);

#endif /* MQ_UDP_MSG_H */
