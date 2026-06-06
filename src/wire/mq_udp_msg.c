// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#include "wire/mq_udp_msg.h"

/* ---- encode / decode ---- */

int
mq_udp_msg_encode_hdr(uint8_t buf[MQ_UDP_MSG_HDR], const mq_udp_msg_hdr_t *h)
{
    /* session_id: 4 bytes BE */
    buf[0] = (uint8_t)((h->session_id >> 24) & 0xFF);
    buf[1] = (uint8_t)((h->session_id >> 16) & 0xFF);
    buf[2] = (uint8_t)((h->session_id >> 8) & 0xFF);
    buf[3] = (uint8_t)(h->session_id & 0xFF);
    /* packet_id: 2 bytes BE */
    buf[4] = (uint8_t)((h->packet_id >> 8) & 0xFF);
    buf[5] = (uint8_t)(h->packet_id & 0xFF);
    /* flags, frag_id, frag_count: 1 byte each */
    buf[6] = h->flags;
    buf[7] = h->frag_id;
    buf[8] = h->frag_count;
    return 0;
}

int
mq_udp_msg_decode_hdr(const uint8_t *buf, size_t len, mq_udp_msg_hdr_t *out)
{
    if (len < MQ_UDP_MSG_HDR) return -1;
    out->session_id = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                      ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
    out->packet_id = (uint16_t)(((uint16_t)buf[4] << 8) | (uint16_t)buf[5]);
    out->flags = buf[6];
    out->frag_id = buf[7];
    out->frag_count = buf[8];
    return 0;
}

/* ---- fragment split ---- */

int
mq_udp_msg_split(uint32_t sid, uint16_t packet_id, const uint8_t *payload, size_t len,
                 size_t mss_payload, mq_udp_frag_emit_fn emit, void *user)
{
    /* mss_payload == 0 is un-splittable */
    if (mss_payload == 0) return -1;

    /* Compute fragment count.  len == 0 → 1 frag of 0 bytes.
     * Use overflow-safe ceil-div: avoid len + mss_payload - 1 which wraps near
     * SIZE_MAX and would silently return 0, bypassing the >255 guard. */
    size_t nfrags = (len == 0) ? 1 : (len / mss_payload) + (len % mss_payload != 0);

    /* frag_count is u8: max 255 */
    if (nfrags > 255) return -1;

    uint8_t frag_count = (uint8_t)nfrags;
    size_t offset = 0;

    for (uint8_t frag_id = 0; frag_id < frag_count; frag_id++) {
        size_t slice_len = (len - offset < mss_payload) ? (len - offset) : mss_payload;

        mq_udp_msg_hdr_t h;
        h.session_id = sid;
        h.packet_id = packet_id;
        h.flags = 0;
        h.frag_id = frag_id;
        h.frag_count = frag_count;

        emit(&h, payload + offset, slice_len, user);
        offset += slice_len;
    }
    return 0;
}
