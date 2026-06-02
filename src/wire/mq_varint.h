// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_VARINT_H
#define MQ_VARINT_H

#include <stddef.h>
#include <stdint.h>

int mq_varint_encode(uint8_t *buf, size_t cap, uint64_t v);
int mq_varint_decode(const uint8_t *buf, size_t len, uint64_t *out);
int mq_varint_len(uint64_t v);

#endif /* MQ_VARINT_H */
