// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#ifndef MQ_UTIL_MQ_BACKOFF_H
#define MQ_UTIL_MQ_BACKOFF_H
#include <stdint.h>
/* Deterministic exponential backoff (no jitter):
 * min(cap_ms, base_ms << min(attempt, 31)).
 * Jitter is applied by the caller at arm time; this stays pure for tests.
 * Caller must use a sane base_ms (e.g. 250) so base_ms << 31 does not overflow
 * u64 (250 << 31 ≈ 5.4e11, well within u64). */
uint64_t mq_backoff_ms(uint64_t base_ms, uint64_t cap_ms, unsigned attempt);
#endif
