// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* mq_gw_fetch_adapter.h — HTTP/1.1 fetch-listener adapter over the neutral
 * mq_gw_client intake boundary.
 *
 * Wraps an mq_gw_client_t (the protocol-agnostic core) with a mq_fetch_cbs_t
 * implementation so the mq_fetch_listener can be wired to the gateway client
 * without the core knowing about HTTP/1.1 framing, handle ops, or chunked
 * encoding. The adapter:
 *
 *   - Implements on_request / on_body / on_body_done / on_aborted as a
 *     mq_fetch_cbs_t (to be passed to mq_fetch_listener_new).
 *   - Builds a neutral mq_h3_header_t list from the mq_http1_req_t, calls
 *     mq_gw_client_prevalidate, parses the X-Mq-Target / X-Mq-Method fetch
 *     envelope, and calls mq_gw_client_req_begin with an H1 sink.
 *   - The H1 sink (internal) renders HTTP/1.1 response bytes (status line,
 *     Transfer-Encoding: chunked / Connection: close, chunk framing) via the
 *     mq_fetch_conn_* handle ops — byte-identical to the former inline path.
 *
 * LIFETIME: mq_gw_fetch_adapter_t does NOT take ownership of the core, the
 * fetch listener, or the H3 engine — it only borrows them. Per the SANCTIONED
 * teardown order (see cli/main.c, where the rationale is spelled out), the core
 * (mq_gw_client) is freed FIRST, while the H3 engine is still live, so a late
 * gateway conn-close callback lands as a no-op into the dying gw_client instead
 * of a use-after-free. The adapter does not dereference the core in
 * mq_gw_fetch_adapter_free, so freeing it after the core is safe:
 *
 *   mq_gw_client_free(core)            -- FIRST, while mq_h3 engine still live
 *   mq_fetch_listener_free(listener)
 *   mq_gw_fetch_adapter_free(adapter)  -- does not touch the freed core
 *   mq_h3_free(engine)
 */
#pragma once
#include "gateway/mq_fetch_listener.h"
#include "gateway/mq_gw_client.h"

typedef struct mq_gw_fetch_adapter mq_gw_fetch_adapter_t;

/* Create an adapter wrapping `core`. Returns NULL on OOM. */
mq_gw_fetch_adapter_t *mq_gw_fetch_adapter_new(mq_gw_client_t *core);

/* The mq_fetch_cbs_t vtable to pass to mq_fetch_listener_new. Points to a
 * static immutable struct (valid for the program lifetime). */
const mq_fetch_cbs_t *mq_gw_fetch_adapter_cbs(mq_gw_fetch_adapter_t *a);

/* The `user` pointer to pass alongside mq_gw_fetch_adapter_cbs() into
 * mq_fetch_listener_new (it is the mq_gw_fetch_adapter_t itself). */
void *mq_gw_fetch_adapter_user(mq_gw_fetch_adapter_t *a);

/* Free the adapter. Does NOT free the core. Safe on NULL. */
void mq_gw_fetch_adapter_free(mq_gw_fetch_adapter_t *a);
