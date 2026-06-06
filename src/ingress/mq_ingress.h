// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

#ifndef MQ_INGRESS_H
#define MQ_INGRESS_H
#include "wire/mq_wire.h"
#include <stddef.h>
#include <stdint.h>
/* delivered asynchronously when the proxy core has a result for a tcp_open */
typedef void (*mq_tcp_open_cb)(int ok, mq_tcp_err_t err, void *user);
/* implemented later by mq_client; ingress calls this and never touches xquic.
 *
 * prebuf/prebuf_len carry app bytes that arrived in the SAME read as the request
 * head (e.g. a TLS ClientHello pipelined behind the SOCKS5/HTTP CONNECT request).
 * The ingress has already consumed them off local_fd, so they cannot be re-read
 * from the socket; the core MUST relay them toward the origin ahead of any fresh
 * local_fd reads or they are silently dropped. prebuf is borrowed (valid only
 * for the duration of the call); the core copies what it needs. prebuf_len may
 * be 0 (prebuf then NULL or ignored). */
typedef void (*mq_tcp_open_fn)(void *core, const uint8_t *host, size_t host_len,
                               mq_addr_type_t atype, uint16_t port, int local_fd,
                               const uint8_t *prebuf, size_t prebuf_len, void *user,
                               mq_tcp_open_cb cb);

/* UDP セッション境界。ingress (mq_udp_assoc) は xquic を知らない。
 *
 * open は session handle を【同期返却】する (local allocation のみ — auth /
 * RESP は待たない)。NULL = 即時失敗 (session 上限 / 負キャッシュ / pre-auth
 * キュー満杯)。返った handle へは直ちに send してよい (楽観送信)。
 * リモート起因の失敗・終了 (RESP error / stream close / idle timeout) は
 * on_err で【最大 1 回】後報され、以後 handle は無効 (caller は send/close を
 * 呼ばない。close 不要 — core が解放済み)。caller 起点の終了は close。
 *
 * 【callback 抑止契約 — UAF 防止の要】
 *   - close が return した後、その session への on_rx / on_err は【二度と】
 *     呼ばれない (close は callback detach を同期的に完了する)。
 *   - on_err / on_rx の dispatch 中に close が再入した場合も同様 (core は
 *     session を closing state にして以降の user callback を抑止する)。
 *   - 遅延イベント (close 直後に届く RESP error / idle 満了 / stream close
 *     notify) は core 内で握り潰す。 */
typedef void (*mq_udp_rx_fn)(const uint8_t *payload, size_t len, void *user);
typedef void (*mq_udp_err_fn)(void *session, mq_udp_err_t err, void *user);
typedef void *(*mq_udp_open_fn)(void *core, const uint8_t *host, size_t host_len,
                                mq_addr_type_t atype, uint16_t port, mq_udp_rx_fn on_rx,
                                mq_udp_err_fn on_err, void *user);
typedef void (*mq_udp_send_fn)(void *session, const uint8_t *payload, size_t len);
typedef void (*mq_udp_close_fn)(void *session);
#endif
