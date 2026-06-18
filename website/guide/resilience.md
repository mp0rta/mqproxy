# Resilience: Reconnect and Keepalive

The client automatically re-establishes its MPQUIC tunnel after a transient loss. On disconnect it enters an exponential back-off retry loop (capped at `--reconnect-max-backoff`, jittered to avoid thundering herds) and retries indefinitely until the tunnel comes back — with no process restart and without touching the local SOCKS5, HTTP CONNECT, or gateway listeners. An idle tunnel is kept alive by periodic QUIC PINGs (`--keepalive-idle`). Reconnect is enabled by default and can be disabled with `--no-reconnect`.

::: warning Limitation
Flows that are in flight at the moment of a total connection loss are failed — they are not resurrected after recovery. New flows opened after the tunnel is back work automatically.
:::

See the [Options Reference](/reference/options#common-flags-all-modes) for the client flags `--reconnect` / `--no-reconnect`, `--reconnect-max-backoff`, and `--keepalive-idle`.
