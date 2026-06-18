# Observability

Pass `--qlog <dir>` to either side to emit xquic qlog. Per-path byte counts confirm that within-stream multipath is actually splitting a flow across paths — the key signal that aggregation is working. (xquic must be built with `XQC_ENABLE_EVENT_LOG=ON`, which `scripts/build-xquic.sh` does.)

## Metrics

- `--metrics-interval <sec>` periodically logs per-path stats as `mq.conn` / `mq.path` logfmt lines. On the server it logs the most-recently-accepted TCP and gateway connection; on the client it logs the proxy connection (and the gateway connection when `--gateway` is set).
- `--request-metrics` (server, gateway) emits one `mq.req` logfmt line per gateway request (method/status/target/ttfb/origin_protocol/cache/…). Opt-in and independent of `--metrics-interval`.

## Testing

After building, run the bundled test suite:

```bash
ctest --test-dir build --output-on-failure
```

It covers wire framing, the relay/flow state machine, ingress parsing, the gateway request path, and the TLS MITM crypto core, alongside end-to-end scripts for multipath aggregation, the full gateway chain, UDP relay, and transparent capture. Tests that need root or `NET_ADMIN` (the multipath and transparent-capture end-to-end runs) skip automatically when run unprivileged.
