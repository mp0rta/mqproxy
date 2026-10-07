# Observability

Pass `--qlog <dir>` to either side to emit xquic qlog. Per-path byte counts confirm that within-stream multipath is actually splitting a flow across paths — the key signal that aggregation is working.

## Metrics

- `--metrics-interval <sec>` periodically logs per-path stats as `mq.conn` / `mq.path` logfmt lines. On the server it logs the most-recently-accepted TCP and gateway connection; on the client it logs the proxy connection (and the gateway connection when `--gateway` is set).
- With `--mitm`, the client also logs a `mq.mitm` line on every tick and at shutdown: live MITM connections and streams, how many connections were terminated versus relayed opaquely (per reason), TLS/h2 failures, leaf-certificate cache hits and misses, and request counts. See the [TLS MITM guide](/guide/tls-mitm#observability) for every field.
- `--request-metrics` (server, gateway) emits one `mq.req` logfmt line per gateway request (method/status/target/ttfb/origin_protocol/cache/…). Opt-in and independent of `--metrics-interval`.

## Testing

Run the test suite from the repository root:

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p mqproxy --bins --examples
bash tests/test_cli_help.sh target/release/mqproxy
bash tests/integration/e2e_udp.sh     # also e2e_{gateway,multipath,tproxy,mitm_h2,...}.sh
```

The cargo tests cover wire framing, the relay/flow state machine, ingress parsing, the gateway request path, and TLS MITM. The `tests/integration/e2e_*.sh` scripts run end to end: multipath aggregation, the full gateway chain, UDP relay, transparent capture and MITM. Scripts that need root or `NET_ADMIN` skip themselves when run unprivileged.
