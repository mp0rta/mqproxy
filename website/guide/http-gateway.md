# HTTP Request Execution Gateway

```text
Application (curl / SDK)
  │  POST /_mqproxy/fetch  (X-Mq-Auth / X-Mq-Target / X-Mq-Method + raw body)
  ▼
mqproxy-client ──────── HTTP/3 over MPQUIC (ALPN h3) ────────► mqproxy-server
     1 HTTP request = 1 H3 request stream = 1 MPQUIC stream       │  hyper + rustls
     spread across paths                                          │  (h2 or HTTP/1.1,
                                                                  │   TLS verify ON)
                                                                  ▼
                                                              Origin server
```

Instead of tunneling opaque bytes, the gateway **executes delegated HTTP requests**: the client validates `X-Mq-*` headers, maps the request onto a standard H3 request stream (QPACK, trailers and stream management come from the H3 stack — no custom HTTP framing on the wire), and the server authenticates each request (`X-Mq-Auth`, per-request), strips the `X-Mq-*` controls, and runs the request against the origin with full TLS verification. Errors map to HTTP statuses (DNS failure → 502, connect timeout → 504, bad token → 403, …) and responses carry an `X-Mq-Origin-Protocol` diagnostic header. Because each request is one MPQUIC stream, large downloads *and uploads* get within-stream multipath aggregation.

## Per-request controls

Per-request `X-Mq-*` controls let a caller opt into gateway features without changing the API:

- `X-Mq-Origin-Protocol`: `h1` forces HTTP/1.1; `h2`, `h3` or no header lets the server negotiate h2 or HTTP/1.1 via ALPN (there is no HTTP/3 origin client). Any other value → `400` with `x-mq-error: bad-origin-protocol`.
- `X-Mq-Accept-Encoding` requests download compression.
- `X-Mq-Forward-Cookie` forwards the `Cookie` header upstream (otherwise withheld).
- `X-Mq-Cache` is still validated (a malformed value → `400` with `x-mq-error: bad-cache-ttl`), but a valid value has no effect: the origin response cache was removed.

The server also pools and reuses origin connections across requests.

## Quick start

The gateway is enabled on the server by default. On the client, add `--gateway` (works with or without `--socks5`):

```bash
./target/release/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --gateway 127.0.0.1:8080

# Delegate a download (any HTTP method via X-Mq-Method; default GET)
curl -X POST http://127.0.0.1:8080/_mqproxy/fetch \
  -H "X-Mq-Auth: Bearer secret123" \
  -H "X-Mq-Target: https://example.com/large.bin" \
  -o large.bin

# Delegate an upload
curl -X POST http://127.0.0.1:8080/_mqproxy/fetch \
  -H "X-Mq-Auth: Bearer secret123" \
  -H "X-Mq-Target: https://example.com/upload" \
  -H "X-Mq-Method: PUT" \
  --data-binary @large.bin
```

`--path` works the same way here: the gateway's MPQUIC connection aggregates each request across all bound paths.

See the [Options Reference](/reference/options#http-gateway-mode) for server-side flags (`--no-gateway`, `--origin-ca`, `--request-metrics`, `--masquerade`).
