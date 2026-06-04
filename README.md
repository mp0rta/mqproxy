# mqproxy

A **multipath application proxy/accelerator** built on [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/), using a [fork of XQUIC](https://github.com/mp0rta/xquic). mqproxy maps application flows directly onto MPQUIC primitives — one TCP flow becomes one MPQUIC stream, one HTTP request becomes one H3 stream over MPQUIC, one UDP session becomes MPQUIC DATAGRAMs — so that applications get path diversity, seamless failover, and **bandwidth aggregation** without implementing MPQUIC themselves.

> **Status: Phase 2 (HTTP Request Execution Gateway) — implemented.** On top of Phase 1's TCP proxy (SOCKS5 / HTTP CONNECT → MPQUIC → origin, ~2× aggregation over two shaped paths), mqproxy now executes delegated HTTP requests: a local `POST /_mqproxy/fetch` API carries each request as one H3 stream over MPQUIC to the server, which runs it against the origin via libcurl (h2→h1, TLS verification always on). Validated end-to-end including 2-path aggregation. Phases 3–7 (UDP relay, …) are on the [roadmap](#roadmap).

mqproxy is the L4/L7 sibling of [mqvpn](https://github.com/mp0rta/mqvpn): where mqvpn is a standards-based L3 VPN that carries IP packets in QUIC DATAGRAMs (MASQUE CONNECT-IP), mqproxy works at the application-flow layer and is **MPQUIC-native**.

| | mqvpn | mqproxy |
|---|---|---|
| Layer | L3 | L4 / L7 |
| Data plane | QUIC DATAGRAM | QUIC STREAM + DATAGRAM |
| Model | IP packet tunnel | Application-flow proxy |
| Strength | IP transparency, standards-oriented | MPQUIC-native flow mapping |

The two are complementary and can coexist: run mqvpn for whole-device transparency while delegating specific high-priority transfers to mqproxy.

## Why MPQUIC-native?

Because a QUIC **stream** is reassembled by offset, the STREAM frames of a single stream can be spread across multiple paths while correctness is preserved. So a single large download/upload — carried as one MPQUIC stream — gets *within-stream* multipath aggregation. This is a structural advantage over carrying inner traffic in DATAGRAMs (the mqvpn/MASQUE path), where flow pinning forces a single path and not-pinning risks inner-QUIC reordering.

## Operating Modes

| Mode | Mapping | Status |
|---|---|---|
| **TCP Proxy** | 1 TCP flow → 1 MPQUIC bidi stream | ✅ Phase 1 |
| **HTTP Request Execution Gateway** | 1 HTTP request → 1 H3 stream over MPQUIC | ✅ Phase 2 |
| UDP Relay | 1 UDP session → MPQUIC DATAGRAM | 🚧 Phase 3 |
| TLS MITM Ingress | terminate TLS → feed the Gateway | 🚧 Phase 7, optional |

TCP Proxy Mode does **not** terminate TLS: for HTTPS, TLS stays end-to-end between the application and the origin. Only the WAN segment between mqproxy-client and mqproxy-server is carried over MPQUIC.

## How It Works

```text
Application (curl / SDK / app)
  │  TCP via SOCKS5 / HTTP CONNECT
  ▼
mqproxy-client ──────────────── MPQUIC (multipath) ──────────────► mqproxy-server
  │  CONNECT_TCP(host:port)        1 TCP flow = 1 bidi stream         │  dial host:port
  │                                spread across paths                ▼
  └─ bidirectional byte relay ◄─────────────────────────────────► Origin server
```

A TCP flow arriving at the client (via SOCKS5 or HTTP CONNECT) opens a new MPQUIC bidirectional stream. The stream begins with a `CONNECT_TCP_REQUEST` (SOCKS5-style address types); the server dials the target and replies `CONNECT_TCP_RESPONSE`, after which the same stream relays raw bytes in both directions. Connection-level authentication happens once on a control stream before any flow is opened.

### HTTP Request Execution Gateway

```text
Application (curl / SDK)
  │  POST /_mqproxy/fetch  (X-Mq-Auth / X-Mq-Target / X-Mq-Method + raw body)
  ▼
mqproxy-client ──────── HTTP/3 over MPQUIC (ALPN h3) ────────► mqproxy-server
     1 HTTP request = 1 H3 request stream = 1 MPQUIC stream       │  libcurl (h2→h1,
     spread across paths                                          │  TLS verify ON)
                                                                  ▼
                                                              Origin server
```

Instead of tunneling opaque bytes, the gateway **executes delegated HTTP requests**: the client validates `X-Mq-*` headers, maps the request onto a standard H3 request stream (QPACK, trailers and stream management come from the H3 stack — no custom HTTP framing on the wire), and the server authenticates each request (`X-Mq-Auth`, per-request), strips the `X-Mq-*` controls, and runs the request against the origin with full TLS verification. Errors map to HTTP statuses (DNS failure → 502, connect timeout → 504, bad token → 403, …) and responses carry an `X-Mq-Origin-Protocol` diagnostic header. Because each request is one MPQUIC stream, large downloads *and uploads* get within-stream multipath aggregation.

## Building from source

**Requirements:** `cmake`, `make`, a C11 compiler, `git`, `libevent`, `libcurl` dev headers (e.g. `libcurl4-openssl-dev` — the gateway's origin client), and `golang` (BoringSSL's build needs Go). Network access is required on first build (BoringSSL is cloned).

```bash
# 1. Clone with the xquic submodule
git clone --recursive https://github.com/mp0rta/mqproxy.git
cd mqproxy
# (if you cloned without --recursive: git submodule update --init --recursive)

# 2. Build the in-tree xquic (BoringSSL + xquic, with qlog enabled)
#    Produces third_party/xquic/build/libxquic.so. Pins BoringSSL to a known commit.
./scripts/build-xquic.sh

# 3. Configure + build mqproxy against that xquic
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build"
cmake --build build -j"$(nproc)"

# The binary is at build/mqproxy
./build/mqproxy --help
```

For an AddressSanitizer/UBSan build (used in development and CI), configure with `-DMQPROXY_SANITIZE=ON` instead of `-DCMAKE_BUILD_TYPE=Release`.

## Quick Start

Run a server and a client locally, then send TCP traffic through the client's SOCKS5 ingress.

```bash
# Server — listens for MPQUIC on UDP :4433, uses the bundled test cert by default.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# Client — connects to the server, exposes a local SOCKS5 listener on :1080.
./build/mqproxy client \
  --server 127.0.0.1:4433 \
  --token  secret123 \
  --socks5 127.0.0.1:1080
```

```bash
# Send traffic through the proxy
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

**Multipath** — bind additional local IPs as MPQUIC paths (e.g. WiFi + LTE) by repeating `--path`; the stream is then aggregated across them:

```bash
./build/mqproxy client \
  --server <server-ip>:4433 --token secret123 \
  --socks5 127.0.0.1:1080 \
  --path 192.168.1.50 \
  --path 10.20.0.30
```

You can also expose an HTTP CONNECT ingress with `--http-connect <ip:port>` (use it via `curl --proxy http://127.0.0.1:<port> https://...`).

### HTTP Gateway quick start

The gateway is enabled on the server by default. On the client, add `--gateway` (works with or without `--socks5`):

```bash
./build/mqproxy client \
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

### Server options

| Flag | Description |
|---|---|
| `--listen <ip:port>` | UDP address to accept MPQUIC connections on (required) |
| `--token <token>` | Shared auth token clients must present (required) |
| `--cert <path>` / `--key <path>` | TLS cert/key (PEM); defaults to the bundled test cert |
| `--origin-ca <pem>` | Extra CA bundle for origin TLS verification (private CAs / tests); verification itself is always on |
| `--no-gateway` | Disable the HTTP gateway (enabled by default) |
| `--qlog <dir>` | Write xquic qlog to `<dir>/server.qlog` |

### Client options

| Flag | Description |
|---|---|
| `--server <ip:port>` | UDP address of the mqproxy server (required) |
| `--token <token>` | Shared auth token (required) |
| `--socks5 <ip:port>` | Local TCP address for the SOCKS5 ingress |
| `--http-connect <ip:port>` | Local TCP address for the HTTP CONNECT ingress |
| `--gateway <ip:port>` | Local TCP address for the HTTP gateway fetch API (`POST /_mqproxy/fetch`) |
| `--path <local ip>` | Local IP to bind a path to (repeatable) |
| `--client-id <id>` | Client identifier sent at auth |
| `--qlog <dir>` | Write xquic qlog to `<dir>/client.qlog` |

> The bundled test certificate is for local testing only. For real deployments, pass your own `--cert`/`--key` and a strong `--token`.

## Testing

```bash
ctest --test-dir build --output-on-failure
```

The unit/integration suite covers wire framing, the relay/flow state machine, ingress parsing, transport setup, the H3 wrapper (a socket-free "fabric" round-trip test), the HTTP/1.1 parser and header policy at the gateway trust boundary, and both gateway halves against in-process fakes. Two end-to-end scripts complete the picture:

- `tests/integration/e2e_multipath.sh` — TCP-proxy multipath aggregation benchmark (`tc`/`netem`); requires `NET_ADMIN` and **self-skips** otherwise.
- `tests/integration/e2e_gateway.sh` — full gateway chain against a local TLS origin: 8 MB download/upload byte-exact, the whole error matrix (403/400/502/504), and a 2-path aggregation smoke (the 2-path case needs `NET_ADMIN`; the rest runs unprivileged).

## Observability

Pass `--qlog <dir>` to either side to emit xquic qlog. Per-path byte counts confirm that within-stream multipath is actually splitting a flow across paths — the key signal that aggregation is working. (xquic must be built with `XQC_ENABLE_EVENT_LOG=ON`, which `scripts/build-xquic.sh` does.)

## Roadmap

| Phase | Scope |
|---|---|
| **1. TCP Proxy MVP** | ✅ MPQUIC client/server, auth, aggregate-BDP transport sizing, SOCKS5 / HTTP CONNECT, CONNECT_TCP, EAGAIN-safe relay |
| **2. HTTP Request Execution Gateway** | ✅ `POST /_mqproxy/fetch` (header + raw body), H3-over-MPQUIC tunnel (ALPN `h3`), libcurl origin client (h2→h1, h3-ready), per-request auth, header policy, error mapping, up/download |
| 3. UDP Relay | UDP session table, MPQUIC DATAGRAM send/recv, DNS / non-QUIC UDP |
| 4. Controlled Web App Integration | mqcurl / SDK, browser upload/download UI, progress, request policy, CORS |
| 5. Production Hardening | TCP half-close, reconnect/keepalive, metrics, masquerade mode, qlog, flow-control tuning, scheduler hints |
| 6. Advanced HTTP Gateway | origin protocol selection, connection pooling, header filtering, cache integration |
| 7. TLS MITM Ingress (optional) | managed-device CA, dynamic certs, H3 termination, Do-Not-Inspect policy |

## Security Model

mqproxy uses a **trusted proxy** model: mqproxy-client, mqproxy-server, and the MPQUIC connection between them are trusted. In TCP Proxy Mode, application↔origin TLS is preserved end-to-end (mqproxy never sees plaintext). The HTTP Request Execution Gateway is an explicit delegation model — the client delegates HTTP request execution to a trusted gateway that establishes (and always verifies) the origin TLS — not a transparent MITM. Gateway requests are authenticated individually (`X-Mq-Auth`, per-request); `Authorization` is reserved for the origin and forwarded, while `Cookie` and `X-Mq-*` never leave the gateway. TLS MITM ingress is a separate, opt-in, last-phase feature for managed/enterprise devices.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) (Alibaba) — the QUIC/MPQUIC transport, via the [mp0rta fork](https://github.com/mp0rta/xquic).
- [BoringSSL](https://boringssl.googlesource.com/boringssl) — TLS backend.
