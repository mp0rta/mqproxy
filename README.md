# mqproxy

A **multipath application proxy/accelerator** built on [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/), using a [fork of XQUIC](https://github.com/mp0rta/xquic). mqproxy maps application flows directly onto MPQUIC primitives — one TCP flow becomes one MPQUIC stream, one HTTP request becomes one H3 stream over MPQUIC, one UDP session becomes MPQUIC DATAGRAMs — so that applications get path diversity, seamless failover, and **bandwidth aggregation** without implementing MPQUIC themselves.

> **Status: production-hardening complete; TLS MITM (Phase 7) is the next milestone.** Phase 1's TCP proxy (SOCKS5 / HTTP CONNECT → MPQUIC → origin, ~2× aggregation over two shaped paths), Phase 2's HTTP Request Execution Gateway (delegated `POST /_mqproxy/fetch` requests carried as H3 streams over MPQUIC, run against origins via libcurl with TLS verification always on), and Phase 3's UDP relay (SOCKS5 UDP ASSOCIATE → session-tagged MPQUIC DATAGRAMs → connected UDP socket, with fragmentation/reassembly and idle-timeout teardown) are all implemented and validated end-to-end including 2-path aggregation. Phase 5 hardening is largely done — reconnect/keepalive, per-path `mq.path` + per-request `mq.req` metrics, congestion-control and multipath-scheduler selection, a pre-auth connection cap, masquerade mode, INI config files, and systemd packaging — and Phase 6's advanced gateway (origin-protocol selection, connection pooling, header filtering, download compression, response caching) is complete. The codebase is fuzzed (libFuzzer) and CodeQL-scanned in CI. Phase 7 (optional TLS MITM ingress) is on the [roadmap](#roadmap).

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
| **UDP Relay** | 1 UDP session → MPQUIC DATAGRAMs | ✅ Phase 3 |
| **Transparent TCP Capture** | kernel-redirected TCP → opaque MPQUIC stream | ✅ Phase 7 Slice 0+1 |
| TLS MITM Ingress | terminate TLS → feed the Gateway | 🚧 Phase 7 Slice 2+3, optional |

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

Per-request `X-Mq-*` controls let a caller opt into gateway features without changing the API: `X-Mq-Origin-Protocol` pins the upstream HTTP version (`h1`/`h2`/`h3`), `X-Mq-Accept-Encoding` requests download compression, `X-Mq-Forward-Cookie` forwards the `Cookie` header upstream (otherwise withheld), and `X-Mq-Cache` opts the response into the in-memory origin cache (`--cache-max-bytes`). The server also pools and reuses origin connections across requests.

### UDP Relay

```text
UDP app (DNS / game / VoIP / …)
  │  SOCKS5 UDP ASSOCIATE
  ▼
mqproxy-client ──────── MPQUIC DATAGRAMs (multipath) ────────► mqproxy-server
     1 UDP session = a bidi signalling stream + DATAGRAMs        │  connected
     carrying session_id-tagged packets                          │  UDP socket
                                                                 ▼
                                                             UDP target
```

UDP relay carries non-QUIC UDP traffic (DNS, NTP, game, VoIP, app-specific UDP) over MPQUIC DATAGRAMs. The ingress is **SOCKS5 UDP ASSOCIATE** (RFC 1928 §7) on the same `--socks5` listener used for TCP. For each target the client opens a small bidi signalling stream (`UDP_SESSION_OPEN`/`RESP`, multiplexed alongside TCP on the one `mqproxy-tcp/1` connection), then sends packets as DATAGRAMs tagged with a session id; the server keeps a connected UDP socket per session and relays both ways. Packets larger than the path MTU are fragmented and reassembled (4-slot LRU, no retransmission — UDP stays lossy). Sessions are torn down on idle timeout (server-driven, `--udp-idle-timeout`), on stream close, or when the SOCKS5 control connection drops. The server advertises the capability at auth and can refuse all UDP with `--no-udp`. UDP relay rides the `mqproxy-tcp/1` connection, so a client running `--gateway` only (H3 connection) does not get it.

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

### UDP relay quick start

UDP relay is exposed on the **same `--socks5` listener** — any SOCKS5 client that speaks UDP ASSOCIATE can use it. The server advertises the capability at auth; pass `--udp-idle-timeout <sec>` to tune session lifetime, or `--no-udp` to refuse UDP entirely.

```bash
# Server (UDP relay on by default; 30s idle timeout shown)
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --udp-idle-timeout 30

# Client — the SOCKS5 listener handles both TCP and UDP
./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --socks5 127.0.0.1:1080
```

`curl` does not speak SOCKS5 UDP ASSOCIATE, so use a UDP-capable SOCKS5 client. The repo ships `udpsocks`, a minimal test client (built by the test suite), which is handy for a quick check:

```bash
# Relay a UDP packet to a target through the client's SOCKS5 listener
./build/udpsocks --proxy 127.0.0.1:1080 --target 8.8.8.8:53 --send 32 --count 1
```

### Transparent capture quick start

Transparent capture redirects TCP connections at the kernel level directly into mqproxy without any application changes — no SOCKS5 configuration, no proxy settings, no app awareness. Each captured connection is relayed **opaquely** (byte-for-byte, without decryption) over the MPQUIC tunnel as a single stream, giving flow-level multipath aggregation. End-to-end TLS is fully preserved between the application and the origin; **mqproxy never sees plaintext in this slice** (TLS MITM is a separate future phase).

> **Linux + IPv4 only** (v1). The end-to-end test (`e2e_tproxy`) requires root/`NET_ADMIN` and self-skips otherwise.

Two kernel capture mechanisms are supported:

- **`redirect` (default)** — uses `nft nat OUTPUT` (REDIRECT target). Captures the *local machine's own outbound* TCP. Does not need `IP_TRANSPARENT` on the socket. This is the right mode when mqproxy and the apps being accelerated run on the same host.
- **`tproxy`** — uses `nft mangle PREROUTING` (TPROXY target) with `IP_TRANSPARENT` on the listening socket. Captures *forwarded* traffic from downstream LAN hosts, as used in an OMR router deployment. Requires `fwmark` + a policy-routing table so the local TCP stack's reply packets are routed back out the right interface.

**Single-host quickstart (redirect mode, `--setup-redirect`):**

```bash
# Server — no change from the regular config.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# Client — transparent listener on :12443; self-installs nft rules (needs root).
sudo ./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --tproxy 127.0.0.1:12443 \
  --setup-redirect

# Any app on this host connecting outbound to TCP :443 (or whatever the nft rule matches)
# is now transparently captured, aggregated over MPQUIC, and forwarded to the origin.
# No curl --socks5 / --proxy flags needed.
curl https://example.com/
```

`--setup-redirect` tells mqproxy to install the nft rules on start and remove them on exit. It needs `root` or `CAP_NET_ADMIN`. Without it, you install the firewall rules yourself (or let OMR manage them) and just point the traffic at the listener.

**OMR/router deployment (tproxy mode):**

Under OMR, leave `--setup-redirect` OFF. OMR owns the firewall rules and places the `TPROXY` target in `PREROUTING`; mqproxy just provides the listener:

```bash
sudo ./build/mqproxy client \
  --server <server>:4433 --token secret123 \
  --tproxy 0.0.0.0:12443 \
  --tproxy-mode tproxy \
  --tproxy-fwmark 1 \
  --tproxy-table 100
  # no --setup-redirect — OMR owns the rules
```

**Loop-avoidance and security notes:**

- `--tproxy-uid <uid>` marks one UID whose *own outbound* traffic is exempt from redirection (so mqproxy's own connections to the server are not re-captured into itself). Defaults to `geteuid()` of the process. Running as a dedicated non-root service account is recommended; using uid 0 would exempt all root traffic, which is wider than intended.
- This slice is **opaque**: mqproxy relays raw TLS bytes and never decrypts them. Applications with certificate pinning continue to work. TLS MITM (cert forge, TLS termination) is the next slice (Phase 7 Slice 2+3) and is off by default even when built.

### Resilience: reconnect and keepalive

The client automatically re-establishes its MPQUIC tunnel after a transient loss. On disconnect it enters an exponential back-off retry loop (capped at `--reconnect-max-backoff`, jittered to avoid thundering herds) and retries indefinitely until the tunnel comes back — with no process restart and without touching the local SOCKS5, HTTP CONNECT, or gateway listeners. An idle tunnel is kept alive by periodic QUIC PINGs (`--keepalive-idle`). Reconnect is enabled by default and can be disabled with `--no-reconnect`.

> **Limitation:** flows that are in flight at the moment of a total connection loss are failed — they are not resurrected after recovery. New flows opened after the tunnel is back work automatically.

## Configuration file

Instead of a long command line, either subcommand can read its settings from a WireGuard-style INI file with `--config <path>`. This is the intended way to run mqproxy as a managed service (one config file per instance) and keeps the shared token out of `ps` / `/proc/<pid>/cmdline`.

```ini
# /etc/mqproxy/edge1.conf   (chmod 0600 — keeps the token private)
[Interface]
Listen   = 0.0.0.0:4433
MaxConns = 64

[TLS]
Cert = /etc/mqproxy/tls/edge1.pem
Key  = /etc/mqproxy/tls/edge1.key

[Auth]
Key = your-shared-token

[Multipath]
CC        = bbr
Scheduler = minrtt
```

```bash
mqproxy server --config /etc/mqproxy/edge1.conf
```

- **Precedence:** built-in defaults < config file < CLI flags. A flag passed alongside `--config` overrides the file, so you can pin steady state in the file and override transiently on the command line (e.g. add `--qlog /tmp/dbg` for one debug run).
- **Format:** sectioned INI, CamelCase keys (case-insensitive), `#` and `;` comments **on their own line** (an inline `# …` after a value is read as part of the value, not stripped), booleans are `true`/`yes`/`1`. `Path` may be repeated for multipath. Unknown keys and bad values warn and are skipped (the default stands); a missing `--config` file is a fatal error.
- **Secrets:** the token lives in `[Auth] Key`. mqproxy warns at startup if the file is group/world-readable — `chmod 0600` it.

**Key reference** — config keys map to the CLI flags in the [Options reference](#options-reference):

| Section | Server keys | Client keys |
|---|---|---|
| `[Interface]` | `Listen`, `MaxConns` | `Reconnect`, `KeepaliveIdle`, `ReconnectMaxBackoff` |
| `[Server]` | — | `Address`, `ClientId` |
| `[TLS]` | `Cert`, `Key` | — |
| `[Auth]` | `Key` (token) | `Key` (token) |
| `[Multipath]` | `CC`, `Scheduler` | `CC`, `Scheduler`, `Path` (repeatable) |
| `[Ingress]` | — | `Socks5`, `HttpConnect`, `Gateway`, `TProxy`, `Mode`, `Fwmark`, `Table`, `SetupRedirect`, `SkipUid` |
| `[Gateway]` | `Enabled`, `Masquerade`, `OriginCA`, `CacheMaxBytes` | — |
| `[UDP]` | `Enabled`, `IdleTimeout` | — |
| `[Metrics]` | `Interval`, `PerRequest` | `Interval` |
| `[Log]` | `QLog` | `QLog` |

See [`server.conf.example`](server.conf.example) and [`client.conf.example`](client.conf.example) for complete starting points.

## Install as a systemd service

mqproxy ships systemd template units so each instance runs as a hardened, unprivileged service. Build a self-contained binary (xquic + BoringSSL statically linked, so the installed binary has no non-standard runtime deps) and install it:

```bash
# -DMQPROXY_STATIC_XQUIC statically links xquic+BoringSSL; the install prefix is
# baked into the unit ExecStart at *configure* time, so set it now (not at --install).
cmake -S . -B build \
      -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build" \
      -DMQPROXY_STATIC_XQUIC=ON -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build --target mqproxy_cli -j
sudo cmake --install build              # → /usr/bin/mqproxy, units, sysusers.d, tmpfiles.d
```

Create the `mqproxy` system user and its directories (declared by the bundled `sysusers.d`/`tmpfiles.d`):

```bash
sudo systemd-sysusers
sudo systemd-tmpfiles --create          # creates /etc/mqproxy (0750 mqproxy:mqproxy)
```

Drop a per-instance config and lock it down (the service reads it as user `mqproxy`):

```bash
sudoedit /etc/mqproxy/edge1.conf        # see the [server config](#configuration-file) above
sudo chown mqproxy:mqproxy /etc/mqproxy/edge1.conf
sudo chmod 0600 /etc/mqproxy/edge1.conf # 0600 keeps the token-permission warning quiet
```

Enable and start the instance — the part after `@` is the config basename:

```bash
sudo systemctl enable --now mqproxy-server@edge1     # → /etc/mqproxy/edge1.conf
journalctl -u mqproxy-server@edge1 -f                # logs
```

The client side uses `mqproxy-client@<name>` the same way (`/etc/mqproxy/<name>.conf`).

**Notes:**
- **qlog:** to capture xquic qlog, set `[Log] QLog = /var/log/mqproxy` in the config. The unit's `LogsDirectory=` creates `/var/log/mqproxy`; `ProtectSystem=strict` blocks writing qlog anywhere else (except `PrivateTmp`). qlog stays off unless `QLog` is set.
- **Privileged ports:** the default `4433` needs no capabilities. To listen on a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` via `sudo systemctl edit mqproxy-server@edge1`.
- **TLS cert:** set `[TLS] Cert`/`Key` to paths the service can read (e.g. under `/etc/mqproxy`); the built-in test cert is not present in a packaged install.

## Options reference

Both binaries take a small set of **common flags** (connection, TLS, paths, metrics) that apply no matter which mode you run. Each operating mode then adds a few mode-specific flags — and crucially, a mode is *selected on the client* by which ingress flag you pass (`--socks5`, `--http-connect`, `--gateway`). The server simply offers all enabled capabilities; the client decides what to use.

The tables below are split: **common flags first**, then one block per mode. Within each mode, server- and client-side flags are listed separately.

### Common flags (all modes)

**Server** — `mqproxy server …`

| Flag | Description |
|---|---|
| `--listen <ip:port>` | **(required)** UDP address to accept MPQUIC connections on |
| `--token <token>` | **(required)** Shared auth token clients must present |
| `--cert <path>` / `--key <path>` | TLS cert/key (PEM); defaults to the bundled test cert |
| `--max-conns <N>` | Cap on simultaneous QUIC connections (default 16; `0` = unlimited). Excess inbound connections are refused (`CONNECTION_REFUSED`) — a pre-auth DoS guard. |
| `--cc <algo>` | Congestion control: `bbr` (default) \| `bbr2` \| `cubic` |
| `--scheduler <s>` | Multipath scheduler: `minrtt` (default) \| `backup` \| `wlb` |
| `--qlog <dir>` | Write xquic qlog to `<dir>/server.qlog` |
| `--metrics-interval <sec>` | Periodically log per-path stats (`mq.conn` / `mq.path` logfmt lines) every `<sec>`s (must be > 0; omit to disable). Logs the most-recently-accepted TCP and gateway conn. |

**Client** — `mqproxy client …`

| Flag | Description |
|---|---|
| `--server <ip:port>` | **(required)** UDP address of the mqproxy server |
| `--token <token>` | **(required)** Shared auth token |
| `--path <local ip>` | Local IP to bind a path to — **repeat for multipath aggregation** (e.g. WiFi + LTE) |
| `--client-id <id>` | Client identifier sent at auth |
| `--cc <algo>` | Congestion control: `bbr` (default) \| `bbr2` \| `cubic` |
| `--scheduler <s>` | Multipath scheduler: `minrtt` (default) \| `backup` \| `wlb` |
| `--qlog <dir>` | Write xquic qlog to `<dir>/client.qlog` |
| `--reconnect` / `--no-reconnect` | Auto-reconnect on tunnel loss (default: enabled) |
| `--reconnect-max-backoff <sec>` | Cap on exponential reconnect backoff in seconds (default 30; floored to 1) |
| `--keepalive-idle <sec>` | Send QUIC PINGs when idle for this many seconds (default 30; 0 = disable; values <15 have no additional effect since xquic's PING cadence is ~15 s) |
| `--metrics-interval <sec>` | Periodically log per-path stats (`mq.conn` / `mq.path` logfmt lines) every `<sec>`s (must be > 0; omit to disable). Logs the proxy conn (and the gateway conn when `--gateway` is set). |

> At least one client ingress flag (`--socks5`, `--http-connect`, or `--gateway`) is what actually puts the client to work — see the per-mode blocks below.

### TCP Proxy mode

*1 TCP flow → 1 MPQUIC bidi stream. TLS stays end-to-end between app and origin (no termination).*

**Server:** no mode-specific flags — TCP proxying is always available.

**Client**

| Flag | Description |
|---|---|
| `--socks5 <ip:port>` | Local SOCKS5 ingress (TCP CONNECT). Also serves UDP ASSOCIATE — see UDP Relay mode. |
| `--http-connect <ip:port>` | Local HTTP CONNECT ingress (use via `curl --proxy http://<ip:port> …`) |

### HTTP Gateway mode

*1 HTTP request → 1 H3 stream over MPQUIC; the server executes the delegated request against the origin. Enabled on the server by default.*

**Server**

| Flag | Description |
|---|---|
| `--no-gateway` | **Disables HTTP Gateway mode for this server** (it is enabled by default). The TCP-proxy core keeps running; only the gateway origin bridge is turned off, so a client's `--gateway` ingress has nothing to talk to. |
| `--origin-ca <pem>` | Extra CA bundle for origin TLS verification (private CAs / tests); verification itself is always on |
| `--request-metrics` | Emit one `mq.req` logfmt line per gateway request (method/status/target/ttfb/origin_protocol/cache/…). Opt-in; off by default. Independent of `--metrics-interval`. |
| `--cache-max-bytes <N>` | In-memory origin response cache bounded to `N` bytes (`0` = off = default; e.g. `67108864` = 64 MiB). Opt-in per request via `X-Mq-Cache`. |
| `--masquerade` | Answer **unauthenticated** gateway requests with a bare `404` (no `X-Mq-*` headers), so probes/scanners see a generic HTTP/3 server instead of a fingerprintable `403 auth-failed`. Authenticated requests are unaffected. Gateway-only; off by default; recommended for internet-exposed servers. |

**Client**

| Flag | Description |
|---|---|
| `--gateway <ip:port>` | Local TCP address for the HTTP gateway fetch API (`POST /_mqproxy/fetch`). Works with or without `--socks5`. |

### UDP Relay mode

*1 UDP session → MPQUIC DATAGRAMs. Exposed on the same `--socks5` listener via SOCKS5 UDP ASSOCIATE; rides the `mqproxy-tcp/1` connection (a `--gateway`-only client does not get it).*

**Server**

| Flag | Description |
|---|---|
| `--no-udp` | **Disables UDP Relay mode entirely for this server** — the capability is not advertised at auth (clients see it as unavailable) and any session that is still attempted is refused. There is no client-side override. |
| `--udp-idle-timeout <sec>` | UDP session idle timeout (default 60); the effective value is `min(client request, this)` |

**Client**

| Flag | Description |
|---|---|
| `--socks5 <ip:port>` | Same listener as TCP Proxy mode — any SOCKS5 client speaking UDP ASSOCIATE uses it. No separate flag needed. |

### Transparent Capture mode

*Kernel-redirected TCP → opaque MPQUIC stream. No app config needed. Linux + IPv4 only (v1). TLS is preserved end-to-end (no termination in this slice).*

**Server:** no mode-specific flags — transparent capture is a client-side ingress mechanism; the server handles the resulting TCP streams exactly like SOCKS5-originated ones.

**Client**

| Flag | Description |
|---|---|
| `--tproxy <ip:port>` | Local TCP address for the transparent capture ingress (redirect or tproxy mode). Enables transparent capture; at least one of `--socks5`, `--http-connect`, `--gateway`, or `--tproxy` is required. |
| `--tproxy-mode redirect\|tproxy` | Kernel capture mechanism (default: `redirect`). `redirect` — `nft nat OUTPUT` REDIRECT target; captures the local machine's own outbound TCP; no `IP_TRANSPARENT` on the socket. `tproxy` — `nft mangle PREROUTING` TPROXY target; captures forwarded LAN traffic on a router/OMR; needs `CAP_NET_ADMIN` for `IP_TRANSPARENT`. |
| `--tproxy-fwmark <n>` | Packet mark for policy routing in tproxy mode (default: 1; tproxy mode only). |
| `--tproxy-table <n>` | IP routing table for tproxy reply routing (default: 100; tproxy mode only). |
| `--setup-redirect` | Install `nft`/`ip rule` firewall rules on start and remove them on exit (requires root or `CAP_NET_ADMIN`; off by default). For single-host self-contained use; leave OFF under OMR and let OMR manage the rules. |
| `--tproxy-uid <uid>` | UID whose outbound traffic is exempt from redirection (default: `geteuid()` of the process). Used for loop avoidance — mqproxy's own tunnel connections are not re-captured into itself. |

> The bundled test certificate is for local testing only. For real deployments, pass your own `--cert`/`--key` and a strong `--token`.

## Testing

```bash
ctest --test-dir build --output-on-failure
```

The unit/integration suite covers wire framing, the relay/flow state machine, ingress parsing, transport setup, the H3 wrapper (a socket-free "fabric" round-trip test), the HTTP/1.1 parser and header policy at the gateway trust boundary, and both gateway halves against in-process fakes. Two end-to-end scripts complete the picture:

- `tests/integration/e2e_multipath.sh` — TCP-proxy multipath aggregation benchmark (`tc`/`netem`); requires `NET_ADMIN` and **self-skips** otherwise.
- `tests/integration/e2e_gateway.sh` — full gateway chain against a local TLS origin: 8 MB download/upload byte-exact, the whole error matrix (403/400/502/504), and a 2-path aggregation smoke (the 2-path case needs `NET_ADMIN`; the rest runs unprivileged).
- `tests/integration/e2e_udp.sh` — UDP relay through SOCKS5 UDP ASSOCIATE against a local UDP echo (`udpsocks` + `udp_echo` helpers): byte-exact small + fragmented (3 KB) echo, concurrent sessions, idle-timeout re-OPEN, control-connection teardown, and a 2-path smoke (NET_ADMIN-gated; the rest runs unprivileged).
- `tests/integration/e2e_tproxy.sh` — transparent capture end-to-end: self-installs nft redirect rules, verifies a connection is intercepted and relayed opaquely through the MPQUIC tunnel. **Requires root/`NET_ADMIN` and self-skips otherwise.**

The wire codecs and ingress parsers (the untrusted-input attack surface) also have a standalone [libFuzzer](fuzz/) harness suite, replayed against a seed corpus in CI; the C/C++ sources are scanned by CodeQL (`security-extended`) on every push to `main`.

## Observability

Pass `--qlog <dir>` to either side to emit xquic qlog. Per-path byte counts confirm that within-stream multipath is actually splitting a flow across paths — the key signal that aggregation is working. (xquic must be built with `XQC_ENABLE_EVENT_LOG=ON`, which `scripts/build-xquic.sh` does.)

## Roadmap

| Phase | Scope |
|---|---|
| **1. TCP Proxy MVP** | ✅ MPQUIC client/server, auth, aggregate-BDP transport sizing, SOCKS5 / HTTP CONNECT, CONNECT_TCP, EAGAIN-safe relay |
| **2. HTTP Request Execution Gateway** | ✅ `POST /_mqproxy/fetch` (header + raw body), H3-over-MPQUIC tunnel (ALPN `h3`), libcurl origin client (h2→h1, h3-ready), per-request auth, header policy, error mapping, up/download |
| **3. UDP Relay** | ✅ SOCKS5 UDP ASSOCIATE ingress, per-session bidi signalling, MPQUIC DATAGRAM send/recv, fragmentation + LRU reassembly, idle timeout, DNS / non-QUIC UDP |
| ~~4. Controlled Web App Integration~~ | **Dropped** — the SDK speaks native MPQUIC directly (no gateway hop needed); the gateway's per-request value is realized via Phase 7 MITM, not a browser/Web-App ingress |
| **5. Production Hardening** | ✅ reconnect/keepalive, per-path `mq.path` + per-request `mq.req` metrics, CC/scheduler selection (`--cc`/`--scheduler`), pre-auth connection cap (`--max-conns`), masquerade mode, INI config files, systemd packaging, fuzzing + CodeQL. Remaining: TLS-error status mapping, flow-control/QoS tuning |
| **6. Advanced HTTP Gateway** | ✅ origin protocol selection (`X-Mq-Origin-Protocol`), connection pooling, header filtering, download compression (`X-Mq-Accept-Encoding`), cache integration (`X-Mq-Cache` / `--cache-max-bytes`) |
| **7. TLS MITM Ingress (optional)** | ✅ Slice 0+1: neutral gateway boundary refactor + transparent TCP capture (`--tproxy`, opaque relay, no MITM). 🚧 Slice 2+3: managed-device CA, dynamic cert forge, TLS termination, H2 adapter (nghttp2), Do-Not-Inspect policy |

## Security Model

mqproxy uses a **trusted proxy** model: mqproxy-client, mqproxy-server, and the MPQUIC connection between them are trusted. In TCP Proxy Mode and Transparent Capture mode, application↔origin TLS is preserved end-to-end (mqproxy never sees plaintext — it relays raw TLS bytes opaquely). Applications with certificate pinning continue to work. The HTTP Request Execution Gateway is an explicit delegation model — the client delegates HTTP request execution to a trusted gateway that establishes (and always verifies) the origin TLS — not a transparent MITM. Gateway requests are authenticated individually (`X-Mq-Auth`, per-request); `Authorization` is reserved for the origin and forwarded, while `Cookie` and `X-Mq-*` never leave the gateway. TLS MITM ingress is a separate, opt-in, phase-7 feature (Slice 2+3) for managed/enterprise devices where a CA is deployed to the device.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) (Alibaba) — the QUIC/MPQUIC transport, via the [mp0rta fork](https://github.com/mp0rta/xquic).
- [BoringSSL](https://boringssl.googlesource.com/boringssl) — TLS backend.
