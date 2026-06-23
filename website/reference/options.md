# Options Reference

Both binaries take a small set of **common flags** (connection, TLS, paths, metrics) that apply no matter which mode you run. Each operating mode then adds a few mode-specific flags — and crucially, a mode is *selected on the client* by which ingress flag you pass (`--socks5`, `--http-connect`, `--gateway`, `--tproxy`). The server simply offers all enabled capabilities; the client decides what to use.

The tables below are split: **common flags first**, then one block per mode. Within each mode, server- and client-side flags are listed separately.

## Common flags (all modes)

### Server — `mqproxy server …`

| Flag | Description |
|---|---|
| `--listen <ip:port>` | **(required)** UDP address to accept MPQUIC connections on |
| `--token <token>` | **(required)** Shared auth token clients must present |
| `--cert <path>` / `--key <path>` | **(required)** TLS cert/key (PEM). The repo ships a self-signed test cert under `tests/certs` for local use. |
| `--max-conns <N>` | Cap on simultaneous QUIC connections (default 16; `0` = unlimited). Excess inbound connections are refused (`CONNECTION_REFUSED`) — a pre-auth DoS guard. |
| `--cc <algo>` | Congestion control: `bbr` (default) \| `bbr2` \| `cubic` |
| `--scheduler <s>` | Multipath scheduler: `minrtt` (default) \| `backup` \| `wlb` |
| `--qlog <dir>` | Write xquic qlog to `<dir>/server.qlog` |
| `--metrics-interval <sec>` | Periodically log per-path stats (`mq.conn` / `mq.path` logfmt lines) every `<sec>`s (must be > 0; omit to disable). Logs the most-recently-accepted TCP and gateway conn. |

### Client — `mqproxy client …`

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
| `--reconnect-max-backoff <sec>` | Cap on exponential reconnect backoff in seconds (default 30; must be > 0) |
| `--keepalive-idle <sec>` | Send QUIC PINGs when idle for this many seconds (default 30; 0 = disable; values <15 have no additional effect since xquic's PING cadence is ~15 s) |
| `--metrics-interval <sec>` | Periodically log per-path stats (`mq.conn` / `mq.path` logfmt lines) every `<sec>`s (must be > 0; omit to disable). Logs the proxy conn (and the gateway conn when `--gateway` is set). |

::: tip
At least one client ingress flag (`--socks5`, `--http-connect`, `--gateway`, or `--tproxy`) is what actually puts the client to work — see the per-mode blocks below.
:::

## TCP Proxy mode

*1 TCP flow → 1 MPQUIC bidi stream. TLS stays end-to-end between app and origin (no termination).*

**Server:** no mode-specific flags — TCP proxying is always available.

**Client**

| Flag | Description |
|---|---|
| `--socks5 <ip:port>` | Local SOCKS5 ingress (TCP CONNECT). Also serves UDP ASSOCIATE — see UDP Relay mode. |
| `--http-connect <ip:port>` | Local HTTP CONNECT ingress (use via `curl --proxy http://<ip:port> …`) |

## HTTP Gateway mode

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

## UDP Relay mode

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

## Transparent Capture mode

*Kernel-redirected TCP → opaque MPQUIC stream. No app config needed. Linux + IPv4 only. TLS is preserved end-to-end by default; add `--mitm` to terminate and inspect it — see [TLS MITM mode](#tls-mitm-mode-client-only).*

**Server:** no mode-specific flags — transparent capture is a client-side ingress mechanism; the server handles the resulting TCP streams exactly like SOCKS5-originated ones.

**Client**

| Flag | Description |
|---|---|
| `--tproxy <ip:port>` | Local TCP address for the transparent capture ingress (redirect or tproxy mode). Enables transparent capture; at least one of `--socks5`, `--http-connect`, `--gateway`, or `--tproxy` is required. |
| `--tproxy-mode redirect\|tproxy` | Kernel capture mechanism (default: `redirect`). `redirect` — `nft nat OUTPUT` REDIRECT target; captures the local machine's own outbound TCP; no `IP_TRANSPARENT` on the socket. `tproxy` — `nft mangle PREROUTING` TPROXY target; captures forwarded LAN traffic on a router/gateway (standard Linux TPROXY; works with any policy-routing stack); needs `CAP_NET_ADMIN` for `IP_TRANSPARENT`. |
| `--tproxy-fwmark <n>` | Packet mark for policy routing in tproxy mode (default: 1; tproxy mode only). |
| `--tproxy-table <n>` | IP routing table for tproxy reply routing (default: 100; tproxy mode only). |
| `--tproxy-dport <port>` | TCP destination port the `--setup-redirect` rule captures (default: 443). |
| `--setup-redirect` | Install `nft`/`ip rule` firewall rules on start and remove them on exit (requires root or `CAP_NET_ADMIN`; off by default). For single-host self-contained use; leave OFF on a router/gateway and let the router stack manage the rules. |
| `--tproxy-uid <uid>` | UID whose outbound traffic is exempt from redirection (default: `geteuid()` of the process). Used for loop avoidance — mqproxy's own tunnel connections are not re-captured into itself. |

## TLS MITM mode (client-only)

*Terminate captured browser TLS with a forged per-host leaf, speak HTTP/2, and map each request onto the Gateway tunnel. Requires `--tproxy`; HTTP/2 only; off unless `--mitm`. See the [TLS MITM guide](/guide/tls-mitm) for the trust model and security posture.*

**Server:** no mode-specific flags — MITM is a client-side ingress mode; the resulting requests reach the server as ordinary Gateway requests.

**Client**

| Flag | Description |
|---|---|
| `--mitm` | Terminate TLS on the transparent-capture path (forge a leaf per SNI, speak h2, feed the Gateway tunnel) instead of relaying opaquely. **Requires `--tproxy`, `--ca-cert`, and `--ca-key`** and a binary built with the BoringSSL archives (`scripts/build-xquic.sh`); any of these missing is a fail-closed startup error. |
| `--ca-cert <pem>` | Signing CA certificate (PEM). The operator's CA must be trusted by the device. |
| `--ca-key <pem>` | Signing CA private key (PEM). Must be unencrypted and not group/world-readable; opened with `O_NOFOLLOW`/`O_CLOEXEC`. |
| `--ignore-host <host>` | Host to splice **opaquely** (bypass MITM — relay raw TLS so the origin's real cert reaches the client; for cert-pinned apps). **Repeatable.** Match is exact or leading-dot suffix on the normalized SNI. |
| `--ignore-hosts <a,b,c>` | Same as `--ignore-host` but a comma-separated list. CLI and `[Mitm] IgnoreHosts` config entries union. |

::: warning
The test certificate under `tests/certs` is for local testing only. For real deployments, pass your own `--cert`/`--key` and a strong `--token`.
:::
