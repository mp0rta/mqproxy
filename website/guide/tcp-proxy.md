# TCP Proxy

The default mode. A TCP flow arriving at the client opens a new MPQUIC **bidirectional stream**: one TCP flow becomes one MPQUIC stream, spread across all bound paths. mqproxy does **not** terminate TLS here — for HTTPS, TLS stays end-to-end between the application and the origin, and only the WAN segment between mqproxy-client and mqproxy-server is carried over MPQUIC.

```text
Application (curl / SDK / app)
  │  TCP via SOCKS5 / HTTP CONNECT
  ▼
mqproxy-client ──────────────── MPQUIC (multipath) ──────────────► mqproxy-server
  │  CONNECT_TCP(host:port)        1 TCP flow = 1 bidi stream         │  dial host:port
  │                                spread across paths                ▼
  └─ bidirectional byte relay ◄─────────────────────────────────► Origin server
```

The stream begins with a `CONNECT_TCP_REQUEST` (SOCKS5-style address types); the server dials the target and replies `CONNECT_TCP_RESPONSE`, after which the same stream relays raw bytes in both directions. Connection-level authentication happens once on a control stream before any flow is opened.

## Two local ingresses

The client exposes the TCP proxy through either (or both) of:

- **SOCKS5** (`--socks5 <ip:port>`) — TCP `CONNECT`. The same listener also serves SOCKS5 UDP `ASSOCIATE` (see [UDP Relay](./udp-relay)).
- **HTTP CONNECT** (`--http-connect <ip:port>`) — used via `curl --proxy http://<ip:port> …`.

## Quick start

```bash
# Server — listens for MPQUIC on UDP :4433, uses the bundled test cert by default.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# Client — connects to the server, exposes a local SOCKS5 listener on :1080.
./build/mqproxy client \
  --server 127.0.0.1:4433 \
  --token  secret123 \
  --socks5 127.0.0.1:1080
```

Send traffic through the SOCKS5 ingress:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Or expose an HTTP CONNECT ingress and use it as a proxy:

```bash
./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --http-connect 127.0.0.1:3128

curl --proxy http://127.0.0.1:3128 https://example.com/
```

## Multipath aggregation

Repeat `--path` to bind additional local IPs as MPQUIC paths; each TCP flow's stream is then aggregated across them:

```bash
./build/mqproxy client \
  --server <server-ip>:4433 --token secret123 \
  --socks5 127.0.0.1:1080 \
  --path 192.168.1.50 \
  --path 10.20.0.30
```

See the [Options Reference](/reference/options#tcp-proxy-mode) for the full flag list. TLS stays end-to-end in this mode — to terminate and inspect it instead, see [TLS MITM](./tls-mitm).
