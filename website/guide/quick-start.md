# Quick Start

Run a server and a client locally, then send TCP traffic through the client's SOCKS5 ingress.

```bash
# Server — listens for MPQUIC on UDP :4433. --cert/--key are required;
# the repo ships a self-signed test cert under tests/certs for local use.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --cert tests/certs/test.crt --key tests/certs/test.key

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

::: warning
The test certificate under `tests/certs` is for local testing only. For real deployments, pass your own `--cert`/`--key` and a strong `--token`.
:::

## Multipath aggregation

Bind additional local IPs as MPQUIC paths (e.g. WiFi + LTE) by repeating `--path`; the stream is then aggregated across them:

```bash
./build/mqproxy client \
  --server <server-ip>:4433 --token secret123 \
  --socks5 127.0.0.1:1080 \
  --path 192.168.1.50 \
  --path 10.20.0.30
```

You can also expose an HTTP CONNECT ingress with `--http-connect <ip:port>` (use it via `curl --proxy http://127.0.0.1:<port> https://...`).

## Next steps

- [HTTP Gateway](./http-gateway) — delegate HTTP request execution to the server.
- [UDP Relay](./udp-relay) — carry DNS/game/VoIP UDP over MPQUIC DATAGRAMs.
- [Transparent Capture](./transparent-capture) — capture TCP at the kernel level, no app config.
- [TLS MITM](./tls-mitm) — terminate and inspect TLS as HTTP/2.
- [Options Reference](/reference/options) — every flag, per mode.
