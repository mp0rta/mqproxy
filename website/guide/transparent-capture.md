# Transparent Capture

Transparent capture redirects TCP connections at the kernel level directly into mqproxy without any application changes — no SOCKS5 configuration, no proxy settings, no app awareness. By default each captured connection is relayed **opaquely** (byte-for-byte, without decryption) over the MPQUIC tunnel as a single stream, giving flow-level multipath aggregation. End-to-end TLS is then fully preserved between the application and the origin; **mqproxy never sees plaintext**. Adding `--mitm` instead terminates and inspects the TLS as HTTP/2 — that opt-in mode is documented in [TLS MITM mode](./tls-mitm).

::: warning Linux + IPv4 only
Transparent capture installs kernel firewall rules, so it needs root or `CAP_NET_ADMIN`.
:::

## Two kernel capture mechanisms

- **`redirect` (default)** — uses `nft nat OUTPUT` (REDIRECT target). Captures the *local machine's own outbound* TCP. Does not need `IP_TRANSPARENT` on the socket. This is the right mode when mqproxy and the apps being accelerated run on the same host.
- **`tproxy`** — uses `nft mangle PREROUTING` (TPROXY target) with `IP_TRANSPARENT` on the listening socket. Captures *forwarded* traffic from downstream LAN hosts, as on a router gateway. Requires `fwmark` + a policy-routing table so the local TCP stack's reply packets are routed back out the right interface. This is the standard Linux TPROXY setup; it composes with any router/policy-routing stack that can mark packets and steer them to the listener — OpenMPTCProuter (OMR) is one such deployment, not a requirement.

## Single-host quickstart (redirect mode, `--setup-redirect`)

```bash
# Server — no change from the regular config.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# Client — transparent listener on :12443; self-installs nft rules (needs root).
sudo ./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --tproxy 127.0.0.1:12443 \
  --setup-redirect

# Any app on this host connecting outbound to TCP :443 is now transparently
# captured, aggregated over MPQUIC, and forwarded to the origin.
# No curl --socks5 / --proxy flags needed.
curl https://example.com/
```

`--setup-redirect` tells mqproxy to install the nft rules on start and remove them on exit. It needs `root` or `CAP_NET_ADMIN`. The self-installed rule captures **TCP destination port 443 by default**; use `--tproxy-dport <port>` to capture a different port. For multiple ports or finer control, install the firewall rules yourself and just point the traffic at the listener — mqproxy reads the original destination of whatever the rules redirect.

## Router/gateway deployment (tproxy mode)

When the router stack already owns the firewall and policy-routing rules (e.g. OpenMPTCProuter, or any setup that places a `TPROXY` target in `PREROUTING` and marks the packets), leave `--setup-redirect` OFF and let mqproxy just provide the listener — match its `--tproxy-fwmark`/`--tproxy-table` to whatever the rules use:

```bash
sudo ./build/mqproxy client \
  --server <server>:4433 --token secret123 \
  --tproxy 0.0.0.0:12443 \
  --tproxy-mode tproxy \
  --tproxy-fwmark 1 \
  --tproxy-table 100
  # no --setup-redirect — the router stack owns the rules
```

## Loop-avoidance and security notes

- `--tproxy-uid <uid>` marks one UID whose *own outbound* traffic is exempt from redirection (so mqproxy's own connections to the server are not re-captured into itself). Defaults to `geteuid()` of the process. Running as a dedicated non-root service account is recommended; using uid 0 would exempt all root traffic, which is wider than intended.
- By default transparent capture is **opaque**: mqproxy relays raw TLS bytes and never decrypts them. Applications with certificate pinning continue to work. Adding `--mitm` turns this capture path into a TLS-terminating L7 proxy — see [TLS MITM mode](./tls-mitm). MITM is off unless `--mitm` is passed.
