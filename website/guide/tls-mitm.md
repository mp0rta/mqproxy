# TLS MITM Mode

`--mitm` turns the transparent-capture path into a **TLS-terminating L7 proxy**. For each captured connection the client peeks the TLS ClientHello SNI, forges a per-host leaf certificate signed by the operator's CA (`--ca-cert`/`--ca-key`), terminates TLS speaking **HTTP/2**, and maps each H2 request stream onto the existing MPQUIC Gateway tunnel (the `X-Mq-Auth` control plane) to the server, which fetches the origin. The browser↔client side speaks plain h2; the client↔server tunnel is unchanged MPQUIC, so each request still gets within-stream multipath aggregation.

::: danger Trust model
This is an **operator-controlled / consenting-endpoint** MITM (a corporate-proxy or personal-VPN posture), not an attack tool. It only works because the operator has installed their own CA on the device so the browser trusts the forged leaves. The CA private key is the trust anchor — protect it: mqproxy opens it with `O_NOFOLLOW`/`O_CLOEXEC` and refuses an encrypted or group/world-readable key.
:::

## Quick start

```bash
# Server — unchanged; the gateway origin bridge does the origin fetch.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123

# Client — transparent capture + MITM. Requires --tproxy and a signing CA.
sudo ./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --tproxy 127.0.0.1:12443 --setup-redirect \
  --mitm \
  --ca-cert /etc/mqproxy/mitm-ca.crt \
  --ca-key  /etc/mqproxy/mitm-ca.key \
  --ignore-host signal.org \
  --ignore-hosts .apple.com,.icloud.com

# With the CA trusted by the device, browsing TCP :443 is now terminated,
# inspected as H2, and carried request-by-request over the MPQUIC tunnel.
curl https://example.com/
```

## Requirements (fail-closed)

`--mitm` requires `--tproxy` (transparent capture is the only MITM ingress in v1) **and** `--ca-cert <pem>` + `--ca-key <pem>`. Missing any of these — or a binary built without the BoringSSL archives (run `scripts/build-xquic.sh` first) — is a startup error with a non-zero exit; mqproxy never silently falls back to opaque passthrough. `--mitm` is client-only (the server subcommand rejects it).

## Ignore-hosts (opaque-splice bypass)

`--ignore-host <host>` (repeatable) and `--ignore-hosts <a,b,c>` (comma-separated) list hosts to **splice opaquely** — the raw TLS is relayed untouched so the origin's real certificate reaches the client (use this for cert-pinned apps that would reject a forged leaf). Matching is on the normalized (lowercased, trailing-dot-stripped) SNI and is either **exact** (`signal.org` matches only `signal.org`) or a **leading-dot suffix** (`.apple.com` matches `x.apple.com` and `a.b.apple.com` but **not** `apple.com` itself). CLI and config entries accumulate (union).

## Config (`[Mitm]`, client-only)

See the [Configuration File](./configuration) page for the full INI format.

```ini
[Mitm]
Enabled  = true
CACert   = /etc/mqproxy/mitm-ca.crt
CAKey    = /etc/mqproxy/mitm-ca.key
IgnoreHosts = .apple.com
IgnoreHosts = signal.org
```

`IgnoreHosts` is repeatable — one host per line, like `[Multipath] Path`. CLI `--ignore-host(s)` and these entries union together.

## Security posture

- **Untrusted browser headers.** All browser-supplied `X-Mq-*` headers are stripped — they are never interpreted as proxy controls; the client injects its own `x-mq-auth` / `x-mq-forward-cookie`. `Cookie` and `Authorization` are forwarded so normal browsing works.
- **Dual-ABI symbol isolation.** The MITM crypto core links the vendored BoringSSL, whose symbols are hidden from the executable's dynamic table (`-Wl,--exclude-libs`) so they cannot interpose libcurl's system OpenSSL.
- **Fail-closed & bounded.** Misconfigured/unavailable MITM is a startup error, never a silent passthrough. The ClientHello drain is bounded (8 KiB cap + deadline), and HTTP/2 resource limits (concurrent streams, frame size, header-list size) bound the new ingress.
- **HTTP/2 only.** The browser must offer ALPN `h2`; non-h2, non-TLS, or no-SNI connections hard-fail when MITM is on.
