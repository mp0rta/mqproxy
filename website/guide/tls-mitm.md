# TLS MITM Mode

`--mitm` turns the transparent-capture path into a **TLS-terminating L7 proxy**. For each captured connection the client peeks the TLS ClientHello SNI, forges a per-host leaf certificate signed by the operator's CA (`--ca-cert`/`--ca-key`), terminates TLS speaking **HTTP/2**, and maps each H2 request onto its own H3 request on the MPQUIC tunnel; the server's gateway fetches the origin. The browser↔client side speaks plain h2; the client↔server tunnel is MPQUIC, so every request gets its own stream (no head-of-line blocking across requests) and its own multipath scheduling.

::: danger Trust model
This is an **operator-controlled / consenting-endpoint** MITM (a corporate-proxy or personal-VPN posture), not an attack tool. It only works because the operator has installed their own CA on the device so the browser trusts the forged leaves. The CA private key is the trust anchor — protect it. mqproxy refuses a CA key file that is a symlink, is not owned by the user running mqproxy, or is readable by group or others (`chmod 600`).
:::

## Create a CA

mqproxy needs a CA certificate and its **unencrypted PKCS#8** private key (a `-----BEGIN PRIVATE KEY-----` PEM). This creates one:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout mitm-ca.key -out mitm-ca.crt -days 825 -subj "/CN=mqproxy MITM CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign
chmod 600 mitm-ca.key
```

Then install `mitm-ca.crt` in the trust store of every device whose traffic you capture (for example, copy it to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` on Debian/Ubuntu).

EC (P-256, P-384), Ed25519 and RSA CAs are accepted. The certificate must be X.509 v3 with `CA:TRUE` and, if it has a `keyUsage` extension, `keyCertSign`; it must not be expired, and the key must match it.

**PKCS#8 only.** A PKCS#1 (`BEGIN RSA PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`) key is a startup error that tells you how to convert it:

```bash
openssl pkcs8 -topk8 -nocrypt -in old.key -out mitm-ca.key
```

An encrypted key (`BEGIN ENCRYPTED PRIVATE KEY`) is rejected too.

### Limit the CA to your own domains (optional)

A CA that every device trusts for *any* name is a large liability. You can add an X.509 `nameConstraints` extension so that the CA is only valid for the domains you intend to inspect; browsers enforce it, and mqproxy relays every other host [opaquely](#what-is-relayed-opaquely) instead of forging a certificate the browser would reject:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout mitm-ca.key -out mitm-ca.crt -days 825 -subj "/CN=mqproxy MITM CA" \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign \
  -addext "nameConstraints=critical,permitted;DNS:example.com,permitted;DNS:example.org"
```

`DNS:example.com` permits `example.com` and all of its subdomains; `DNS:.example.com` permits subdomains only. `excluded;DNS:…` entries work the same way. `IP` constraints are ignored; any other constraint type, or a `DNS` constraint that is not a host name, is a startup error.

## Quick start

```bash
# Server — unchanged; the gateway origin bridge does the origin fetch.
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --cert /etc/mqproxy/tls/server.pem --key /etc/mqproxy/tls/server.key

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

`--mitm` requires `--tproxy` (transparent capture is the only MITM ingress) **and** `--ca-cert <pem>` + `--ca-key <pem>`. Any of these missing, a CA that cannot be loaded (see above), or an invalid ignore entry is a startup error with exit code 2 and a message naming the problem — mqproxy never silently falls back to opaque passthrough because of a configuration mistake. `--mitm` is client-only: the `server` subcommand rejects it, and a `[Mitm]` section in a server config file is skipped with a warning.

Without `--mitm`, the CA and ignore options are accepted but have no effect.

## What is relayed opaquely

MITM is applied only when everything is positively confirmed. Every other captured connection is **relayed opaquely** — byte for byte, through the normal TCP proxy path, so the client sees the origin's real certificate — and keeps working rather than being dropped:

- the client does not offer `h2` in its TLS ALPN (this includes `curl --http1.1`, many non-browser clients, and **WebSocket**, which arrives as HTTP/1.1);
- the traffic is not TLS at all;
- there is no SNI, the SNI is invalid, or the SNI is an IP address;
- the host is in the ignore list;
- the host is outside the scope of a `nameConstraints` CA;
- the client's TLS settings are incompatible with the forged certificate (for example, it accepts none of its signature algorithms);
- the ClientHello does not arrive within 5 seconds, or is larger than 8 KiB;
- the client closes the connection before the ClientHello is complete;
- the client already has 256 connections in MITM (extra connections degrade to opaque relay instead of being refused).

## Ignore hosts

`--ignore-host <host>` (repeatable) and `--ignore-hosts <a,b,c>` (comma-separated, no spaces) list hosts to relay opaquely — the origin's real certificate reaches the client. Use this for certificate-pinned apps that would reject a forged leaf.

Matching is on the lowercased SNI with any trailing dot removed, and is either:

- **exact** — `example.com` matches `example.com` only;
- **subdomains only** — `.example.com` matches `www.example.com` and `a.b.example.com`, but **not** `example.com` itself.

To exclude a site and all of its subdomains, list both. Entries from the CLI and the config file are combined.

An entry that is not a valid host name (an IP address, a wildcard, characters outside letters, digits, `-` and `.`, an empty `--ignore-host ""`, …) is a **startup error** (exit code 2) that names the offending entry; mqproxy does not skip it silently. (Empty items in a comma-separated `--ignore-hosts a,,b` are skipped.)

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

`IgnoreHosts` is a repeatable key with **one host per line** (not a comma-separated list), like `[Multipath] Path`. CLI `--ignore-host(s)` and these entries are combined.

## Block UDP/443

mqproxy MITMs TCP only. Browsers that see an `Alt-Svc` header or a cached HTTPS DNS record may switch a site to QUIC/HTTP/3 over UDP/443, which bypasses the proxy entirely. mqproxy strips `alt-svc` from responses it relays, but you should also block UDP/443 on the capture path so browsers fall back to TCP and TLS. On a router:

```bash
nft add table inet mqproxy_block
nft add chain inet mqproxy_block forward '{ type filter hook forward priority 0; }'
nft add rule  inet mqproxy_block forward udp dport 443 reject
```

For the local machine's own browsers, hook `output` instead of `forward`.

## Request handling and limits

- **One host per connection.** Each TLS connection is bound to the SNI it was opened for. A request whose `:authority` names a different host gets `421 Misdirected Request`, and the browser retries on a connection of its own.
- **Header limits** (the same on both ends of the gateway tunnel): a header field (name + value) up to 8 KiB, a whole header section up to 32 KiB, up to 256 fields, and a request path (with query string) up to about 8 KiB. A browser request head over the limits is answered by the h2 layer with `431` (or a stream reset); large cookies, long URLs and big CSP headers within these limits pass.
- **HTTP/2 limits:** up to 128 concurrent streams per connection, 256 KiB receive window per stream, 512 KiB per connection.
- **Connections:** at most 256 MITM connections per client; an idle connection with no open streams is closed after 60 seconds, and a peer that has been silent for 60 s while streams are open is pinged and closed after 90 s of silence. A long-lived response such as server-sent events is fine.
- **Methods** keep their case and may be up to 32 bytes; `CONNECT` and asterisk-form (`OPTIONS *`) requests are rejected with `400`.
- **Cookies:** a browser's split `cookie` fields are joined into one, and `Cookie` and `Authorization` are forwarded to the origin.
- **`alt-svc` is removed** from responses (see [Block UDP/443](#block-udp-443)).

## Observability

With `--metrics-interval`, the client also prints a `mq.mitm` line on every tick and once at shutdown (nothing is printed while every counter is still zero):

```
mq.mitm conns=<live> streams=<open> mitm=<n> opaque_not_tls=<n> opaque_no_sni=<n> opaque_bad_sni=<n> opaque_no_h2=<n> opaque_ignored=<n> opaque_ca_scope=<n> opaque_tls_incompat=<n> opaque_timeout=<n> opaque_too_large=<n> opaque_eof=<n> opaque_capacity=<n> tls_fail=<n> h2_fail=<n> dead=<n> leaf_hit=<n> leaf_miss=<n> reqs=<n> rejects=<n>
```

`conns` and `streams` are the MITM connections and h2 streams open right now; everything else is cumulative. `mitm` counts connections that were terminated, and each `opaque_*` counter counts connections relayed opaquely for one of the reasons listed [above](#what-is-relayed-opaquely). `tls_fail`, `h2_fail` and `dead` count connections that ended on a TLS error, an h2 error, or a dead peer. `leaf_hit`/`leaf_miss` count forged-certificate cache hits and misses, and `reqs` counts every h2 request received, and `rejects` counts those refused before a tunnel request was opened: an `x-mq-error` or 421 answer from the request mapping, an unavailable or refused tunnel, an `RST_STREAM` for a malformed request, or a `REFUSED_STREAM` past the per-connection stream limit. At debug log level each routing decision is logged as `mq_mitm: <sni|-> → mitm|opaque(<why>)`. Header and body values are never logged.

## Security posture

- **Untrusted browser headers.** All browser-supplied `X-Mq-*` headers are stripped — they are never interpreted as proxy controls; the client injects its own `x-mq-auth` / `x-mq-forward-cookie`. `Cookie` and `Authorization` are forwarded so normal browsing works.
- **Fail-closed & bounded.** A misconfigured MITM is a startup error, never a silent passthrough. The ClientHello is read with a size cap and a deadline, and the limits above bound the new ingress.
- **Leaf certificates** are forged per SNI with a short life (24 hours), signed by your CA, and kept in a small in-memory cache. The CA key stays in memory while mqproxy runs.
- **HTTP/2 only.** Other protocols are relayed opaquely, not inspected.

## Known limitation: large downloads to slow devices

The client's HTTP/3 receive side does not yet apply end-to-end back-pressure: xquic copies response data into client memory as it arrives and returns flow-control credit to the server straight away. If a browser (or the device it runs on) consumes a large download more slowly than the tunnel delivers it, the client buffers the difference in memory. The same applies to the gateway's `POST /_mqproxy/fetch` ingress. The fix is tracked upstream in xquic ([alibaba/xquic#959](https://github.com/alibaba/xquic/issues/959) and [PR #960](https://github.com/alibaba/xquic/pull/960)) and will be picked up when it lands. Until then, on memory-constrained routers, watch the client's memory during large downloads to slow clients, or add the affected hosts to the [ignore list](#ignore-hosts) so they take the bounded opaque path.
