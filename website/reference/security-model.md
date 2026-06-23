# Security Model

mqproxy uses a **trusted proxy** model: mqproxy-client, mqproxy-server, and the MPQUIC connection between them are trusted. In TCP Proxy Mode and Transparent Capture mode (without `--mitm`), application↔origin TLS is preserved end-to-end (mqproxy never sees plaintext — it relays raw TLS bytes opaquely). Applications with certificate pinning continue to work.

The HTTP Request Execution Gateway is an explicit delegation model — the client delegates HTTP request execution to a trusted gateway that establishes (and always verifies) the origin TLS — not a transparent MITM. Gateway requests are authenticated individually (`X-Mq-Auth`, per-request); `Authorization` is reserved for the origin and forwarded, while `Cookie` and `X-Mq-*` never leave the gateway.

## TLS MITM ingress

**TLS MITM ingress** (`--mitm`, opt-in) is an **operator-controlled / consenting-endpoint** model for managed devices where the operator's CA is installed locally — a corporate-proxy or personal-VPN posture, not a transparent attack on third parties. The client forges per-host leaves from that CA, terminates the browser's TLS as HTTP/2, and maps each request onto the Gateway tunnel.

Its trust assumptions:

- The **CA private key is the anchor** (loaded with `O_NOFOLLOW`/`O_CLOEXEC`, refused if encrypted or group/world-readable).
- Browser-supplied `X-Mq-*` headers are **always stripped** (never interpreted as controls — the client injects its own `x-mq-auth`).
- Vendored-BoringSSL symbols are **isolated** from libcurl's system OpenSSL.
- The feature is **fail-closed** (misconfiguration is a startup error, never silent passthrough, with a bounded ClientHello drain and H2 resource limits).

Cert-pinned hosts can be excluded with `--ignore-host(s)`, which splices them opaquely so the origin's real certificate reaches the client. See the [TLS MITM guide](/guide/tls-mitm) for the operational details.

## License

Apache-2.0. See [LICENSE](https://github.com/mp0rta/mqproxy/blob/main/LICENSE).

## Disclaimer

mqproxy is licensed under the Apache License 2.0 and is provided "AS IS", without warranties or conditions of any kind.

Use of mqproxy is at your own risk. Users are solely responsible for validating its suitability, security, and operational safety, especially in production or commercial environments.

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) (Alibaba) — the QUIC/MPQUIC transport, via the [mp0rta fork](https://github.com/mp0rta/xquic).
- [BoringSSL](https://boringssl.googlesource.com/boringssl) — TLS backend.
- [nghttp2](https://nghttp2.org/) — HTTP/2 framing for the TLS MITM ingress.
