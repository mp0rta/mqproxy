# Security Model

mqproxy uses a **trusted proxy** model: mqproxy-client, mqproxy-server, and the MPQUIC connection between them are trusted. In TCP Proxy Mode and Transparent Capture mode (without `--mitm`), application↔origin TLS is preserved end-to-end (mqproxy never sees plaintext — it relays raw TLS bytes opaquely). Applications with certificate pinning continue to work.

The HTTP Request Execution Gateway is an explicit delegation model — the client delegates HTTP request execution to a trusted gateway that establishes (and always verifies) the origin TLS — not a transparent MITM. Gateway requests are authenticated individually (`X-Mq-Auth`, per-request); `Authorization` is reserved for the origin and forwarded, while `Cookie` and `X-Mq-*` never leave the gateway.

## TLS MITM ingress

**TLS MITM ingress** (`--mitm`, opt-in) is an **operator-controlled / consenting-endpoint** model for managed devices where the operator's CA is installed locally — a corporate-proxy or personal-VPN posture, not a transparent attack on third parties. The client forges per-host leaves from that CA, terminates the browser's TLS as HTTP/2, and maps each request onto the Gateway tunnel.

Its trust assumptions:

- The **CA private key is the anchor**: it must be an unencrypted PKCS#8 file owned by the running user, not group/other accessible, and not a symlink. It stays in memory while mqproxy runs.
- A CA can be limited to your own domains with an X.509 `nameConstraints` extension; mqproxy relays out-of-scope hosts opaquely.
- Browser-supplied `X-Mq-*` headers are **always stripped** (never interpreted as controls — the client injects its own `x-mq-auth`).
- The feature is **fail-closed** (misconfiguration is a startup error, never silent passthrough), with a bounded ClientHello read and header, stream and connection limits.
- Anything that is not positively an HTTP/2 TLS client for a valid host name (non-h2, non-TLS, no SNI, ignored hosts, …) is relayed opaquely and never inspected.

Cert-pinned hosts can be excluded with `--ignore-host(s)`, which relays them opaquely so the origin's real certificate reaches the client.

Known limitation: the client's HTTP/3 receive side buffers a large download in memory if the device consuming it is slower than the tunnel, until an upstream xquic fix lands (details in the guide). See the [TLS MITM guide](/guide/tls-mitm) for the operational details.

## License

Apache-2.0. See [LICENSE](https://github.com/mp0rta/mqproxy/blob/main/LICENSE).

## Disclaimer

mqproxy is licensed under the Apache License 2.0 and is provided "AS IS", without warranties or conditions of any kind.

Use of mqproxy is at your own risk. Users are solely responsible for validating its suitability, security, and operational safety, especially in production or commercial environments.

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) (Alibaba) — the QUIC/MPQUIC transport, via the [mp0rta fork](https://github.com/mp0rta/xquic).
- [BoringSSL](https://boringssl.googlesource.com/boringssl) — TLS backend.
- [nghttp2](https://nghttp2.org/) — HTTP/2 framing for the C build's TLS MITM ingress (the Rust binary uses the `h2` crate and rustls).
