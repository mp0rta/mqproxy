# Introduction

**mqproxy** is a **multipath application proxy/accelerator** built on [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/), using a [fork of XQUIC](https://github.com/mp0rta/xquic). mqproxy maps application flows directly onto MPQUIC primitives — one TCP flow becomes one MPQUIC stream, one HTTP request becomes one H3 stream over MPQUIC, one UDP session becomes MPQUIC DATAGRAMs — so that applications get path diversity, seamless failover, and **bandwidth aggregation** without implementing MPQUIC themselves.

mqproxy runs as a **client/server pair**: the client exposes one or more local ingresses, carries traffic to the server over a single multipath QUIC tunnel, and the server reaches the origin. Four ingress modes are available — a **TCP proxy** (SOCKS5 / HTTP CONNECT), an **HTTP request gateway** (`POST /_mqproxy/fetch`, executed against origins with TLS verification always on), a **UDP relay** (SOCKS5 UDP ASSOCIATE over MPQUIC DATAGRAMs), and **transparent capture** of kernel-redirected TCP with an optional TLS-terminating MITM mode. Every mode gets path diversity, seamless failover, and within-stream bandwidth aggregation across the bound paths.

It also provides automatic reconnect/keepalive, per-path and per-request metrics, congestion-control and multipath-scheduler selection, a pre-auth connection cap, masquerade mode, INI config files, and systemd service packaging.

## Relationship to mqvpn

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

**Measured:** in a 2-path 100 Mbit/s testbed the TCP proxy aggregates even a *single* TCP stream — **1.81× single-path at `-P 1`**, 1.93× at `-P 16` — whereas a flow-pinned L3 datagram tunnel needs multiple parallel flows before its second path engages. Full matrix (`-P 1…16`, symmetric + asymmetric, vs mqvpn `wlb`/`minrtt`) in the [TCP aggregation benchmark](https://github.com/mp0rta/mqproxy/blob/main/docs/report/2026-06-23-single-tcp-aggregation-mqvpn-vs-mqproxy.md).

## Operating Modes

| Mode | Mapping | |
|---|---|---|
| **TCP Proxy** | 1 TCP flow → 1 MPQUIC bidi stream | ✅ |
| **HTTP Request Execution Gateway** | 1 HTTP request → 1 H3 stream over MPQUIC | ✅ |
| **UDP Relay** | 1 UDP session → MPQUIC DATAGRAMs | ✅ |
| **Transparent TCP Capture** | kernel-redirected TCP → opaque MPQUIC stream | ✅ |
| **TLS MITM Ingress** | terminate browser TLS (forged leaf) → H2 → Gateway tunnel | ✅ optional |

**What each mode gives you:**

- **TCP Proxy** — zero app changes, end-to-end TLS preserved (mqproxy never sees plaintext). Each TCP connection becomes one MPQUIC stream, so even a single download aggregates bandwidth across all paths. Separate TCP connections get separate MPQUIC streams and do not block each other. The trade-off: when a browser multiplexes many HTTP/2 requests over a *single* TCP connection, all those requests share one MPQUIC stream, so a retransmission within that stream stalls them all (the same transport-layer head-of-line blocking that HTTP/3 was designed to eliminate).
- **TLS MITM** — opt-in TLS termination lifts the proxy to L7 visibility. Each HTTP/2 request stream is mapped to its *own* MPQUIC stream, so a loss on one request does not block others — your HTTP/2 traffic effectively gains HTTP/3-class stream independence, plus multipath aggregation that even native HTTP/3 does not provide. Requires installing the operator's CA on the device.
- **HTTP Gateway** — an explicit request-delegation API (`POST /_mqproxy/fetch`); each request is one H3 stream with independent multipath aggregation. Useful for SDKs and server-to-server calls that can set `X-Mq-*` headers directly, without SOCKS5 or transparent capture.
- **UDP Relay** — carries non-QUIC UDP (DNS, game, VoIP) over MPQUIC DATAGRAMs, preserving the lossy/unordered semantics applications expect. Packets ride the multipath tunnel but are not retransmitted — latency-sensitive traffic stays latency-sensitive.
- **Transparent Capture** (without `--mitm`) — kernel-level redirect with no app config; same aggregation and end-to-end TLS guarantees as TCP Proxy mode, but apps need no SOCKS5/proxy configuration at all.

TCP Proxy and Transparent Capture (without `--mitm`) do **not** terminate TLS: for HTTPS, TLS stays end-to-end between the application and the origin. Only the WAN segment between mqproxy-client and mqproxy-server is carried over MPQUIC.

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

Continue to [Building from Source](./building) and the [Quick Start](./quick-start), or jump to a specific mode: [TCP Proxy](./tcp-proxy), [HTTP Gateway](./http-gateway), [UDP Relay](./udp-relay), [Transparent Capture](./transparent-capture), [TLS MITM](./tls-mitm).
