---
layout: home

hero:
  name: mqproxy
  text: MPQUIC-native multipath application proxy
  tagline: Map TCP, HTTP, and UDP flows directly onto Multipath QUIC for path diversity, seamless failover, and bandwidth aggregation — without your apps implementing MPQUIC.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: Quick Start
      link: /guide/quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/mp0rta/mqproxy

features:
  - icon: 🧬
    title: MPQUIC-Native Flow Mapping
    details: One TCP flow becomes one MPQUIC stream, one HTTP request one H3 stream, one UDP session MPQUIC DATAGRAMs — so a single transfer aggregates within-stream across all bound paths.
  - icon: 🛣️
    title: Bandwidth Aggregation & Failover
    details: Because a QUIC stream is reassembled by offset, its frames can be spread across multiple paths (WiFi + LTE) with correctness preserved. Add paths with --path.
  - icon: 🧰
    title: Five Ingress Modes
    details: TCP proxy (SOCKS5 / HTTP CONNECT), HTTP request gateway, UDP relay, transparent capture, and an opt-in TLS-terminating MITM L7 proxy.
  - icon: 🛡️
    title: Production-Ready
    details: Auto reconnect/keepalive, per-path & per-request metrics, CC/scheduler selection, a pre-auth connection cap, masquerade mode, INI config files, and systemd packaging.
---
