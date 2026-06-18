# UDP Relay

```text
UDP app (DNS / game / VoIP / …)
  │  SOCKS5 UDP ASSOCIATE
  ▼
mqproxy-client ──────── MPQUIC DATAGRAMs (multipath) ────────► mqproxy-server
     1 UDP session = a bidi signalling stream + DATAGRAMs        │  connected
     carrying session_id-tagged packets                          │  UDP socket
                                                                 ▼
                                                             UDP target
```

UDP relay carries non-QUIC UDP traffic (DNS, NTP, game, VoIP, app-specific UDP) over MPQUIC DATAGRAMs. The ingress is **SOCKS5 UDP ASSOCIATE** (RFC 1928 §7) on the same `--socks5` listener used for TCP. For each target the client opens a small bidi signalling stream (`UDP_SESSION_OPEN`/`RESP`, multiplexed alongside TCP on the one `mqproxy-tcp/1` connection), then sends packets as DATAGRAMs tagged with a session id; the server keeps a connected UDP socket per session and relays both ways.

Packets larger than the path MTU are fragmented and reassembled (4-slot LRU, no retransmission — UDP stays lossy). Sessions are torn down on idle timeout (server-driven, `--udp-idle-timeout`), on stream close, or when the SOCKS5 control connection drops. The server advertises the capability at auth and can refuse all UDP with `--no-udp`.

::: tip
UDP relay rides the `mqproxy-tcp/1` connection, so a client running `--gateway` only (H3 connection) does not get it.
:::

## Quick start

UDP relay is exposed on the **same `--socks5` listener** — any SOCKS5 client that speaks UDP ASSOCIATE can use it. The server advertises the capability at auth; pass `--udp-idle-timeout <sec>` to tune session lifetime, or `--no-udp` to refuse UDP entirely.

```bash
# Server (UDP relay on by default; 30s idle timeout shown)
./build/mqproxy server --listen 0.0.0.0:4433 --token secret123 \
  --udp-idle-timeout 30

# Client — the SOCKS5 listener handles both TCP and UDP
./build/mqproxy client \
  --server 127.0.0.1:4433 --token secret123 \
  --socks5 127.0.0.1:1080
```

`curl` does not speak SOCKS5 UDP ASSOCIATE, so use a UDP-capable SOCKS5 client. The repo ships `udpsocks`, a minimal test client (built by the test suite), which is handy for a quick check:

```bash
# Relay a UDP packet to a target through the client's SOCKS5 listener
./build/udpsocks --proxy 127.0.0.1:1080 --target 8.8.8.8:53 --send 32 --count 1
```
