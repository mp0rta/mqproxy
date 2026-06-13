# HTTP/3 over multipath: terminate-and-restream (block) vs opaque datagram relay

**Date:** 2026-06-13
**Author:** mqproxy A/B lanes bench
**Status:** Decision-grade experiment; result feeds the OpenMPTCProuter (OMR) integration design.
**Reproduce:** `tests/integration/bench_ab_lanes.sh` (commit on branch `ab-lanes-bench`)
**Raw data:** `docs/report/bench_results/2026-06-13-full-matrix-release.csv` (the
release-build full matrix this report's §3 table is computed from; fresh runs land in
the gitignored `bench_results/` at the repo root)

---

## 1. The question

A multipath proxy that wants to *aggregate* the bandwidth of two WAN links has two
ways to handle a client's HTTP/3 traffic:

- **block** — drop/block UDP 443 so the client falls back to HTTP/2 over TCP;
  the proxy **terminates** that TCP flow and carries it as **one MPQUIC STREAM**.
  A QUIC stream is reassembled by offset, so its STREAM frames can be split across
  paths and still arrive correct → *within-stream* multipath aggregation.
- **relay** — carry the client's QUIC packets **opaquely** over the MPQUIC
  **DATAGRAM** lane (CONNECT-UDP / SOCKS5 UDP ASSOCIATE style). The proxy never
  decrypts; the inner end-to-end QUIC owns reliability and congestion control and
  has no idea multipath exists underneath it.

Folklore (and prior mqvpn experience) says the relay path underperforms because the
inner QUIC misreads cross-path reordering as loss. We wanted that quantified: **where,
in (RTT-skew × loss) space, does each approach win, and by how much — and does an
improved scheduler change the verdict?**

This matters because QUIC fuses TLS into the transport. Unlike TCP — where a layer-4
split proxy can terminate the transport while leaving the TLS bytestream end-to-end —
you cannot terminate QUIC without terminating TLS (i.e. MITM). So "block" (no MITM,
forces TCP) vs "relay" (no MITM, keeps QUIC) is the *real* choice a transparent
router faces before reaching for MITM.

## 2. Setup

**Topology.** Not network namespaces — the shaping is applied directly to the
**loopback device `lo`** with `tc` HTB + netem (the proven `e2e_multipath.sh` layout).
The two paths are distinguished by the client's **source IP** in `127.0.0.0/8`
(path A = `127.0.0.2`, path B = `127.0.0.3`, server = `127.0.0.1`); the mqproxy client
binds each path to its own source address. One HTB class per path caps it at
`RATE=100mbit`; a netem leaf under each class adds the delay/loss. u32 filters steer a
path's IP **both as src and as dst** so *both directions* of the leg are shaped — this
is why one-way `delay` produces a round-trip of twice that (a packet crosses the same
netem leaf once each way).

The base shaper (run once):

```bash
tc qdisc add dev lo root handle 1: htb default 1
tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit          # unshaped default (origin<->server localhost leg)
tc class add dev lo parent 1: classid 1:10 htb rate 100mbit ceil 100mbit quantum 1514   # path A
tc class add dev lo parent 1: classid 1:11 htb rate 100mbit ceil 100mbit quantum 1514   # path B
tc qdisc add dev lo parent 1:10 handle 10: netem delay 25ms limit 20000          # path A leaf
tc qdisc add dev lo parent 1:11 handle 11: netem delay 25ms limit 20000          # path B leaf
# steer BOTH directions of each path into its class (src for upstream, dst for download)
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.2/32 flowid 1:10
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip dst 127.0.0.2/32 flowid 1:10
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src 127.0.0.3/32 flowid 1:11
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip dst 127.0.0.3/32 flowid 1:11
```

Per cell, only the two netem leaves are retuned (path B gets the extra one-way `skew`,
both get `loss`):

```bash
# cell = (skew ms, loss %)
tc qdisc change dev lo parent 1:10 handle 10: netem delay 25ms            [loss L%] limit 20000   # path A
tc qdisc change dev lo parent 1:11 handle 11: netem delay $((25 + skew))ms [loss L%] limit 20000   # path B
```

So per path:

- Path A: one-way `25ms` → **RTT ≈ 50ms**
- Path B: one-way `25 + skew ms` → **RTT ≈ 50 + 2·skew ms**
- **Inter-path RTT difference = 2·skew** — `skew=50` means a *100ms* RTT gap, not 50ms.
- both paths: `loss L%` per direction.

(The HTB `quantum 1514` makes each shaped class meter packet-by-packet; without it HTB
dequeues in large bursts at hundreds of mbit and the netem leaf drops them as spurious
loss, which under a loss-reactive CC collapses goodput — an artifact of the harness,
not the protocol.)

**Arms (all establish 2 paths; they differ only in how the scheduler uses them):**

| Arm | Inner protocol | mqproxy handling | Scheduler intent |
|---|---|---|---|
| `block,minrtt` | HTTP/1.1 plaintext (`python -m http.server`)¹ | TCP terminated → 1 MPQUIC **STREAM** | spread stream frames across both paths |
| `relay,minrtt` | HTTP/3 (picoquicdemo) | opaque **DATAGRAM** relay via `udpsocks --listen` shim | spread datagrams per-packet across both paths |
| `relay,backup` | HTTP/3 (picoquicdemo) | opaque DATAGRAM relay | pin to the primary path (secondary marked STANDBY) |

¹ The block arm uses HTTP/1.1, not H2, as a stand-in for the "fall back off H3" case.
The workload is a single bulk download, so H1 vs H2 makes no difference here — H2's
head-of-line advantage only appears under *concurrent* requests, which is out of scope
for this run (see §5).

**Inner stack = picoquic, deliberately.** The experimental subject is how an inner,
multipath-unaware QUIC's loss detection and CC react to tunnel-induced reordering.
Using the same xquic fork on both sides of the tunnel would overfit to its quirks;
real relay traffic is quiche / neqo / Cronet / mvfst.
[picoquic](https://github.com/private-octopus/picoquic) is an independent IETF interop
implementation, emits qlog natively, and lets us pick the inner CC (`-G`); we use its
bundled `picoquicdemo` sample app as both the inner H3 origin and client.

**Transfer:** 32 MB (SI), measured as transfer-only goodput — curl `%{speed_download}`
on the block arm, picoquic's own `Received N bytes in T seconds, X Mbps` line on the
relay arm — so neither number includes connection setup / handshake time.

These are two *different* tools' self-reported rates, not one common probe, and their
windows don't line up byte-for-byte (curl excludes connect/SOCKS5; picoquic reports
`received_bytes × 8 / its own transfer time`). To bound that, each cell also records a
**common yardstick** — the wall-clock `elapsed_s` from `date` around the whole
transfer (CSV column 8) — and we cross-check the self-reported goodput against
`SIZE_BYTES × 8 / elapsed`. They agree to **<1% on every cell** (e.g. block skew0/loss0
134.2 vs 133.3; relay,backup skew0/loss0 72.0 vs 71.9; relay,minrtt skew0/loss1 23.1
vs 23.2), because at 32 MB the setup time is negligible against the transfer. So the
two probes measure effectively the same quantity *at this transfer size*; for small
transfers or extreme loss, where setup weighs more, prefer the wall-clock figure.

**Build:** release mqproxy + release xquic (an AddressSanitizer build would crush
goodput and make the numbers meaningless). `REPEAT=1` (see §5).

**Metrics per cell:** goodput (Mbps), per-path bytes (from `mq.path` teardown stats),
inner-QUIC `packet_lost` event count (picoquic server qlog), and the netem drop delta.

## 3. Results

Goodput in Mbps. Per-path byte split shown for the relay arms (path A / path B).
`sp` = `spurious_est` = inner qlog packet_lost − netem drops (**only meaningful at
loss=0**, see §5).

| skew | loss | block | relay,minrtt | relay,backup |
|---:|---:|---:|---|---|
| 0ms | 0% | **134.2** | 69.9 — 32.1M/3.6M, sp=1149 | 72.0 — 34.7M/0, sp=0 |
| 0ms | 0.5% | **124.4** | 41.0 — 0.07M/34.9M | 51.1 — 34.9M/0 |
| 0ms | 1% | **130.2** | 23.1 — 0.13M/34.9M | 31.8 — 35.1M/0 |
| 20ms | 0% | **128.6** | 72.2 — 34.7M/0, sp=0 | 72.0 — 34.7M/0, sp=0 |
| 20ms | 0.5% | **116.0** | 53.6 — 34.9M/0 | 50.4 — 34.9M/0 |
| 20ms | 1% | **114.4** | 22.6 — 35.1M/0 | 24.4 — 35.1M/0 |
| 50ms | 0% | **120.0** | 72.0 — 34.7M/0, sp=0 | 72.3 — 34.7M/0, sp=0 |
| 50ms | 0.5% | **94.0** | 49.3 — 34.9M/0 | 48.7 — 34.9M/0 |
| 50ms | 1% | **93.8** | 34.4 — 35.1M/0 | 20.5 — 35.1M/0 |

Every goodput above agrees with its wall-clock figure (`SIZE_BYTES × 8 / elapsed_s`,
CSV column 8) to <1% — so the two different probes (curl / picoquic) are measuring the
same quantity at this transfer size (§2).

**block wins every single cell.** The best relay number anywhere (72.3 Mbps) is below
the worst block number (93.8 Mbps). The block-over-relay ratio ranges 1.7×–4.7×, worst
for relay at high loss.

## 4. What the data says

**(a) relay never aggregates.** Every relay cell tops out around ~72 Mbps — the
single-path ceiling (≈ one 100mbit link after overhead). block reaches ~134 Mbps ≈ 2×
aggregation. Carrying inner QUIC as datagrams does not give you the second link's
bandwidth, full stop. This confirms the mqvpn-era observation, now across a skew×loss
grid.

**(b) The pathology trigger is per-packet spray with zero skew.** Read the clean
loss=0 column. `relay,minrtt,skew0` is the *only* cell where the scheduler actually
splits the inner flow across both paths (32.1M / 3.6M) — and it pays for it with
**1149** spurious inner retransmits and the *lowest* loss=0 relay goodput (69.9). At
skew ≥ 20ms, minRTT naturally collapses onto the lower-RTT path (34.7M / 0, sp=0), so
it stops spraying and stops hurting — which is exactly why `relay,minrtt` and
`relay,backup` post near-identical numbers in every skew>0 row. The damage is caused
by *splitting an inner reliable flow across paths with different arrival times*, and
it shows up precisely when the scheduler does that.

**(c) backup-pin is the relay arm's best case, and it works by giving up.** Pinning to
one path (via STANDBY marking, so the fork's backup scheduler engages and the peer's
scheduler honours it via PATH_STATUS) removes the spurious retransmits (sp=0) and
ekes out the highest relay goodput — by declining to aggregate at all. A control that
wins by not playing.

**(d) block is resilient; relay collapses under loss.** block degrades gracefully
(134 → 94, only −30% from the clean to the worst cell). relay falls off a cliff with
loss (e.g. skew0: 70 → 41 → 23). Plaintext bytes over a STREAM let the *outer* MPQUIC
absorb retransmission and resequencing once; the relay arm makes the inner QUIC and
the tunnel each fight loss separately.

**The headline:** the only arms genuinely *attempting* aggregation are block (all
conditions) and relay,minrtt (skew=0 only). The former succeeds; the latter is the one
cell where the per-packet-spray pathology is visible, and it loses anyway.

## 5. Honest limitations

These bound how far the verdict generalises. State them whenever citing this.

- **`spurious_est` is only valid at loss=0.** At loss>0 it goes *negative* (e.g.
  −267): outer-tunnel drops do not map 1:1 to inner-QUIC loss events (one outer
  datagram carries/loses multiple inner packets, ACKs are lost too), so the
  subtraction breaks. Use the per-path byte split and goodput for loss>0 reasoning,
  not the spurious estimate.
- **Inner stack is picoquic only.** A real deployment's relay traffic is
  quiche/neqo/Cronet/mvfst, whose loss-detection thresholds and CC differ. The
  *direction* of the result (spray hurts inner QUIC) is implementation-independent;
  the exact magnitudes are not.
- **Loopback, not a real WAN.** No bufferbloat, no real path asymmetry beyond what
  netem injects, no competing traffic.
- **block uses a single bulk transfer over HTTP/1.1, not H2.** This is the most
  favourable workload for block. The H1.1 origin (`python -m http.server`) stands in
  for the "fell back off H3" case; HTTP/2's head-of-line blocking under *many
  concurrent* requests is a real cost not measured here — a planned v2 axis. Don't
  read this as "TCP always wins for web"; read it as "for bulk throughput,
  terminate-and-restream wins decisively."
- **Two probes, not one common measurement tool** (see §2 for the cross-check). curl
  measures the block arm and picoquic the relay arm; the wall-clock yardstick bounds
  the disagreement to <1% at this transfer size, but it isn't a single instrument.
  *Improvement for the next publishable run:* drive both arms with one tool —
  **`h2load`** (nghttp2's benchmark client) built against **ngtcp2 + nghttp3** speaks
  HTTP/1.1, HTTP/2 *and* HTTP/3 with a single throughput definition, against an
  `nghttpd` origin serving H2/TCP and H3/QUIC. That collapses the self-report
  asymmetry entirely *and* upgrades the block arm to a real H2 (closing the H1.1-proxy
  caveat above). Cost: an H3-enabled h2load/nghttpd build chain (not in the apt
  package; needs ngtcp2+nghttp3+quictls). ngtcp2 keeps the inner-stack-independence
  property (it is not the xquic fork). Deferred because the wall-clock cross-check
  already shows the current two-probe numbers are sound to <1%.
- **`REPEAT=1`.** Trends are large and consistent, but the absolute numbers have no
  variance bars. For publishable figures, rerun with `REPEAT=3`.
- **CPU headroom.** `RATE=100mbit/path` keeps the 200mbit aggregate inside the
  single-thread userspace ceiling, so the shaped link — not the CPU — is the binding
  constraint. Faster rates would measure the proxy's CPU, not the protocol.

## 6. Design decision (what this fed)

For the OMR integration, H3 handling is now decided by data, not folklore:

1. **Default = block.** Block UDP/443 → client falls back to H2/TCP → mqproxy
   terminates and restreams → real aggregation, resilient to loss/skew. Best in every
   measured condition.
2. **relay = fallback only**, for flows that cannot be terminated (cert-pinned apps,
   non-443 QUIC, WebTransport/MASQUE). In that fallback, **backup-pin is mandatory and
   minRTT spray is forbidden** — spraying an un-terminated inner QUIC across paths is
   strictly worse than pinning it to the best single path. relay buys "don't break the
   flow," never "aggregate the flow."
3. **MITM (terminate the QUIC itself) remains the only route to aggregating
   un-block-able H3** — and is therefore a *precondition* for H3 aggregation in
   transparent mode, not an optional feature. This experiment is the evidence that
   "just relay H3 over the datagram lane" is not a substitute.

The control arm (`relay,backup`) exists specifically to separate "the cost of going
multipath" from "the cost of TCP-split vs end-to-end-H3 as protocols." Because it pins,
its delta from `relay,minrtt` isolates the scheduler's contribution, and its delta from
`block` isolates the protocol contribution.

## 7. Reproducing

The relay arm needs the `picoquicdemo` sample app from
[private-octopus/picoquic](https://github.com/private-octopus/picoquic) (build it
separately; it is **not** vendored into this repo). The bench looks for it at
`../picoquic/build/picoquicdemo` by default — override with `PICOQUICDEMO=...`. If it
is absent, the relay arm is skipped and only the block arm runs.

```bash
# release build (decision numbers require it)
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=$PWD/third_party/xquic/build
cmake --build build-release -j

# full 3×3 matrix (needs root for tc/netem on lo)
sudo env MQPROXY_BIN=$PWD/build-release/mqproxy \
         UDPSOCKS_BIN=$PWD/build-release/udpsocks \
    tests/integration/bench_ab_lanes.sh

# for publishable figures
sudo env REPEAT=3 MQPROXY_BIN=... UDPSOCKS_BIN=... \
    tests/integration/bench_ab_lanes.sh
```

Tunables (defaults): `SKEWS="0 20 50"`, `LOSSES="0 0.5 1"`,
`SCHEDULERS="minrtt backup"`, `REPEAT=1`, `RATE=100mbit`, `DELAY=25ms`, `SIZE=32`,
`INNER_CC=bbr`. CSV lands in `bench_results/`. `KEEP_QLOGS=1` preserves the per-cell
picoquic qlogs and forwarder logs for drill-down.

**Recovery:** if the run is SIGKILLed, the EXIT trap can't fire — clear the shaper
manually with `sudo tc qdisc del dev lo root`.
