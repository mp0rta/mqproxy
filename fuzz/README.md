# mqproxy fuzzing

In-tree [libFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses over the
wire/ingress byte-parsing attack surface (the decoders that consume
attacker-controlled bytes). Each harness compiles only the `src/*.c`
translation units it needs — no xquic / libevent / boringssl / curl — so this is
a **standalone CMake project** that builds in seconds without a submodule build.

## Build

Requires clang (libFuzzer + ASan/UBSan):

```bash
cmake -S fuzz -B build-fuzz -DCMAKE_C_COMPILER=clang
cmake --build build-fuzz
```

All harness binaries land in `build-fuzz/fuzz_*`.

## Targets

| binary | parser under test |
|---|---|
| `fuzz_varint` | `mq_varint_decode` |
| `fuzz_wire_auth_req` / `_resp` | `mq_decode_auth_req` / `_resp` |
| `fuzz_wire_connect_tcp_req` / `_resp` | `mq_decode_connect_tcp_req` / `_resp` |
| `fuzz_wire_udp_session_open` / `_resp` | `mq_decode_udp_session_open` / `_resp` |
| `fuzz_udp_msg_hdr` | `mq_udp_msg_decode_hdr` |
| `fuzz_socks5_feed` | `mq_socks5_feed` (greeting + request) |
| `fuzz_socks5_udp_hdr` | `mq_socks5_parse_udp_hdr` |
| `fuzz_http_connect` | `mq_http_connect_parse` |
| `fuzz_clienthello` | `mq_clienthello_parse` (TLS ClientHello SNI/ALPN peek) |

## Run

Replay the committed corpus (deterministic — this is the CI regression gate):

```bash
./build-fuzz/<target> fuzz/corpus/<target>/*
```

Explore for new bugs (time-boxed):

```bash
./build-fuzz/<target> fuzz/corpus/<target> -max_total_time=30
```

Corpus dir name = binary name minus the `fuzz_` prefix
(`fuzz_wire_auth_req` → `fuzz/corpus/wire_auth_req/`).

## On a crash (regression discipline)

```bash
./build-fuzz/<target> -minimize_crash=1 -runs=10000 <crashfile>   # minimize
cp <minimized> fuzz/corpus/<target>/                              # commit the reproducer
```

Then fix the bug. The committed reproducer is replayed on every CI run, so a
crash found once can never silently return.

## Seed (re)generation

Wire seeds are produced by `fuzz/scripts/gen_wire_seeds.c` (a non-built helper).
To regenerate, compile and run it **per the command in its header comment** —
that comment is the single source of truth; it is not duplicated here.
