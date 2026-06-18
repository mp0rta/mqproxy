# Building from Source

**Requirements:** `cmake`, `make`, a C11 compiler, `git`, the `openssl` CLI (used at configure time to generate the bundled test certificates), `libevent`, `libcurl` dev headers (e.g. `libcurl4-openssl-dev` — the gateway's origin client), `libnghttp2` dev headers (`libnghttp2-dev` — HTTP/2 termination for the TLS MITM L7 path; the static binary additionally needs the bundled `libnghttp2.a`), and `golang` (BoringSSL's build needs Go). Network access is required on first build (BoringSSL is cloned).

On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential cmake git openssl \
  libevent-dev libcurl4-openssl-dev libnghttp2-dev golang-go
```

::: tip Runtime packaging dependency
The dynamically-linked binary depends on the nghttp2 shared library (Debian/Ubuntu package `libnghttp2-14`). The `-DMQPROXY_STATIC_XQUIC=ON` packaging binary instead statically links `libnghttp2.a` and so carries no runtime nghttp2 dependency.
:::

## Build steps

```bash
# 1. Clone with the xquic submodule
git clone --recursive https://github.com/mp0rta/mqproxy.git
cd mqproxy
# (if you cloned without --recursive: git submodule update --init --recursive)

# 2. Build the in-tree xquic (BoringSSL + xquic, with qlog enabled)
#    Produces third_party/xquic/build/libxquic.so. Pins BoringSSL to a known commit.
./scripts/build-xquic.sh

# 3. Configure + build mqproxy against that xquic
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build"
cmake --build build -j"$(nproc)"

# The binary is at build/mqproxy
./build/mqproxy --help
```

Once built, head to the [Quick Start](./quick-start) to run a server/client pair locally. To run mqproxy as a managed service, see [Installation](./installation).
