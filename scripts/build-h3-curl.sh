#!/usr/bin/env bash
#
# build-h3-curl.sh — build an HTTP/3-capable libcurl (ngtcp2 + nghttp3) on top
# of mqproxy's already-pinned BoringSSL, into third_party/h3-curl/install.
#
# WHY THIS EXISTS:
#   The system libcurl (8.5.0 on Ubuntu) has NO HTTP/3 — so mqproxy's
#   origin-protocol selection (`X-Mq-Origin-Protocol: h3`) silently falls back
#   to the default. To actually speak h3 to an origin, libcurl must be built
#   with the ngtcp2 (QUIC) + nghttp3 (HTTP/3) stack against a QUIC-capable TLS
#   library. We reuse the BoringSSL that scripts/build-xquic.sh already builds
#   (xquic also needs BoringSSL), so there is exactly one TLS build in the tree.
#
#   This is an OPT-IN build. The default mqproxy build links the system libcurl
#   and does not need this script. Configure mqproxy against the produced curl
#   with:
#       cmake -S . -B build \
#         -DXQUIC_BUILD_DIR="$(pwd)/third_party/xquic/build" \
#         -DMQPROXY_H3_CURL="$(pwd)/third_party/h3-curl/install"
#
# DISCOVERY NOTES (why the explicit paths below):
#   The pinned BoringSSL is built STATIC-ONLY (libssl.a / libcrypto.a under
#   .../boringssl/build), is NEVER installed, and ships NO openssl.pc. So:
#     * ngtcp2's cmake cannot auto-find it → we pass -DBORINGSSL_INCLUDE_DIR /
#       -DBORINGSSL_LIBRARIES explicitly.
#     * curl's configure cannot auto-find it via pkg-config → we feed it
#       OPENSSL_CFLAGS / OPENSSL_LIBS explicitly. (PKG_CONFIG_PATH only helps
#       discover ngtcp2/nghttp3, which DO emit .pc files into $PREFIX.)
#   BoringSSL is built -fPIC (build-xquic.sh), so linking its static .a into a
#   SHARED libcurl.so is valid — that is the precondition for --enable-shared.
#   We build libcurl SHARED so the .so ABSORBS the whole static QUIC+TLS stack;
#   the mqproxy link then stays a single -lcurl (no transitive .a ordering).
#
# USAGE:
#   scripts/build-h3-curl.sh [--clean]
#
# REQUIREMENTS: cmake, make, cc/c++, git, pkg-config, tar + network (clones
#   ngtcp2/nghttp3 and downloads the curl release tarball on first run).
#   NOTE: the curl RELEASE tarball ships a pre-generated ./configure, so
#   autoconf/autoreconf are NOT required. ngtcp2/nghttp3 use cmake.
#   Not run by CI by default — it is the privileged/one-time h3 bootstrap.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

NPROC=$(nproc 2>/dev/null || echo 4)

# ---------- Pinned versions (mutually compatible stable releases) ----------
# ngtcp2 1.11.x and nghttp3 1.8.x are contemporaneous releases that interoperate;
# curl 8.13.0 supports that ngtcp2/nghttp3 API. Bump these together.
NGHTTP3_TAG="v1.8.0"
NGTCP2_TAG="v1.11.0"
CURL_VER="8.13.0"

# ---------- Paths ----------
H3_DIR="$REPO_ROOT/third_party/h3-curl"
SRC_DIR="$H3_DIR/src"
PREFIX="$H3_DIR/install"

XQUIC_DIR="$REPO_ROOT/third_party/xquic"
BSSL_DIR="$XQUIC_DIR/third_party/boringssl"
BSSL_BUILD="$BSSL_DIR/build"
BSSL_INCLUDE="$BSSL_DIR/include"

# ---------- Options ----------

if [ "${1:-}" = "--clean" ]; then
    echo "Cleaning h3-curl build directories..."
    rm -rf "$H3_DIR"
    shift
fi

# ---------- Dependency checks ----------

err=0
for cmd in cmake make cc c++ git pkg-config tar; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Please install it."
        err=1
    fi
done
if [ "$err" -ne 0 ]; then
    exit 1
fi

# ---------- 0. Reuse the pinned BoringSSL (build it if absent) ----------

if [ ! -f "$BSSL_BUILD/libssl.a" ] || [ ! -f "$BSSL_BUILD/libcrypto.a" ]; then
    echo "=== BoringSSL static libs not found — running build-xquic.sh to produce them ==="
    "$SCRIPT_DIR/build-xquic.sh"
fi
if [ ! -f "$BSSL_BUILD/libssl.a" ] || [ ! -f "$BSSL_BUILD/libcrypto.a" ]; then
    echo "ERROR: BoringSSL static libs still missing at $BSSL_BUILD after build-xquic.sh." >&2
    exit 1
fi
if [ ! -f "$BSSL_INCLUDE/openssl/ssl.h" ]; then
    echo "ERROR: BoringSSL headers missing at $BSSL_INCLUDE (no openssl/ssl.h)." >&2
    exit 1
fi

BSSL_COMMIT="$(git -C "$BSSL_DIR" rev-parse HEAD 2>/dev/null || echo '<unknown>')"
echo "=== Using BoringSSL at $BSSL_DIR (commit $BSSL_COMMIT) ==="
echo "    include: $BSSL_INCLUDE"
echo "    libs:    $BSSL_BUILD/libssl.a ; $BSSL_BUILD/libcrypto.a"

mkdir -p "$SRC_DIR" "$PREFIX"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:$PREFIX/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"

# ---------- 1. nghttp3 (no TLS dependency) ----------

NGHTTP3_SRC="$SRC_DIR/nghttp3"
if [ ! -f "$NGHTTP3_SRC/CMakeLists.txt" ]; then
    echo "=== Cloning nghttp3 ($NGHTTP3_TAG) ==="
    git clone --recursive --depth 1 --branch "$NGHTTP3_TAG" \
        https://github.com/ngtcp2/nghttp3.git "$NGHTTP3_SRC"
fi
if [ ! -f "$PREFIX/lib/pkgconfig/libnghttp3.pc" ] && \
   [ ! -f "$PREFIX/lib64/pkgconfig/libnghttp3.pc" ]; then
    echo "=== Building nghttp3 ==="
    cmake -S "$NGHTTP3_SRC" -B "$NGHTTP3_SRC/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DENABLE_LIB_ONLY=ON \
        -DENABLE_SHARED_LIB=OFF \
        -DENABLE_STATIC_LIB=ON
    cmake --build "$NGHTTP3_SRC/build" -j"$NPROC"
    cmake --install "$NGHTTP3_SRC/build"
else
    echo "=== nghttp3 already installed in $PREFIX — skipping ==="
fi

# ---------- 2. ngtcp2 (BoringSSL crypto backend, explicit paths) ----------

NGTCP2_SRC="$SRC_DIR/ngtcp2"
if [ ! -f "$NGTCP2_SRC/CMakeLists.txt" ]; then
    echo "=== Cloning ngtcp2 ($NGTCP2_TAG) ==="
    git clone --recursive --depth 1 --branch "$NGTCP2_TAG" \
        https://github.com/ngtcp2/ngtcp2.git "$NGTCP2_SRC"
fi
if [ ! -f "$PREFIX/lib/pkgconfig/libngtcp2.pc" ] && \
   [ ! -f "$PREFIX/lib64/pkgconfig/libngtcp2.pc" ]; then
    echo "=== Building ngtcp2 (BoringSSL crypto backend) ==="
    # BoringSSL is static + un-installed + no .pc, so feed ngtcp2's cmake the
    # paths explicitly (semicolon-separated CMake list for the two .a files).
    set +e
    cmake -S "$NGTCP2_SRC" -B "$NGTCP2_SRC/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DENABLE_LIB_ONLY=ON \
        -DENABLE_SHARED_LIB=OFF \
        -DENABLE_STATIC_LIB=ON \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_BORINGSSL=ON \
        -DBORINGSSL_INCLUDE_DIR="$BSSL_INCLUDE" \
        -DBORINGSSL_LIBRARIES="$BSSL_BUILD/libssl.a;$BSSL_BUILD/libcrypto.a"
    cfg_rc=$?
    set -e
    if [ "$cfg_rc" -ne 0 ]; then
        echo >&2 ""
        echo >&2 "ERROR: ngtcp2 ($NGTCP2_TAG) cmake REJECTED the pinned BoringSSL"
        echo >&2 "  ($BSSL_COMMIT at $BSSL_DIR) — almost always a QUIC-API mismatch."
        echo >&2 "  Bump the BoringSSL commit (scripts/build-xquic.sh + ci.yml cache keys) to"
        echo >&2 "  one compatible with both xquic AND ngtcp2 $NGTCP2_TAG, re-run build-xquic.sh,"
        echo >&2 "  then re-run this. Not continuing — the libcurl would lack working HTTP/3."
        exit 1
    fi
    cmake --build "$NGTCP2_SRC/build" -j"$NPROC"
    cmake --install "$NGTCP2_SRC/build"
else
    echo "=== ngtcp2 already installed in $PREFIX — skipping ==="
fi

# Sanity: the BoringSSL crypto helper must have been built (it is the proof the
# BoringSSL backend was actually enabled, not silently skipped).
if ! ls "$PREFIX"/lib*/libngtcp2_crypto_boringssl.a >/dev/null 2>&1; then
    echo "ERROR: libngtcp2_crypto_boringssl.a not found in $PREFIX — the BoringSSL" >&2
    echo "       crypto backend did not build. Cannot link an h3 libcurl." >&2
    exit 1
fi

# ---------- 3. libcurl (SHARED, with ngtcp2 + nghttp3 over BoringSSL) ----------

CURL_SRC="$SRC_DIR/curl-$CURL_VER"
CURL_TARBALL="$SRC_DIR/curl-$CURL_VER.tar.gz"
if [ ! -f "$CURL_SRC/configure" ]; then
    if [ ! -f "$CURL_TARBALL" ]; then
        echo "=== Downloading curl $CURL_VER release tarball (ships ./configure) ==="
        # Release tarball has a pre-generated configure → no autoreconf needed.
        curl -fSL -o "$CURL_TARBALL" \
            "https://github.com/curl/curl/releases/download/curl-${CURL_VER//./_}/curl-$CURL_VER.tar.gz"
    fi
    echo "=== Extracting curl $CURL_VER ==="
    tar -C "$SRC_DIR" -xzf "$CURL_TARBALL"
fi

# Stage a conventional OpenSSL-layout dir for BoringSSL (lib/ + include/), via
# symlinks (zero copy). EMPIRICAL DISCOVERY (config.log): the env form
# OPENSSL_CFLAGS/OPENSSL_LIBS is consumed ONLY when curl finds OpenSSL via
# pkg-config; BoringSSL has no .pc, so `--with-openssl` (bare) fell back to a
# pathless `-lssl -lcrypto` and curl's QUIC probe link failed with
# "undefined reference to SSL_set_quic_use_legacy_codepoint" — the symbol IS in
# libssl.a, the linker just had no -L to find it. `--with-openssl=<dir>` makes
# curl add `-L<dir>/lib -I<dir>/include`, which resolves it. (Plan Step 1.4:
# "configure's own error dictates the staged-prefix alternative.")
BSSL_STAGE="$H3_DIR/boringssl-stage"
mkdir -p "$BSSL_STAGE/lib"
ln -sf "$BSSL_BUILD/libssl.a" "$BSSL_STAGE/lib/libssl.a"
ln -sf "$BSSL_BUILD/libcrypto.a" "$BSSL_STAGE/lib/libcrypto.a"
ln -sfn "$BSSL_INCLUDE" "$BSSL_STAGE/include"

if [ ! -x "$PREFIX/bin/curl" ] || ! "$PREFIX/bin/curl" --version 2>/dev/null | grep -qi HTTP3; then
    echo "=== Building libcurl $CURL_VER (--enable-shared, h3 via ngtcp2/nghttp3) ==="
    # ngtcp2/nghttp3 are found via PKG_CONFIG_PATH ($PREFIX/lib*/pkgconfig).
    # BoringSSL is fed as a path prefix (see staging note above).
    # BoringSSL's libssl.a/libcrypto.a are C++ ARCHIVES (built from .cc) that
    # reference the C++ runtime (__cxa_*, std::exception vtables, operator
    # delete, __gxx_personality_v0). curl's autoconf probes link with the C
    # driver and no C++ runtime, so "checking for SSL_connect in -lssl" fails
    # with a wall of undefined C++ symbols → "OpenSSL libs not found". Feed the
    # C++ runtime + pthread via LIBS so the probes (and the final libcurl.so)
    # link. (This tree's other targets likewise link `stdc++` — CMakeLists.txt.)
    (
        cd "$CURL_SRC"
        ./configure \
            --prefix="$PREFIX" \
            --enable-shared \
            --disable-static \
            --with-openssl="$BSSL_STAGE" \
            --with-ngtcp2 \
            --with-nghttp3 \
            --without-libpsl \
            LIBS="-lstdc++ -lpthread"
        make -j"$NPROC"
        make install
    )
else
    echo "=== libcurl already built with HTTP3 in $PREFIX — skipping ==="
fi

# ---------- 4. Verify HTTP/3 is actually present ----------

echo ""
echo "=== Verifying $PREFIX/bin/curl reports HTTP3 ==="
if ! "$PREFIX/bin/curl" --version | grep -qi HTTP3; then
    echo "ERROR: built curl does NOT report HTTP3 in its features line:" >&2
    "$PREFIX/bin/curl" --version >&2
    exit 1
fi
"$PREFIX/bin/curl" --version | head -2

echo ""
echo "Build complete: $PREFIX/lib/libcurl.so (HTTP3 enabled)"
echo "Configure mqproxy with:"
echo "  cmake -S \"$REPO_ROOT\" -B \"$REPO_ROOT/build\" \\"
echo "    -DXQUIC_BUILD_DIR=\"$XQUIC_DIR/build\" \\"
echo "    -DMQPROXY_H3_CURL=\"$PREFIX\""
