#!/usr/bin/env bash
#
# build-xquic.sh — build mqproxy's in-tree xquic submodule with qlog enabled.
#
# WHY THIS EXISTS:
#   mqproxy currently links the xquic build that lives under the SIBLING mqvpn
#   checkout (mqvpn/third_party/xquic/build). That coupling is a stopgap. The
#   clean end-state is for mqproxy to build its OWN submodule
#   (third_party/xquic, pinned to the same commit as mqvpn) so the two repos
#   are decoupled. This script is that decoupling: it builds
#   third_party/xquic into third_party/xquic/build/libxquic.so.
#
#   It mirrors mqvpn/build.sh's BoringSSL + xquic steps, with one critical
#   addition: -DXQC_ENABLE_EVENT_LOG=ON.
#
# WHY -DXQC_ENABLE_EVENT_LOG=ON IS REQUIRED:
#   The qlog-based milestone 1-B benchmark (tests/integration/e2e_multipath.sh)
#   and the unit test `test_qlog_blocked` both assert on qlog EXTRA-importance
#   events (frames_processed, xqc_parse_*_blocked_frame). Those events are only
#   emitted when xquic is compiled with XQC_ENABLE_EVENT_LOG=ON. A stock xquic
#   build will make those assertions vacuous (empty qlog) or fail outright.
#   => Any xquic you point mqproxy at for those tests MUST have this flag on.
#
# USAGE:
#   scripts/build-xquic.sh [--clean]
#   Then configure mqproxy against the produced build:
#     cmake -S . -B build \
#       -DXQUIC_BUILD_DIR="$(pwd)/third_party/xquic/build"
#
# REQUIREMENTS: cmake, make, cc, git, time + network (clones BoringSSL on first
#   run). Not run by CI automatically — it is the privileged/one-time bootstrap.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

NPROC=$(nproc 2>/dev/null || echo 4)

XQUIC_DIR="$REPO_ROOT/third_party/xquic"
XQUIC_BUILD="$XQUIC_DIR/build"
BSSL_DIR="$XQUIC_DIR/third_party/boringssl"
BSSL_BUILD="$BSSL_DIR/build"

# ---------- Options ----------

if [ "${1:-}" = "--clean" ]; then
    echo "Cleaning xquic + boringssl build directories..."
    rm -rf "$XQUIC_BUILD"
    rm -rf "$BSSL_BUILD"
    shift
fi

# ---------- Dependency checks ----------

err=0
for cmd in cmake make cc git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: '$cmd' not found. Please install it."
        err=1
    fi
done
if [ "$err" -ne 0 ]; then
    exit 1
fi

# Ensure the submodule is checked out.
if [ ! -f "$XQUIC_DIR/CMakeLists.txt" ]; then
    echo "=== Initializing xquic submodule ==="
    git -C "$REPO_ROOT" submodule update --init --recursive third_party/xquic
fi

# ---------- 1. BoringSSL ----------

# BoringSSL is not a git submodule of xquic; clone it if absent (mirrors mqvpn).
if [ ! -f "$BSSL_DIR/CMakeLists.txt" ]; then
    echo "=== Cloning BoringSSL ==="
    git clone https://github.com/google/boringssl.git "$BSSL_DIR"
fi

echo "=== Building BoringSSL ==="
mkdir -p "$BSSL_BUILD"
if [ ! -f "$BSSL_BUILD/CMakeCache.txt" ]; then
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_CXX_FLAGS="-fPIC"
fi
make -C "$BSSL_BUILD" -j"$NPROC" ssl crypto

# ---------- 2. xquic (with qlog / event-log enabled) ----------

echo "=== Building xquic (XQC_ENABLE_EVENT_LOG=ON) ==="
mkdir -p "$XQUIC_BUILD"
# Re-configure if the cache is missing OR was configured WITHOUT the qlog flag
# (a prior stock build would otherwise silently lack the qlog events the
# 1-B benchmark + test_qlog_blocked depend on).
NEED_CONFIGURE=0
if [ ! -f "$XQUIC_BUILD/CMakeCache.txt" ]; then
    NEED_CONFIGURE=1
elif ! grep -q "^XQC_ENABLE_EVENT_LOG:BOOL=ON" "$XQUIC_BUILD/CMakeCache.txt"; then
    echo "  Existing xquic build lacks XQC_ENABLE_EVENT_LOG — wiping and reconfiguring"
    rm -rf "$XQUIC_BUILD"
    mkdir -p "$XQUIC_BUILD"
    NEED_CONFIGURE=1
fi
if [ "$NEED_CONFIGURE" -eq 1 ]; then
    cmake -S "$XQUIC_DIR" -B "$XQUIC_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSSL_TYPE=boringssl \
        -DSSL_PATH="$BSSL_DIR" \
        -DXQC_ENABLE_EVENT_LOG=ON \
        -DXQC_ENABLE_BBR2=ON \
        -DXQC_ENABLE_UNLIMITED=ON \
        -DXQC_ENABLE_FEC=ON \
        -DXQC_ENABLE_XOR=ON
fi
make -C "$XQUIC_BUILD" -j"$NPROC"

# ---------- Done ----------

echo ""
echo "Build complete: $XQUIC_BUILD/libxquic.so"
echo "Configure mqproxy with:"
echo "  cmake -S \"$REPO_ROOT\" -B \"$REPO_ROOT/build\" \\"
echo "    -DXQUIC_BUILD_DIR=\"$XQUIC_BUILD\""
