#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
# Build the pinned xquic fork for its standalone CUnit suite and diagnostics.
# The Rust application builds its own static xquic/BoringSSL through Cargo.
# Requires cmake, make, C/C++, Go and git. Usage: scripts/build-xquic.sh [--clean]
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
if [ ! -f "$XQUIC_DIR/CMakeLists.txt" ] || [ ! -f "$BSSL_DIR/CMakeLists.txt" ]; then
    echo "=== Initializing xquic submodule ==="
    git -C "$REPO_ROOT" submodule update --init --recursive third_party/xquic
fi

# ---------- 1. BoringSSL ----------

# BoringSSL is xquic's nested submodule (pinned by the xquic revision); the
# recursive submodule init above checks it out.
if [ ! -f "$BSSL_BUILD/libssl.a" ]; then
    echo "=== Building BoringSSL ==="
    cmake -S "$BSSL_DIR" -B "$BSSL_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_C_FLAGS=-fPIC \
        -DCMAKE_CXX_FLAGS=-fPIC
    cmake --build "$BSSL_BUILD" -j"$NPROC"
fi

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
