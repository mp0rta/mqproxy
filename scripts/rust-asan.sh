#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
# Run the Rust tests under AddressSanitizer.
# clang: the C side (xquic + BoringSSL) must link the same ASan runtime as Rust.
# rust-src: -Zbuild-std rebuilds std with ASan (needs the nightly rust-src component).
# Extra args pass through to cargo test, e.g. `scripts/rust-asan.sh --test engine`.
set -euo pipefail
cd "$(dirname "$0")/.."
CC=clang CXX=clang++ MQ_XQUIC_ASAN=1 RUSTFLAGS="-Zsanitizer=address" \
  cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu \
  -p xquic-sys -p mq-transport -p mq-integration "$@"
