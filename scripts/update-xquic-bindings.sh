#!/usr/bin/env bash
# Regenerate crates/xquic-sys/src/bindings.rs (spec §2.1).
# Requires bindgen-cli 0.72.1 (cargo install bindgen-cli --version 0.72.1 --locked)
# and libclang 18 (apt install libclang-18-dev; export LIBCLANG_PATH=/usr/lib/llvm-18/lib).
set -euo pipefail
cd "$(dirname "$0")/.."
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-18/lib}"

bindgen crates/xquic-sys/wrapper.h -o crates/xquic-sys/src/bindings.rs \
  --rust-target 1.85 --use-core --no-prepend-enum-name --disable-header-comment \
  --allowlist-function 'xqc_.*' --allowlist-type 'xqc_.*' \
  --allowlist-var 'XQC_.*' --allowlist-var 'xqc_.*' \
  --blocklist-type 'sockaddr|socklen_t|iovec' \
  --raw-line 'use libc::{sockaddr, socklen_t, iovec};' \
  -- -I third_party/xquic/include
