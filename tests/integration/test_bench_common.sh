#!/usr/bin/env bash
# test_bench_common.sh — unit tests for bench_common.sh pure helpers (no privilege).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${REPO_ROOT}/scripts/ci_benchmarks/bench_common.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d /tmp/test_bench_common.XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT
export CI_BENCH_RESULTS_DIR="${WORK}/ci_bench_results"   # bench_common honors this override

# emit one metric; assert the JSONL line is valid + has the required keys/values
CI_BENCH_COMMIT="deadbeef" bench_emit_json proxy_overhead tunnel_overhead_pct 12.4 pct \
    '{"direct_mbps":210.5,"proxy_mbps":184.4}'

OUT="$(ls "${CI_BENCH_RESULTS_DIR}"/proxy_overhead_*.jsonl 2>/dev/null)" \
    || fail "no jsonl written (dir not auto-created?)"
line="$(cat "${OUT}")"
echo "${line}" | jq -e . >/dev/null            || fail "not valid json: ${line}"
[ "$(echo "${line}" | jq -r .bench)"  = "proxy_overhead" ]      || fail "bench key"
[ "$(echo "${line}" | jq -r .metric)" = "tunnel_overhead_pct" ] || fail "metric key"
[ "$(echo "${line}" | jq -r .value)"  = "12.4" ]                || fail "value"
[ "$(echo "${line}" | jq -r .status)" = "ok" ]                  || fail "status default ok"
[ "$(echo "${line}" | jq -r .build)"  = "release" ]             || fail "build release"
[ "$(echo "${line}" | jq -r .commit)" = "deadbeef" ]            || fail "commit"
[ "$(echo "${line}" | jq -r .meta.direct_mbps)" = "210.5" ]     || fail "meta passthrough"

# emit a skip status; assert it round-trips
bench_emit_json ab_lanes relay_goodput 0 mbps '{}' skip
sline="$(cat "${CI_BENCH_RESULTS_DIR}"/ab_lanes_*.jsonl)"
[ "$(echo "${sline}" | jq -r .status)" = "skip" ] || fail "explicit skip status"

echo "PASS test_bench_common"
