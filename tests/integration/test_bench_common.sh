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

# bench_require_root_netem must return non-zero (skip) when not root, never crash.
if [ "$(id -u)" -ne 0 ]; then
    ( bench_require_root_netem ); rc=$?
    [ "${rc}" -eq 77 ] || fail "guard should exit 77 when unprivileged, got ${rc}"
fi

# bench_pctile_or_skip: ≥30 samples → emits p50/p99/ratio; <30 → insufficient_samples.
SF="${WORK}/samples.txt"; : >"${SF}"; for i in $(seq 1 40); do echo "0.0${i}" >>"${SF}"; done
bench_pctile_or_skip mitm "${SF}" mitm '{}'
[ "$(cat "${CI_BENCH_RESULTS_DIR}"/mitm_*.jsonl | jq -r 'select(.metric=="mitm_p99_over_p50").value' | head -1)" != "" ] \
    || fail "pctile helper did not emit ratio for 40 samples"
SF2="${WORK}/few.txt"; printf '0.01\n0.02\n' >"${SF2}"
bench_pctile_or_skip gateway "${SF2}" gw '{}'
[ "$(cat "${CI_BENCH_RESULTS_DIR}"/gateway_*.jsonl | jq -r 'select(.status=="insufficient_samples").metric' | head -1)" != "" ] \
    || fail "pctile helper should emit insufficient_samples for 2 samples"

echo "PASS test_bench_common"
