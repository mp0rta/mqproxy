#!/usr/bin/env bash
# test_perf_gate.sh — drive perf_gate.sh against fixture JSONL dirs, assert exit codes.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE="${REPO_ROOT}/scripts/ci_benchmarks/perf_gate.sh"
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir_fixture() { local d; d="$(mktemp -d)"; echo "${d}"; }
emit() { # emit <dir> <bench> <metric> <value> [status] [meta]
    local d="$1" b="$2" m="$3" v="$4" s="${5:-ok}" meta="${6:-{\}}"
    jq -cn --arg b "$b" --arg m "$m" --argjson v "$v" --arg s "$s" --argjson meta "$meta" \
       '{bench:$b,metric:$m,value:$v,status:$s,build:"release",meta:$meta}' \
       >>"${d}/${b}_1_1.jsonl"
}

# Case A: block >= relay  => PASS (exit 0)
A="$(mkdir_fixture)"
emit "$A" ab_lanes block_goodput 134 ok '{"skew_ms":0,"loss_pct":0}'
emit "$A" ab_lanes relay_goodput  70 ok '{"skew_ms":0,"loss_pct":0}'
bash "${GATE}" "$A"; rc=$?; [ "${rc}" -eq 0 ] || fail "A: expected pass, got ${rc}"

# Case B: block < relay at skew0/loss0 => HARD FAIL (exit 1)
B="$(mkdir_fixture)"
emit "$B" ab_lanes block_goodput  50 ok '{"skew_ms":0,"loss_pct":0}'
emit "$B" ab_lanes relay_goodput  70 ok '{"skew_ms":0,"loss_pct":0}'
bash "${GATE}" "$B"; rc=$?; [ "${rc}" -eq 1 ] || fail "B: expected hard fail, got ${rc}"

# Case C: relay status:skip => invariant SKIPPED, warn-only => PASS (exit 0)
C="$(mkdir_fixture)"
emit "$C" ab_lanes block_goodput 134 ok   '{"skew_ms":0,"loss_pct":0}'
emit "$C" ab_lanes relay_goodput   0 skip '{"skew_ms":0,"loss_pct":0}'
bash "${GATE}" "$C"; rc=$?; [ "${rc}" -eq 0 ] || fail "C: skip should not fail, got ${rc}"

# Case D: warn-only breach (overhead high) does NOT fail the build (exit 0)
D="$(mkdir_fixture)"
emit "$D" ab_lanes block_goodput 134 ok '{"skew_ms":0,"loss_pct":0}'
emit "$D" ab_lanes relay_goodput  70 ok '{"skew_ms":0,"loss_pct":0}'
emit "$D" proxy_overhead tunnel_overhead_pct 95 ok '{}'   # > 60 ceiling, but warn
bash "${GATE}" "$D"; rc=$?; [ "${rc}" -eq 0 ] || fail "D: warn must not fail, got ${rc}"

echo "PASS test_perf_gate"
