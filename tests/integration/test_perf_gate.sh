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

# Case E: full profile, 3 reps; median block(50,134,130)=130 >= median relay(40,70,60)=60 => PASS
E="$(mkdir_fixture)"
for v in 50 134 130; do emit "$E" ab_lanes block_goodput "$v" ok '{"skew_ms":0,"loss_pct":0}'; done
for v in 40 70 60;  do emit "$E" ab_lanes relay_goodput "$v" ok '{"skew_ms":0,"loss_pct":0}'; done
bash "${GATE}" "$E"; rc=$?; [ "${rc}" -eq 0 ] || fail "E: median block>=relay should pass, got ${rc}"

# Case F: full profile where MEDIAN flips a first-rep pass into a real fail.
# block reps (200,40,40) median=40; relay reps (60,60,60) median=60 => 40<60 => HARD FAIL.
# (With the old first-rep logic this would have PASSED on block rep1=200 => proves median is used.)
F="$(mkdir_fixture)"
for v in 200 40 40; do emit "$F" ab_lanes block_goodput "$v" ok '{"skew_ms":0,"loss_pct":0}'; done
for v in 60 60 60;  do emit "$F" ab_lanes relay_goodput "$v" ok '{"skew_ms":0,"loss_pct":0}'; done
bash "${GATE}" "$F"; rc=$?; [ "${rc}" -eq 1 ] || fail "F: median block<relay should hard-fail, got ${rc}"

# Case G: full profile, relay has a MIX of skip + ok reps. One flaky skip must NOT
# disarm the hard gate: the two ok relay reps (median 70) are evaluated vs block.
# block median(134,130,132)=132 >= relay median(70,72)=71 => PASS, and it must NOT
# be reported as "relay skipped".
G="$(mkdir_fixture)"
for v in 134 130 132; do emit "$G" ab_lanes block_goodput "$v" ok '{"skew_ms":0,"loss_pct":0}'; done
emit "$G" ab_lanes relay_goodput  0 skip '{"skew_ms":0,"loss_pct":0}'
emit "$G" ab_lanes relay_goodput 70 ok   '{"skew_ms":0,"loss_pct":0}'
emit "$G" ab_lanes relay_goodput 72 ok   '{"skew_ms":0,"loss_pct":0}'
out="$(bash "${GATE}" "$G")"; rc=$?
[ "${rc}" -eq 0 ] || fail "G: mixed skip+ok should pass, got ${rc}"
echo "${out}" | grep -q "relay skipped" && fail "G: must NOT report 'relay skipped' when ok reps exist"
echo "${out}" | grep -q "block_ge_relay : 132" || fail "G: should evaluate block>=relay (median 132)"

# Case H: full profile, ALL relay reps skip => invariant skipped (WARN), exit 0.
H="$(mkdir_fixture)"
emit "$H" ab_lanes block_goodput 134 ok '{"skew_ms":0,"loss_pct":0}'
for _ in 1 2 3; do emit "$H" ab_lanes relay_goodput 0 skip '{"skew_ms":0,"loss_pct":0}'; done
out="$(bash "${GATE}" "$H")"; rc=$?
[ "${rc}" -eq 0 ] || fail "H: all-skip should pass, got ${rc}"
echo "${out}" | grep -q "relay skipped" || fail "H: all-skip should report 'relay skipped'"

echo "PASS test_perf_gate"
