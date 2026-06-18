#!/usr/bin/env bash
# perf_gate.sh — the ONLY thing allowed to fail the perf build. Reads all JSONL in the
# results dir, evaluates a declarative invariant table, exits 1 iff a HARD invariant
# breaches. spec §6. Usage: perf_gate.sh [results_dir]
set -u
RESULTS_DIR="${1:-${CI_BENCH_RESULTS_DIR:-ci_bench_results}}"
shopt -s nullglob
FILES=("${RESULTS_DIR}"/*.jsonl)

# Collect all ok metrics into a single JSON array for jq queries.
ALL="$(cat "${FILES[@]}" 2>/dev/null | jq -sc '.' )"
[ -n "${ALL}" ] || ALL='[]'

hard_fail=0
summary=""

# value <bench> <metric>  -> prints numeric value of first matching ok metric, or empty
val() {
    echo "${ALL}" | jq -r --arg b "$1" --arg m "$2" \
        'map(select(.bench==$b and .metric==$m and (.status//"ok")=="ok")) | .[0].value // empty'
}
# value at a meta-joined cell (skew_ms==0 && loss_pct==0)
val_cell() {
    echo "${ALL}" | jq -r --arg b "$1" --arg m "$2" \
        'map(select(.bench==$b and .metric==$m and (.status//"ok")=="ok"
                    and .meta.skew_ms==0 and .meta.loss_pct==0)) | .[0].value // empty'
}
status_of() {
    echo "${ALL}" | jq -r --arg b "$1" --arg m "$2" \
        'map(select(.bench==$b and .metric==$m)) | .[0].status // "missing"'
}
record() { summary="${summary}\n$1"; }

# --- HARD: ab_lanes block >= relay at skew0/loss0 ---
relay_status="$(status_of ab_lanes relay_goodput)"
if [ "${relay_status}" = "skip" ]; then
    record "WARN  ab_lanes.block_ge_relay : relay skipped (picoquic absent)"
else
    b="$(val_cell ab_lanes block_goodput)"; r="$(val_cell ab_lanes relay_goodput)"
    if [ -z "${b}" ] || [ -z "${r}" ]; then
        record "FAIL  ab_lanes.block_ge_relay : operand missing (relay crashed?)"; hard_fail=1
    elif awk "BEGIN{exit !(${b} >= ${r})}"; then
        record "PASS  ab_lanes.block_ge_relay : ${b} >= ${r}"
    else
        record "FAIL  ab_lanes.block_ge_relay : ${b} < ${r}"; hard_fail=1
    fi
fi

# --- WARN: declarative table (never fails the build) ---
warn_check() {
    local b="$1" m="$2" op="$3" thr="$4" label="$5" v; v="$(val "$b" "$m")"
    [ -n "${v}" ] || { record "WARN  ${label} : no sample"; return; }
    if awk "BEGIN{exit !(${v} ${op} ${thr})}"; then record "PASS  ${label} : ${v} ${op} ${thr}"
    else record "WARN  ${label} : ${v} !${op} ${thr}"; fi
}
warn_check proxy_overhead tunnel_overhead_pct "<" 60  "proxy.tunnel_overhead_pct<60"
warn_check proxy_overhead proxy_goodput_mbps  ">" 1   "proxy.goodput>floor"
warn_check mitm    mitm_p99_over_p50 "<" 3.0 "mitm.p99/p50<3"
warn_check gateway gw_p99_over_p50   "<" 3.0 "gateway.p99/p50<3"

# --- Output: stdout always; $GITHUB_STEP_SUMMARY only if set ---
table="$(printf 'perf gate results:%b\n' "${summary}")"
echo "${table}"
# shellcheck disable=SC2016  # backticks are literal markdown fences, not command substitution
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '```\n%s\n```\n' "${table}" >>"${GITHUB_STEP_SUMMARY}"

exit "${hard_fail}"
