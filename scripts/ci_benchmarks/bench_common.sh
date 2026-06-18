#!/usr/bin/env bash
# bench_common.sh — thin sourced helpers for the CI perf benchmarks. NO executable
# entrypoint (source only). See docs/superpowers/specs/2026-06-18-perf-ci-design.md §3.
# Responsibilities: (1) skip-guards, (2) lo HTB/netem, (3) JSON emit, (4) cleanup trap.

# Resolve repo root from this file's location so callers need not set it.
_BC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_REPO_ROOT="$(cd "${_BC_DIR}/../.." && pwd)"
CI_BENCH_RESULTS_DIR="${CI_BENCH_RESULTS_DIR:-${BENCH_REPO_ROOT}/ci_bench_results}"
CI_BENCH_COMMIT="${CI_BENCH_COMMIT:-$(git -C "${BENCH_REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

# bench_emit_json <bench> <metric> <value> <unit> <meta-json> [status]
# Appends one JSONL line. Creates the results dir if absent. Default status=ok.
bench_emit_json() {
    local bench="$1" metric="$2" value="$3" unit="$4" meta="${5:-{\}}" status="${6:-ok}"
    mkdir -p "${CI_BENCH_RESULTS_DIR}"
    local ts; ts="$(date +%s)"
    local out="${CI_BENCH_RESULTS_DIR}/${bench}_${ts}_$$.jsonl"
    # jq builds the object so value/meta are correctly typed and strings escaped.
    jq -cn \
        --arg bench "${bench}" --arg metric "${metric}" \
        --argjson value "${value}" --arg unit "${unit}" \
        --arg commit "${CI_BENCH_COMMIT}" --argjson ts "${ts}" \
        --arg status "${status}" --argjson meta "${meta}" \
        '{bench:$bench,metric:$metric,value:$value,unit:$unit,commit:$commit,
          ts:$ts,build:"release",status:$status,meta:$meta}' >>"${out}"
}
