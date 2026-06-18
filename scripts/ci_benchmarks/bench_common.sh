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

SKIP=77

# bench_require_root_netem — root + tc-on-lo capability, else exit 77. (① and ②.)
bench_require_root_netem() {
    [ "$(id -u)" -eq 0 ] || { echo "bench: not root; SKIP" >&2; exit "${SKIP}"; }
    if ! tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
        echo "bench: cannot tc on lo; SKIP" >&2; exit "${SKIP}"
    fi
    tc qdisc del dev lo root 2>/dev/null || true
}

# bench_require_capture — additionally nft + sudo + the nobody user. (③ only.)
bench_require_capture() {
    bench_require_root_netem
    command -v nft  >/dev/null || { echo "bench: no nft; SKIP"  >&2; exit "${SKIP}"; }
    command -v sudo >/dev/null || { echo "bench: no sudo; SKIP" >&2; exit "${SKIP}"; }
    id nobody >/dev/null 2>&1   || { echo "bench: no nobody; SKIP" >&2; exit "${SKIP}"; }
}

# bench_netem_lo <rate> <delay> — HTB rate (NOT netem rate) + netem delay on lo; GSO/TSO off.
bench_netem_lo() {
    local rate="${1:-100mbit}" delay="${2:-25ms}"
    ethtool -K lo gso off tso off 2>/dev/null || true
    tc qdisc del dev lo root 2>/dev/null || true
    tc qdisc add dev lo root handle 1: htb default 10
    tc class add dev lo parent 1: classid 1:10 htb rate "${rate}"
    tc qdisc add dev lo parent 1:10 handle 10: netem delay "${delay}"
}
bench_clear_lo() { tc qdisc del dev lo root 2>/dev/null || true; }

# bench_cleanup — EXIT/INT/TERM trap for NEW benchmarks (①③④). NOT for ② (it owns its
# own trap; see spec §3 #4). Register with: trap bench_cleanup EXIT INT TERM
# NOTE: the MITM client installs its REDIRECT table as `ip mqproxy` (src/ingress/
# mq_tproxy_setup.c; e2e_mitm_h2.sh cleans the same) — match that name exactly.
bench_cleanup() {
    bench_clear_lo
    nft delete table ip mqproxy 2>/dev/null || true
}

# bench_pctile_or_skip <bench> <samples_file> <metric_prefix> <meta-json>
# Shared by ③ and ④: the only real logic in the benchmark bodies, so it lives here under
# test rather than duplicated+untested in each script. Reads one float-seconds-per-line
# samples file; if <30 samples emits <prefix>_p50_ms=0 with status:insufficient_samples;
# else emits <prefix>_p50_ms, <prefix>_p99_ms (ms), and <prefix>_p99_over_p50 (ratio).
bench_pctile_or_skip() {
    local bench="$1" sf="$2" pfx="$3" meta="${4:-{\}}"
    local n; n="$(grep -c . "${sf}" 2>/dev/null || echo 0)"
    if [ "${n}" -lt 30 ]; then
        bench_emit_json "${bench}" "${pfx}_p50_ms" 0 ms "${meta}" insufficient_samples
        return 0
    fi
    local p50 p99
    read -r p50 p99 < <(python3 - "${sf}" <<'PY'
import sys
xs=sorted(float(l)*1000 for l in open(sys.argv[1]) if l.strip())
k=lambda p: xs[max(0,min(len(xs)-1,round(p/100*(len(xs)-1))))]
print(f"{k(50):.3f} {k(99):.3f}")
PY
)
    local ratio; ratio="$(awk "BEGIN{printf \"%.3f\", (${p50}>0)?${p99}/${p50}:0}")"
    bench_emit_json "${bench}" "${pfx}_p50_ms"       "${p50}"   ms    "${meta}"
    bench_emit_json "${bench}" "${pfx}_p99_ms"       "${p99}"   ms    "${meta}"
    bench_emit_json "${bench}" "${pfx}_p99_over_p50" "${ratio}" ratio "${meta}"
}
