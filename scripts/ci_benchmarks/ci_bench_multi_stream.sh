#!/usr/bin/env bash
# ci_bench_multi_stream.sh — Weekly multi-stream sweep benchmark.
#
# Sources ci_bench_env.sh for netns topology.
# Sweeps P=1,2,4,8,16 across symmetric and asymmetric profiles.
# For each (profile, P): measures single_path and multipath throughput.
#
# Output: ci_bench_results/multi_stream_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_multi_stream.sh [path/to/mqproxy]
#
# Env:
#   MQPROXY_BIN       path to mqproxy binary (default: build/mqproxy)
#   MQPROXY_CERT/KEY  TLS cert/key (default: tests/certs/test.*)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQPROXY_BIN="${1:-${MQPROXY_BIN}}"

DURATION=10  # seconds per cell
STREAM_COUNTS=(1 2 4 8 16)

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    echo "error: requires root (NET_ADMIN for netns/tc)" >&2
    exit 1
fi
ci_bench_check_deps
trap ci_bench_cleanup EXIT INT TERM

# ── Setup netns ──
ci_bench_setup_netns
ci_bench_setup_routing multi  # policy routing for both paths

echo ""
echo "================================================================"
echo "  CI Multi-Stream Sweep Benchmark"
echo "  Binary:  ${MQPROXY_BIN}"
echo "  Streams: ${STREAM_COUNTS[*]}"
echo "  Duration: ${DURATION}s per cell"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

RESULTS_JSON="["
FIRST_ROW=1

run_profile() {
    local profile="$1"
    local delay_a="$2" rate_a="$3"
    local delay_b="$4" rate_b="$5"

    echo ""
    echo "── profile=${profile} ───────────────────────────────────────"
    ci_bench_setup_netem "${delay_a}" "${rate_a}" "${delay_b}" "${rate_b}"

    for P in "${STREAM_COUNTS[@]}"; do
        echo ""
        echo "  P=${P}: single_path..."
        ci_bench_start_server
        ci_bench_start_client single
        json_sp=$(ci_bench_run_iperf "${DURATION}" "${P}")
        mbps_sp=$(ci_bench_parse_throughput "${json_sp}")
        ci_bench_stop_proxy
        echo "    single_path: ${mbps_sp} Mbps"

        echo "  P=${P}: multipath..."
        ci_bench_start_server
        ci_bench_start_client multi
        json_mp=$(ci_bench_run_iperf "${DURATION}" "${P}")
        mbps_mp=$(ci_bench_parse_throughput "${json_mp}")
        ci_bench_stop_proxy
        echo "    multipath: ${mbps_mp} Mbps"

        # Compute gain_pct
        gain=$(python3 -c "
sp = float('${mbps_sp}')
mp = float('${mbps_mp}')
if sp > 0:
    print('%.1f' % ((mp / sp - 1) * 100))
else:
    print('null')
" 2>/dev/null || echo "null")

        if [ "${FIRST_ROW}" -eq 0 ]; then
            RESULTS_JSON="${RESULTS_JSON},"
        fi
        RESULTS_JSON="${RESULTS_JSON}
    {
      \"profile\": \"${profile}\",
      \"streams\": ${P},
      \"single_path_mbps\": ${mbps_sp},
      \"multipath_mbps\": ${mbps_mp},
      \"gain_pct\": ${gain}
    }"
        FIRST_ROW=0
    done

    ci_bench_clear_netem
}

# symmetric: 100 Mbit / 25 ms each path
run_profile symmetric 25 "100mbit" 25 "100mbit"

# asymmetric: 300 Mbit / 10 ms (path A) + 80 Mbit / 30 ms (path B)
run_profile asymmetric 10 "300mbit" 30 "80mbit"

RESULTS_JSON="${RESULTS_JSON}
]"

# ── Generate JSON output ──
echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/multi_stream_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

results_raw = json.loads("""${RESULTS_JSON}""")

output = {
    "test": "multi_stream",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "duration_sec": ${DURATION},
    "results": results_raw,
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

ci_bench_sanity_check "${OUTPUT_FILE}" "multi_stream"

echo ""
echo "================================================================"
echo "  Multi-Stream Sweep DONE"
echo "================================================================"
