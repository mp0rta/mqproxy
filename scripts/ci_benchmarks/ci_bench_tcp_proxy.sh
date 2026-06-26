#!/usr/bin/env bash
# ci_bench_tcp_proxy.sh — Per-commit TCP proxy throughput benchmark.
#
# Measures TCP proxy overhead and multipath aggregation:
#   1. direct      — iperf3 path A only, no proxy (raw link ceiling)
#   2. single_path — mqproxy, 1 path (proxy overhead baseline)
#   3. multipath   — mqproxy, 2 paths (aggregation measurement)
#
# Topology: 2 netns, 2 veth pairs, symmetric 100 Mbit / 25 ms each path.
# Duration: 10 s, P=4, DL only. iperf3 uses -O 2 (2 s omit / warmup).
#
# Output: ci_bench_results/tcp_proxy_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_tcp_proxy.sh [path/to/mqproxy]
#
# Env:
#   MQPROXY_BIN    path to mqproxy binary (default: build/mqproxy)
#   MQPROXY_CERT   TLS cert (default: tests/certs/test.crt)
#   MQPROXY_KEY    TLS key  (default: tests/certs/test.key)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQPROXY_BIN="${1:-${MQPROXY_BIN}}"

DURATION=10
PARALLEL=4
# symmetric: 100 Mbit / 25 ms per path
DELAY_A=25; RATE_A="100mbit"
DELAY_B=25; RATE_B="100mbit"

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    echo "error: requires root (NET_ADMIN for netns/tc)" >&2
    exit 1
fi
ci_bench_check_deps
trap ci_bench_cleanup EXIT INT TERM

# ── Setup netns topology ──
ci_bench_setup_netns

echo ""
echo "================================================================"
echo "  CI TCP Proxy Benchmark"
echo "  Binary:  ${MQPROXY_BIN}"
echo "  Profile: symmetric ${RATE_A}/${DELAY_A}ms each path"
echo "  Params:  ${DURATION}s duration, P=${PARALLEL} streams, DL"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Apply netem ──
ci_bench_setup_netem "${DELAY_A}" "${RATE_A}" "${DELAY_B}" "${RATE_B}"

# ── Variant 1: direct ──
echo ""
echo "==> Variant 1/3: direct (no proxy, path A only)"
ci_bench_setup_routing direct
json_direct=$(ci_bench_run_iperf_direct "${DURATION}" "${PARALLEL}")
mbps_direct=$(ci_bench_parse_throughput "${json_direct}")
echo "    direct: ${mbps_direct} Mbps"
ci_bench_reset_routing

# ── Variant 2: single_path ──
echo ""
echo "==> Variant 2/3: single_path (mqproxy, 1 path)"
ci_bench_setup_routing single
ci_bench_start_server
ci_bench_start_client single
json_single=$(ci_bench_run_iperf "${DURATION}" "${PARALLEL}")
mbps_single=$(ci_bench_parse_throughput "${json_single}")
echo "    single_path: ${mbps_single} Mbps"
ci_bench_stop_proxy
ci_bench_reset_routing

# ── Variant 3: multipath ──
echo ""
echo "==> Variant 3/3: multipath (mqproxy, 2 paths)"
ci_bench_setup_routing multi
ci_bench_start_server
ci_bench_start_client multi
json_multi=$(ci_bench_run_iperf "${DURATION}" "${PARALLEL}")
mbps_multi=$(ci_bench_parse_throughput "${json_multi}")
echo "    multipath: ${mbps_multi} Mbps"
ci_bench_stop_proxy
ci_bench_reset_routing

# ── Generate JSON output ──
echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/tcp_proxy_$(date -u '+%Y%m%d_%H%M%S').json"
mkdir -p "${CI_BENCH_RESULTS}"

python3 <<PYEOF
import json

direct = float("${mbps_direct}")
single = float("${mbps_single}")
multi  = float("${mbps_multi}")

aggregation_ratio = round(multi / direct, 3) if direct > 0 else None
overhead_single   = round((1 - single / direct) * 100, 1) if direct > 0 else None

output = {
    "test": "tcp_proxy",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "profile": "symmetric",
    "duration_sec": ${DURATION},
    "parallel_streams": ${PARALLEL},
    "results": {
        "DL": {
            "direct_mbps":      direct,
            "single_path_mbps": single,
            "multipath_mbps":   multi,
        }
    },
    "aggregation_ratio": aggregation_ratio,
    "overhead_pct": {
        "single_path": overhead_single,
    },
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

ci_bench_sanity_check "${OUTPUT_FILE}" "tcp_proxy"

echo ""
echo "================================================================"
echo "  TCP Proxy Benchmark DONE"
echo "================================================================"
