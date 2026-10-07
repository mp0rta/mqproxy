#!/usr/bin/env bash
# ci_bench_idle.sh — Idle CPU benchmark.
#
# Brings the two-path tunnel up (one short iperf3 transfer through SOCKS5 so
# the QUIC connection and both paths are established), then waits IDLE_SEC
# seconds with no traffic and reports the CPU time (utime+stime from
# /proc/<pid>/stat fields 14+15, all threads) each mqproxy process consumed
# during that idle window.
#
# Criterion: < IDLE_LIMIT_MS (default 50) CPU-ms per process; exits 1 if not.
#
# Output: ci_bench_results/idle_<label>_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_idle.sh [path/to/mqproxy]
#
# Env:
#   MQPROXY_BIN       path to mqproxy binary (default: target/release/mqproxy)
#   MQPROXY_CERT/KEY  TLS cert/key (default: tests/certs/test.*)
#   BENCH_LABEL       name used in the output file (default: binary's parent dir)
#   IDLE_SEC          idle window in seconds (default: 10)
#   IDLE_LIMIT_MS     per-process CPU limit in ms (default: 50)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci_benchmarks/ci_bench_env.sh
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQPROXY_BIN="${1:-${MQPROXY_BIN}}"
BENCH_LABEL="${BENCH_LABEL:-$(basename "$(dirname "${MQPROXY_BIN}")")}"

IDLE_SEC="${IDLE_SEC:-10}"
IDLE_LIMIT_MS="${IDLE_LIMIT_MS:-50}"
CLK_TCK="$(getconf CLK_TCK)"

# cpu_ticks PID — utime+stime (fields 14+15) of PID, summed over its threads.
cpu_ticks() {
    local stat f
    stat="$(cat "/proc/$1/stat")" || return 1
    read -r -a f <<< "${stat##*) }"
    echo $(( f[11] + f[12] ))
}

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    echo "error: requires root (NET_ADMIN for netns/tc)" >&2
    exit 1
fi
ci_bench_check_deps
trap ci_bench_cleanup EXIT INT TERM

ci_bench_setup_netns
ci_bench_setup_routing multi
ci_bench_start_server || exit 1
ci_bench_start_client multi || exit 1

echo ""
echo "================================================================"
echo "  CI Idle CPU Benchmark"
echo "  Binary:  ${MQPROXY_BIN} (label ${BENCH_LABEL})"
echo "  Idle:    ${IDLE_SEC}s, limit ${IDLE_LIMIT_MS} ms/process, CLK_TCK=${CLK_TCK}"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

# ── Bring the tunnel up: a short transfer opens the connection + paths ──
json_warm=$(ci_bench_run_iperf 1 1)
mbps_warm=$(ci_bench_parse_throughput "${json_warm}")
echo "    warm-up transfer: ${mbps_warm} Mbps"
sleep 1  # let the warm-up's ACK/close tail drain before the idle window

c0=$(cpu_ticks "${_CB_CLIENT_PID}"); s0=$(cpu_ticks "${_CB_SERVER_PID}")
sleep "${IDLE_SEC}"
c1=$(cpu_ticks "${_CB_CLIENT_PID}"); s1=$(cpu_ticks "${_CB_SERVER_PID}")

client_ms=$(( (c1 - c0) * 1000 / CLK_TCK ))
server_ms=$(( (s1 - s0) * 1000 / CLK_TCK ))
echo "    idle ${IDLE_SEC}s: client ${client_ms} ms, server ${server_ms} ms (total since start: client $(( c1 * 1000 / CLK_TCK )) ms, server $(( s1 * 1000 / CLK_TCK )) ms)"

ci_bench_stop_proxy

verdict=PASS
if [ "${client_ms}" -ge "${IDLE_LIMIT_MS}" ] || [ "${server_ms}" -ge "${IDLE_LIMIT_MS}" ]; then
    verdict=FAIL
fi

OUTPUT_FILE="${CI_BENCH_RESULTS}/idle_${BENCH_LABEL}_$(date -u '+%Y%m%d_%H%M%S').json"
mkdir -p "${CI_BENCH_RESULTS}"
cat > "${OUTPUT_FILE}" <<JSONEOF
{
  "test": "idle",
  "binary": "${MQPROXY_BIN}",
  "label": "${BENCH_LABEL}",
  "commit": "${CI_BENCH_COMMIT}",
  "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "idle_sec": ${IDLE_SEC},
  "clk_tck": ${CLK_TCK},
  "warmup_mbps": ${mbps_warm},
  "client_idle_cpu_ms": ${client_ms},
  "server_idle_cpu_ms": ${server_ms},
  "limit_ms": ${IDLE_LIMIT_MS},
  "verdict": "${verdict}"
}
JSONEOF
cat "${OUTPUT_FILE}"
echo ""
echo "Results written to: ${OUTPUT_FILE}"
echo "Idle verdict: ${verdict}"
[ "${verdict}" = PASS ]
