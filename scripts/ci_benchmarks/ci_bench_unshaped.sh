#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
# ci_bench_unshaped.sh — Unshaped throughput-per-CPU benchmark.
#
# Two paths, NO netem: the proxy itself is the bottleneck, so the figure of
# merit is efficiency — bits delivered per CPU-second of each mqproxy process.
# For each stream count (P=1, P=8) and each of REPEAT runs: read utime+stime
# (/proc/<pid>/stat fields 14+15, all threads) of the client and the server
# immediately before and after a DURATION-second iperf3 download through
# SOCKS5, and divide the bits transferred by each process's CPU delta.
# The figure compared across binaries is the median over the REPEAT runs.
#
# Topology: ci_bench_env.sh (2 netns, 2 veth pairs), tunnel kept up for all
# runs. iperf3 runs with -O 0 so the byte count covers the whole CPU window.
#
# Output: ci_bench_results/unshaped_<label>_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_unshaped.sh [path/to/mqproxy]
#
# Env:
#   MQPROXY_BIN       path to mqproxy binary (default: target/release/mqproxy)
#   MQPROXY_CERT/KEY  TLS cert/key (default: tests/certs/test.*)
#   BENCH_LABEL       name used in the output file (default: binary's parent dir,
#                     e.g. "build" for C, "release" for target/release)
#   REPEAT            runs per stream count (default: 5)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci_benchmarks/ci_bench_env.sh
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQPROXY_BIN="${1:-${MQPROXY_BIN}}"
BENCH_LABEL="${BENCH_LABEL:-$(basename "$(dirname "${MQPROXY_BIN}")")}"

DURATION=10
REPEAT="${REPEAT:-5}"
STREAM_COUNTS=(1 8)
CLK_TCK="$(getconf CLK_TCK)"

# cpu_ticks PID — utime+stime (fields 14+15) of PID, summed over its threads.
# Fields are counted after the ")" that closes comm (comm may hold spaces).
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

# ── Setup netns (no netem) + tunnel ──
ci_bench_setup_netns
ci_bench_setup_routing multi
ci_bench_start_server || exit 1
ci_bench_start_client multi || exit 1

echo ""
echo "================================================================"
echo "  CI Unshaped Throughput-per-CPU Benchmark"
echo "  Binary:  ${MQPROXY_BIN} (label ${BENCH_LABEL})"
echo "  Params:  ${DURATION}s, P=${STREAM_COUNTS[*]}, REPEAT=${REPEAT}, no netem, DL"
echo "  CPU:     /proc/<pid>/stat utime+stime, CLK_TCK=${CLK_TCK}"
echo "  PIDs:    client=${_CB_CLIENT_PID} ($(cat "/proc/${_CB_CLIENT_PID}/comm")) server=${_CB_SERVER_PID} ($(cat "/proc/${_CB_SERVER_PID}/comm"))"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

RAW="${_CB_WORK_DIR}/raw.tsv"
: > "${RAW}"

for p in "${STREAM_COUNTS[@]}"; do
    for rep in $(seq 1 "${REPEAT}"); do
        ip netns exec "${CB_NS_SERVER}" iperf3 -s -1 \
            -B "${CB_SERVER_LO}" -p "${CB_IPERF_PORT}" \
            > "${_CB_WORK_DIR}/iperf-server.log" 2>&1 &
        _CB_IPERF_S_PID=$!
        for _ in $(seq 50); do
            ip netns exec "${CB_NS_SERVER}" ss -ltn "src ${CB_SERVER_LO}:${CB_IPERF_PORT}" 2>/dev/null \
                | grep -q LISTEN && break
            sleep 0.1
        done

        json="${_CB_WORK_DIR}/iperf-P${p}-${rep}.json"
        c0=$(cpu_ticks "${_CB_CLIENT_PID}"); s0=$(cpu_ticks "${_CB_SERVER_PID}")
        timeout 60 ip netns exec "${CB_NS_CLIENT}" iperf3 \
            -c 127.0.0.1 -p "${CB_SOCAT_PORT}" \
            -P "${p}" -t "${DURATION}" -O 0 -R -J > "${json}" 2>&1 || true
        c1=$(cpu_ticks "${_CB_CLIENT_PID}"); s1=$(cpu_ticks "${_CB_SERVER_PID}")

        kill "${_CB_IPERF_S_PID}" 2>/dev/null || true
        wait "${_CB_IPERF_S_PID}" 2>/dev/null || true
        _CB_IPERF_S_PID=""

        bytes=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['end']['sum_received']['bytes'])" \
            "${json}" 2>/dev/null || echo 0)
        printf '%s\t%s\t%s\t%s\t%s\n' "${p}" "${rep}" "${bytes}" \
            "$(( c1 - c0 ))" "$(( s1 - s0 ))" >> "${RAW}"
        echo "    P=${p} rep=${rep}: bytes=${bytes} client_ticks=$(( c1 - c0 )) server_ticks=$(( s1 - s0 ))"
    done
done

ci_bench_stop_proxy

# ── JSON output ──
OUTPUT_FILE="${CI_BENCH_RESULTS}/unshaped_${BENCH_LABEL}_$(date -u '+%Y%m%d_%H%M%S').json"
mkdir -p "${CI_BENCH_RESULTS}"

python3 - "${RAW}" "${OUTPUT_FILE}" <<PYEOF
import json, statistics, sys

raw, out = sys.argv[1], sys.argv[2]
tck, dur = ${CLK_TCK}, ${DURATION}
results = {}
for line in open(raw):
    p, rep, nbytes, cticks, sticks = (int(x) for x in line.split())
    bits = nbytes * 8
    run = {"rep": rep, "bytes": nbytes, "throughput_mbps": round(bits / dur / 1e6, 2),
           "client_cpu_s": cticks / tck, "server_cpu_s": sticks / tck,
           "client_bits_per_cpu_s": bits * tck / cticks if cticks else None,
           "server_bits_per_cpu_s": bits * tck / sticks if sticks else None}
    results.setdefault("P%d" % p, {"runs": []})["runs"].append(run)

for cell in results.values():
    for k in ("throughput_mbps", "client_cpu_s", "server_cpu_s",
              "client_bits_per_cpu_s", "server_bits_per_cpu_s"):
        vals = [r[k] for r in cell["runs"] if r[k] is not None]
        cell["median_" + k] = statistics.median(vals) if vals else None

output = {
    "test": "unshaped",
    "binary": "${MQPROXY_BIN}",
    "label": "${BENCH_LABEL}",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "duration_sec": dur,
    "repeat": ${REPEAT},
    "clk_tck": tck,
    "results": results,
}
with open(out, "w") as f:
    json.dump(output, f, indent=2)
for name, cell in sorted(results.items()):
    print("%s: median %.1f Mbps, client %.3g bit/cpu-s, server %.3g bit/cpu-s" % (
        name, cell["median_throughput_mbps"],
        cell["median_client_bits_per_cpu_s"] or 0, cell["median_server_bits_per_cpu_s"] or 0))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

ci_bench_sanity_check "${OUTPUT_FILE}" "unshaped"

echo ""
echo "================================================================"
echo "  Unshaped Benchmark DONE"
echo "================================================================"
