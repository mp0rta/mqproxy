#!/usr/bin/env bash
# Rust HTTP gateway benchmark: download/upload x P={1,4,16}, unshaped two paths.
# Each cell must complete REPEAT positive-throughput runs with no failed transfers.
# Reports throughput and bits per CPU-second. C comparison ended with SP5.
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_gateway.sh [path/to/mqproxy]
# Env: REPEAT=3, DURATION=10, CI_BENCH_RESULTS=ci_bench_results/

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/ci_benchmarks/ci_bench_env.sh
source "${SCRIPT_DIR}/ci_bench_env.sh"

BIN_RUST="$(realpath -m "${1:-${MQPROXY_BIN_RUST:-${MQPROXY_BIN}}}")"
ORIGIN_CERT="${REPO_ROOT}/tests/certs/origin.crt"
ORIGIN_KEY="${REPO_ROOT}/tests/certs/origin.key"
ORIGIN_CA="${REPO_ROOT}/tests/certs/origin-ca.crt"

DURATION="${DURATION:-10}"
REPEAT="${REPEAT:-3}"
case "${REPEAT}" in
    ''|*[!0-9]*|0) echo "error: REPEAT must be an integer >= 1 (got '${REPEAT}')" >&2; exit 1 ;;
esac
DIRECTIONS=(download upload)
STREAM_COUNTS=(1 4 16)
GW_PORT=18080
ORIGIN_PORT=18443
BLOB_BYTES=$(( 8 * 1024 * 1024 ))
CLK_TCK="$(getconf CLK_TCK)"

# cpu_ticks PID — utime+stime (fields 14+15) of PID, summed over its threads.
cpu_ticks() {
    local stat f
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || { echo 0; return; }
    read -r -a f <<< "${stat##*) }"
    echo $(( f[11] + f[12] ))
}

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    echo "error: requires root (netns)" >&2
    exit 1
fi
for f in "${BIN_RUST}"; do
    [ -x "${f}" ] || { echo "error: binary not found or not executable: ${f}" >&2; exit 1; }
done
for f in "${MQPROXY_CERT}" "${MQPROXY_KEY}" "${ORIGIN_CERT}" "${ORIGIN_KEY}" "${ORIGIN_CA}"; do
    [ -f "${f}" ] || { echo "error: missing ${f}" >&2; exit 1; }
done
for tool in ip curl go python3; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "error: required tool not found: ${tool}" >&2; exit 1; }
done
mkdir -p "${CI_BENCH_RESULTS}"
_CB_WORK_DIR="$(mktemp -d /tmp/mqproxy_ci_bench_gw.XXXXXX)"
chmod 755 "${_CB_WORK_DIR}"

# ci_bench_cleanup also kills the origin (every pid left in the two netns).
trap ci_bench_cleanup EXIT INT TERM

# ── Origin: 8 MiB blob + Go TLS/H1 server in the server netns ──
head -c "${BLOB_BYTES}" /dev/urandom > "${_CB_WORK_DIR}/blob.bin"
if ! go build -o "${_CB_WORK_DIR}/bench_origin" "${SCRIPT_DIR}/bench_origin_server.go" \
        2> "${_CB_WORK_DIR}/go-build.log"; then
    cat "${_CB_WORK_DIR}/go-build.log" >&2
    echo "error: Go origin build failed" >&2
    exit 1
fi

ci_bench_setup_netns
ci_bench_setup_routing multi

ip netns exec "${CB_NS_SERVER}" "${_CB_WORK_DIR}/bench_origin" \
    -cert "${ORIGIN_CERT}" -key "${ORIGIN_KEY}" \
    -port "${ORIGIN_PORT}" -root "${_CB_WORK_DIR}" \
    > "${_CB_WORK_DIR}/origin.log" 2>&1 &
origin_ready=0
for _ in $(seq 50); do
    if ip netns exec "${CB_NS_SERVER}" curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CA}" \
        "https://127.0.0.1:${ORIGIN_PORT}/blob.bin"; then
        origin_ready=1
        break
    fi
    sleep 0.1
done
if [ "${origin_ready}" -ne 1 ]; then
    echo "error: origin not ready" >&2
    tail -5 "${_CB_WORK_DIR}/origin.log" >&2
    exit 1
fi

TARGET_DL="https://127.0.0.1:${ORIGIN_PORT}/blob.bin"
TARGET_UL="https://127.0.0.1:${ORIGIN_PORT}/sink"
FETCH_URL="http://127.0.0.1:${GW_PORT}/_mqproxy/fetch"

# load_worker DIR END_NS OUT — start fetches back to back until END_NS (epoch ns),
# one line per transfer: "<http_code> <size_download> <size_upload> <exitcode>".
# Runs inside the client netns (exported through declare -f).
# shellcheck disable=SC2329  # invoked through declare -f inside the netns
load_worker() {
    local dir="$1" end="$2" out="$3"
    local args=(-s -o /dev/null -w '%{http_code} %{size_download} %{size_upload} %{exitcode}\n'
                -X POST -H "X-Mq-Auth: Bearer ${CB_TOKEN}")
    if [ "${dir}" = download ]; then
        args+=(-H "X-Mq-Target: ${TARGET_DL}")
    else
        args+=(-H "X-Mq-Method: PUT" -H "X-Mq-Target: ${TARGET_UL}" -H "Expect:"
               --data-binary "@${_CB_WORK_DIR}/blob.bin")
    fi
    while [ "$(date +%s%N)" -lt "${end}" ]; do
        curl "${args[@]}" --max-time 60 "${FETCH_URL}" >> "${out}"
    done
}

# start_gateway BIN LABEL — gateway server (server netns) + gateway-only client
# (client netns, both paths); waits until a fetch through the tunnel answers 200.
start_gateway() {
    local bin="$1" label="$2"
    ip netns exec "${CB_NS_SERVER}" "${bin}" server \
        --listen "${CB_SERVER_LO}:${CB_PROXY_PORT}" \
        --token "${CB_TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        --origin-ca "${ORIGIN_CA}" \
        > "${_CB_WORK_DIR}/server-${label}.log" 2>&1 &
    _CB_SERVER_PID=$!
    ip netns exec "${CB_NS_CLIENT}" "${bin}" client \
        --server "${CB_SERVER_LO}:${CB_PROXY_PORT}" \
        --token "${CB_TOKEN}" \
        --gateway "127.0.0.1:${GW_PORT}" \
        --path "${CB_IP_A_CLIENT}" --path "${CB_IP_B_CLIENT}" \
        > "${_CB_WORK_DIR}/client-${label}.log" 2>&1 &
    _CB_CLIENT_PID=$!

    local code="" resp="${_CB_WORK_DIR}/warmup.txt"
    for _ in $(seq 100); do
        code="$(ip netns exec "${CB_NS_CLIENT}" curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            -X POST -H "X-Mq-Auth: Bearer ${CB_TOKEN}" -H "X-Mq-Target: ${TARGET_DL}" \
            "${FETCH_URL}")"
        [ "${code}" = 200 ] && break
        sleep 0.1
    done
    # Upload warm-up doubles as the sink check.
    ip netns exec "${CB_NS_CLIENT}" curl -s -o "${resp}" --max-time 10 \
        -X POST -H "X-Mq-Auth: Bearer ${CB_TOKEN}" -H "X-Mq-Method: PUT" \
        -H "X-Mq-Target: ${TARGET_UL}" -H "Expect:" \
        --data-binary "@${_CB_WORK_DIR}/blob.bin" "${FETCH_URL}"
    if [ "${code}" != 200 ] || [ "$(cat "${resp}" 2>/dev/null)" != "len=${BLOB_BYTES}" ]; then
        echo "error: ${label} gateway not ready (download ${code}, upload '$(head -c 80 "${resp}" 2>/dev/null)')" >&2
        tail -5 "${_CB_WORK_DIR}/server-${label}.log" "${_CB_WORK_DIR}/client-${label}.log" >&2
        return 1
    fi
}

echo ""
echo "================================================================"
echo "  CI Gateway Benchmark (Rust)"
echo "  Rust:    ${BIN_RUST}"
echo "  Params:  ${DURATION}s, P=${STREAM_COUNTS[*]}, REPEAT=${REPEAT}, no netem, 8 MiB transfers"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

RAW="${_CB_WORK_DIR}/raw.tsv"
: > "${RAW}"
export CB_TOKEN TARGET_DL TARGET_UL FETCH_URL _CB_WORK_DIR

impl=rust
bin="${BIN_RUST}"
for dir in "${DIRECTIONS[@]}"; do
    for p in "${STREAM_COUNTS[@]}"; do
        for rep in $(seq 1 "${REPEAT}"); do
            # A fresh pair per run: no run inherits another's state (or crash).
            run="${impl}-${dir}-P${p}-${rep}"
            start_gateway "${bin}" "${run}" || exit 1
            out="${_CB_WORK_DIR}/xfer-${run}.txt"
            : > "${out}"
            c0=$(cpu_ticks "${_CB_CLIENT_PID}"); s0=$(cpu_ticks "${_CB_SERVER_PID}")
            t0=$(date +%s%N)
            end=$(( t0 + DURATION * 1000000000 ))
            pids=()
            for w in $(seq 1 "${p}"); do
                ip netns exec "${CB_NS_CLIENT}" bash -c "$(declare -f load_worker); load_worker \"\$@\"" _ \
                    "${dir}" "${end}" "${out}.${w}" &
                pids+=($!)
            done
            wait "${pids[@]}"
            t1=$(date +%s%N)
            c1=$(cpu_ticks "${_CB_CLIENT_PID}"); s1=$(cpu_ticks "${_CB_SERVER_PID}")
            # A worker that left no output file counts as a failure.
            missing=0
            for w in $(seq 1 "${p}"); do
                [ -f "${out}.${w}" ] || missing=$(( missing + 1 ))
            done
            cat "${out}".* > "${out}" 2>/dev/null
            # Count completed 200s; anything else is a failure.
            read -r nbytes ok errs < <(awk -v d="${dir}" '
                { b = (d == "download") ? $2 : $3 }
                $4 == 0 && $1 == 200 { s += b; n++; next }
                { e++ }
                END { printf "%d %d %d\n", s, n, e }' "${out}")
            if [ "${missing}" -gt 0 ]; then
                echo "error: ${run}: ${missing} of ${p} workers left no output" >&2
                errs=$(( errs + missing ))
            fi
            if ! kill -0 "${_CB_SERVER_PID}" 2>/dev/null || ! kill -0 "${_CB_CLIENT_PID}" 2>/dev/null; then
                echo "error: ${run}: an mqproxy process died during the run" >&2
                tail -5 "${_CB_WORK_DIR}/server-${run}.log" "${_CB_WORK_DIR}/client-${run}.log" >&2
                errs=$(( errs + 1 ))
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${impl}" "${dir}" "${p}" "${rep}" \
                "${nbytes}" "$(( t1 - t0 ))" "$(( c1 - c0 ))" "$(( s1 - s0 ))" "${errs}" >> "${RAW}"
            echo "    ${impl} ${dir} P=${p} rep=${rep}: $(( nbytes * 8 * 1000 / (t1 - t0) )) Mbps," \
                 "${ok} complete, ${errs} failed, client_ticks=$(( c1 - c0 )) server_ticks=$(( s1 - s0 ))"
            ci_bench_stop_proxy
        done
    done
done
# ── JSON output + completion gate ──
OUTPUT_FILE="${CI_BENCH_RESULTS}/gateway_$(date -u '+%Y%m%d_%H%M%S').json"
python3 - "${RAW}" "${OUTPUT_FILE}" <<PYEOF
import json, statistics, sys

raw, out = sys.argv[1], sys.argv[2]
tck, repeat = ${CLK_TCK}, ${REPEAT}
expected_cells = ["%s_P%s" % (d, p) for d in "${DIRECTIONS[*]}".split() for p in "${STREAM_COUNTS[*]}".split()]
results = {"rust": {}}
for line in open(raw):
    impl, d, p, rep, nbytes, ns, cticks, sticks, errs = line.split()
    nbytes, ns, cticks, sticks = int(nbytes), int(ns), int(cticks), int(sticks)
    bits = nbytes * 8
    run = {"rep": int(rep), "bytes": nbytes, "elapsed_s": ns / 1e9, "failed": int(errs),
           "throughput_mbps": round(bits * 1e3 / ns, 2),
           "client_cpu_s": cticks / tck, "server_cpu_s": sticks / tck,
           "client_bits_per_cpu_s": bits * tck / cticks if cticks else None,
           "server_bits_per_cpu_s": bits * tck / sticks if sticks else None,
           "bits_per_cpu_s": bits * tck / (cticks + sticks) if cticks + sticks else None}
    results[impl].setdefault("%s_P%s" % (d, p), {"runs": []})["runs"].append(run)

keys = ("throughput_mbps", "client_bits_per_cpu_s", "server_bits_per_cpu_s", "bits_per_cpu_s")
for cells in results.values():
    for cell in cells.values():
        for k in keys:
            vals = [r[k] for r in cell["runs"] if r[k] is not None]
            cell["median_" + k] = statistics.median(vals) if vals else None

ok = True
for name in expected_cells:
    cell = results["rust"].get(name, {})
    runs = cell.get("runs", [])
    good = len(runs) == repeat and all(r["failed"] == 0 and r["throughput_mbps"] > 0 for r in runs)
    ok = ok and good
    print("%s: %.2f Mbps %s" % (name, cell.get("median_throughput_mbps", 0), "PASS" if good else "FAIL"))

output = {
    "test": "gateway",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "binaries": {"rust": "${BIN_RUST}"},
    "duration_sec": ${DURATION},
    "repeat": ${REPEAT},
    "transfer_bytes": ${BLOB_BYTES},
    "clk_tck": tck,
    "results": results,
    "pass": ok,
}
with open(out, "w") as f:
    json.dump(output, f, indent=2)
print("\nResults written to: %s" % out)
sys.exit(0 if ok else 1)
PYEOF
rc=$?

echo ""
echo "================================================================"
[ "${rc}" -eq 0 ] && echo "  Gateway Benchmark PASS (all cells completed, no failed transfers)" \
                 || echo "  Gateway Benchmark FAIL"
echo "================================================================"
exit "${rc}"
