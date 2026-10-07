#!/usr/bin/env bash
# ci_bench_mitm.sh — Per-commit MITM H2 throughput benchmark; Rust vs C when
# MQPROXY_BIN_RUST is set (SP4 spec §11.5).
#
# Standalone loopback topology (does NOT source ci_bench_env.sh).
# Measures MITM proxy throughput with tc-netem shaping on lo.
# Follows e2e_mitm_h2.sh for MITM setup, e2e_multipath.sh for tc shaping.
#
# Origin: Go TLS server (bench_origin_server.go) — goroutine-per-connection,
# no GIL bottleneck.  Replaced the Python HTTP/1.1 origin that capped
# multipath throughput at ~150 Mbps.
#
# Measurement: P=4 parallel H2 streams via curl --parallel (matches TCP proxy
# bench P=4).  Aggregate throughput = sum(bytes) / max(time) across streams.
#
# Variants:
#   1. single_path — path A only (127.0.0.2)
#   2. multipath   — path A (127.0.0.2) + path B (127.0.0.3)
#
# Each run starts a fresh server + client pair. CPU seconds of both mqproxy
# processes over the curl window come from /proc/<pid>/stat (utime+stime).
#
# Modes:
#   single binary (MQPROXY_BIN_RUST unset): one run per variant, positive-
#     throughput check only. Output: ci_bench_results/mitm_<timestamp>.json
#   Rust vs C (MQPROXY_BIN_RUST set): REPEAT runs per variant and binary,
#     interleaved C/Rust, median per cell, ratio table Rust / C. Exits non-zero
#     when any throughput ratio is below GATE (0.95), when a Rust transfer
#     failed or a Rust process died, or when a cell lacks REPEAT runs. C
#     failures and bits/CPU-s are reported, not gated.
#     Output: ci_bench_results/mitm_rust_vs_c_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_mitm.sh [path/to/mqproxy]
#        sudo MQPROXY_BIN_C=target/release/mqproxy MQPROXY_BIN_RUST=target/release/mqproxy \
#            bash scripts/ci_benchmarks/ci_bench_mitm.sh
#
# Env:
#   MQPROXY_BIN       path to mqproxy binary (default: target/release/mqproxy)
#   MQPROXY_BIN_C     the C binary in Rust-vs-C mode (default: MQPROXY_BIN)
#   MQPROXY_BIN_RUST  the Rust binary; set to enable Rust-vs-C mode
#   REPEAT            runs per cell in Rust-vs-C mode (default: 3)
#   MQPROXY_CERT/KEY  tunnel TLS cert/key (default: tests/certs/test.*)
#   MQ_MITM_CA_CRT    MITM CA cert (default: tests/certs/mitm-ca.crt)
#   MQ_MITM_CA_KEY    MITM CA key  (default: tests/certs/mitm-ca.key)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../" && pwd)"

MQPROXY_BIN="${1:-${MQPROXY_BIN_C:-${MQPROXY_BIN:-${REPO_ROOT}/target/release/mqproxy}}}"
BIN_RUST="${MQPROXY_BIN_RUST:-}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
MITM_CA_CRT="${MQ_MITM_CA_CRT:-${REPO_ROOT}/tests/certs/mitm-ca.crt}"
MITM_CA_KEY="${MQ_MITM_CA_KEY:-${REPO_ROOT}/tests/certs/mitm-ca.key}"
CI_BENCH_RESULTS="${CI_BENCH_RESULTS:-${REPO_ROOT}/ci_bench_results}"
CI_BENCH_COMMIT="${CI_BENCH_COMMIT:-$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"
SERVER_IP="127.0.0.1"
MITM_HOST="ci-bench-mitm.test"
HOSTS_LINE="127.0.0.1 ${MITM_HOST}"

DURATION=10      # curl max-time per stream (seconds)
PARALLEL=4       # H2 streams (matches TCP proxy bench P=4)
RATE="100mbit"   # per-path bandwidth
DELAY="25ms"     # per-path one-way delay (RTT ≈ 2×delay)
BLOB_MB=128      # origin blob size
GATE=0.95        # Rust/C throughput floor (Rust-vs-C mode)
REPEAT="${REPEAT:-3}"
case "${REPEAT}" in
    ''|*[!0-9]*|0) echo "error: REPEAT must be an integer >= 1 (got '${REPEAT}')" >&2; exit 1 ;;
esac
CLK_TCK="$(getconf CLK_TCK)"

# cpu_ticks PID — utime+stime (fields 14+15) of PID, summed over its threads.
cpu_ticks() {
    local stat f
    stat="$(cat "/proc/$1/stat" 2>/dev/null)" || { echo 0; return; }
    read -r -a f <<< "${stat##*) }"
    echo $(( f[11] + f[12] ))
}

SKIP=77
note() { printf '%s\n' "ci_bench_mitm: $*" >&2; }

# ── State ──
WORK=""
ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""
QUIC_PORT=""
TPROXY_PORT=""
ORIGIN_PORT=""
HOSTS_BACKED_UP=0

# ── Preflight ──
if [ "$(id -u)" -ne 0 ]; then
    note "SKIP: requires root (NET_ADMIN for nft/tc)"
    exit "${SKIP}"
fi

if ! command -v nft >/dev/null 2>&1; then
    note "SKIP: nft (nftables) not found"
    exit "${SKIP}"
fi
if ! nft add table ip mqproxy_mitm_probe 2>/dev/null; then
    note "SKIP: cannot add nft table (no CAP_NET_ADMIN?)"
    exit "${SKIP}"
fi
nft delete table ip mqproxy_mitm_probe 2>/dev/null || true

for tool in curl openssl sudo python3 tc go; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        note "SKIP: required tool not found: ${tool}"
        exit "${SKIP}"
    fi
done

if ! id nobody >/dev/null 2>&1; then
    note "SKIP: user 'nobody' not found (required for curl capture)"
    exit "${SKIP}"
fi

if ! curl --version 2>/dev/null | grep -qi 'HTTP2'; then
    note "SKIP: curl lacks HTTP/2 support"
    exit "${SKIP}"
fi

for f in "${MQPROXY_BIN}" ${BIN_RUST:+"${BIN_RUST}"}; do
    if [ ! -x "${f}" ]; then
        note "error: mqproxy binary not found: ${f}" >&2
        exit 1
    fi
done
for f in "${MQPROXY_CERT}" "${MQPROXY_KEY}" "${MITM_CA_CRT}" "${MITM_CA_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "SKIP: cert/key missing: ${f}"
        exit "${SKIP}"
    fi
done

# ── Port selection ──
free_port() {
    python3 - "$1" <<'PY'
import socket, sys
kind = sys.argv[1]
t = socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM
s = socket.socket(socket.AF_INET, t)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
QUIC_PORT="$(free_port udp)"
TPROXY_PORT="$(free_port tcp)"
ORIGIN_PORT="$(free_port tcp)"
while [ "${ORIGIN_PORT}" = "${TPROXY_PORT}" ]; do
    ORIGIN_PORT="$(free_port tcp)"
done

# ── Workspace ──
WORK="$(mktemp -d /tmp/mqproxy_ci_bench_mitm.XXXXXX)"
chmod 755 "${WORK}"
mkdir -p "${CI_BENCH_RESULTS}"

ORIGIN_CERT="${WORK}/origin.crt"
ORIGIN_KEY="${WORK}/origin.key"
ORIGIN_CA="${WORK}/origin-ca.crt"
ORIGIN_CA_KEY="${WORK}/origin-ca.key"
MITM_CA_CRT_RUN="${WORK}/ca.crt"
MITM_CA_KEY_RUN="${WORK}/ca.key"
BLOB_FILE="${WORK}/blob.bin"

# ── tc loopback shaping helpers ──
setup_tc() {
    local path_count="$1"  # 1 or 2

    # HTB root + netem per path via u32 src/dst filters.
    # Matches the proven e2e_multipath.sh layout:
    #   - default class 1:1 at 10gbit for unmatched traffic (origin fetch,
    #     curl→nft, etc.) — WITHOUT a valid default class HTB can pass
    #     packets unshaped, defeating the bench.
    #   - quantum 1514 prevents large-burst dequeuing that causes spurious
    #     loss under netem, which confuses BBR's pacing.
    # Use `replace` (not del+add) to avoid a race where the kernel hasn't
    # finished tearing down the old qdisc before the new add arrives.
    tc qdisc replace dev lo root handle 1: htb default 1
    tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
    tc class add dev lo parent 1: classid 1:10 htb rate "${RATE}" ceil "${RATE}" quantum 1514
    tc qdisc add dev lo parent 1:10 handle 10: netem delay "${DELAY}" limit 25000
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip src "${PATH_A_IP}/32" flowid 1:10
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip dst "${PATH_A_IP}/32" flowid 1:10

    if [ "${path_count}" -eq 2 ]; then
        tc class add dev lo parent 1: classid 1:11 htb rate "${RATE}" ceil "${RATE}" quantum 1514
        tc qdisc add dev lo parent 1:11 handle 11: netem delay "${DELAY}" limit 25000
        tc filter add dev lo protocol ip parent 1: prio 1 u32 \
            match ip src "${PATH_B_IP}/32" flowid 1:11
        tc filter add dev lo protocol ip parent 1: prio 1 u32 \
            match ip dst "${PATH_B_IP}/32" flowid 1:11
    fi

    # Netlink fence: force a round-trip so the kernel finishes installing
    # the qdisc/classes/filters before any traffic flows. Without this,
    # packets arriving before filters are ready fall to the unshaped default.
    tc qdisc show dev lo > /dev/null 2>&1
}

clear_tc() {
    tc qdisc del dev lo root 2>/dev/null || true
}

# ── Cleanup ──
cleanup() {
    local rc=$?
    set +e

    # Kill client first (runs nft teardown)
    if [ -n "${CLIENT_PID}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null
        wait "${CLIENT_PID}" 2>/dev/null
    fi
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null && wait "${SERVER_PID}" 2>/dev/null || true
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null && wait "${ORIGIN_PID}" 2>/dev/null || true

    nft delete table ip mqproxy 2>/dev/null || true
    clear_tc

    if [ "${HOSTS_BACKED_UP}" -eq 1 ] && [ -f "${WORK}/hosts.bak" ]; then
        cp "${WORK}/hosts.bak" /etc/hosts 2>/dev/null || \
            sed -i "/ ${MITM_HOST}\$/d" /etc/hosts 2>/dev/null || true
    fi

    rm -rf "${WORK}" 2>/dev/null || true
    exit "${rc}"
}
trap cleanup EXIT INT TERM

# ── Mint origin CA + leaf ──
# A CA:FALSE leaf under a separate CA: the Rust server verifies with webpki,
# which rejects a self-signed cert used as its own end entity.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${ORIGIN_CA_KEY}" -out "${ORIGIN_CA}" -days 2 \
    -subj "/CN=mqproxy-bench-origin-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${ORIGIN_KEY}" -out "${WORK}/origin.csr" \
    -subj "/CN=${MITM_HOST}" >/dev/null 2>&1
printf '%s\n' \
    "subjectAltName=DNS:${MITM_HOST},DNS:localhost,IP:127.0.0.1" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" >"${WORK}/origin-ext.cnf"
openssl x509 -req -in "${WORK}/origin.csr" -CA "${ORIGIN_CA}" \
    -CAkey "${ORIGIN_CA_KEY}" -CAcreateserial -days 2 \
    -extfile "${WORK}/origin-ext.cnf" -out "${ORIGIN_CERT}" >/dev/null 2>&1

# Stage root-owned CA copies (mq_mitm_core requires ca.key owned by euid)
cp "${MITM_CA_CRT}" "${MITM_CA_CRT_RUN}" && chmod 644 "${MITM_CA_CRT_RUN}"
cp "${MITM_CA_KEY}" "${MITM_CA_KEY_RUN}" && chmod 600 "${MITM_CA_KEY_RUN}"

# ── Create blob ──
note "Generating ${BLOB_MB}MB origin blob..."
dd if=/dev/urandom of="${BLOB_FILE}" bs=1M count="${BLOB_MB}" 2>/dev/null
chmod 644 "${BLOB_FILE}"
BLOB_BASENAME="$(basename "${BLOB_FILE}")"

# ── Build + start Go TLS origin ──
note "Building Go origin server..."
ORIGIN_BIN="${WORK}/bench_origin"
if ! go build -o "${ORIGIN_BIN}" "${SCRIPT_DIR}/bench_origin_server.go" 2>"${WORK}/go-build.log"; then
    cat "${WORK}/go-build.log" >&2
    note "error: Go origin build failed" >&2; exit 1
fi

"${ORIGIN_BIN}" \
    -cert "${ORIGIN_CERT}" -key "${ORIGIN_KEY}" \
    -port "${ORIGIN_PORT}" -root "${WORK}" \
    > "${WORK}/origin.log" 2>&1 &
ORIGIN_PID=$!

# Wait for origin to be ready
for _ in $(seq 1 50); do
    if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
        note "error: TLS origin died on startup" >&2; exit 1
    fi
    if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CA}" \
        "https://localhost:${ORIGIN_PORT}/" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# ── /etc/hosts entry ──
cp /etc/hosts "${WORK}/hosts.bak"
HOSTS_BACKED_UP=1
printf '%s\n' "${HOSTS_LINE}" >> /etc/hosts

# Small file for the warm-up request (tunnel up + leaf forged before timing).
printf 'ok\n' > "${WORK}/warm.txt"
chmod 644 "${WORK}/warm.txt"

# ── measure_variant BIN PATH_MODE LABEL — run one MITM bench variant ──
# Sets MV_OUT="<mbps> <bytes> <client_ticks> <server_ticks> <failed>". Runs in
# the main shell (no $(...)), so the EXIT trap sees SERVER_PID/CLIENT_PID.
measure_variant() {
    local bin="$1" path_mode="$2" label="$3"  # path_mode: single | multi
    local path_count
    [ "${path_mode}" = "single" ] && path_count=1 || path_count=2

    # Apply tc shaping (setup_tc uses replace, no separate clear needed)
    setup_tc "${path_count}"

    # Fresh server per run: no run inherits another's state.
    "${bin}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" \
        --token "ci-mitm-bench" \
        --cert "${MQPROXY_CERT}" \
        --key "${MQPROXY_KEY}" \
        --origin-ca "${ORIGIN_CA}" \
        > "${WORK}/server-${label}.log" 2>&1 &
    SERVER_PID=$!
    sleep 1

    # Build path args for client
    local path_args="--path ${PATH_A_IP}"
    [ "${path_mode}" = "multi" ] && path_args="${path_args} --path ${PATH_B_IP}"

    # Start client
    # shellcheck disable=SC2086
    "${bin}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "ci-mitm-bench" \
        --tproxy "127.0.0.1:${TPROXY_PORT}" \
        --tproxy-mode redirect \
        --tproxy-dport "${ORIGIN_PORT}" \
        --setup-redirect \
        --tproxy-uid 0 \
        --mitm \
        --ca-cert "${MITM_CA_CRT_RUN}" \
        --ca-key "${MITM_CA_KEY_RUN}" \
        ${path_args} \
        > "${WORK}/client-${label}.log" 2>&1 &
    CLIENT_PID=$!

    # Wait for MITM client ready (nft rules installed + tunnel up)
    local ready=0
    for _ in $(seq 1 80); do
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            break
        fi
        if grep -q "REDIRECT rules installed" "${WORK}/client-${label}.log" 2>/dev/null || \
           nft list table ip mqproxy 2>/dev/null | grep -q REDIRECT; then
            ready=1; break
        fi
        sleep 0.15
    done

    # Warm-up through the MITM: the tunnel is up and the leaf is forged.
    if [ "${ready}" -eq 1 ]; then
        ready=0
        for _ in $(seq 1 50); do
            if [ "$(sudo -u nobody curl -s -o /dev/null -w '%{http_code}' --http2 --max-time 2 \
                    --cacert "${MITM_CA_CRT_RUN}" \
                    "https://${MITM_HOST}:${ORIGIN_PORT}/warm.txt" 2>/dev/null)" = 200 ]; then
                ready=1; break
            fi
            sleep 0.2
        done
    fi

    local mbps="0.0" nbytes=0 errs=0 c0 s0 c1 s1
    c0=$(cpu_ticks "${CLIENT_PID}"); s0=$(cpu_ticks "${SERVER_PID}")
    if [ "${ready}" -eq 1 ]; then
        # P parallel H2 streams over one multiplexed connection
        local curl_outputs="" curl_urls=""
        for _ in $(seq 1 "${PARALLEL}"); do
            curl_outputs="${curl_outputs} -o /dev/null"
            curl_urls="${curl_urls} https://${MITM_HOST}:${ORIGIN_PORT}/${BLOB_BASENAME}"
        done

        local stat_file="${WORK}/curl-stats-${label}.txt"
        # shellcheck disable=SC2086,SC2024
        sudo -u nobody \
            curl --http2 --cacert "${MITM_CA_CRT_RUN}" \
            --parallel --parallel-max "${PARALLEL}" \
            ${curl_outputs} \
            --max-time "${DURATION}" \
            -w '%{size_download} %{time_total} %{http_code} %{exitcode}\n' \
            ${curl_urls} \
            > "${stat_file}" 2>/dev/null || true

        # Aggregate: throughput = sum(bytes) * 8 / max(time) / 1e6
        mbps=$(awk '{b+=$1; if($2>t)t=$2} END{if(t>0) printf "%.2f\n",b*8/t/1e6; else print "0.0"}' \
            "${stat_file}" 2>/dev/null || echo "0.0")
        # A transfer is good with a 200 and exit 0 or 28 (--max-time ends it).
        read -r nbytes errs < <(awk -v p="${PARALLEL}" '
            { b += $1; n++ }
            $3 != 200 || ($4 != 0 && $4 != 28) || $1 == 0 { e++ }
            END { if (n < p) e += p - n; printf "%d %d\n", b, e }' "${stat_file}")
    else
        note "warning: MITM client not ready for variant=${label}" >&2
        errs=1
    fi
    c1=$(cpu_ticks "${CLIENT_PID}"); s1=$(cpu_ticks "${SERVER_PID}")
    if ! kill -0 "${SERVER_PID}" 2>/dev/null || ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
        note "error: ${label}: an mqproxy process died during the run" >&2
        errs=$(( errs + 1 ))
    fi

    # Stop client, then server
    if [ -n "${CLIENT_PID}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break; sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null || true
        wait "${CLIENT_PID}" 2>/dev/null || true
    fi
    CLIENT_PID=""
    kill "${SERVER_PID}" 2>/dev/null && wait "${SERVER_PID}" 2>/dev/null
    SERVER_PID=""
    nft delete table ip mqproxy 2>/dev/null || true
    clear_tc

    MV_OUT="${mbps} ${nbytes} $(( c1 - c0 )) $(( s1 - s0 )) ${errs}"
}

# ── Rust vs C mode ──
if [ -n "${BIN_RUST}" ]; then
    echo ""
    echo "================================================================"
    echo "  CI MITM Benchmark (Rust vs C)"
    echo "  C:       ${MQPROXY_BIN}"
    echo "  Rust:    ${BIN_RUST}"
    echo "  Profile: symmetric ${RATE}/${DELAY} each path"
    echo "  Params:  ${DURATION}s duration, P=${PARALLEL} H2 streams, DL, REPEAT=${REPEAT}"
    echo "  Commit:  ${CI_BENCH_COMMIT}"
    echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
    echo "================================================================"
    RAW="${WORK}/raw.tsv"
    : > "${RAW}"
    # C and Rust alternate run by run, so host drift hits both alike.
    for rep_i in $(seq 1 "${REPEAT}"); do
        for mode in single multi; do
            for impl in c rust; do
                bin="${MQPROXY_BIN}"; [ "${impl}" = rust ] && bin="${BIN_RUST}"
                run="${impl}-${mode}-${rep_i}"
                measure_variant "${bin}" "${mode}" "${run}"
                read -r mbps nbytes cticks sticks errs <<< "${MV_OUT}"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${impl}" "${mode}" "${rep_i}" \
                    "${mbps}" "${nbytes}" "${cticks}" "${sticks}" "${errs}" >> "${RAW}"
                echo "    ${impl} ${mode} rep=${rep_i}: ${mbps} Mbps, ${errs} failed," \
                     "client_ticks=${cticks} server_ticks=${sticks}"
                if [ "${errs}" -ne 0 ] && [ "${impl}" = rust ]; then
                    tail -n 5 "${WORK}/curl-stats-${run}.txt" "${WORK}/server-${run}.log" \
                        "${WORK}/client-${run}.log" >&2
                fi
            done
        done
    done

    OUTPUT_FILE="${CI_BENCH_RESULTS}/mitm_rust_vs_c_$(date -u '+%Y%m%d_%H%M%S').json"
    python3 - "${RAW}" "${OUTPUT_FILE}" <<PYEOF
import json, statistics, sys

raw, out = sys.argv[1], sys.argv[2]
tck, gate, repeat = ${CLK_TCK}, ${GATE}, ${REPEAT}
names = {"single": "single_path", "multi": "multipath"}
results = {"c": {}, "rust": {}}
for line in open(raw):
    impl, mode, rep, mbps, nbytes, cticks, sticks, errs = line.split()
    bits, cticks, sticks = int(nbytes) * 8, int(cticks), int(sticks)
    run = {"rep": int(rep), "throughput_mbps": float(mbps), "bytes": int(nbytes),
           "failed": int(errs), "client_cpu_s": cticks / tck, "server_cpu_s": sticks / tck,
           "client_bits_per_cpu_s": bits * tck / cticks if cticks else None,
           "server_bits_per_cpu_s": bits * tck / sticks if sticks else None,
           "bits_per_cpu_s": bits * tck / (cticks + sticks) if cticks + sticks else None}
    results[impl].setdefault(names[mode], {"runs": []})["runs"].append(run)

keys = ("throughput_mbps", "client_bits_per_cpu_s", "server_bits_per_cpu_s", "bits_per_cpu_s")
for cells in results.values():
    for cell in cells.values():
        for k in keys:
            vals = [r[k] for r in cell["runs"] if r[k] is not None]
            cell["median_" + k] = statistics.median(vals) if vals else None

def ratio(a, b):
    return round(a / b, 3) if a and b else None

ratios, ok = {}, True
print("\n%-12s %9s %9s %6s %10s %10s %10s %10s %6s" % (
    "cell", "C Mbps", "Rust Mbps", "ratio", "C cli b/c", "R cli b/c", "C srv b/c", "R srv b/c", "ratio"))
for name in names.values():
    c, r = results["c"].get(name, {}), results["rust"].get(name, {})
    # Every cell needs REPEAT runs of both binaries; a short cell fails.
    short = [i for i, x in (("C", c), ("Rust", r)) if len(x.get("runs", [])) != repeat]
    tr = ratio(r.get("median_throughput_mbps"), c.get("median_throughput_mbps"))
    er = ratio(r.get("median_bits_per_cpu_s"), c.get("median_bits_per_cpu_s"))
    # Rust failures gate. C failures are reported only: the C MITM (WIP, SP4
    # spec §0) resets its h2 downloads after a few seconds; its throughput is
    # then the rate up to the reset.
    failed = sum(x["failed"] for x in r.get("runs", []))
    c_failed = sum(x["failed"] for x in c.get("runs", []))
    ratios[name] = {"throughput": tr, "bits_per_cpu_s": er,
                    "client_bits_per_cpu_s": ratio(r.get("median_client_bits_per_cpu_s"), c.get("median_client_bits_per_cpu_s")),
                    "server_bits_per_cpu_s": ratio(r.get("median_server_bits_per_cpu_s"), c.get("median_server_bits_per_cpu_s"))}
    bad = tr is None or tr < gate or failed or short
    ok = ok and not bad
    print("%-12s %9.1f %9.1f %6s %10.3g %10.3g %10.3g %10.3g %6s%s%s" % (
        name, c.get("median_throughput_mbps") or 0, r.get("median_throughput_mbps") or 0, tr,
        c.get("median_client_bits_per_cpu_s") or 0, r.get("median_client_bits_per_cpu_s") or 0,
        c.get("median_server_bits_per_cpu_s") or 0, r.get("median_server_bits_per_cpu_s") or 0, er,
        ("  FAIL" + (" (%d failed Rust transfers)" % failed if failed else "")
         + (" (missing runs: %s)" % "/".join(short) if short else "")) if bad else "",
        "  (C: %d failed transfers)" % c_failed if c_failed else ""))

output = {
    "test": "mitm_rust_vs_c",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "binaries": {"c": "${MQPROXY_BIN}", "rust": "${BIN_RUST}"},
    "profile": "symmetric",
    "duration_sec": ${DURATION},
    "parallel_streams": ${PARALLEL},
    "repeat": repeat,
    "clk_tck": tck,
    "gate": gate,
    "results": results,
    "ratios": ratios,
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
    [ "${rc}" -eq 0 ] && echo "  MITM Benchmark PASS (every throughput ratio >= ${GATE})" \
                     || echo "  MITM Benchmark FAIL"
    echo "================================================================"
    exit "${rc}"
fi

echo ""
echo "================================================================"
echo "  CI MITM Benchmark"
echo "  Binary:  ${MQPROXY_BIN}"
echo "  Profile: symmetric ${RATE}/${DELAY} each path"
echo "  Params:  ${DURATION}s duration, P=${PARALLEL} H2 streams, DL"
echo "  Commit:  ${CI_BENCH_COMMIT}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

echo ""
echo "==> Variant 1/2: single_path (path A only)"
measure_variant "${MQPROXY_BIN}" single single
read -r mbps_single _ <<< "${MV_OUT}"
echo "    single_path: ${mbps_single} Mbps"

echo ""
echo "==> Variant 2/2: multipath (path A + B)"
measure_variant "${MQPROXY_BIN}" multi multi
read -r mbps_multi _ <<< "${MV_OUT}"
echo "    multipath: ${mbps_multi} Mbps"

# ── Generate JSON output ──
echo ""
echo "Generating JSON output..."

TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
OUTPUT_FILE="${CI_BENCH_RESULTS}/mitm_$(date -u '+%Y%m%d_%H%M%S').json"

python3 <<PYEOF
import json

single = float("${mbps_single}")
multi  = float("${mbps_multi}")

aggregation_ratio = round(multi / single, 3) if single > 0 else None

output = {
    "test": "mitm",
    "commit": "${CI_BENCH_COMMIT}",
    "timestamp": "${TIMESTAMP}",
    "profile": "symmetric",
    "duration_sec": ${DURATION},
    "parallel_streams": ${PARALLEL},
    "results": {
        "DL": {
            "single_path_mbps": single,
            "multipath_mbps":   multi,
        }
    },
    "aggregation_ratio": aggregation_ratio,
}

with open("${OUTPUT_FILE}", "w") as f:
    json.dump(output, f, indent=2)

print(json.dumps(output, indent=2))
PYEOF

echo ""
echo "Results written to: ${OUTPUT_FILE}"

# Sanity check: ALL _mbps fields must be positive (not just any)
python3 -c "
import json, sys
d = json.load(open('${OUTPUT_FILE}'))
zeros = []
for dir_key, dir_vals in d.get('results', {}).items():
    if isinstance(dir_vals, dict):
        for k, v in dir_vals.items():
            if k.endswith('_mbps') and isinstance(v, (int, float)) and v <= 0:
                zeros.append(f'results.{dir_key}.{k}')
if zeros:
    print(f'FAIL: zero-value fields: {\" \".join(zeros)}', file=sys.stderr)
    sys.exit(1)
print('OK: sanity check passed')
" || { note "SANITY FAIL: zero-value throughput fields" >&2; exit 1; }

echo ""
echo "================================================================"
echo "  MITM Benchmark DONE"
echo "================================================================"
