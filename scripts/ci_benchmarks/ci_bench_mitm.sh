#!/usr/bin/env bash
# ci_bench_mitm.sh — Per-commit MITM H2 throughput benchmark.
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
# Output: ci_bench_results/mitm_<timestamp>.json
#
# Usage: sudo bash scripts/ci_benchmarks/ci_bench_mitm.sh [path/to/mqproxy]
#
# Env:
#   MQPROXY_BIN       path to mqproxy binary (default: build/mqproxy)
#   MQPROXY_CERT/KEY  tunnel TLS cert/key (default: tests/certs/test.*)
#   MQ_MITM_CA_CRT    MITM CA cert (default: tests/certs/mitm-ca.crt)
#   MQ_MITM_CA_KEY    MITM CA key  (default: tests/certs/mitm-ca.key)
#   CI_BENCH_RESULTS  output directory (default: ci_bench_results/)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../" && pwd)"

MQPROXY_BIN="${1:-${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}}"
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

if [ ! -x "${MQPROXY_BIN}" ]; then
    note "error: mqproxy binary not found: ${MQPROXY_BIN}" >&2
    exit 1
fi
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

# ── Mint origin cert ──
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${ORIGIN_KEY}" -out "${ORIGIN_CERT}" -days 2 \
    -subj "/CN=${MITM_HOST}" \
    -addext "subjectAltName=DNS:${MITM_HOST},DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

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
    if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CERT}" \
        "https://localhost:${ORIGIN_PORT}/" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# ── /etc/hosts entry ──
cp /etc/hosts "${WORK}/hosts.bak"
HOSTS_BACKED_UP=1
printf '%s\n' "${HOSTS_LINE}" >> /etc/hosts

# ── Start mqproxy server ──
"${MQPROXY_BIN}" server \
    --listen "${SERVER_IP}:${QUIC_PORT}" \
    --token "ci-mitm-bench" \
    --cert "${MQPROXY_CERT}" \
    --key "${MQPROXY_KEY}" \
    --origin-ca "${ORIGIN_CERT}" \
    > "${WORK}/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# ── measure_variant PATH_MODE — run one MITM bench variant ──
# Returns throughput in Mbps to stdout.
measure_variant() {
    local path_mode="$1"  # single | multi
    local path_count
    [ "${path_mode}" = "single" ] && path_count=1 || path_count=2

    # Apply tc shaping (setup_tc uses replace, no separate clear needed)
    setup_tc "${path_count}"

    # Build path args for client
    local path_args="--path ${PATH_A_IP}"
    [ "${path_mode}" = "multi" ] && path_args="${path_args} --path ${PATH_B_IP}"

    # Start client
    # shellcheck disable=SC2086
    "${MQPROXY_BIN}" client \
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
        > "${WORK}/client-${path_mode}.log" 2>&1 &
    CLIENT_PID=$!

    # Wait for MITM client ready (nft rules installed + tunnel up)
    local ready=0
    for _ in $(seq 1 80); do
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            break
        fi
        if grep -q "REDIRECT rules installed" "${WORK}/client-${path_mode}.log" 2>/dev/null || \
           nft list table ip mqproxy 2>/dev/null | grep -q REDIRECT; then
            ready=1; break
        fi
        sleep 0.15
    done

    local mbps="0.0"
    if [ "${ready}" -eq 1 ]; then
        # P parallel H2 streams over one multiplexed connection
        local curl_outputs="" curl_urls=""
        for _ in $(seq 1 "${PARALLEL}"); do
            curl_outputs="${curl_outputs} -o /dev/null"
            curl_urls="${curl_urls} https://${MITM_HOST}:${ORIGIN_PORT}/${BLOB_BASENAME}"
        done

        local stat_file="${WORK}/curl-stats-${path_mode}.txt"
        # shellcheck disable=SC2086,SC2024
        sudo -u nobody \
            curl --http2 --cacert "${MITM_CA_CRT_RUN}" \
            --parallel --parallel-max "${PARALLEL}" \
            ${curl_outputs} \
            --max-time "${DURATION}" \
            -w '%{size_download} %{time_total}\n' \
            ${curl_urls} \
            > "${stat_file}" 2>/dev/null || true

        # Aggregate: throughput = sum(bytes) * 8 / max(time) / 1e6
        mbps=$(awk '{b+=$1; if($2>t)t=$2} END{if(t>0) printf "%.2f\n",b*8/t/1e6; else print "0.0"}' \
            "${stat_file}" 2>/dev/null || echo "0.0")
    else
        note "warning: MITM client not ready for variant=${path_mode}" >&2
    fi

    # Stop client
    if [ -n "${CLIENT_PID}" ] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break; sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null || true
        wait "${CLIENT_PID}" 2>/dev/null || true
    fi
    CLIENT_PID=""
    nft delete table ip mqproxy 2>/dev/null || true
    clear_tc

    echo "${mbps}"
}

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
mbps_single=$(measure_variant single)
echo "    single_path: ${mbps_single} Mbps"

echo ""
echo "==> Variant 2/2: multipath (path A + B)"
mbps_multi=$(measure_variant multi)
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
