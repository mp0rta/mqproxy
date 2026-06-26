#!/usr/bin/env bash
# ci_bench_env.sh — Shared CI benchmark environment for mqproxy.
#
# Source this file from CI benchmark scripts:
#   source "$(dirname "$0")/ci_bench_env.sh"
#
# Extracted from tests/integration/bench_single_tcp_aggregation.sh.
# API modelled after mqvpn's scripts/ci_benchmarks/ci_bench_env.sh but
# adapted for mqproxy's two-binary setup (server + client + socat SOCKS5 bridge).
#
# Topology (2-netns, no middlebox — matches mqvpn CI bench layout):
#   client netns                         server netns
#   ─────────────┐                      ┌─────────────
#   10.50.1.1  ci-a0 ────────────── ci-a1  10.50.1.254
#   10.50.2.1  ci-b0 ────────────── ci-b1  10.50.2.254
#                                    lo:   10.70.0.1/32
#
# iperf3 runs through a socat SOCKS5-CONNECT bridge because iperf3 has no
# native SOCKS5 support. socat --experimental is required (1.8.x flag).

CI_BENCH_ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${CI_BENCH_ENV_DIR}/../../" && pwd)"

# ── Binary paths (overridable) ──
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"

# ── Output directory ──
CI_BENCH_RESULTS="${CI_BENCH_RESULTS:-${REPO_ROOT}/ci_bench_results}"

# ── Git SHA for JSON output ──
CI_BENCH_COMMIT="${CI_BENCH_COMMIT:-$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

# ── Netns + veth names (ci-bench-* prefix avoids collision with manual bench) ──
CB_NS_SERVER="ci-bench-server"
CB_NS_CLIENT="ci-bench-client"
CB_VETH_A0="ci-a0"
CB_VETH_A1="ci-a1"
CB_VETH_B0="ci-b0"
CB_VETH_B1="ci-b1"

# ── IP addressing (matches bench_single_tcp_aggregation.sh; NOT mqvpn's 10.100.x.x) ──
CB_IP_A_CLIENT="10.50.1.1"
CB_IP_A_SERVER="10.50.1.254"
CB_IP_B_CLIENT="10.50.2.1"
CB_IP_B_SERVER="10.50.2.254"
CB_SERVER_LO="10.70.0.1"   # /32 on server lo — iperf3 target

# ── Fixed ports ──
CB_PROXY_PORT="${CB_PROXY_PORT:-4434}"
CB_SOCKS_PORT="${CB_SOCKS_PORT:-11080}"
CB_SOCAT_PORT="${CB_SOCAT_PORT:-15301}"
CB_IPERF_PORT="${CB_IPERF_PORT:-15201}"
CB_TOKEN="ci-bench-token-$$"

# ── Process state ──
_CB_SERVER_PID=""
_CB_CLIENT_PID=""
_CB_SOCAT_PID=""
_CB_IPERF_S_PID=""
_CB_WORK_DIR=""

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_check_deps — assert all required tools and binaries present
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_check_deps() {
    if [ ! -x "${MQPROXY_BIN}" ]; then
        echo "error: mqproxy binary not found or not executable: ${MQPROXY_BIN}" >&2
        exit 1
    fi
    if [ ! -f "${MQPROXY_CERT}" ]; then
        echo "error: TLS cert not found: ${MQPROXY_CERT}" >&2
        exit 1
    fi
    if [ ! -f "${MQPROXY_KEY}" ]; then
        echo "error: TLS key not found: ${MQPROXY_KEY}" >&2
        exit 1
    fi
    for tool in ip tc iperf3 socat python3 openssl; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            echo "error: required tool not found: ${tool}" >&2
            exit 1
        fi
    done
    mkdir -p "${CI_BENCH_RESULTS}"
    _CB_WORK_DIR="$(mktemp -d /tmp/mqproxy_ci_bench.XXXXXX)"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_setup_netns — create 2 netns + 2 veth pairs + routing
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_setup_netns() {
    # Idempotent: delete stale state from a prior interrupted run.
    for ns in "${CB_NS_SERVER}" "${CB_NS_CLIENT}"; do
        ip netns del "${ns}" 2>/dev/null || true
    done
    ip link del "${CB_VETH_A0}" 2>/dev/null || true
    ip link del "${CB_VETH_B0}" 2>/dev/null || true

    ip netns add "${CB_NS_SERVER}"
    ip netns add "${CB_NS_CLIENT}"

    ip -n "${CB_NS_SERVER}" link set lo up
    ip -n "${CB_NS_CLIENT}" link set lo up

    # Path A: 10.50.1.0/24
    ip link add "${CB_VETH_A0}" type veth peer name "${CB_VETH_A1}"
    ip link set "${CB_VETH_A0}" netns "${CB_NS_CLIENT}"
    ip link set "${CB_VETH_A1}" netns "${CB_NS_SERVER}"
    ip -n "${CB_NS_CLIENT}" addr add "${CB_IP_A_CLIENT}/24" dev "${CB_VETH_A0}"
    ip -n "${CB_NS_SERVER}" addr add "${CB_IP_A_SERVER}/24" dev "${CB_VETH_A1}"
    ip -n "${CB_NS_CLIENT}" link set "${CB_VETH_A0}" up
    ip -n "${CB_NS_SERVER}" link set "${CB_VETH_A1}" up

    # Path B: 10.50.2.0/24
    ip link add "${CB_VETH_B0}" type veth peer name "${CB_VETH_B1}"
    ip link set "${CB_VETH_B0}" netns "${CB_NS_CLIENT}"
    ip link set "${CB_VETH_B1}" netns "${CB_NS_SERVER}"
    ip -n "${CB_NS_CLIENT}" addr add "${CB_IP_B_CLIENT}/24" dev "${CB_VETH_B0}"
    ip -n "${CB_NS_SERVER}" addr add "${CB_IP_B_SERVER}/24" dev "${CB_VETH_B1}"
    ip -n "${CB_NS_CLIENT}" link set "${CB_VETH_B0}" up
    ip -n "${CB_NS_SERVER}" link set "${CB_VETH_B1}" up

    # Server loopback /32 — the iperf3 target; reachable from either path
    ip -n "${CB_NS_SERVER}" addr add "${CB_SERVER_LO}/32" dev lo

    # rp_filter=0: server lo /32 is reached via both veths; strict RP drops
    # path-B packets destined for the lo /32 (which is on a path-A iface).
    for ns in "${CB_NS_CLIENT}" "${CB_NS_SERVER}"; do
        ip netns exec "${ns}" sysctl -qw net.ipv4.conf.all.rp_filter=0
        ip netns exec "${ns}" sysctl -qw net.ipv4.conf.default.rp_filter=0
        ip netns exec "${ns}" sysctl -qw net.ipv4.conf.lo.rp_filter=0
    done
    for dev in "${CB_VETH_A0}" "${CB_VETH_B0}"; do
        ip netns exec "${CB_NS_CLIENT}" sysctl -qw "net.ipv4.conf.${dev}.rp_filter=0" 2>/dev/null || true
    done
    for dev in "${CB_VETH_A1}" "${CB_VETH_B1}"; do
        ip netns exec "${CB_NS_SERVER}" sysctl -qw "net.ipv4.conf.${dev}.rp_filter=0" 2>/dev/null || true
    done

    echo "OK: netns ${CB_NS_SERVER}/${CB_NS_CLIENT} created"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_setup_routing VARIANT — configure client routing for variant
#   direct:  path A only, no proxy
#   single:  policy routing for both paths, mqproxy binds path A only
#   multi:   policy routing for both paths, mqproxy binds A + B
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_setup_routing() {
    local variant="$1"

    # Flush ARP caches so a prior variant's warm ARP doesn't bias RTT
    for ns in "${CB_NS_CLIENT}" "${CB_NS_SERVER}"; do
        ip netns exec "${ns}" ip neigh flush all 2>/dev/null || true
    done

    case "${variant}" in
        direct)
            ip netns exec "${CB_NS_CLIENT}" ip route replace \
                "${CB_SERVER_LO}/32" via "${CB_IP_A_SERVER}" dev "${CB_VETH_A0}"
            ;;
        single|multi)
            # Policy routing: src IP → correct path table (same as bench script)
            ip netns exec "${CB_NS_CLIENT}" ip rule add from "${CB_IP_A_CLIENT}" lookup 100 2>/dev/null || true
            ip netns exec "${CB_NS_CLIENT}" ip rule add from "${CB_IP_B_CLIENT}" lookup 200 2>/dev/null || true
            ip netns exec "${CB_NS_CLIENT}" ip route replace \
                "${CB_SERVER_LO}/32" via "${CB_IP_A_SERVER}" dev "${CB_VETH_A0}" table 100
            ip netns exec "${CB_NS_CLIENT}" ip route replace \
                "${CB_SERVER_LO}/32" via "${CB_IP_B_SERVER}" dev "${CB_VETH_B0}" table 200
            ip netns exec "${CB_NS_CLIENT}" ip route replace \
                "${CB_SERVER_LO}/32" via "${CB_IP_A_SERVER}" dev "${CB_VETH_A0}"
            ;;
        *)
            echo "ci_bench_setup_routing: unknown variant '${variant}'" >&2
            return 1
            ;;
    esac
}

ci_bench_reset_routing() {
    ip netns exec "${CB_NS_CLIENT}" ip rule del from "${CB_IP_A_CLIENT}" lookup 100 2>/dev/null || true
    ip netns exec "${CB_NS_CLIENT}" ip rule del from "${CB_IP_B_CLIENT}" lookup 200 2>/dev/null || true
    ip netns exec "${CB_NS_CLIENT}" ip route flush table 100 2>/dev/null || true
    ip netns exec "${CB_NS_CLIENT}" ip route flush table 200 2>/dev/null || true
    ip netns exec "${CB_NS_CLIENT}" ip route del "${CB_SERVER_LO}/32" 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_setup_netem DELAY_A RATE_A DELAY_B RATE_B
#   Apply tc-netem shaping to all 4 veths. RTT ≈ 2×delay.
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_setup_netem() {
    local delay_a="${1:-25}" rate_a="${2:-100mbit}"
    local delay_b="${3:-${delay_a}}" rate_b="${4:-${rate_a}}"

    _netem_one() {
        local ns="$1" dev="$2" delay="$3" rate="$4"
        ip netns exec "${ns}" tc qdisc replace dev "${dev}" root \
            netem delay "${delay}ms" rate "${rate}" limit 25000
    }
    _netem_one "${CB_NS_CLIENT}" "${CB_VETH_A0}" "${delay_a}" "${rate_a}"
    _netem_one "${CB_NS_SERVER}" "${CB_VETH_A1}" "${delay_a}" "${rate_a}"
    _netem_one "${CB_NS_CLIENT}" "${CB_VETH_B0}" "${delay_b}" "${rate_b}"
    _netem_one "${CB_NS_SERVER}" "${CB_VETH_B1}" "${delay_b}" "${rate_b}"
}

ci_bench_clear_netem() {
    for ns in "${CB_NS_CLIENT}" "${CB_NS_SERVER}"; do
        for dev in "${CB_VETH_A0}" "${CB_VETH_A1}" "${CB_VETH_B0}" "${CB_VETH_B1}"; do
            ip netns exec "${ns}" tc qdisc del dev "${dev}" root 2>/dev/null || true
        done
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_start_server — start mqproxy server in server netns
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_start_server() {
    ip netns exec "${CB_NS_SERVER}" "${MQPROXY_BIN}" server \
        --listen "${CB_SERVER_LO}:${CB_PROXY_PORT}" \
        --token "${CB_TOKEN}" \
        --cert "${MQPROXY_CERT}" \
        --key "${MQPROXY_KEY}" \
        --no-gateway \
        > "${_CB_WORK_DIR}/mqproxy-server.log" 2>&1 &
    _CB_SERVER_PID=$!

    local deadline=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if kill -0 "${_CB_SERVER_PID}" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done

    if ! kill -0 "${_CB_SERVER_PID}" 2>/dev/null; then
        echo "error: mqproxy server died — see ${_CB_WORK_DIR}/mqproxy-server.log" >&2
        return 1
    fi
    echo "OK: mqproxy server PID=${_CB_SERVER_PID}"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_start_client PATH_MODE — start mqproxy client + socat bridge
#   PATH_MODE: "single" (path A only) | "multi" (path A + B)
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_start_client() {
    local path_mode="${1:-multi}"
    local path_args
    case "${path_mode}" in
        single) path_args="--path ${CB_IP_A_CLIENT}" ;;
        multi)  path_args="--path ${CB_IP_A_CLIENT} --path ${CB_IP_B_CLIENT}" ;;
        *)
            echo "ci_bench_start_client: unknown path_mode '${path_mode}'" >&2
            return 1
            ;;
    esac

    # shellcheck disable=SC2086
    ip netns exec "${CB_NS_CLIENT}" "${MQPROXY_BIN}" client \
        --server "${CB_SERVER_LO}:${CB_PROXY_PORT}" \
        --token "${CB_TOKEN}" \
        --socks5 "127.0.0.1:${CB_SOCKS_PORT}" \
        ${path_args} \
        > "${_CB_WORK_DIR}/mqproxy-client.log" 2>&1 &
    _CB_CLIENT_PID=$!

    # Wait for SOCKS5 port to LISTEN
    local deadline=$(( $(date +%s) + 8 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec "${CB_NS_CLIENT}" ss -ltn "( sport = :${CB_SOCKS_PORT} )" 2>/dev/null \
                | grep -q LISTEN; then
            break
        fi
        sleep 0.2
    done

    if ! ip netns exec "${CB_NS_CLIENT}" ss -ltn "( sport = :${CB_SOCKS_PORT} )" 2>/dev/null \
            | grep -q LISTEN; then
        echo "error: mqproxy client SOCKS5 not ready — see ${_CB_WORK_DIR}/mqproxy-client.log" >&2
        return 1
    fi

    # socat SOCKS5-CONNECT bridge (--experimental required for SOCKS5-CONNECT)
    ip netns exec "${CB_NS_CLIENT}" socat --experimental \
        "TCP-LISTEN:${CB_SOCAT_PORT},reuseaddr,fork,bind=127.0.0.1" \
        "SOCKS5-CONNECT:127.0.0.1:${CB_SOCKS_PORT}:${CB_SERVER_LO}:${CB_IPERF_PORT}" \
        > "${_CB_WORK_DIR}/socat.log" 2>&1 &
    _CB_SOCAT_PID=$!

    deadline=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec "${CB_NS_CLIENT}" ss -ltn "( sport = :${CB_SOCAT_PORT} )" 2>/dev/null \
                | grep -q LISTEN; then
            echo "OK: mqproxy client + socat bridge ready (mode=${path_mode})"
            return 0
        fi
        sleep 0.2
    done

    echo "error: socat bridge not ready" >&2
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_stop_proxy — kill server, client, socat
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_stop_proxy() {
    for pid in "${_CB_SOCAT_PID}" "${_CB_CLIENT_PID}" "${_CB_SERVER_PID}"; do
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null
            # SIGKILL after 2 s if SIGTERM didn't work (prevent hangs).
            local _dl=$(( $(date +%s) + 2 ))
            while kill -0 "${pid}" 2>/dev/null && [ "$(date +%s)" -lt "${_dl}" ]; do
                sleep 0.1
            done
            kill -9 "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null
        fi
    done 2>/dev/null || true
    _CB_SOCAT_PID=""; _CB_CLIENT_PID=""; _CB_SERVER_PID=""
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_run_iperf DURATION PARALLEL — run iperf3 DL through socat bridge
#   Outputs path to JSON result file (caller must clean up).
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_run_iperf() {
    local duration="${1:-10}"
    local parallel="${2:-4}"
    local json_file="${_CB_WORK_DIR}/iperf-$(date +%s%N).json"

    # iperf3 server in server netns (bound to lo /32)
    ip netns exec "${CB_NS_SERVER}" iperf3 -s -1 \
        -B "${CB_SERVER_LO}" -p "${CB_IPERF_PORT}" \
        > "${_CB_WORK_DIR}/iperf-server.log" 2>&1 &
    _CB_IPERF_S_PID=$!

    # Wait for iperf3 server to listen
    local deadline=$(( $(date +%s) + 5 ))
    local _iperf_ready=0
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec "${CB_NS_SERVER}" ss -ltn "src ${CB_SERVER_LO}:${CB_IPERF_PORT}" 2>/dev/null \
                | grep -q LISTEN; then
            _iperf_ready=1
            break
        fi
        sleep 0.1
    done
    if [ "${_iperf_ready}" -ne 1 ]; then
        echo "ERROR: iperf3 server not listening after 5s" >&2
        kill "${_CB_IPERF_S_PID}" 2>/dev/null || true
        wait "${_CB_IPERF_S_PID}" 2>/dev/null || true
        _CB_IPERF_S_PID=""
        echo "/dev/null"
        return 1
    fi

    # iperf3 client via socat bridge (DL = reverse: data flows server→client)
    timeout 60 ip netns exec "${CB_NS_CLIENT}" iperf3 \
        -c 127.0.0.1 -p "${CB_SOCAT_PORT}" \
        -P "${parallel}" -t "${duration}" -O 2 -R -J \
        > "${json_file}" 2>&1 || true

    kill "${_CB_IPERF_S_PID}" 2>/dev/null || true
    wait "${_CB_IPERF_S_PID}" 2>/dev/null || true
    _CB_IPERF_S_PID=""

    echo "${json_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_run_iperf_direct DURATION PARALLEL — direct iperf3 (no proxy)
#   Used for the direct baseline variant (no socat, binds path-A client IP).
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_run_iperf_direct() {
    local duration="${1:-10}"
    local parallel="${2:-4}"
    local json_file="${_CB_WORK_DIR}/iperf-direct-$(date +%s%N).json"

    ip netns exec "${CB_NS_SERVER}" iperf3 -s -1 \
        -B "${CB_SERVER_LO}" -p "${CB_IPERF_PORT}" \
        > "${_CB_WORK_DIR}/iperf-server-direct.log" 2>&1 &
    _CB_IPERF_S_PID=$!

    local deadline=$(( $(date +%s) + 5 ))
    local _iperf_ready=0
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec "${CB_NS_SERVER}" ss -ltn "src ${CB_SERVER_LO}:${CB_IPERF_PORT}" 2>/dev/null \
                | grep -q LISTEN; then
            _iperf_ready=1
            break
        fi
        sleep 0.1
    done
    if [ "${_iperf_ready}" -ne 1 ]; then
        echo "ERROR: iperf3 server not listening after 5s (direct)" >&2
        kill "${_CB_IPERF_S_PID}" 2>/dev/null || true
        wait "${_CB_IPERF_S_PID}" 2>/dev/null || true
        _CB_IPERF_S_PID=""
        echo "/dev/null"
        return 1
    fi

    timeout 60 ip netns exec "${CB_NS_CLIENT}" iperf3 \
        -c "${CB_SERVER_LO}" -p "${CB_IPERF_PORT}" \
        -B "${CB_IP_A_CLIENT}" \
        -P "${parallel}" -t "${duration}" -O 2 -R -J \
        > "${json_file}" 2>&1 || true

    kill "${_CB_IPERF_S_PID}" 2>/dev/null || true
    wait "${_CB_IPERF_S_PID}" 2>/dev/null || true
    _CB_IPERF_S_PID=""

    echo "${json_file}"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_parse_throughput JSON_FILE — extract Mbps from iperf3 JSON
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_parse_throughput() {
    local json_file="$1"
    python3 -c "
import json, sys
try:
    d = json.load(open('${json_file}'))
    bps = d['end']['sum_received']['bits_per_second']
    print('%.2f' % (bps / 1e6))
except Exception as e:
    print('0.0')
" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_sanity_check JSON_FILE DESCRIPTION — verify non-zero throughput
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_sanity_check() {
    local json_file="$1"
    local desc="${2:-benchmark}"

    local bad
    bad=$(python3 -c "
import json, sys
with open('${json_file}') as f:
    d = json.load(f)

zeros = []
def check_mbps(obj, path=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f'{path}.{k}' if path else k
            if isinstance(v, (int, float)) and p.endswith('_mbps') and v <= 0:
                zeros.append(p)
            elif isinstance(v, (dict, list)):
                check_mbps(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            check_mbps(v, f'{path}[{i}]')

check_mbps(d.get('results', d))
if zeros:
    print(' '.join(zeros))
" 2>/dev/null || echo "PARSE_ERROR")

    if [ -n "${bad}" ]; then
        echo "SANITY FAIL: ${desc} — zero-value throughput fields: ${bad}" >&2
        exit 1
    fi
    echo "OK: sanity check passed for ${desc}"
}

# ─────────────────────────────────────────────────────────────────────────────
# ci_bench_cleanup — tear down netns, veths, stale processes
# ─────────────────────────────────────────────────────────────────────────────
ci_bench_cleanup() {
    local rc=$?
    set +eu

    # Suppress "Segmentation fault (core dumped)" and similar async SIGCHLD
    # messages that bash prints when collecting crashed children — they are
    # harmless but pollute CI output and can confuse failure scanners.
    exec 2>/dev/null

    for pid in "${_CB_SOCAT_PID}" "${_CB_CLIENT_PID}" "${_CB_SERVER_PID}" "${_CB_IPERF_S_PID}"; do
        if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null
            local _dl=$(( $(date +%s) + 2 ))
            while kill -0 "${pid}" 2>/dev/null && [ "$(date +%s)" -lt "${_dl}" ]; do
                sleep 0.1
            done
            kill -9 "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null
        fi
    done

    for ns in "${CB_NS_CLIENT}" "${CB_NS_SERVER}"; do
        ip netns pids "${ns}" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 0.5

    ci_bench_clear_netem 2>/dev/null || true

    ip netns del "${CB_NS_SERVER}" 2>/dev/null || true
    ip netns del "${CB_NS_CLIENT}" 2>/dev/null || true
    ip link del "${CB_VETH_A0}" 2>/dev/null || true
    ip link del "${CB_VETH_B0}" 2>/dev/null || true

    [ -n "${_CB_WORK_DIR}" ] && [ -d "${_CB_WORK_DIR}" ] && rm -rf "${_CB_WORK_DIR}"

    exit "${rc}"
}
