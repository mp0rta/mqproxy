#!/usr/bin/env bash
# bench_single_tcp_aggregation.sh — single-TCP aggregation A/B/C bench.
#
# THIS FILE IS THE CONTRACT for the bench. The 2-netns direct topology
# matches mqvpn's CI bench layout for fair comparison.
#
# Superseded design doc (for history only; do NOT use as spec):
#   docs/superpowers/specs/2026-06-19-single-tcp-aggregation-bench-design.md
#   (described a 3-netns + middlebox layout; superseded after empirically
#    finding mqvpn's wlb scheduler needs the simpler 2-netns topology to
#    engage path 2 — see report Interpretation section)
#
# Run:   sudo tests/integration/bench_single_tcp_aggregation.sh
# Env:   REPEAT=3 STREAMS="1 2 4 8 16" PROFILES="symmetric asymmetric"
#        VARIANTS="direct mqvpn-single mqproxy-single mqvpn-minrtt mqvpn-wlb mqproxy-tcp"
#        MQPROXY_BIN MQPROXY_CERT MQPROXY_KEY MQVPN_BIN MQVPN_DIR KEEP_LOGS
# Smoke: sudo BENCH_SMOKE={routing|shaping|mqvpn|mqproxy|matrix2} <script>
#
# Topology (mqvpn-CI-style, no middlebox):
#   client netns                       server netns
#   ─────────────┐                    ┌─────────────
#   10.50.1.1  veth1 ────────────── veth1_p  10.50.1.254
#   10.50.2.1  veth2 ────────────── veth2_p  10.50.2.254
#                                    lo:     10.70.0.1/32
#
# Client main table:
#   10.70.0.1/32 via 10.50.1.254 dev veth1            # path A (default)
#   10.70.0.1/32 via 10.50.2.254 dev veth2 metric 200 # path B (backup)
# Source-IP based route selection picks the right path for both mqproxy
# (--path <ip>) and mqvpn (SO_BINDTODEVICE).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
MQVPN_DIR="${MQVPN_DIR:-${REPO_ROOT}/../mqvpn}"
MQVPN_BIN="${MQVPN_BIN:-${MQVPN_DIR}/build/mqvpn}"

REPEAT="${REPEAT:-3}"
STREAMS="${STREAMS:-1 2 4 8 16}"
PROFILES="${PROFILES:-symmetric asymmetric}"
VARIANTS="${VARIANTS:-direct mqvpn-single mqproxy-single mqvpn-minrtt mqvpn-wlb mqproxy-tcp}"
KEEP_LOGS="${KEEP_LOGS:-0}"

MQVPN_PORT=4433
MQPROXY_PORT=4434
IPERF_PORT=5201
MQPROXY_SOCKS_PORT=1080
SOCAT_LISTEN_PORT=5301
MQPROXY_TOKEN="bench-token-$$"
# mqvpn's inner tun subnet must NOT collide with the server-netns lo /32
# (10.70.0.1) used by `direct` and `mqproxy-tcp` variants. iperf3 inside
# mqvpn-* variants targets this inner IP so traffic actually traverses the
# tunnel rather than going direct via veth.
MQVPN_INNER_SERVER_IP=10.80.0.1
MQVPN_INNER_SUBNET=10.80.0.0/24

SKIP=77
note() { printf '%s\n' "$*" >&2; }

declare -a BENCH_PIDS=()
WORK=""
MQVPN_PSK=""
MQVPN_SERVER_PID=""
MQVPN_CLIENT_PID=""
MQPROXY_SERVER_PID=""
MQPROXY_CLIENT_PID=""
MQPROXY_SOCAT_PID=""

cleanup() {
    local rc=$?
    set +u
    for pid in "${BENCH_PIDS[@]}"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    for ns in client server; do
        ip netns del "$ns" 2>/dev/null || true
    done
    if [ "${KEEP_LOGS}" != "1" ] && [ -n "${WORK}" ] && [ -d "${WORK}" ]; then
        rm -rf "${WORK}"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
    note "not root; netns/tc need NET_ADMIN. SKIPPING."
    exit "${SKIP}"
fi

for tool in ip tc iperf3 python3 openssl socat awk; do
    command -v "$tool" >/dev/null || { note "missing tool: $tool"; exit "${SKIP}"; }
done
python3 -c 'import matplotlib' 2>/dev/null \
    || { note "python3 matplotlib not installed (tail plot would fail). SKIPPING."; exit "${SKIP}"; }
[ -x "${MQPROXY_BIN}" ] || { note "missing mqproxy binary: ${MQPROXY_BIN}"; exit "${SKIP}"; }
[ -x "${MQVPN_BIN}"   ] || { note "missing mqvpn binary: ${MQVPN_BIN}";     exit "${SKIP}"; }
[ -f "${MQPROXY_CERT}" ] || { note "missing mqproxy cert: ${MQPROXY_CERT}"; exit "${SKIP}"; }
[ -f "${MQPROXY_KEY}"  ] || { note "missing mqproxy key:  ${MQPROXY_KEY}";  exit "${SKIP}"; }

WORK="$(mktemp -d /tmp/mqproxy_single_tcp.XXXXXX)"
CSV="${REPO_ROOT}/bench_results/single_tcp_aggregation_$(date +%s).csv"
mkdir -p "$(dirname "${CSV}")"
echo "variant,profile,streams,rep,goodput_mbps" > "${CSV}"
note "CSV=${CSV}  WORK=${WORK}"

# ── Testbed: 2 netns + 2 veth pairs (direct, no middlebox) ───────────────────
setup_testbed() {
    # Idempotent recreation — survives prior-run SIGKILL that left netns
    # behind (otherwise `ip netns add` fails with EEXIST and subsequent
    # commands inherit stale state).
    for ns in client server; do
        ip netns del "$ns" 2>/dev/null || true
        ip netns add "$ns"
        ip -n "$ns" link set lo up
    done
    ip link del veth1 2>/dev/null || true
    ip link del veth2 2>/dev/null || true

    ip link add veth1 type veth peer name veth1_p
    ip link add veth2 type veth peer name veth2_p

    ip link set veth1   netns client
    ip link set veth1_p netns server
    ip link set veth2   netns client
    ip link set veth2_p netns server

    ip -n client addr add 10.50.1.1/24    dev veth1
    ip -n client addr add 10.50.2.1/24    dev veth2
    ip -n server addr add 10.50.1.254/24  dev veth1_p
    ip -n server addr add 10.50.2.254/24  dev veth2_p
    ip -n server addr add 10.70.0.1/32    dev lo

    ip -n client link set veth1   up
    ip -n client link set veth2   up
    ip -n server link set veth1_p up
    ip -n server link set veth2_p up
}

# ── Sysctl + routing per variant ─────────────────────────────────────────────
# CI-style: rp_filter=0 across the board, plus per-variant client main-table
# routes to 10.70.0.1 (path A direct + path B backup).
setup_sysctl_and_routing() {
    local variant="$1"

    # Flush ARP/neigh caches so a prior variant's traffic doesn't leave one
    # path warm-ARPed and the other cold — empirically when direct asymm
    # runs first on path A only, the cold ARP on path B inflates wlb's
    # initial RTT measurement on B (~134 ms instead of ~75 ms) which biases
    # MPQUIC's scheduler weighting.
    for ns in client server; do
        ip netns exec "$ns" ip neigh flush all 2>/dev/null || true
    done

    # rp_filter=0 (disabled) in both netns. Server's /32 on lo is reached via
    # either veth — strict RP would drop path-B-arriving packets destined for
    # the lo /32.
    for ns in client server; do
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
        ip netns exec "$ns" sysctl -qw net.ipv4.conf.lo.rp_filter=0
    done
    for d in veth1 veth2; do
        ip netns exec client sysctl -qw "net.ipv4.conf.${d}.rp_filter=0" 2>/dev/null || true
    done
    for d in veth1_p veth2_p; do
        ip netns exec server sysctl -qw "net.ipv4.conf.${d}.rp_filter=0" 2>/dev/null || true
    done

    # Client routing per variant.
    #
    # mqvpn uses SO_BINDTODEVICE for per-path egress — backup-metric route alone
    # would suffice. But mqproxy uses bind() to source IP (NOT SO_BINDTODEVICE),
    # and Linux's main-table backup-metric does NOT force per-source path
    # selection: kernel picks lowest-metric route then uses the socket's bound
    # src directly (spoofing out the wrong iface; rp_filter=0 lets the server
    # accept it, so the failure is silent — single-path-equivalent goodput).
    # Add explicit `from <src> lookup <table>` policy rules so source-IP→path
    # mapping is unambiguous for both mqproxy and mqvpn.
    case "$variant" in
        direct)
            # Single-path baseline — path A only
            ip netns exec client ip route replace 10.70.0.1/32 via 10.50.1.254 dev veth1
            ;;
        mqvpn-*|mqproxy-*)
            # Same routing for single- and multi-path tunnel variants. The
            # *-single variants only bind one veth at the daemon level, but
            # having the policy rules + tables for BOTH veths present makes
            # the routing surface identical so any goodput delta between
            # *-single and *-multi is purely scheduler/aggregation, not
            # routing-state artifact.
            ip netns exec client ip rule add from 10.50.1.1 lookup 100 2>/dev/null || true
            ip netns exec client ip rule add from 10.50.2.1 lookup 200 2>/dev/null || true
            ip netns exec client ip route replace 10.70.0.1/32 via 10.50.1.254 dev veth1 table 100
            ip netns exec client ip route replace 10.70.0.1/32 via 10.50.2.254 dev veth2 table 200
            # Main-table fallback (SO_BINDTODEVICE veth1 lookup, unbound traffic)
            ip netns exec client ip route replace 10.70.0.1/32 via 10.50.1.254 dev veth1
            ;;
    esac
}

reset_routing() {
    # Client-side only — server netns never had per-variant routes/rules.
    ip netns exec client ip rule del from 10.50.1.1 lookup 100 2>/dev/null || true
    ip netns exec client ip rule del from 10.50.2.1 lookup 200 2>/dev/null || true
    ip netns exec client ip route flush table 100 2>/dev/null || true
    ip netns exec client ip route flush table 200 2>/dev/null || true
    ip netns exec client ip route del 10.70.0.1/32 2>/dev/null || true
}

# ── tc-netem shaping ─────────────────────────────────────────────────────────
apply_profile() {
    local profile="$1"
    local a_delay a_rate b_delay b_rate
    case "$profile" in
        symmetric)
            a_delay=25; a_rate=100mbit
            b_delay=25; b_rate=100mbit
            ;;
        asymmetric)
            # Matches mqvpn CI (ci_bench_aggregate.sh)
            a_delay=10; a_rate=300mbit
            b_delay=30; b_rate=80mbit
            ;;
        *) note "unknown profile: $profile"; exit 1 ;;
    esac
    _netem() {
        local ns="$1" dev="$2" delay="$3" rate="$4"
        ip netns exec "$ns" tc qdisc replace dev "$dev" root \
            netem delay "${delay}ms" rate "${rate}" limit 25000
    }
    _netem client veth1   "$a_delay" "$a_rate"
    _netem client veth2   "$b_delay" "$b_rate"
    _netem server veth1_p "$a_delay" "$a_rate"
    _netem server veth2_p "$b_delay" "$b_rate"
}
clear_profile() {
    for ns in client server; do
        for d in veth1 veth2 veth1_p veth2_p; do
            ip netns exec "$ns" tc qdisc del dev "$d" root 2>/dev/null || true
        done
    done
}

# ── mqvpn variant start_pair ─────────────────────────────────────────────────
start_mqvpn() {
    # $1 = scheduler (minrtt | wlb)
    # $2 = path_mode: "multi" (default) → both paths; "single" → path A only,
    #      establishing the tunnel-overhead baseline (= mqvpn CI "Single" column).
    local scheduler="$1"
    local path_mode="${2:-multi}"
    local mqvpn_path_args
    case "${path_mode}" in
        single) mqvpn_path_args=( --path veth1 ) ;;
        multi)  mqvpn_path_args=( --path veth1 --path veth2 ) ;;
        *)      note "start_mqvpn: bad path_mode '${path_mode}'"; return 1 ;;
    esac
    if [ -z "${MQVPN_PSK}" ]; then
        MQVPN_PSK=$("${MQVPN_BIN}" --genkey 2>/dev/null)
        if [ -z "${MQVPN_PSK}" ]; then
            note "mqvpn --genkey returned empty; check ${MQVPN_BIN} build"
            return 1
        fi
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "${WORK}/mqvpn.key" -out "${WORK}/mqvpn.crt" \
            -days 1 -nodes -subj "/CN=mqvpn-bench" 2>/dev/null
    fi
    ip netns exec server "${MQVPN_BIN}" \
        --mode server \
        --listen "10.70.0.1:${MQVPN_PORT}" \
        --subnet "${MQVPN_INNER_SUBNET}" \
        --cert "${WORK}/mqvpn.crt" --key "${WORK}/mqvpn.key" \
        --auth-key "${MQVPN_PSK}" \
        --scheduler "${scheduler}" \
        --log-level info \
        > "${WORK}/mqvpn-server.log" 2>&1 &
    MQVPN_SERVER_PID=$!
    BENCH_PIDS+=( "${MQVPN_SERVER_PID}" )
    sleep 2
    if ! kill -0 "${MQVPN_SERVER_PID}" 2>/dev/null; then
        note "mqvpn server died — see ${WORK}/mqvpn-server.log"
        stop_mqvpn
        return 1
    fi

    ip netns exec client "${MQVPN_BIN}" \
        --mode client \
        --server "10.70.0.1:${MQVPN_PORT}" \
        "${mqvpn_path_args[@]}" \
        --auth-key "${MQVPN_PSK}" \
        --scheduler "${scheduler}" \
        --insecure \
        --log-level info \
        > "${WORK}/mqvpn-client.log" 2>&1 &
    MQVPN_CLIENT_PID=$!
    BENCH_PIDS+=( "${MQVPN_CLIENT_PID}" )

    local deadline=$(( $(date +%s) + 8 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec client ip route get "${MQVPN_INNER_SERVER_IP}" 2>/dev/null \
                | grep -q 'dev mqvpn0'; then
            note "OK: mqvpn tun route up (${MQVPN_INNER_SERVER_IP} via mqvpn0)"
            return 0
        fi
        sleep 0.2
    done
    note "mqvpn start_pair: tun route to ${MQVPN_INNER_SERVER_IP} not present after 8s"
    note "  see ${WORK}/mqvpn-{server,client}.log"
    stop_mqvpn
    return 1
}

stop_mqvpn() {
    for pid in "${MQVPN_CLIENT_PID}" "${MQVPN_SERVER_PID}"; do
        if [ -n "${pid}" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    MQVPN_CLIENT_PID=""; MQVPN_SERVER_PID=""
}

# ── mqproxy variant start_pair (SOCKS5 + socat bridge) ───────────────────────
start_mqproxy() {
    # $1 = path_mode: "multi" (default) → both paths; "single" → path A only,
    #      establishing the tunnel-overhead baseline.
    local path_mode="${1:-multi}"
    local mqproxy_path_args
    case "${path_mode}" in
        single) mqproxy_path_args=( --path 10.50.1.1 ) ;;
        multi)  mqproxy_path_args=( --path 10.50.1.1 --path 10.50.2.1 ) ;;
        *)      note "start_mqproxy: bad path_mode '${path_mode}'"; return 1 ;;
    esac
    ip netns exec server "${MQPROXY_BIN}" server \
        --listen "10.70.0.1:${MQPROXY_PORT}" \
        --token "${MQPROXY_TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        --no-gateway \
        > "${WORK}/mqproxy-server.log" 2>&1 &
    MQPROXY_SERVER_PID=$!
    BENCH_PIDS+=( "${MQPROXY_SERVER_PID}" )
    sleep 0.5
    if ! kill -0 "${MQPROXY_SERVER_PID}" 2>/dev/null; then
        note "mqproxy server died — see ${WORK}/mqproxy-server.log"
        stop_mqproxy
        return 1
    fi

    ip netns exec client "${MQPROXY_BIN}" client \
        --server "10.70.0.1:${MQPROXY_PORT}" \
        --token "${MQPROXY_TOKEN}" \
        --socks5 "127.0.0.1:${MQPROXY_SOCKS_PORT}" \
        "${mqproxy_path_args[@]}" \
        > "${WORK}/mqproxy-client.log" 2>&1 &
    MQPROXY_CLIENT_PID=$!
    BENCH_PIDS+=( "${MQPROXY_CLIENT_PID}" )

    local deadline=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec client ss -ltn "( sport = :${MQPROXY_SOCKS_PORT} )" 2>/dev/null \
                | grep -q LISTEN; then
            break
        fi
        sleep 0.2
    done

    ip netns exec client socat --experimental \
        "TCP-LISTEN:${SOCAT_LISTEN_PORT},reuseaddr,fork,bind=127.0.0.1" \
        "SOCKS5-CONNECT:127.0.0.1:${MQPROXY_SOCKS_PORT}:10.70.0.1:${IPERF_PORT}" \
        > "${WORK}/socat.log" 2>&1 &
    MQPROXY_SOCAT_PID=$!
    BENCH_PIDS+=( "${MQPROXY_SOCAT_PID}" )

    deadline=$(( $(date +%s) + 3 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ip netns exec client ss -ltn "( sport = :${SOCAT_LISTEN_PORT} )" 2>/dev/null \
                | grep -q LISTEN; then
            note "OK: mqproxy socks5 + socat bridge ready"
            return 0
        fi
        sleep 0.2
    done
    note "mqproxy start_pair: socat listen not ready"
    stop_mqproxy
    return 1
}

stop_mqproxy() {
    for pid in "${MQPROXY_SOCAT_PID}" "${MQPROXY_CLIENT_PID}" "${MQPROXY_SERVER_PID}"; do
        if [ -n "${pid}" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    MQPROXY_SOCAT_PID=""; MQPROXY_CLIENT_PID=""; MQPROXY_SERVER_PID=""
}

# ── Cell runner ──────────────────────────────────────────────────────────────
run_cell() {
    local variant="$1" profile="$2" streams="$3" rep="$4"
    local target port bind_arg="" iperf_s_bind
    case "$variant" in
        mqproxy-*)
            target="127.0.0.1"; port="${SOCAT_LISTEN_PORT}"
            iperf_s_bind="10.70.0.1"
            ;;
        direct)
            target="10.70.0.1"; port="${IPERF_PORT}"; bind_arg="-B 10.50.1.1"
            iperf_s_bind="10.70.0.1"
            ;;
        mqvpn-*)
            target="${MQVPN_INNER_SERVER_IP}"; port="${IPERF_PORT}"
            iperf_s_bind="${MQVPN_INNER_SERVER_IP}"
            ;;
        *)
            target="10.70.0.1"; port="${IPERF_PORT}"
            iperf_s_bind="10.70.0.1"
            ;;
    esac

    ip netns exec server iperf3 -s -1 -B "${iperf_s_bind}" -p "${IPERF_PORT}" \
        > "${WORK}/iperf-s-${variant}-${profile}-${streams}-${rep}.log" 2>&1 &
    local iperf_s_pid=$!
    BENCH_PIDS+=( "${iperf_s_pid}" )

    local d=$(( $(date +%s) + 3 ))
    while [ "$(date +%s)" -lt "$d" ]; do
        if ip netns exec server ss -ltn "src ${iperf_s_bind}:${IPERF_PORT}" 2>/dev/null \
                | grep -q LISTEN; then
            break
        fi
        sleep 0.1
    done

    local json="${WORK}/iperf-c-${variant}-${profile}-${streams}-${rep}.json"
    if ! timeout 60 ip netns exec client iperf3 \
            -c "${target}" -p "${port}" \
            -P "${streams}" -t 20 -O 2 -R -J ${bind_arg} \
            > "${json}" 2>&1; then
        note "cell ${variant}/${profile}/${streams}/${rep}: iperf3 timeout"
        echo "${variant},${profile},${streams},${rep},NaN" >> "${CSV}"
        kill "${iperf_s_pid}" 2>/dev/null || true
        wait "${iperf_s_pid}" 2>/dev/null || true
        return
    fi
    kill "${iperf_s_pid}" 2>/dev/null || true
    wait "${iperf_s_pid}" 2>/dev/null || true

    local mbps
    mbps=$(python3 -c '
import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print("%.2f" % (d["end"]["sum_received"]["bits_per_second"]/1e6))
except Exception:
    print("NaN")
' "${json}" 2>/dev/null)
    [ -z "${mbps}" ] && mbps="NaN"
    echo "${variant},${profile},${streams},${rep},${mbps}" >> "${CSV}"
    note "  ${variant}/${profile}/P=${streams}/r=${rep}: ${mbps} Mbps"
}

# ── Diagnostic state dump ────────────────────────────────────────────────────
# Gated by DIAG=1. Captures kernel state that can plausibly leak between
# variants: tun/veth devices, ip rules+routes, tc qdiscs, listening UDP/TCP
# sockets, conntrack entries.
diagnose_state() {
    [ "${DIAG:-0}" = "1" ] || return 0
    local profile="$1" variant="$2" when="$3"
    local log="${WORK}/diag-${profile}-${variant}-${when}.log"
    {
        echo "=== $(date '+%H:%M:%S.%N') profile=${profile} variant=${variant} when=${when} ==="
        for ns in client server; do
            echo "--- ${ns} ip link ---"
            ip -n "$ns" -br link 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ip rule ---"
            ip -n "$ns" rule 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ip route (main) ---"
            ip -n "$ns" route 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ip route table 100 ---"
            ip -n "$ns" route show table 100 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ip route table 200 ---"
            ip -n "$ns" route show table 200 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ip neigh ---"
            ip -n "$ns" neigh 2>&1 | sed 's/^/  /'
            echo "--- ${ns} tc qdisc ---"
            ip netns exec "$ns" tc qdisc show 2>&1 | sed 's/^/  /'
            echo "--- ${ns} tc -s qdisc (with stats — netem backlog) ---"
            ip netns exec "$ns" tc -s qdisc show 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ss -lnpu (UDP listen) ---"
            ip netns exec "$ns" ss -lnpu 2>&1 | sed 's/^/  /'
            echo "--- ${ns} ss -lnpt (TCP listen) ---"
            ip netns exec "$ns" ss -lnpt 2>&1 | sed 's/^/  /'
            echo "--- ${ns} conntrack -L (if available) ---"
            ip netns exec "$ns" conntrack -L 2>/dev/null | wc -l | sed 's/^/  count=/'
        done
    } > "$log" 2>&1
    note "  diag → $(basename "$log")"
}

# ── Matrix driver ────────────────────────────────────────────────────────────
run_matrix() {
    for profile in ${PROFILES}; do
        note "── profile=${profile} ───────────────────────────────────────────"
        # Fresh netns per profile. Smoke runs do this implicitly (each smoke
        # calls setup_testbed); matrix used to share one testbed across all
        # profiles, which leaks state across the symmetric→asymmetric switch
        # (see bench_results/single_tcp_aggregation_1781973208.csv:
        #  mqvpn-wlb asym wedges at 80 Mbps = path-B-only after a symmetric
        #  warmup, whereas isolated/smoke wlb-asym hits ~335 Mbps).
        for variant in ${VARIANTS}; do
            note "── variant=${variant} ${profile} ──"
            for streams in ${STREAMS}; do
                for rep in $(seq 1 "${REPEAT}"); do
                    # Per-cell fresh netns + tunnel lifecycle — matches mqvpn's
                    # CI bench (ci_bench_multipath_scheduler.sh:147), which
                    # tears down and recreates everything before every measured
                    # scheduler run. Sharing one mqvpn QUIC connection across
                    # reps lets the wlb scheduler's per-path weighting drift
                    # toward path B and stay there (empirically r1 partial
                    # aggregation → r2 path-B-only ~75 Mbps). 1 cell = 1
                    # tunnel lifecycle keeps every measurement at the same
                    # fresh-state baseline.
                    setup_testbed
                    apply_profile "${profile}"
                    diagnose_state "${profile}" "${variant}" "pre-setup-s${streams}-r${rep}"
                    setup_sysctl_and_routing "${variant}"
                    case "${variant}" in
                        mqvpn-single) start_mqvpn minrtt single || { note "  skipping cell"; reset_routing; continue; } ;;
                        mqvpn-minrtt) start_mqvpn minrtt        || { note "  skipping cell"; reset_routing; continue; } ;;
                        mqvpn-wlb)    start_mqvpn wlb           || { note "  skipping cell"; reset_routing; continue; } ;;
                        mqproxy-single) start_mqproxy single    || { note "  skipping cell"; reset_routing; continue; } ;;
                        mqproxy-tcp)  start_mqproxy             || { note "  skipping cell"; reset_routing; continue; } ;;
                        direct)       : ;;
                    esac
                    run_cell "${variant}" "${profile}" "${streams}" "${rep}"
                    diagnose_state "${profile}" "${variant}" "post-cell-s${streams}-r${rep}"
                    case "${variant}" in
                        mqvpn-*)     stop_mqvpn
                                     if [ "${KEEP_LOGS}" = "1" ]; then
                                         local tag="${variant}-${profile}-${streams}-r${rep}"
                                         mv "${WORK}/mqvpn-server.log" "${WORK}/mqvpn-server-${tag}.log" 2>/dev/null || true
                                         mv "${WORK}/mqvpn-client.log" "${WORK}/mqvpn-client-${tag}.log" 2>/dev/null || true
                                     fi ;;
                        mqproxy-*)   stop_mqproxy ;;
                    esac
                    reset_routing
                done
            done
        done
        clear_profile
    done
}

# ── Smoke functions ──────────────────────────────────────────────────────────
smoke_routing() {
    setup_testbed
    setup_sysctl_and_routing direct
    ip netns exec server iperf3 -s -1 -B 10.70.0.1 -p "${IPERF_PORT}" >/dev/null 2>&1 &
    BENCH_PIDS+=( $! )
    sleep 0.5
    ip netns exec client ping -c 1 -W 2 10.70.0.1 >/dev/null && note "OK: direct E2E ping"
    ip netns exec client iperf3 -c 10.70.0.1 -p "${IPERF_PORT}" -t 2 -O 1 -J -B 10.50.1.1 \
        > "${WORK}/iperf-direct.json" 2>/dev/null
    python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
g=d["end"]["sum_received"]["bits_per_second"]/1e6
print("OK: direct unshaped goodput=%.1f Mbps" % g)
' "${WORK}/iperf-direct.json" || { note "FAIL: direct smoke"; exit 1; }
}

smoke_shaping() {
    setup_testbed
    setup_sysctl_and_routing direct
    apply_profile symmetric
    ip netns exec server iperf3 -s -1 -B 10.70.0.1 -p "${IPERF_PORT}" >/dev/null 2>&1 &
    BENCH_PIDS+=( $! )
    sleep 0.5
    ip netns exec client iperf3 -c 10.70.0.1 -p "${IPERF_PORT}" -t 5 -O 1 -J -B 10.50.1.1 \
        > "${WORK}/iperf-shaped.json" 2>/dev/null
    python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
g=d["end"]["sum_received"]["bits_per_second"]/1e6
assert 70 < g < 100, f"out of range: {g}"
print("OK: shaped goodput=%.1f Mbps" % g)
' "${WORK}/iperf-shaped.json" || { note "FAIL: shaping smoke"; exit 1; }
}

smoke_mqvpn() {
    setup_testbed
    setup_sysctl_and_routing mqvpn-wlb
    apply_profile asymmetric
    start_mqvpn wlb || { note "FAIL: mqvpn start_pair"; exit 1; }
    ip netns exec server iperf3 -s -1 -B "${MQVPN_INNER_SERVER_IP}" -p "${IPERF_PORT}" \
        >/dev/null 2>&1 &
    BENCH_PIDS+=( $! )
    sleep 1
    ip netns exec client ping -c 2 -W 2 "${MQVPN_INNER_SERVER_IP}" >/dev/null \
        && note "OK: mqvpn E2E ping via tun"
    ip netns exec client iperf3 -c "${MQVPN_INNER_SERVER_IP}" -p "${IPERF_PORT}" \
        -t 8 -O 2 -J -P 16 > "${WORK}/iperf-mqvpn.json" 2>/dev/null
    python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
g=d["end"]["sum_received"]["bits_per_second"]/1e6
print("OK: mqvpn-wlb asymmetric P=16 goodput=%.1f Mbps" % g)
print("  (CI ref shows ~322 Mbps with aggregation; 280+ Mbps means path 2 engaged)")
' "${WORK}/iperf-mqvpn.json" || { note "FAIL: mqvpn smoke"; exit 1; }
}

smoke_mqproxy() {
    setup_testbed
    setup_sysctl_and_routing mqproxy-tcp
    apply_profile symmetric
    ip netns exec server iperf3 -s -1 -B 10.70.0.1 -p "${IPERF_PORT}" >/dev/null 2>&1 &
    BENCH_PIDS+=( $! )
    sleep 0.5
    start_mqproxy || { note "FAIL: mqproxy start_pair"; exit 1; }
    ip netns exec client iperf3 -c 127.0.0.1 -p "${SOCAT_LISTEN_PORT}" -t 5 -O 1 -J \
        > "${WORK}/iperf-mqproxy.json" 2>/dev/null
    python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
g=d["end"]["sum_received"]["bits_per_second"]/1e6
print("OK: mqproxy-tcp symmetric P=1 goodput=%.1f Mbps" % g)
assert g > 130, f"NOT AGGREGATING: {g} <= 130 ≈ single-path"
' "${WORK}/iperf-mqproxy.json" || { note "FAIL: mqproxy smoke"; exit 1; }
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
case "${BENCH_SMOKE:-}" in
    routing) smoke_routing; exit 0 ;;
    shaping) smoke_shaping; exit 0 ;;
    mqvpn)   smoke_mqvpn;   exit 0 ;;
    mqproxy) smoke_mqproxy; exit 0 ;;
    matrix2) REPEAT=1; STREAMS=1; PROFILES=symmetric; VARIANTS="direct mqvpn-wlb" ;;
esac

run_matrix
note "bench complete. CSV=${CSV} ($(wc -l < "${CSV}") lines incl header)"

FIGS_DIR="${REPO_ROOT}/docs/report/figures"
mkdir -p "${FIGS_DIR}"
python3 "${REPO_ROOT}/scripts/ci_benchmarks/plot_single_tcp.py" "${CSV}" "${FIGS_DIR}"
note "figures in ${FIGS_DIR}"
