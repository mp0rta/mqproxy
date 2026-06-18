#!/usr/bin/env bash
# bench_proxy_overhead.sh — single-path QUIC-tunnel overhead via the SOCKS5 listener.
# spec §5.1. Emits proxy/direct goodput + tunnel_overhead_pct. SKIP(77) w/o root+netem.
#
# Measures goodput of a fixed SIZE_MB transfer through mqproxy's SOCKS5 listener
# over a SINGLE QUIC path, vs a `direct` (no-proxy) baseline to the SAME origin
# under the SAME `lo` shaping (HTB rate + netem delay). Reports:
#   proxy_goodput_mbps   — curl %{speed_download} through --socks5-hostname × 8 / 1e6
#   direct_goodput_mbps  — curl %{speed_download} straight to the origin × 8 / 1e6
#   tunnel_overhead_pct  — (direct - proxy) / direct * 100
#
# Plumbing (origin / server / single-path SOCKS client / SOCKS goodput math) is
# copied from tests/integration/bench_ab_lanes.sh's block arm, reduced to ONE path.
#
# Env:  RATE=100mbit DELAY=25ms SIZE=32 REPEAT=1 CELL_TIMEOUT=120
#       MQPROXY_BIN=... MQPROXY_CERT=... MQPROXY_KEY=...
#
# SIGKILL recovery after an aborted run: tc qdisc del dev lo root
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${REPO_ROOT}/scripts/ci_benchmarks/bench_common.sh"

bench_require_root_netem

MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"

RATE="${RATE:-100mbit}"
DELAY="${DELAY:-25ms}"
SIZE_MB="${SIZE:-32}"
N="${REPEAT:-1}"
CELL_TIMEOUT="${CELL_TIMEOUT:-120}"

case "${DELAY}" in *ms) ;; *) DELAY="${DELAY}ms" ;; esac  # tolerate DELAY=25

SERVER_IP="127.0.0.1"
PATH_A_IP="127.0.0.1"          # SINGLE path — bind the primary path to loopback
TOKEN="bench-proxy-overhead-token"
# SI MB on both arms (dd bs=1000000 below) keeps proxy vs direct goodput bias-free.

note() { printf '%s\n' "bench_proxy_overhead: $*" >&2; }

[ -x "${MQPROXY_BIN}" ] || { note "missing binary: ${MQPROXY_BIN}"; exit 1; }
if ldd "${MQPROXY_BIN}" 2>/dev/null | grep -qi 'libasan'; then
    note "WARNING: ASan build — numbers are diagnostic-only."
fi

# ── free-port selection (e2e_gateway idiom; never hardcode) ──────────────────
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

ORIGIN_PORT="$(free_port tcp)"
QUIC_PORT="$(free_port udp)"
SOCKS_PORT="$(free_port tcp)"
if [ -z "${ORIGIN_PORT}" ] || [ -z "${QUIC_PORT}" ] || [ -z "${SOCKS_PORT}" ]; then
    note "free-port selection failed (python3 socket bind). SKIPPING."
    exit "${SKIP}"
fi

WORK="$(mktemp -d /tmp/mqproxy_proxy_overhead.XXXXXX)"
ORIGIN_PID=""; SERVER_PID=""; CLIENT_PID=""

# shellcheck disable=SC2329  # invoked indirectly via the EXIT/INT/TERM trap below
cleanup() {
    set +e
    trap - EXIT
    [ -n "${CLIENT_PID}" ] && kill "${CLIENT_PID}" 2>/dev/null
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    wait 2>/dev/null
    bench_cleanup            # tears down the lo qdisc (+ any stray nft table)
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── lo shaping: HTB rate + netem delay (bench_common helper) ─────────────────
bench_netem_lo "${RATE}" "${DELAY}"

# ── TLS-less HTTP origin (copy of bench_ab_lanes' block-arm origin) ──────────
# bs=1000000 (SI), NOT 1M (MiB): the transfer must move exactly SIZE_BYTES so
# proxy and direct goodput are on the same SI footing.
start_origin() {
    dd if=/dev/urandom of="${WORK}/bigfile.bin" bs=1000000 count="${SIZE_MB}" status=none
    ( cd "${WORK}" && exec python3 -m http.server "${ORIGIN_PORT}" --bind 127.0.0.1 \
        >"${WORK}/origin.log" 2>&1 ) &
    ORIGIN_PID=$!
    for _ in $(seq 1 50); do
        if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
            note "origin process died on startup; see ${WORK}/origin.log"; return 1
        fi
        curl -s -o /dev/null --range 0-0 "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin" \
            && return 0
        sleep 0.1
    done
    note "origin did not come up"; return 1
}

# ── single-path mqproxy server + SOCKS5 client ───────────────────────────────
# Copied from bench_ab_lanes' start_pair, reduced to a SINGLE --path (PATH_A_IP)
# and with --scheduler minrtt explicit so the label can't silently lie.
start_pair() {
    stop_pair
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --socks5 "127.0.0.1:${SOCKS_PORT}" \
        --path "${PATH_A_IP}" --scheduler minrtt \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
    kill -0 "${SERVER_PID}" 2>/dev/null && kill -0 "${CLIENT_PID}" 2>/dev/null
}

stop_pair() {
    [ -n "${CLIENT_PID}" ] && { kill -TERM "${CLIENT_PID}" 2>/dev/null; wait "${CLIENT_PID}" 2>/dev/null; CLIENT_PID=""; }
    [ -n "${SERVER_PID}" ] && { kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""; }
}

# Readiness gate: the SOCKS client logs no single-path "up" marker, so probe the
# real path — a tiny --range 0-0 fetch THROUGH the SOCKS proxy can only succeed
# once the listener is bound AND the tunnel + control AUTH are established. Poll
# up to ~16s (80 × 0.2s).
wait_socks_ready() {
    for _ in $(seq 1 80); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "server died during startup; see ${WORK}/server.log"; return 1
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            note "client died during startup; see ${WORK}/client.log"; return 1
        fi
        if curl -s -o /dev/null --max-time 2 \
            --socks5-hostname "127.0.0.1:${SOCKS_PORT}" --range 0-0 \
            "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    note "SOCKS tunnel did not become ready within timeout."; return 1
}

# ── goodput measurement (curl %{speed_download}, transfer-only) ──────────────
# Goodput from curl's own %{speed_download} (bytes/s, transfer-only — excludes
# the SOCKS5/TCP handshake, DNS, connect); × 8 / 1e6 → Mbps. Same math on both
# arms, so proxy vs direct is apples-to-apples. Echoes "" on failure.

# _best_mbps <speed-bytes-per-s> <prev-best> — keep the larger Mbps; echo it.
_keep_best() {
    local speed="$1" best="$2" mbps
    awk -v s="${speed}" 'BEGIN { exit !(s+0 > 0) }' || { printf '%s' "${best}"; return; }
    mbps="$(awk -v s="${speed}" 'BEGIN { printf "%.2f", s*8/1000000 }')"
    if [ -z "${best}" ] || awk -v a="${mbps}" -v b="${best}" 'BEGIN { exit !(a+0 > b+0) }'; then
        printf '%s' "${mbps}"
    else
        printf '%s' "${best}"
    fi
}

# measure_socks — N timed transfers through the SOCKS5 listener; echo best Mbps.
measure_socks() {
    local best="" speed
    for _ in $(seq 1 "${N}"); do
        if speed="$(timeout -k 5 "${CELL_TIMEOUT}" curl -s -o /dev/null \
            --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -w '%{speed_download}' \
            "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin")"; then
            best="$(_keep_best "${speed}" "${best}")"
        fi
    done
    printf '%s' "${best}"
}

# measure_direct — same object, same lo shaping, NO proxy/SOCKS; echo best Mbps.
measure_direct() {
    local best="" speed
    for _ in $(seq 1 "${N}"); do
        if speed="$(timeout -k 5 "${CELL_TIMEOUT}" curl -s -o /dev/null \
            -w '%{speed_download}' \
            "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin")"; then
            best="$(_keep_best "${speed}" "${best}")"
        fi
    done
    printf '%s' "${best}"
}

# ── run ──────────────────────────────────────────────────────────────────────
start_origin || exit 1
start_pair   || { note "server/client failed to start"; exit 1; }
wait_socks_ready || exit 1

note "transferring ${SIZE_MB}MB (×${N}) over shaping: htb ${RATE} + netem ${DELAY}"
proxy_mbps="$(measure_socks)"
direct_mbps="$(measure_direct)"
stop_pair

if [ -z "${proxy_mbps}" ] || [ -z "${direct_mbps}" ]; then
    note "FAIL: a transfer produced no goodput (proxy='${proxy_mbps}' direct='${direct_mbps}')"
    exit 1
fi
if ! awk -v d="${direct_mbps}" 'BEGIN { exit !(d+0 > 0) }'; then
    note "FAIL: direct goodput not positive ('${direct_mbps}')"; exit 1
fi

overhead="$(awk "BEGIN{printf \"%.2f\", (${direct_mbps}-${proxy_mbps})/${direct_mbps}*100}")"
note "proxy=${proxy_mbps} Mbps  direct=${direct_mbps} Mbps  overhead=${overhead}%"

meta="$(jq -cn --argjson d "${direct_mbps}" --argjson p "${proxy_mbps}" \
    --arg shaping "htb ${RATE} + netem ${DELAY}" \
    '{shaping:$shaping,direct_mbps:$d,proxy_mbps:$p}')"
bench_emit_json proxy_overhead proxy_goodput_mbps  "${proxy_mbps}"  mbps "${meta}"
bench_emit_json proxy_overhead direct_goodput_mbps "${direct_mbps}" mbps "${meta}"
bench_emit_json proxy_overhead tunnel_overhead_pct "${overhead}"    pct  "${meta}"
exit 0
