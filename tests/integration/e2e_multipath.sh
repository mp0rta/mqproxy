#!/usr/bin/env bash
#
# e2e_multipath.sh — Phase 1 milestone 1-B: multipath aggregation benchmark.
#
# WHAT THIS PROVES (design §9.2):
#   Two shaped loopback paths, each ~RATE with ~DELAY one-way latency, carry a
#   bulk TCP download through the mqproxy SOCKS5 ingress. We measure throughput
#   over ONE path vs TWO paths and assert the 1-B exit criteria:
#     1. aggregate (2-path) throughput >= 1.5x single-path  (the concrete floor)
#     2. ZERO flow-control blocking: the client qlog contains no
#        `xqc_parse_data_blocked_frame` and no `xqc_parse_stream_data_blocked_frame`
#        tokens (the "not window-limited" signal).
#     3. qlog sanity: `frames_processed` > 0 (proves qlog EXTRA importance is on,
#        so the absence in (2) is meaningful and not an empty file).
#     4. per-path split: both paths moved real bytes (client stats / qlog).
#
# HOW TO RUN:
#     sudo tests/integration/e2e_multipath.sh
#   or via ctest (registered as `e2e_multipath`, skips cleanly without root):
#     sudo ctest --test-dir build -R e2e_multipath --output-on-failure
#
#   Requires NET_ADMIN (tc/netem on `lo`). WITHOUT it the script prints a notice
#   and exits 77 (the autotools "skip" code) — ctest is configured with
#   SKIP_RETURN_CODE 77 so it reports SKIPPED, not FAILED.
#
# TUNABLE ENV VARS (defaults in parens):
#   RATE   (250mbit)  per-path rate cap applied with tbf.
#   DELAY  (25ms)     per-path one-way netem delay (RTT ~= 2*DELAY).
#   SIZE   (64)       bulk file size in MB.
#   MQPROXY_BIN       path to the `mqproxy` binary (default: ./build/mqproxy).
#   MQPROXY_CERT/KEY  TLS cert/key for the server (default: tests/certs/test.*).
#
# tc SHAPING APPROACH (documented):
#   We attach an HTB root qdisc to `lo`, create one HTB class per path with a
#   ceil of RATE, hang a netem (delay DELAY) leaf under each class, and steer
#   traffic into the right class with u32 filters matching the CLIENT SOURCE IP:
#       127.0.0.2 -> class 1:10 (path A),  127.0.0.3 -> class 1:11 (path B).
#   The server listens on 127.0.0.1; each client path binds a distinct source IP
#   in 127.0.0.0/8 (all local), so egress from each path hits its own shaped
#   class. Shaping `lo` affects ALL loopback traffic, so the trap restores `lo`
#   to its pristine (qdisc-less) state on EXIT.
#
set -u

# ── config ──────────────────────────────────────────────────────────────────
RATE="${RATE:-250mbit}"
DELAY="${DELAY:-25ms}"
SIZE_MB="${SIZE:-64}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"

PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"
SERVER_IP="127.0.0.1"

# Ephemeral-ish ports (fixed within a run; chosen high to avoid collisions).
ORIGIN_PORT="${ORIGIN_PORT:-18080}"
QUIC_PORT="${QUIC_PORT:-18443}"
SOCKS_PORT="${SOCKS_PORT:-11080}"

TOKEN="bench-token"

# ── skip if not privileged (no NET_ADMIN -> can't shape lo) ───────────────────
SKIP=77
note() { printf '%s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    note "e2e_multipath: not root; tc/netem on lo needs NET_ADMIN. SKIPPING."
    note "  Run with: sudo $0"
    exit "${SKIP}"
fi
# Probe that we can actually add a netem qdisc (catches no-NET_ADMIN-as-root too,
# e.g. unprivileged container). Add+delete a throwaway qdisc on lo.
if ! tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    note "e2e_multipath: cannot add tc qdisc on lo (no NET_ADMIN). SKIPPING."
    exit "${SKIP}"
fi
tc qdisc del dev lo root 2>/dev/null || true

if [ ! -x "${MQPROXY_BIN}" ]; then
    note "e2e_multipath: mqproxy binary not found/executable: ${MQPROXY_BIN}"
    note "  Build first (cmake --build build) or set MQPROXY_BIN."
    exit 1
fi

# ── workspace + cleanup ───────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_multipath.XXXXXX)"
QLOG_DIR="${WORK}/qlog"
mkdir -p "${QLOG_DIR}"
BIGFILE="${WORK}/bigfile.bin"

ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    set +e
    [ -n "${CLIENT_PID}" ] && kill "${CLIENT_PID}" 2>/dev/null
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    # Restore lo to pristine state.
    tc qdisc del dev lo root 2>/dev/null
    wait 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── tc shaping: two shaped classes on lo, steered by client source IP ────────
setup_tc() {
    tc qdisc del dev lo root 2>/dev/null || true
    # HTB root; default class 1:1 (unshaped-ish, high ceil) for everything else
    # (e.g. the origin <-> server localhost leg and control traffic).
    tc qdisc add dev lo root handle 1: htb default 1
    tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
    tc class add dev lo parent 1: classid 1:10 htb rate "${RATE}" ceil "${RATE}"
    tc class add dev lo parent 1: classid 1:11 htb rate "${RATE}" ceil "${RATE}"
    # netem delay leaf under each shaped class (one-way DELAY each -> RTT ~2*DELAY).
    tc qdisc add dev lo parent 1:10 handle 10: netem delay "${DELAY}"
    tc qdisc add dev lo parent 1:11 handle 11: netem delay "${DELAY}"
    # Steer by CLIENT SOURCE IP into the matching shaped class.
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip src "${PATH_A_IP}/32" flowid 1:10
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip src "${PATH_B_IP}/32" flowid 1:11
    note "e2e_multipath: tc shaping applied to lo (RATE=${RATE} DELAY=${DELAY} each path)"
}

# ── bulk origin (plain HTTP over a generated N-MB file) ──────────────────────
start_origin() {
    # Deterministic N-MB file.
    dd if=/dev/urandom of="${BIGFILE}" bs=1M count="${SIZE_MB}" status=none
    ( cd "${WORK}" && exec python3 -m http.server "${ORIGIN_PORT}" --bind 127.0.0.1 \
        >"${WORK}/origin.log" 2>&1 ) &
    ORIGIN_PID=$!
    # Wait for the origin to accept.
    for _ in $(seq 1 50); do
        if curl -s -o /dev/null "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin" \
            --range 0-0 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "e2e_multipath: origin did not come up"
    return 1
}

start_server() {
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        --qlog "${QLOG_DIR}" \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
}

# Start the client with N path args. $@ = list of --path local IPs.
start_client() {
    local path_args=()
    local ip
    for ip in "$@"; do
        path_args+=(--path "${ip}")
    done
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --socks5 "127.0.0.1:${SOCKS_PORT}" \
        --qlog "${QLOG_DIR}" \
        "${path_args[@]}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
    # Give the connection + extra paths time to come up and validate.
    sleep 2.0
}

stop_client() {
    # SIGTERM: the CLI handles it (mq_engine_stop -> loop breaks -> it logs
    # mq_conn_dump_stats per-path counters to client.log before teardown).
    [ -n "${CLIENT_PID}" ] && kill -TERM "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
    CLIENT_PID=""
}

# Pull the big file through the SOCKS5 proxy; echo the download speed (bytes/s).
run_transfer() {
    curl -s -o /dev/null \
        --socks5-hostname "127.0.0.1:${SOCKS_PORT}" \
        -w '%{speed_download}' \
        "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin"
}

# ── run ───────────────────────────────────────────────────────────────────────
setup_tc || exit 1
start_origin || exit 1
start_server || exit 1

note "e2e_multipath: === single-path run (path A only) ==="
start_client "${PATH_A_IP}"
SINGLE_BPS="$(run_transfer)"
stop_client
note "e2e_multipath: single-path speed = ${SINGLE_BPS} bytes/s"

# Fresh qlog for the two-path run (the assertions read the two-path client qlog).
rm -f "${QLOG_DIR}/client.qlog"

note "e2e_multipath: === two-path run (path A + path B) ==="
start_client "${PATH_A_IP}" "${PATH_B_IP}"
DUAL_BPS="$(run_transfer)"
# Dump the client's per-path stats before killing it (logged at INFO on signal/
# exit via mq_conn_dump_stats — captured in client.log). Give it a moment.
stop_client
note "e2e_multipath: two-path speed   = ${DUAL_BPS} bytes/s"

# ── assertions ─────────────────────────────────────────────────────────────────
CLIENT_QLOG="${QLOG_DIR}/client.qlog"
fail=0

# (1) aggregation >= 1.5x
RATIO="$(awk -v d="${DUAL_BPS}" -v s="${SINGLE_BPS}" \
    'BEGIN { if (s+0 <= 0) { print "0"; } else { printf "%.3f", d/s } }')"
note "e2e_multipath: aggregation ratio = ${RATIO}x (need >= 1.5)"
PASS_RATIO="$(awk -v r="${RATIO}" 'BEGIN { print (r+0 >= 1.5) ? 1 : 0 }')"
if [ "${PASS_RATIO}" -ne 1 ]; then
    note "e2e_multipath: FAIL: aggregate throughput < 1.5x single-path"
    fail=1
fi

# count_token <pattern> <file> — print the match count (0 if no match / no file).
# grep -c exits 1 when the count is 0 but still prints "0"; capture stdout only.
count_token() {
    local n
    n="$(grep -c "$1" "$2" 2>/dev/null)"
    [ -n "${n}" ] || n=0
    printf '%s' "${n}"
}

# (3) qlog sanity FIRST (an empty qlog would make (2) vacuously pass).
if [ ! -s "${CLIENT_QLOG}" ]; then
    note "e2e_multipath: FAIL: client qlog missing/empty: ${CLIENT_QLOG}"
    fail=1
    FRAMES=0
else
    FRAMES="$(count_token 'frames_processed' "${CLIENT_QLOG}")"
fi
note "e2e_multipath: frames_processed count = ${FRAMES} (need > 0)"
if [ "${FRAMES}" -le 0 ]; then
    note "e2e_multipath: FAIL: no frames_processed events (qlog EXTRA importance not on)"
    fail=1
fi

# (2) zero blocked frames — the "not window-limited" signal.
BLOCKED_CONN="$(count_token 'xqc_parse_data_blocked_frame' "${CLIENT_QLOG}")"
BLOCKED_STREAM="$(count_token 'xqc_parse_stream_data_blocked_frame' "${CLIENT_QLOG}")"
note "e2e_multipath: blocked frames: conn=${BLOCKED_CONN} stream=${BLOCKED_STREAM} (need 0/0)"
if [ "${BLOCKED_CONN}" -ne 0 ] || [ "${BLOCKED_STREAM}" -ne 0 ]; then
    note "e2e_multipath: FAIL: flow-control blocking detected (window-limited)"
    fail=1
fi

# (4) per-path split: both paths moved real bytes. The client logs lines like
#   "mq_conn stats: path <id>: sent=<n> recv=<n>"  on teardown (mq_conn_dump_stats).
# Count distinct path ids whose sent>0 OR recv>0.
PATHS_WITH_BYTES="$(grep -Eo 'path [0-9]+: sent=[0-9]+ recv=[0-9]+' "${WORK}/client.log" 2>/dev/null \
    | sed -E 's/path ([0-9]+): sent=([0-9]+) recv=([0-9]+)/\1 \2 \3/' \
    | awk '($2+0 > 0 || $3+0 > 0) { print $1 }' \
    | sort -u | wc -l)"
note "e2e_multipath: paths carrying bytes (from client stats) = ${PATHS_WITH_BYTES} (need >= 2)"
if [ "${PATHS_WITH_BYTES}" -lt 2 ]; then
    note "e2e_multipath: FAIL: fewer than 2 paths carried bytes (no real aggregation)."
    note "  Inspect ${WORK}/client.log for the per-path 'mq_conn stats:' lines."
    fail=1
fi

if [ "${fail}" -ne 0 ]; then
    note "e2e_multipath: RESULT = FAIL"
    exit 1
fi
note "e2e_multipath: RESULT = PASS (aggregation ${RATIO}x, 0 blocked frames, qlog OK)"
exit 0
