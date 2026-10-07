#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
#
# e2e_path_recovery.sh — a black-holed path is removed and re-added (Rust client).
#
# WHAT THIS PROVES:
#   The client runs two paths (A = primary 127.0.0.2, B = extra 127.0.0.3) to the
#   server on 127.0.0.1. For each of B and A in turn, every packet from or to that
#   path's IP is dropped (tc netem loss 100% on lo). Then:
#     1. xquic removes the dead path after the idle timeout (--keepalive-idle) and
#        the client logs "path_id N removed";
#     2. the connection survives: no "tunnel down", and a download through the
#        SOCKS5 ingress succeeds while the path is still black-holed;
#     3. once the black hole lifts, the client re-adds a path from the same
#        address ("path up: bind ...") and after a download the new path id has
#        received bytes (the `mq.path` lines logged at exit).
#
# HOW TO RUN:
#     sudo tests/integration/e2e_path_recovery.sh
#   Needs NET_ADMIN (tc on lo); without it the script exits 77 (skip).
#
# ENV:
#   MQPROXY_BIN   the Rust `mqproxy` binary (default: target/release/mqproxy).
#   IDLE          --keepalive-idle seconds (default 20; must exceed xquic's 15 s PING).
#
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/target/release/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
IDLE="${IDLE:-20}"

SERVER_IP="127.0.0.1"
PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"
ORIGIN_PORT="${ORIGIN_PORT:-18081}"
QUIC_PORT="${QUIC_PORT:-18444}"
SOCKS_PORT="${SOCKS_PORT:-11081}"
TOKEN="recovery-token"

SKIP=77
note() { printf 'e2e_path_recovery: %s\n' "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    note "not root; tc on lo needs NET_ADMIN. SKIPPING."
    exit "${SKIP}"
fi
if ! tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    note "cannot add a tc qdisc on lo (no NET_ADMIN). SKIPPING."
    exit "${SKIP}"
fi
tc qdisc del dev lo root 2>/dev/null || true
if [ ! -x "${MQPROXY_BIN}" ]; then
    note "mqproxy binary not found: ${MQPROXY_BIN} (cargo build --release -p mqproxy)"
    exit 1
fi

WORK="$(mktemp -d /tmp/mqproxy_e2e_path_recovery.XXXXXX)"
ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    set +e
    for p in "${CLIENT_PID}" "${SERVER_PID}" "${ORIGIN_PID}"; do
        [ -n "${p}" ] && kill "${p}" 2>/dev/null
    done
    tc qdisc del dev lo root 2>/dev/null
    wait 2>/dev/null
    if [ "${KEEP:-0}" = "1" ] || [ "${RESULT:-fail}" != "pass" ]; then
        note "logs kept in ${WORK}"
    else
        rm -rf "${WORK}"
    fi
}
trap cleanup EXIT INT TERM

# A prio root whose 4th band is a netem leaf; `blackhole <ip>` steers both
# directions of <ip> into it and drops everything, `lift` stops dropping.
setup_tc() {
    tc qdisc add dev lo root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
    tc qdisc add dev lo parent 1:4 handle 40: netem loss 0%
}
blackhole() {
    tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src "$1/32" flowid 1:4
    tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip dst "$1/32" flowid 1:4
    tc qdisc change dev lo parent 1:4 handle 40: netem loss 100%
}
lift() {
    tc qdisc change dev lo parent 1:4 handle 40: netem loss 0%
    tc filter del dev lo parent 1: prio 1
}

# wait_log <file> <fixed string> <seconds>
wait_log() {
    local i
    for i in $(seq 1 $(($3 * 10))); do
        grep -qF -- "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

fetch() {
    curl -s -o /dev/null --max-time 10 -w '%{http_code}' \
        --socks5-hostname "127.0.0.1:${SOCKS_PORT}" \
        "http://127.0.0.1:${ORIGIN_PORT}/$1"
}

start_origin() {
    dd if=/dev/urandom of="${WORK}/small.bin" bs=64K count=1 status=none
    dd if=/dev/urandom of="${WORK}/big.bin" bs=1M count=8 status=none
    ( cd "${WORK}" && exec python3 -m http.server "${ORIGIN_PORT}" --bind 127.0.0.1 \
        >"${WORK}/origin.log" 2>&1 ) &
    ORIGIN_PID=$!
    for _ in $(seq 1 50); do
        curl -s -o /dev/null "http://127.0.0.1:${ORIGIN_PORT}/small.bin" && return 0
        sleep 0.1
    done
    note "origin did not come up"
    return 1
}

start_server() {
    "${MQPROXY_BIN}" server --listen "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
}

# run_case <name> <dead ip> <expected re-add bind text>
run_case() {
    local name="$1" dead="$2" bind="$3" log="${WORK}/client-$1.log" fail=0
    note "=== ${name}: black-hole ${dead} ==="
    "${MQPROXY_BIN}" client --server "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --socks5 "127.0.0.1:${SOCKS_PORT}" --keepalive-idle "${IDLE}" \
        --path "${PATH_A_IP}" --path "${PATH_B_IP}" >"${log}" 2>&1 &
    CLIENT_PID=$!
    if ! wait_log "${log}" "path up: bind ${PATH_B_IP}" 10; then
        note "FAIL ${name}: the extra path never came up"
        return 1
    fi
    [ "$(fetch small.bin)" = "200" ] || { note "FAIL ${name}: no relay before the black hole"; return 1; }

    blackhole "${dead}"
    # Keep a little traffic going so the surviving path carries the connection.
    local removed=0 i
    for i in $(seq 1 $((IDLE + 20))); do
        fetch small.bin >/dev/null
        if grep -qE 'path_id [0-9]+ removed' "${log}"; then
            removed=1
            break
        fi
        sleep 1
    done
    if [ "${removed}" -ne 1 ]; then
        note "FAIL ${name}: the black-holed path was never removed"
        fail=1
    fi
    local code
    code="$(fetch small.bin)"
    if [ "${code}" != "200" ]; then
        note "FAIL ${name}: relay failed while ${dead} is black-holed (http ${code})"
        fail=1
    fi
    local ups
    ups="$(grep -c "path up: bind ${bind}" "${log}")"

    lift
    local readded=0
    for i in $(seq 1 100); do
        if [ "$(grep -c "path up: bind ${bind}" "${log}")" -gt "${ups}" ]; then
            readded=1
            break
        fi
        sleep 0.1
    done
    if [ "${readded}" -ne 1 ]; then
        note "FAIL ${name}: no path re-added on ${bind} after the black hole lifted"
        fail=1
    fi
    sleep 1 # let the new path validate
    [ "$(fetch big.bin)" = "200" ] || { note "FAIL ${name}: relay failed after recovery"; fail=1; }

    kill -TERM "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
    CLIENT_PID=""

    if grep -q 'tunnel down' "${log}"; then
        note "FAIL ${name}: the connection was lost (tunnel down)"
        fail=1
    fi
    local new_id
    new_id="$(grep -oE "path up: bind ${bind} -> path_id [0-9]+" "${log}" | tail -1 | grep -oE '[0-9]+$')"
    local recv
    recv="$(grep -E "mq\.path id=${new_id} " "${log}" | tail -1 | sed -E 's/.* recv=([0-9]+).*/\1/')"
    note "${name}: re-added path_id=${new_id:-?} recv=${recv:-?}"
    if [ -z "${recv}" ] || [ "${recv}" -le 0 ]; then
        note "FAIL ${name}: the re-added path carried nothing"
        fail=1
    fi
    [ "${fail}" -eq 0 ] && note "${name}: PASS"
    return "${fail}"
}

setup_tc || exit 1
start_origin || exit 1
start_server || exit 1

rc=0
run_case extra "${PATH_B_IP}" "${PATH_B_IP}" || rc=1
run_case primary "${PATH_A_IP}" "the primary socket" || rc=1

if [ "${rc}" -ne 0 ]; then
    note "RESULT = FAIL"
    exit 1
fi
RESULT=pass
note "RESULT = PASS"
exit 0
