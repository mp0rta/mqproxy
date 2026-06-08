#!/usr/bin/env bash
#
# e2e_udp.sh — Phase 3 Task 7.2: UDP relay end-to-end scenarios.
#
# WHAT THIS PROVES (design §6.x / §9.2):
#   The full UDP relay path works end-to-end and the observable surface
#   matches the spec:
#
#     udpsocks (SOCKS5 UDP ASSOCIATE client)
#          → SOCKS5 TCP ingress (mq_listener / mq_udp_assoc)
#          → mq_udp_cli (client-side session table, frag, datagram)
#          → MPQUIC tunnel
#          → mq_udp_srv (server-side session table, defrag, UDP forward)
#          → udp_echo (loopback UDP echo server)
#          → back along the same path.
#
#   Cases:
#     1. 64-byte packet, byte-exact echo (basic happy path).
#     2. 3000-byte packet, byte-exact echo; THEN at server teardown the stats
#        line `mq_udp_srv: stats frags_reassembled=N ...` is grepped from
#        server.log and asserted N > 0 — proves the frag/defrag path ran.
#     3. Two concurrent udp_echo targets (two ports); udpsocks to both in
#        parallel — both exit 0 (byte-exact).
#     4. --udp-idle-timeout 1 on server; udpsocks one packet (OK), sleep 1.5s
#        (session expires), udpsocks again (must succeed → re-OPEN path).
#     5. udpsocks in background with large --count; kill -9 the udpsocks
#        process mid-flight (TCP EOF → server reaps session); assert server
#        health by running a fresh udpsocks that succeeds.
#     6. (NET_ADMIN-gated) 2-path: tc shapes two loopback paths; both paths'
#        recv bytes > 0 from `mq_conn_dump_stats` in client.log after
#        SIGTERM. Without NET_ADMIN this sub-case prints a SKIP note; the
#        script continues and exits 0 (cases 1-5 decide the result, mirroring
#        e2e_gateway semantics).
#
# SERVER GROUPINGS (to minimise restarts while keeping scenario isolation):
#   Server A (default flags):  cases 1, 2, 3, 5.
#   Server B (--udp-idle-timeout 1): case 4.
#   Server C (default, 2-path paths for case 6): NET_ADMIN-gated only.
#
#   Case 2 frag assertion: the frags_sent / frags_reassembled counters live on
#   the per-conn mq_udp_srv struct and are logged at mq_udp_srv_free time
#   (conn teardown, not per-session).  So the assertion fires at Server A
#   teardown (after all A-group cases complete), by grepping server_a.log.
#
# SKIP DISCIPLINE (matches e2e_gateway):
#   The WHOLE script exits 77 (SKIP) ONLY if mqproxy/udpsocks/udp_echo
#   binaries are missing or udp_echo fails to bind — without them nothing
#   can be tested.  All other failures are real FAILs (exit 1).  Case 6 alone
#   skipping (no NET_ADMIN) does NOT skip the script.
#
# HOW TO RUN:
#   tests/integration/e2e_udp.sh                  # cases 1-5 (+ case-6 skip)
#   sudo tests/integration/e2e_udp.sh             # also runs case 6
#   ctest --test-dir build -R e2e_udp --output-on-failure
#
# ENV (passed by CMake; overridable):
#   MQPROXY_BIN     the `mqproxy` binary.
#   UDPSOCKS_BIN    the `udpsocks` binary.
#   UDPECHO_BIN     the `udp_echo` binary.
#   MQPROXY_CERT/KEY  tunnel TLS cert/key (CN=mqproxy-test).
#
set -u

SKIP=77
note() { printf '%s\n' "e2e_udp: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
UDPSOCKS_BIN="${UDPSOCKS_BIN:-${REPO_ROOT}/build/udpsocks}"
UDPECHO_BIN="${UDPECHO_BIN:-${REPO_ROOT}/build/udp_echo}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"

TOKEN="udp-e2e-token"
SERVER_IP="127.0.0.1"
PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"

for bin in "${MQPROXY_BIN}" "${UDPSOCKS_BIN}" "${UDPECHO_BIN}"; do
    if [ ! -x "${bin}" ]; then
        note "binary not found/executable: ${bin}"
        note "  Build first (cmake --build build) or set MQPROXY_BIN/UDPSOCKS_BIN/UDPECHO_BIN."
        exit "${SKIP}"
    fi
done
for f in "${MQPROXY_CERT}" "${MQPROXY_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "cert/key missing: ${f}. SKIPPING."
        exit "${SKIP}"
    fi
done

# ── free-port selection ──────────────────────────────────────────────────────
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

# Grab all ports up front (avoids races between free_port calls).
QUIC_PORT_A="$(free_port udp)"
QUIC_PORT_B="$(free_port udp)"
QUIC_PORT_C="$(free_port udp)"
SOCKS_PORT_A="$(free_port tcp)"
SOCKS_PORT_B="$(free_port tcp)"
SOCKS_PORT_C="$(free_port tcp)"
ECHO_PORT_1="$(free_port udp)"
ECHO_PORT_2="$(free_port udp)"

for v in "${QUIC_PORT_A}" "${QUIC_PORT_B}" "${QUIC_PORT_C}" \
         "${SOCKS_PORT_A}" "${SOCKS_PORT_B}" "${SOCKS_PORT_C}" \
         "${ECHO_PORT_1}" "${ECHO_PORT_2}"; do
    if [ -z "${v}" ]; then
        note "free-port selection failed (python3 socket bind). SKIPPING."
        exit "${SKIP}"
    fi
done

# ── workspace + cleanup ──────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_udp.XXXXXX)"

SERVER_A_PID=""
SERVER_B_PID=""
SERVER_C_PID=""
CLIENT_A_PID=""
CLIENT_B_PID=""
CLIENT_C_PID=""
ECHO1_PID=""
ECHO2_PID=""
C5_BG_PID=""
TC_ON=0

cleanup() {
    set +e
    for pid in "${CLIENT_A_PID}" "${CLIENT_B_PID}" "${CLIENT_C_PID}" \
               "${SERVER_A_PID}" "${SERVER_B_PID}" "${SERVER_C_PID}" \
               "${ECHO1_PID}" "${ECHO2_PID}" "${C5_BG_PID}"; do
        [ -n "${pid}" ] && kill "${pid}" 2>/dev/null
    done
    [ "${TC_ON}" -eq 1 ] && tc qdisc del dev lo root 2>/dev/null
    wait 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── server / client launchers ────────────────────────────────────────────────

# start_server <quic_port> <logfile> [extra_args...]
# Sets the variable named by the 4th arg to the PID.
start_server_at() {
    local quic_port="$1" logfile="$2"
    shift 2
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${quic_port}" \
        --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        "$@" \
        >"${logfile}" 2>&1 &
    echo $!
}

# start_client <quic_port> <socks_port> <logfile> [extra_path_IPs...]
start_client_at() {
    local quic_port="$1" socks_port="$2" logfile="$3"
    shift 3
    local path_args=()
    for ip in "$@"; do path_args+=(--path "${ip}"); done
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${quic_port}" \
        --token "${TOKEN}" \
        --socks5 "127.0.0.1:${socks_port}" \
        "${path_args[@]}" \
        >"${logfile}" 2>&1 &
    echo $!
}

stop_process() {
    local pid="$1"
    [ -n "${pid}" ] && kill -TERM "${pid}" 2>/dev/null
    wait "${pid}" 2>/dev/null || true
}

# ── udp_echo launcher ────────────────────────────────────────────────────────
start_echo() {
    local port="$1" logfile="$2"
    "${UDPECHO_BIN}" --port "${port}" >"${logfile}" 2>&1 &
    local pid=$!
    # Wait for "udp_echo: bound 127.0.0.1:<port>" on stdout (→ logfile).
    for _ in $(seq 1 50); do
        if ! kill -0 "${pid}" 2>/dev/null; then
            note "udp_echo (port ${port}) died on startup; see ${logfile}"
            return 1
        fi
        if grep -q "udp_echo: bound 127.0.0.1:${port}" "${logfile}" 2>/dev/null; then
            echo "${pid}"
            return 0
        fi
        sleep 0.1
    done
    note "udp_echo (port ${port}) did not become ready within timeout"
    kill "${pid}" 2>/dev/null
    return 1
}

# ── UDP relay readiness poll ─────────────────────────────────────────────────
# Polls udpsocks (1-byte send, short timeout) against a known-good echo port
# until the relay is up and carrying traffic, or up to ~5s.
# Usage: wait_udp_ready <socks_port> <echo_port> <server_pid> <client_pid>
wait_udp_ready() {
    local socks_port="$1" echo_port="$2" server_pid="$3" client_pid="$4"
    for _ in $(seq 1 50); do
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            note "server (pid ${server_pid}) died during udp-ready poll"
            return 1
        fi
        if ! kill -0 "${client_pid}" 2>/dev/null; then
            note "client (pid ${client_pid}) died during udp-ready poll"
            return 1
        fi
        # udpsocks: 1-byte send, 300ms timeout; exit 0 = echo succeeded.
        if "${UDPSOCKS_BIN}" \
                --proxy "127.0.0.1:${socks_port}" \
                --target "127.0.0.1:${echo_port}" \
                --send 1 --count 1 --timeout-ms 300 \
                >/dev/null 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "UDP relay did not become ready within timeout (socks=${socks_port} echo=${echo_port})"
    return 1
}

# ── case helpers ─────────────────────────────────────────────────────────────
PASS_COUNT=0
fail() { note "CASE $1 FAIL: $2"; exit 1; }
ok()   { PASS_COUNT=$((PASS_COUNT + 1)); note "case $1 PASS: $2"; }

# ── Start persistent echo servers (used by cases 1-5) ───────────────────────
ECHO1_PID="$(start_echo "${ECHO_PORT_1}" "${WORK}/echo1.log")" || exit "${SKIP}"
ECHO2_PID="$(start_echo "${ECHO_PORT_2}" "${WORK}/echo2.log")" || exit "${SKIP}"

# ─────────────────────────────────────────────────────────────────────────────
# ── Server A group: cases 1, 2, 3, 5 (default idle timeout) ─────────────────
# ─────────────────────────────────────────────────────────────────────────────

SERVER_A_PID="$(start_server_at "${QUIC_PORT_A}" "${WORK}/server_a.log")"
CLIENT_A_PID="$(start_client_at "${QUIC_PORT_A}" "${SOCKS_PORT_A}" "${WORK}/client_a.log")"

wait_udp_ready "${SOCKS_PORT_A}" "${ECHO_PORT_1}" "${SERVER_A_PID}" "${CLIENT_A_PID}" || {
    note "Server A group failed to become ready; logs:"
    sed 's/^/  server_a| /' "${WORK}/server_a.log" >&2 2>/dev/null
    sed 's/^/  client_a| /' "${WORK}/client_a.log" >&2 2>/dev/null
    exit 1
}

# ── case 1: 64-byte packet, byte-exact echo ───────────────────────────────────
if "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_A}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 64 --count 1 --timeout-ms 3000 \
        >/dev/null 2>"${WORK}/c1_udpsocks.err"; then
    ok 1 "64-byte packet byte-exact echo"
else
    fail 1 "udpsocks exit non-zero; stderr: $(head -c 200 "${WORK}/c1_udpsocks.err")"
fi

# ── case 2: 3000-byte packet, byte-exact echo (proves frag path ran) ─────────
# The 3000-byte payload is large enough to require fragmentation over QUIC
# datagrams (MSS is typically ~1200-1400 bytes). The byte-exact assertion is
# handled by udpsocks internally (exit 0 = all sent/received/matched).
# The frags_reassembled > 0 assertion happens at Server A teardown below
# (mq_udp_srv_free logs the stats line to server_a.log on conn close).
if "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_A}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 3000 --count 1 --timeout-ms 5000 \
        >/dev/null 2>"${WORK}/c2_udpsocks.err"; then
    ok 2 "3000-byte packet byte-exact echo (frag path; counter asserted at server teardown)"
else
    fail 2 "udpsocks exit non-zero; stderr: $(head -c 200 "${WORK}/c2_udpsocks.err")"
fi

# ── case 3: two concurrent targets, both byte-exact ───────────────────────────
# Run two udpsocks processes in background concurrently (one per echo port),
# wait for both, assert both exit 0. This proves the session table handles
# multiple independent sessions through one client connection.
"${UDPSOCKS_BIN}" \
    --proxy "127.0.0.1:${SOCKS_PORT_A}" \
    --target "127.0.0.1:${ECHO_PORT_1}" \
    --send 64 --count 3 --timeout-ms 3000 \
    >/dev/null 2>"${WORK}/c3a_udpsocks.err" &
C3A_PID=$!

"${UDPSOCKS_BIN}" \
    --proxy "127.0.0.1:${SOCKS_PORT_A}" \
    --target "127.0.0.1:${ECHO_PORT_2}" \
    --send 64 --count 3 --timeout-ms 3000 \
    >/dev/null 2>"${WORK}/c3b_udpsocks.err" &
C3B_PID=$!

wait "${C3A_PID}"; C3A_RC=$?
wait "${C3B_PID}"; C3B_RC=$?

if [ "${C3A_RC}" -ne 0 ] || [ "${C3B_RC}" -ne 0 ]; then
    fail 3 "concurrent 2-target echo failed: port1_rc=${C3A_RC} port2_rc=${C3B_RC}; err1: $(head -c 200 "${WORK}/c3a_udpsocks.err") err2: $(head -c 200 "${WORK}/c3b_udpsocks.err")"
fi
ok 3 "two concurrent targets (ports ${ECHO_PORT_1} + ${ECHO_PORT_2}), both byte-exact"

# ── case 5: kill udpsocks mid-flight → server reaps session; health check ────
# Start udpsocks with a large --count to keep the TCP control connection alive,
# then kill -9 it after a brief pause. The TCP EOF tells the client, which
# closes the session. Then assert the server is still healthy by running a
# fresh udpsocks invocation that must succeed.

# Snapshot BEFORE launching so earlier cases' closed-session lines are excluded.
C5_PRE=$(grep -c 'mq_udp_srv: session .* closed' "${WORK}/server_a.log" 2>/dev/null || true)

# Use --count 20000 so the process is still running when we kill it (~2s at
# observed throughput; 0.5s sleep is well inside that window).
"${UDPSOCKS_BIN}" \
    --proxy "127.0.0.1:${SOCKS_PORT_A}" \
    --target "127.0.0.1:${ECHO_PORT_1}" \
    --send 64 --count 20000 --timeout-ms 30000 \
    >/dev/null 2>"${WORK}/c5_bg.err" &
C5_BG_PID=$!

# Give it time to send a few packets (session established, traffic in flight).
sleep 0.5

# Kill the udpsocks process mid-flight (simulates abrupt client disconnect).
kill -9 "${C5_BG_PID}" 2>/dev/null
wait "${C5_BG_PID}" 2>/dev/null || true

# Poll up to ~2 s for the count to EXCEED $C5_PRE (the kill-induced reap).
# srv_reap_session fires on the TCP-EOF close-notify, which may be one
# event-loop tick after the kill.
C5_REAP_SEEN=0
for _ in $(seq 1 20); do
    C5_NOW=$(grep -c 'mq_udp_srv: session .* closed' "${WORK}/server_a.log" 2>/dev/null || true)
    if [ "${C5_NOW}" -gt "${C5_PRE}" ]; then
        C5_REAP_SEEN=1
        break
    fi
    sleep 0.1
done
if [ "${C5_REAP_SEEN}" -ne 1 ]; then
    fail 5 "kill-induced reap not seen: 'mq_udp_srv: session N closed' count did not increase (pre=${C5_PRE}) after udpsocks kill; log tail: $(tail -5 "${WORK}/server_a.log" | tr '\n' '|')"
fi

# Server health check: a fresh udpsocks invocation must succeed.
if "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_A}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 64 --count 1 --timeout-ms 3000 \
        >/dev/null 2>"${WORK}/c5_health.err"; then
    ok 5 "kill udpsocks mid-flight → server reaps session (log confirmed); fresh send succeeds"
else
    fail 5 "server unhealthy after udpsocks kill; stderr: $(head -c 200 "${WORK}/c5_health.err"); server_a: $(tail -5 "${WORK}/server_a.log" | tr '\n' '|')"
fi

# ── Tear down Server A group + assert case 2 frags_reassembled > 0 ───────────
# SIGTERM the client first (normal teardown), then the server.
# mq_udp_srv_free → mq_udp_srv_dump_stats fires on server conn close, writing
#   "mq_udp_srv: stats frags_sent=... frags_reassembled=... ..."
# to server_a.log. We wait for this line to appear after server exit.
stop_process "${CLIENT_A_PID}"; CLIENT_A_PID=""
stop_process "${SERVER_A_PID}"; SERVER_A_PID=""

# Wait up to 3s for the stats line to appear (the server may not flush
# immediately; it writes on mq_udp_srv_free which runs at conn teardown).
STATS_A=""
for _ in $(seq 1 30); do
    STATS_A="$(grep 'mq_udp_srv: stats ' "${WORK}/server_a.log" 2>/dev/null | tail -1)"
    if [ -n "${STATS_A}" ]; then break; fi
    sleep 0.1
done

if [ -z "${STATS_A}" ]; then
    fail 2 "(frag assertion) no 'mq_udp_srv: stats' line in server_a.log after teardown; log tail: $(tail -10 "${WORK}/server_a.log" | tr '\n' '|')"
fi

# Parse frags_reassembled=N from the stats line.
FRAGS_REASSEMBLED="$(printf '%s' "${STATS_A}" | grep -oE 'frags_reassembled=[0-9]+' | cut -d= -f2)"
if [ -z "${FRAGS_REASSEMBLED}" ]; then
    fail 2 "(frag assertion) could not parse frags_reassembled from: ${STATS_A}"
fi
if [ "${FRAGS_REASSEMBLED}" -le 0 ]; then
    fail 2 "(frag assertion) frags_reassembled=${FRAGS_REASSEMBLED} (want > 0); stats: ${STATS_A}"
fi
note "case 2 frag assertion: frags_reassembled=${FRAGS_REASSEMBLED} > 0 (stats: ${STATS_A})"

note "cases 1, 2, 3, 5 PASS (${PASS_COUNT}/4 so far)."

# ─────────────────────────────────────────────────────────────────────────────
# ── Server B group: case 4 (--udp-idle-timeout 1) ────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
SERVER_B_PID="$(start_server_at "${QUIC_PORT_B}" "${WORK}/server_b.log" --udp-idle-timeout 1)"
CLIENT_B_PID="$(start_client_at "${QUIC_PORT_B}" "${SOCKS_PORT_B}" "${WORK}/client_b.log")"

wait_udp_ready "${SOCKS_PORT_B}" "${ECHO_PORT_1}" "${SERVER_B_PID}" "${CLIENT_B_PID}" || {
    note "Server B group failed to become ready"
    sed 's/^/  server_b| /' "${WORK}/server_b.log" >&2 2>/dev/null
    exit 1
}

# ── case 4: idle-timeout expiry → re-OPEN path ───────────────────────────────
# First send: proves the session opens.
if ! "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_B}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 64 --count 1 --timeout-ms 3000 \
        >/dev/null 2>"${WORK}/c4a_udpsocks.err"; then
    fail 4 "(initial send) udpsocks failed; stderr: $(head -c 200 "${WORK}/c4a_udpsocks.err")"
fi

# Sleep > 1s (the idle timeout) to let the session expire server-side.
sleep 1.5

# Second send: the session was reaped server-side (idle expiry) and the client
# will see the stream close → re-OPEN on next send. The negative-cache
# distinction (MQ_UDP_CLOSED not permanently cached) is what this proves.
if "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_B}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 64 --count 1 --timeout-ms 5000 \
        >/dev/null 2>"${WORK}/c4b_udpsocks.err"; then
    ok 4 "idle-timeout 1s expiry → re-OPEN path succeeds on second send"
else
    fail 4 "(re-OPEN send) udpsocks failed after idle expiry; stderr: $(head -c 200 "${WORK}/c4b_udpsocks.err"); server_b: $(grep 'idle-expired' "${WORK}/server_b.log" | tail -3 | tr '\n' '|')"
fi

stop_process "${CLIENT_B_PID}"; CLIENT_B_PID=""
stop_process "${SERVER_B_PID}"; SERVER_B_PID=""

note "case 4 PASS (5/5 so far)."
note "cases 1-5 PASS (${PASS_COUNT}/5 checks)."

# ─────────────────────────────────────────────────────────────────────────────
# ── case 6: 2-path aggregation smoke (NET_ADMIN-gated) ───────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Requires tc/netem on lo (NET_ADMIN). Without it: print a note and exit 0
# (cases 1-5 already passed). With it: shape two equal-rate loopback paths,
# start a client bound to both --path IPs, send a packet, SIGTERM the client,
# and confirm BOTH paths carried bytes via `mq_conn_dump_stats` in client.log.
RATE="50mbit"; DELAY="10ms"
can_tc=0
if [ "$(id -u)" -eq 0 ] && tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    tc qdisc del dev lo root 2>/dev/null
    can_tc=1
fi

if [ "${can_tc}" -ne 1 ]; then
    note "case 6 skipped (no NET_ADMIN): 2-path smoke needs tc on lo."
    note "RESULT = PASS (cases 1-5; case 6 skipped)."
    exit 0
fi

# Apply tc shaping: same pattern as e2e_gateway case 8 and e2e_multipath.
tc qdisc del dev lo root 2>/dev/null || true
tc qdisc add dev lo root handle 1: htb default 1
tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
tc class add dev lo parent 1: classid 1:10 htb rate "${RATE}" ceil "${RATE}" quantum 1514
tc class add dev lo parent 1: classid 1:11 htb rate "${RATE}" ceil "${RATE}" quantum 1514
tc qdisc add dev lo parent 1:10 handle 10: netem delay "${DELAY}" limit 20000
tc qdisc add dev lo parent 1:11 handle 11: netem delay "${DELAY}" limit 20000
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src "${PATH_A_IP}/32" flowid 1:10
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip dst "${PATH_A_IP}/32" flowid 1:10
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip src "${PATH_B_IP}/32" flowid 1:11
tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip dst "${PATH_B_IP}/32" flowid 1:11
TC_ON=1
note "case 6: tc shaping applied (RATE=${RATE} DELAY=${DELAY} per path)."

SERVER_C_PID="$(start_server_at "${QUIC_PORT_C}" "${WORK}/server_c.log")"
CLIENT_C_PID="$(start_client_at "${QUIC_PORT_C}" "${SOCKS_PORT_C}" "${WORK}/client_c.log" \
    "${PATH_A_IP}" "${PATH_B_IP}")"

# Give the second path time to come up (mirrors e2e_gateway case-8 sleep).
sleep 2

wait_udp_ready "${SOCKS_PORT_C}" "${ECHO_PORT_1}" "${SERVER_C_PID}" "${CLIENT_C_PID}" || {
    note "case 6 FAIL: 2-path server/client not ready"
    exit 1
}

# Send a burst of 64-byte packets to exercise both paths.
if ! "${UDPSOCKS_BIN}" \
        --proxy "127.0.0.1:${SOCKS_PORT_C}" \
        --target "127.0.0.1:${ECHO_PORT_1}" \
        --send 64 --count 20 --timeout-ms 5000 \
        >/dev/null 2>"${WORK}/c6_udpsocks.err"; then
    note "case 6 FAIL: udpsocks failed in 2-path mode; stderr: $(head -c 200 "${WORK}/c6_udpsocks.err")"
    exit 1
fi

# SIGTERM the client → it dumps mq_conn_dump_stats per-path counters to client_c.log.
stop_process "${CLIENT_C_PID}"; CLIENT_C_PID=""

# Assert both paths carried bytes: "mq.path id=<id> ... sent=<n> recv=<n> ..." lines
# where (sent > 0 OR recv > 0). The client logs these at INFO on SIGTERM via
# mq_conn_dump_stats (same pattern as e2e_multipath and e2e_gateway case 8).
PATHS_WITH_BYTES="$(grep -E 'mq\.path id=' \
        "${WORK}/client_c.log" 2>/dev/null \
    | sed -E 's/.*mq\.path id=([0-9]+).*sent=([0-9]+) recv=([0-9]+).*/\1 \2 \3/' \
    | awk '($2+0 > 0 || $3+0 > 0) { print $1 }' \
    | sort -u | wc -l)"
note "case 6: gateway paths carrying bytes = ${PATHS_WITH_BYTES} (need >= 2)"
if [ "${PATHS_WITH_BYTES}" -lt 2 ]; then
    note "case 6 FAIL: fewer than 2 paths carried bytes."
    note "  per-path stats in ${WORK}/client_c.log:"
    grep -E 'mq\.path id=' "${WORK}/client_c.log" >&2 2>/dev/null
    exit 1
fi
ok 6 "2-path: both paths carried bytes (${PATHS_WITH_BYTES} paths)"

note "RESULT = PASS (cases 1-6)."
exit 0
