#!/usr/bin/env bash
#
# bench_ab_lanes.sh — block (TCP->STREAM) vs relay (inner H3 -> DATAGRAM) A/B.
# Spec: docs/superpowers/specs/2026-06-13-ab-lanes-bench-design.md
#
# Matrix: SKEWS x LOSSES x (block once + relay x SCHEDULERS) x REPEAT.
# Output: bench_results/ab_lanes_<epoch>.csv + stdout summary.
#
# Run:  sudo tests/integration/bench_ab_lanes.sh
# Env:  SKEWS="0 20 50" LOSSES="0 0.5 1" SCHEDULERS="minrtt backup" REPEAT=1
#       RATE=100mbit DELAY=25ms SIZE=32 INNER_CC=bbr CELL_TIMEOUT=120
#       KEEP_QLOGS=1 PICOQUICDEMO=... MQPROXY_BIN=... MQPROXY_CERT/KEY=...
#
# NOTE: decisions need REPEAT>=3 (REPEAT=1 is spec default, adequate for CI
#       smoke but not for publication-quality conclusions).
#
# SIGKILL recovery after aborted run: tc qdisc del dev lo root
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
UDPSOCKS_BIN="${UDPSOCKS_BIN:-${REPO_ROOT}/build/udpsocks}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
PICOQUICDEMO="${PICOQUICDEMO:-${REPO_ROOT}/../picoquic/build/picoquicdemo}"

SKEWS="${SKEWS:-0 20 50}"            # ms, extra delay on path B
LOSSES="${LOSSES:-0 0.5 1}"          # %, per path, each direction
SCHEDULERS="${SCHEDULERS:-minrtt backup}"
REPEAT="${REPEAT:-1}"
RATE="${RATE:-100mbit}"
DELAY="${DELAY:-25ms}"               # path A delay, each direction
SIZE_MB="${SIZE:-32}"
INNER_CC="${INNER_CC:-bbr}"          # picoquic -G
CELL_TIMEOUT="${CELL_TIMEOUT:-120}"  # seconds per transfer

PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"
SERVER_IP="127.0.0.1"
ORIGIN_PORT="${ORIGIN_PORT:-18090}"
QUIC_PORT="${QUIC_PORT:-18453}"
SOCKS_PORT="${SOCKS_PORT:-11090}"
PQ_PORT="${PQ_PORT:-14443}"          # picoquic H3 origin
FWD_PORT="${FWD_PORT:-14720}"        # udpsocks --listen

case "${DELAY}" in *ms) ;; *) DELAY="${DELAY}ms" ;; esac  # tolerate DELAY=25
DELAY_MS="${DELAY%ms}"
SIZE_BYTES=$(( SIZE_MB * 1000000 ))  # SI MB on BOTH arms (dd bs=1000000 below)
                                     # so cross-arm goodput is bias-free
TOKEN="bench-token"
SKIP=77
note() { printf '%s\n' "$*" >&2; }

# ── privilege / binary checks (e2e_multipath conventions) ────────────────────
if [ "$(id -u)" -ne 0 ]; then
    note "bench_ab_lanes: not root; tc/netem on lo needs NET_ADMIN. SKIPPING."
    exit "${SKIP}"
fi
if ! tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    note "bench_ab_lanes: cannot add tc qdisc on lo. SKIPPING."
    exit "${SKIP}"
fi
tc qdisc del dev lo root 2>/dev/null || true
for b in "${MQPROXY_BIN}" "${UDPSOCKS_BIN}"; do
    [ -x "$b" ] || { note "bench_ab_lanes: missing binary: $b"; exit 1; }
done
if ldd "${MQPROXY_BIN}" 2>/dev/null | grep -qi 'libasan'; then
    note "bench_ab_lanes: WARNING: ASan build — numbers are diagnostic-only."
fi
RELAY_ON=1
if [ ! -x "${PICOQUICDEMO}" ]; then
    note "bench_ab_lanes: ============================================="
    note "bench_ab_lanes: PICOQUICDEMO not found (${PICOQUICDEMO})"
    note "bench_ab_lanes: RELAY ARM SKIPPED — block arm only."
    note "bench_ab_lanes: ============================================="
    RELAY_ON=0
fi

WORK="$(mktemp -d /tmp/mqproxy_ab_lanes.XXXXXX)"
RESULTS_DIR="${REPO_ROOT}/bench_results"
mkdir -p "${RESULTS_DIR}"
CSV="${RESULTS_DIR}/ab_lanes_$(date +%s).csv"
echo "arm,scheduler,skew_ms,loss_pct,rep,status,goodput_mbps,elapsed_s,path_a_bytes,path_b_bytes,inner_qlog_lost,netem_drops" >"${CSV}"

ORIGIN_PID=""; SERVER_PID=""; CLIENT_PID=""; PQ_PID=""; FWD_PID=""
cleanup() {
    set +e
    trap - EXIT   # don't run twice on INT/TERM
    for p in "${FWD_PID}" "${PQ_PID}" "${CLIENT_PID}" "${SERVER_PID}" "${ORIGIN_PID}"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
    tc qdisc del dev lo root 2>/dev/null
    wait 2>/dev/null
    [ "${KEEP_QLOGS:-0}" = "1" ] || rm -rf "${WORK}"
    [ "${KEEP_QLOGS:-0}" = "1" ] && note "bench_ab_lanes: KEEP_QLOGS -> ${WORK}"
}
trap cleanup EXIT INT TERM

# ── tc: e2e_multipath layout + per-path delay/loss knobs ─────────────────────
setup_tc() {
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
}

# set_netem <skew_ms> <loss_pct> — retune both leaves for the current cell.
set_netem() {
    local skew="$1" loss="$2" loss_arg_a="" loss_arg_b=""
    if awk -v l="$loss" 'BEGIN { exit !(l+0 > 0) }'; then
        loss_arg_a="loss ${loss}%"; loss_arg_b="loss ${loss}%"
    fi
    # shellcheck disable=SC2086
    tc qdisc change dev lo parent 1:10 handle 10: netem delay "${DELAY_MS}ms" ${loss_arg_a} limit 20000
    # shellcheck disable=SC2086
    tc qdisc change dev lo parent 1:11 handle 11: netem delay "$((DELAY_MS + skew))ms" ${loss_arg_b} limit 20000
}

# total netem drops across both leaves (absolute; caller takes deltas).
netem_drops() {
    tc -s qdisc show dev lo | awk '
        /^qdisc netem (10|11):/ { take = 1; next }
        take && /dropped/ {
            line = $0; gsub(/[(),]/, " ", line); n = split(line, f, /[ \t]+/)
            for (i = 1; i < n; i++) if (f[i] == "dropped") sum += f[i+1]
            take = 0
        }
        END { print sum + 0 }'
}

# ── endpoints ────────────────────────────────────────────────────────────────
start_origin() {
    # bs=1000000 (SI), NOT 1M (MiB): block must transfer exactly SIZE_BYTES,
    # same as the relay arm's /SIZE_BYTES object, or block goodput reads ~4.9%
    # low in every cell.
    dd if=/dev/urandom of="${WORK}/bigfile.bin" bs=1000000 count="${SIZE_MB}" status=none
    ( cd "${WORK}" && exec python3 -m http.server "${ORIGIN_PORT}" --bind 127.0.0.1 \
        >"${WORK}/origin.log" 2>&1 ) &
    ORIGIN_PID=$!
    for _ in $(seq 1 50); do
        curl -s -o /dev/null --range 0-0 "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin" && return 0
        sleep 0.1
    done
    note "bench_ab_lanes: origin did not come up"; return 1
}

# start_pair <logtag> [extra args...] — (re)start mqproxy server+client 2-path.
# Path-readiness gate: after launching the client we poll (up to 8 s, 0.2 s
# steps) for evidence that the extra MPQUIC path has been established before
# returning.  The marker is:
#
#   "mq_client: extra path up: bind <ip> -> path_id <n>"
#   (src/proxy/mq_client.c, client_mp_timer_cb)
#
# The bench passes --path PATH_A (primary bind, no log) and --path PATH_B
# (one extra path, logged once when mp-ready fires).  We therefore poll for 1
# occurrence of "extra path up" in the client log.  On timeout we continue but
# emit a loud stderr warning so the CSV row is flagged by the consumer.
start_pair() {
    local tag="$1"; shift
    stop_pair
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" "$@" \
        >"${WORK}/server_${tag}.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" --token "${TOKEN}" \
        --socks5 "127.0.0.1:${SOCKS_PORT}" \
        --path "${PATH_A_IP}" --path "${PATH_B_IP}" "$@" \
        >"${WORK}/client_${tag}.log" 2>&1 &
    CLIENT_PID=$!
    # Poll for the extra-path log marker (up to 8 s).
    local waited=0 found=0 clog="${WORK}/client_${tag}.log"
    while [ "${waited}" -lt 40 ]; do
        sleep 0.2; waited=$((waited + 1))
        if grep -q 'extra path up:' "${clog}" 2>/dev/null; then
            found=1; break
        fi
    done
    if [ "${found}" -eq 0 ]; then
        note "bench_ab_lanes: WARNING: ${tag}: second path not confirmed at start (extra path up not seen after 8 s) — continuing, CSV row may be 1-path only"
    fi
    kill -0 "${SERVER_PID}" 2>/dev/null && kill -0 "${CLIENT_PID}" 2>/dev/null
}

stop_pair() {
    [ -n "${CLIENT_PID}" ] && { kill -TERM "${CLIENT_PID}" 2>/dev/null; wait "${CLIENT_PID}" 2>/dev/null; CLIENT_PID=""; }
    [ -n "${SERVER_PID}" ] && { kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""; }
}

# path_bytes <client log> — echo "path_a_bytes path_b_bytes" (by ascending id).
# POSIX-awk only (system awk is mawk — no gawk asorti); sort does the ordering.
#
# Assumes each mq.path line appears exactly once per path (the teardown dump
# emitted at connection close, when --metrics-interval is off).  If
# --metrics-interval is set, each interval emits a cumulative counter and awk's
# { tot[$1] += ... } will N×-overcount.  Leave --metrics-interval at its
# default (off) when using this bench.
path_bytes() {
    grep -E 'mq\.path id=' "$1" 2>/dev/null \
        | sed -E 's/.*mq\.path id=([0-9]+).*sent=([0-9]+) recv=([0-9]+).*/\1 \2 \3/' \
        | awk '{ tot[$1] += $2 + $3 } END { for (p in tot) print p, tot[p] }' \
        | sort -n \
        | awk '{ if (NR == 1) a = $2; else if (NR == 2) b = $2 }
               END { print a + 0, b + 0 }'
}

emit() { echo "$1" >>"${CSV}"; note "bench_ab_lanes: ${1}"; }

# ── block arm: curl bulk download via SOCKS5 TCP -> STREAM lane ──────────────
run_block_cell() {
    local skew="$1" loss="$2" rep="$3"
    # --scheduler minrtt explicit: label must not silently lie if default changes.
    start_pair "block_${skew}_${loss}_${rep}" --scheduler minrtt || { emit "block,minrtt,${skew},${loss},${rep},FAIL,,,,,,"; return; }
    local d0 d1 t0 t1 rc speed status="OK" elapsed="" goodput="" pa="" pb=""
    d0="$(netem_drops)"; t0="$(date +%s%3N)"
    # Goodput from curl's own %{speed_download} (bytes/s, transfer-only —
    # excludes SOCKS5 handshake, DNS, connect); convert to Mbps.
    # elapsed_s is still wall-clock (informational).
    speed="$(timeout -k 5 "${CELL_TIMEOUT}" curl -s -o /dev/null \
        --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -w '%{speed_download}' \
        "http://127.0.0.1:${ORIGIN_PORT}/bigfile.bin")"
    rc=$?
    t1="$(date +%s%3N)"; d1="$(netem_drops)"
    stop_pair
    read -r pa pb <<<"$(path_bytes "${WORK}/client_block_${skew}_${loss}_${rep}.log")"
    if [ "${rc}" -eq 124 ]; then status="TIMEOUT"
    elif [ "${rc}" -ne 0 ] || ! awk -v s="${speed}" 'BEGIN { exit !(s+0 > 0) }'; then status="FAIL"
    fi
    elapsed="$(awk -v a="${t0}" -v b="${t1}" 'BEGIN { printf "%.2f", (b-a)/1000 }')"
    # goodput only for completed transfers — a TIMEOUT row must not carry a
    # fake SIZE/CELL_TIMEOUT number that someone plots later.
    # speed_download is in bytes/s; × 8 / 1e6 → Mbps.
    if [ "${status}" = "OK" ]; then
        goodput="$(awk -v s="${speed}" 'BEGIN { if (s+0<=0) print ""; else printf "%.2f", s*8/1000000 }')"
    fi
    emit "block,minrtt,${skew},${loss},${rep},${status},${goodput},${elapsed},${pa},${pb},,$((d1-d0))"
}

# ── relay arm: picoquic H3 via udpsocks shim -> DATAGRAM lane ────────────────
run_relay_cell() {
    local sched="$1" skew="$2" loss="$3" rep="$4"
    local tag="relay_${sched}_${skew}_${loss}_${rep}"
    start_pair "${tag}" --scheduler "${sched}" || { emit "relay,${sched},${skew},${loss},${rep},FAIL,,,,,,"; return; }

    local qdir="${WORK}/qlog_${tag}" scratch="${WORK}/dl_${tag}"
    mkdir -p "${qdir}" "${scratch}"
    "${PICOQUICDEMO}" -p "${PQ_PORT}" -c "${MQPROXY_CERT}" -k "${MQPROXY_KEY}" \
        -q "${qdir}" >"${WORK}/pqsrv_${tag}.log" 2>&1 &
    PQ_PID=$!
    "${UDPSOCKS_BIN}" --proxy "127.0.0.1:${SOCKS_PORT}" \
        --target "127.0.0.1:${PQ_PORT}" --listen "${FWD_PORT}" \
        >"${WORK}/fwd_${tag}.log" 2>&1 &
    FWD_PID=$!
    sleep 0.5
    # Fail fast if the shim or origin died at startup (e.g. ASSOCIATE refused):
    # otherwise a dead shim burns the full CELL_TIMEOUT for every affected cell.
    if ! kill -0 "${FWD_PID}" 2>/dev/null || ! kill -0 "${PQ_PID}" 2>/dev/null; then
        note "bench_ab_lanes: ${tag}: shim/origin died at startup (see fwd_/pqsrv_ logs)"
        kill "${FWD_PID}" "${PQ_PID}" 2>/dev/null; FWD_PID=""; PQ_PID=""
        stop_pair
        emit "relay,${sched},${skew},${loss},${rep},FAIL,,,,,,"
        return
    fi

    local d0 d1 t0 t1 rc got status="OK" elapsed="" goodput="" pa="" pb="" lost="" pq_mbps=""
    d0="$(netem_drops)"; t0="$(date +%s%3N)"
    # -n localhost: required for H3 ALPN negotiation (NULL SNI breaks H3 SETTINGS
    # exchange and causes "Cannot send GET command" even after handshake completes).
    # cd into WORK: picoquicdemo writes demo_{ticket,token}_store.bin into CWD;
    # keep them in the temp dir instead of littering the repo root. The token
    # store also enables 0-RTT on later cells if left shared — same dir for all
    # cells keeps that behaviour uniform across the matrix.
    ( cd "${WORK}" && timeout -k 5 "${CELL_TIMEOUT}" "${PICOQUICDEMO}" -a h3 -G "${INNER_CC}" \
        -n localhost -o "${scratch}" 127.0.0.1 "${FWD_PORT}" "/${SIZE_BYTES}" \
        >"${WORK}/pqcli_${tag}.log" 2>&1 )
    rc=$?
    t1="$(date +%s%3N)"; d1="$(netem_drops)"

    kill "${FWD_PID}" 2>/dev/null; wait "${FWD_PID}" 2>/dev/null; FWD_PID=""
    kill "${PQ_PID}" 2>/dev/null; wait "${PQ_PID}" 2>/dev/null; PQ_PID=""
    stop_pair
    read -r pa pb <<<"$(path_bytes "${WORK}/client_${tag}.log")"

    got="$(find "${scratch}" -type f -printf '%s\n' 2>/dev/null | awk '{ s += $1 } END { print s + 0 }')"
    lost="$(grep -aho 'packet_lost' "${qdir}"/*.qlog 2>/dev/null | wc -l)"
    if [ "${rc}" -eq 124 ]; then status="TIMEOUT"
    elif [ "${rc}" -ne 0 ] || [ "${got}" -ne "${SIZE_BYTES}" ]; then status="FAIL"
    fi
    [ "${KEEP_QLOGS:-0}" = "1" ] || rm -rf "${qdir}" "${scratch}"
    elapsed="$(awk -v a="${t0}" -v b="${t1}" 'BEGIN { printf "%.2f", (b-a)/1000 }')"
    if [ "${status}" = "OK" ]; then
        # Prefer picoquicdemo's own transfer-rate summary line (transfer-only,
        # excludes QUIC handshake).  Format (verbatim from picoquicdemo v1.1.x):
        #   "Received 1000057 bytes in 0.006582 seconds, 1215.505318 Mbps."
        # The Mbps figure is bytes_received * 8 / elapsed_transfer, so it is
        # symmetric with curl's %{speed_download}×8/1e6 on the block arm.
        # grep -oE + mawk (POSIX awk, no gawk match($0,re,arr) extension).
        pq_mbps="$(grep -oE '[0-9]+\.[0-9]+ Mbps\.' \
            "${WORK}/pqcli_${tag}.log" 2>/dev/null \
            | awk 'NR==1 { sub(/ Mbps\./, ""); print }')"
        if [ -n "${pq_mbps}" ] && awk -v m="${pq_mbps}" 'BEGIN { exit !(m+0 > 0) }'; then
            goodput="${pq_mbps}"
        else
            # Fallback: wall-clock goodput (includes QUIC handshake, ~2-3 RTT
            # bias against relay; asymmetric vs block arm's transfer-only rate).
            goodput="$(awk -v sz="${SIZE_BYTES}" -v e="${elapsed}" \
                'BEGIN { if (e+0<=0) print ""; else printf "%.2f", sz*8/e/1000000 }')"
        fi
    fi
    emit "relay,${sched},${skew},${loss},${rep},${status},${goodput},${elapsed},${pa},${pb},${lost},$((d1-d0))"
}

# ── run ──────────────────────────────────────────────────────────────────────
setup_tc || exit 1
start_origin || exit 1
note "bench_ab_lanes: matrix skews=[${SKEWS}] losses=[${LOSSES}] scheds=[${SCHEDULERS}] repeat=${REPEAT} size=${SIZE_MB}MB"

for skew in ${SKEWS}; do
    for loss in ${LOSSES}; do
        set_netem "${skew}" "${loss}"
        note "bench_ab_lanes: === cell skew=${skew}ms loss=${loss}% ==="
        for rep in $(seq 1 "${REPEAT}"); do
            run_block_cell "${skew}" "${loss}" "${rep}"
            if [ "${RELAY_ON}" -eq 1 ]; then
                for sched in ${SCHEDULERS}; do
                    run_relay_cell "${sched}" "${skew}" "${loss}" "${rep}"
                done
            fi
        done
    done
done

note ""
note "bench_ab_lanes: results -> ${CSV}"
note "bench_ab_lanes: ── summary (goodput Mbps; relay rows add spurious_est = qlog_lost - netem_drops, an ESTIMATE) ──"
awk -F, 'NR > 1 {
    sp = ""
    if ($1 == "relay" && $11 != "" && $12 != "") sp = sprintf("  spurious_est=%d", $11 - $12)
    printf "  %-6s %-7s skew=%-3s loss=%-4s %-8s %s%s\n", $1, $2, $3, $4, $6, $7, sp
}' "${CSV}" >&2
exit 0
