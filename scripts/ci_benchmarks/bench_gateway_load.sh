#!/usr/bin/env bash
# bench_gateway_load.sh — gateway req/s + p50/p99 latency, new-conn-per-request. spec §5.4.
#
# Drives N independent POST /_mqproxy/fetch requests through the gateway fetch
# ingress, each on a FRESH TCP connection (the ingress is HTTP/1.1 one-request-
# per-connection — Connection: close — so one curl process == one connection ==
# one request). Captures per-request %{time_total}; req_per_sec is therefore
# connection-establishment-bound. Emits req_per_sec + p50/p99/ratio (the latter
# via bench_pctile_or_skip).
#
# The whole live data path is the gateway-fetch chain from
# tests/integration/e2e_gateway.sh:
#   curl → POST /_mqproxy/fetch (plaintext HTTP/1.1 on GW_PORT) → mq_gw_client →
#   H3 over MPQUIC → mqproxy-server (gateway) → libcurl → ORIGIN (TLS, verified
#   against --origin-ca) → back.
#
# The STARTUP preamble below (TLS origin + object staging, mqproxy gateway client
# exposing the fetch ingress on GW_PORT, gateway server, auth TOKEN, origin-CA
# wiring, readiness wait, free-port selection) is COPIED from e2e_gateway.sh —
# see that file for the exhaustive rationale on each step. e2e_gateway has NO load
# machinery; the load loop here is entirely new.
#
# ④ is a LOCAL-listener load test: it does NOT shape lo (no bench_netem_lo) and
# needs no nft/nobody. The root guard (bench_require_root_netem) is only for
# consistent skip behavior with ①–③ in CTest; self-skips (exit 77) unprivileged.
#
# Env (passed by CMake; overridable):
#   MQPROXY_BIN              the mqproxy binary.
#   MQPROXY_CERT/KEY         tunnel TLS cert/key.
#   MQPROXY_ORIGIN_CERT/KEY  origin TLS cert/key (server verifies via --origin-ca).
#   REQUESTS                 number of fetches (default 200; pctile needs >=30).
#   CONC                     xargs parallelism (default 8).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${REPO_ROOT}/scripts/ci_benchmarks/bench_common.sh"
bench_require_root_netem
trap bench_cleanup EXIT INT TERM

note() { printf '%s\n' "bench_gateway_load: $*" >&2; }

N="${REQUESTS:-200}"
CONC="${CONC:-8}"

# ── env / fixtures (copied from e2e_gateway.sh) ──────────────────────────────
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
ORIGIN_CERT="${MQPROXY_ORIGIN_CERT:-${REPO_ROOT}/tests/certs/origin.crt}"
ORIGIN_KEY="${MQPROXY_ORIGIN_KEY:-${REPO_ROOT}/tests/certs/origin.key}"

TOKEN="gw-load-bench-token"
SERVER_IP="127.0.0.1"

# ── pre-flight (real errors, not skips) + origin skip-guards ──────────────────
if [ ! -x "${MQPROXY_BIN}" ]; then
    note "ERROR: mqproxy binary not found/executable: ${MQPROXY_BIN}"
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    note "SKIP: curl not found.  (NB: libcurl-dev is NOT the curl CLI — install 'curl'.)"
    exit "${SKIP}"
fi
if ! command -v python3 >/dev/null 2>&1; then
    note "SKIP: python3 not found — cannot stand up the TLS origin."
    exit "${SKIP}"
fi
if ! python3 -c 'import ssl, http.server' 2>/dev/null; then
    note "SKIP: python3 lacks ssl/http.server — cannot stand up the TLS origin."
    exit "${SKIP}"
fi
for f in "${ORIGIN_CERT}" "${ORIGIN_KEY}" "${MQPROXY_CERT}" "${MQPROXY_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "ERROR: cert/key missing: ${f} (CMake generates it; set MQPROXY_ORIGIN_CERT/KEY)."
        exit 1
    fi
done

# ── free-port selection (copied from e2e_gateway.sh) ──────────────────────────
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
GW_PORT="$(free_port tcp)"
if [ -z "${ORIGIN_PORT}" ] || [ -z "${QUIC_PORT}" ] || [ -z "${GW_PORT}" ]; then
    note "free-port selection failed (python3 socket bind). SKIPPING."
    exit "${SKIP}"
fi

# ── workspace + cleanup (extends bench_cleanup with process teardown) ─────────
WORK="$(mktemp -d /tmp/mqproxy_gateway_load.XXXXXX)"
SAMPLES_FILE="$(mktemp)"
ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""

# shellcheck disable=SC2329  # invoked indirectly via the EXIT/INT/TERM trap below
cleanup() {
    set +e
    [ -n "${CLIENT_PID}" ] && kill "${CLIENT_PID}" 2>/dev/null
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    wait 2>/dev/null
    bench_cleanup
    rm -rf "${WORK}"
    rm -f "${SAMPLES_FILE}" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ── TLS origin (python3 http.server + wrap_socket) — copied from e2e_gateway.sh
write_origin_py() {
    cat >"${WORK}/origin.py" <<'PY'
import http.server, os, ssl

ROOT = os.environ["MQ_ORIGIN_ROOT"]
PORT = int(os.environ["MQ_ORIGIN_PORT"])
CERT = os.environ["MQ_ORIGIN_CERT"]
KEY = os.environ["MQ_ORIGIN_KEY"]


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = os.path.join(ROOT, os.path.basename(self.path))
        if not os.path.isfile(path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
}

start_origin() {
    # Stage a small 4KB object (spec §5.4) so each fetch moves meaningful bytes
    # while keeping req_per_sec connection-establishment-bound (not transfer-bound).
    head -c 4096 /dev/urandom >"${WORK}/4k.bin"
    write_origin_py
    MQ_ORIGIN_ROOT="${WORK}" MQ_ORIGIN_PORT="${ORIGIN_PORT}" \
        MQ_ORIGIN_CERT="${ORIGIN_CERT}" MQ_ORIGIN_KEY="${ORIGIN_KEY}" \
        python3 "${WORK}/origin.py" >"${WORK}/origin.log" 2>&1 &
    ORIGIN_PID=$!
    for _ in $(seq 1 50); do
        if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
            note "TLS origin process died on startup; see ${WORK}/origin.log"
            return 1
        fi
        if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CERT}" \
            "https://127.0.0.1:${ORIGIN_PORT}/4k.bin" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "TLS origin did not become ready within timeout."
    return 1
}

# Gateway SERVER — copied from e2e_gateway.sh start_server().
start_server() {
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        --origin-ca "${ORIGIN_CERT}" \
        --request-metrics \
        --cache-max-bytes 67108864 \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
}

# Gateway-only CLIENT exposing the fetch ingress on GW_PORT — copied from
# e2e_gateway.sh start_client().
start_client() {
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --gateway "127.0.0.1:${GW_PORT}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
}

# Readiness wait — copied from e2e_gateway.sh wait_gateway_ready().
wait_gateway_ready() {
    for _ in $(seq 1 80); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "server died during startup; see ${WORK}/server.log"
            return 1
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            note "client died during startup; see ${WORK}/client.log"
            return 1
        fi
        if grep -q "tunnel conn established" "${WORK}/client.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "gateway tunnel did not establish within timeout."
    return 1
}

# ── run ──────────────────────────────────────────────────────────────────────
note "Starting TLS origin on 127.0.0.1:${ORIGIN_PORT} ..."
start_origin || { note "origin unavailable — cannot run gateway load bench."; exit 1; }

note "Starting mqproxy gateway server on ${SERVER_IP}:${QUIC_PORT} ..."
start_server

note "Starting mqproxy gateway client (fetch ingress on 127.0.0.1:${GW_PORT}) ..."
start_client
wait_gateway_ready || exit 1
note "gateway client + tunnel ready."

GW="127.0.0.1:${GW_PORT}"
TARGET="https://127.0.0.1:${ORIGIN_PORT}/4k.bin"

# One curl process == one TCP connection == one HTTP/1.1 request (the ingress
# closes the connection — Connection: close — so curl cannot keep-alive it).
# shellcheck disable=SC2329  # invoked indirectly via `export -f req` + bash -c 'req' below
req() {
    curl -s -o /dev/null -w '%{time_total}\n' --max-time 20 \
        -X POST "http://${GW}/_mqproxy/fetch" \
        -H "X-Mq-Auth: Bearer ${TOKEN}" \
        -H "X-Mq-Target: ${TARGET}"
}
export -f req
export GW TOKEN TARGET

note "collecting ${N} req/s + %{time_total} samples (conc=${CONC}, conn-per-request) ..."
start="$(date +%s.%N)"
seq 1 "${N}" | xargs -P "${CONC}" -I{} bash -c 'req' >>"${SAMPLES_FILE}"
end="$(date +%s.%N)"

rps="$(awk "BEGIN{printf \"%.1f\", ${N}/(${end}-${start})}")"
meta="$(jq -cn --argjson c "${CONC}" --argjson n "${N}" '{conc:$c,requests:$n}')"
bench_emit_json gateway req_per_sec "${rps}" rps "${meta}"
note "req_per_sec=${rps} (N=${N}, conc=${CONC})"

# Emit p50/p99/ratio (gw_p50_ms / gw_p99_ms / gw_p99_over_p50); emits
# insufficient_samples if <30 lines collected.
bench_pctile_or_skip gateway "${SAMPLES_FILE}" gw "${meta}"
exit 0
