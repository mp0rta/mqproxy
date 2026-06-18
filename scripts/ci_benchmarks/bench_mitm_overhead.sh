#!/usr/bin/env bash
# bench_mitm_overhead.sh — absolute MITM(H2) latency/goodput trend. spec §5.3.
#
# Transparently MITM N curl --http2 fetches (driven as `nobody`, so their TCP
# connection IS captured by the nft REDIRECT) of one staged 4KB object through
# the LIVE MITM path, capture per-request %{time_total}, and emit ABSOLUTE
# p50/p99/ratio via bench_pctile_or_skip (NO cross-protocol subtraction).
#
# The whole live data path is identical to tests/integration/e2e_mitm_h2.sh:
#   curl (as nobody, --http2) → nft REDIRECT → mqproxy-client tproxy listener →
#   mq_mitm_conn orchestrator (forge leaf for SNI, terminate TLS, ALPN=h2) →
#   mq_gw_h2_adapter → gwc → MPQUIC tunnel → mqproxy-server (gateway) → libcurl →
#   ORIGIN (HTTPS).
#
# The MITM preamble below (TLS origin + object staging, MITM CA + world-readable
# copy for nobody, nft REDIRECT table `ip mqproxy`, /etc/hosts mapping, mqproxy
# MITM client + gateway server, readiness wait) is COPIED VERBATIM from
# e2e_mitm_h2.sh — see that file for the exhaustive rationale on each step.
#
# Needs root + CAP_NET_ADMIN (nft) + sudo + the nobody user + an h2-capable curl
# + openssl + python3 + a MITM-capable binary; self-skips (exit 77) otherwise.
#
# Env (passed by CMake; overridable):
#   MQPROXY_BIN          the mqproxy binary (MUST be MITM-capable).
#   MQPROXY_CERT/KEY     tunnel TLS cert/key.
#   MQ_MITM_CA_CRT/KEY   the MITM signing CA (configure-time fixtures).
#   SAMPLES              number of fetches (default 40; bench_pctile needs >=30).
#
# SIGKILL recovery after an aborted run: nft delete table ip mqproxy
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${REPO_ROOT}/scripts/ci_benchmarks/bench_common.sh"
bench_require_capture
trap bench_cleanup EXIT INT TERM

N="${SAMPLES:-40}"
SAMPLES_FILE="$(mktemp)"
chmod 666 "${SAMPLES_FILE}"   # nobody writes samples, root reads them

note() { printf '%s\n' "bench_mitm_overhead: $*" >&2; }

# ── env / fixtures (copied from e2e_mitm_h2.sh) ──────────────────────────────
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
MITM_CA_CRT="${MQ_MITM_CA_CRT:-${REPO_ROOT}/tests/certs/mitm-ca.crt}"
MITM_CA_KEY="${MQ_MITM_CA_KEY:-${REPO_ROOT}/tests/certs/mitm-ca.key}"

TOKEN="mitm-overhead-bench-token"
SERVER_IP="127.0.0.1"
MITM_HOST="mitm.test"        # MITM'd host (SNI → forged leaf signed by MITM CA)
HOSTS_LINE="127.0.0.1 ${MITM_HOST}"
ORIGIN_PORT=""

# ── additional pre-flight skips beyond bench_require_capture ──────────────────
# bench_require_capture covers root+netem+nft+sudo+nobody. The MITM path also
# needs an h2-capable curl, openssl, python3(ssl), and a MITM-capable binary.
if ! command -v curl >/dev/null 2>&1; then
    note "SKIP: curl not found.  (NB: libcurl-dev is NOT the curl CLI — install 'curl'.)"
    exit "${SKIP}"
fi
if ! command -v openssl >/dev/null 2>&1; then
    note "SKIP: openssl CLI not found — needed to mint the runtime origin cert."
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
if ! curl --version 2>/dev/null | grep -qi 'HTTP2'; then
    note "SKIP: curl lacks HTTP/2 support (no 'HTTP2' feature).  Needs an h2-capable curl."
    exit "${SKIP}"
fi

# ── binary + fixture pre-flight (real errors, not skips) ─────────────────────
if [ ! -x "${MQPROXY_BIN}" ]; then
    note "ERROR: mqproxy binary not found/executable: ${MQPROXY_BIN}"
    exit 1
fi
for f in "${MITM_CA_CRT}" "${MITM_CA_KEY}" "${MQPROXY_CERT}" "${MQPROXY_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "ERROR: cert/key missing: ${f} (CMake generates the MITM CA; set MQ_MITM_CA_*)."
        exit 1
    fi
done

# ── free-port selection (QUIC server UDP, tproxy listener TCP, origin TCP) ────
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
while [ -n "${ORIGIN_PORT}" ] && [ "${ORIGIN_PORT}" = "${TPROXY_PORT}" ]; do
    ORIGIN_PORT="$(free_port tcp)"
done
if [ -z "${QUIC_PORT}" ] || [ -z "${TPROXY_PORT}" ] || [ -z "${ORIGIN_PORT}" ]; then
    note "free-port selection failed (python3 socket bind). SKIPPING."
    exit "${SKIP}"
fi

# ── workspace + cleanup (extends bench_cleanup with process+hosts teardown) ──
WORK="$(mktemp -d /tmp/mqproxy_mitm_overhead.XXXXXX)"
# nobody must traverse WORK to write its -o output (mktemp -d is 0700/root).
chmod 755 "${WORK}"

ORIGIN_CERT="${WORK}/origin.crt"   # runtime origin cert (SAN covers MITM_HOST)
ORIGIN_KEY="${WORK}/origin.key"
# World-readable MITM CA copy so the unprivileged `nobody` curl can --cacert it
# (the configure-time MQ_MITM_CA_CRT is root-owned / under a 0700 dir nobody
# cannot traverse — nobody CANNOT read it).
MITM_CA_PUB="${WORK}/mitm_ca.crt"
# Private euid-owned 0600 CA copies that --ca-cert/--ca-key consume (the core's
# read_pem_file_safely rejects a key not owned by geteuid() or with any
# group/other perm; staging root-owned 0600 copies satisfies that gate).
MITM_CA_CRT_RUN="${WORK}/ca.crt"
MITM_CA_KEY_RUN="${WORK}/ca.key"

ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""
HOSTS_BACKED_UP=0

# shellcheck disable=SC2329  # invoked indirectly via the EXIT/INT/TERM trap below
cleanup() {
    rc=$?
    set +e
    trap - EXIT
    # Kill the client FIRST so it runs --setup-redirect teardown (nft delete).
    if [ -n "${CLIENT_PID}" ]; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null
        wait "${CLIENT_PID}" 2>/dev/null
    fi
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    wait 2>/dev/null
    # bench_cleanup tears down the lo qdisc + the `ip mqproxy` nft table (the same
    # table name the MITM client installs / e2e_mitm_h2.sh deletes).
    bench_cleanup
    # Remove the /etc/hosts entry we appended.
    if [ "${HOSTS_BACKED_UP}" -eq 1 ] && [ -f "${WORK}/hosts.bak" ]; then
        cp "${WORK}/hosts.bak" /etc/hosts 2>/dev/null || \
            sed -i "\| ${MITM_HOST}\$|d" /etc/hosts 2>/dev/null
    fi
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne "${SKIP}" ]; then
        for lg in client server origin; do
            if [ -s "${WORK}/${lg}.log" ]; then
                note "──── ${lg}.log (tail) ────"
                tail -n 40 "${WORK}/${lg}.log" | sed 's/^/  '"${lg}"'| /' >&2
            fi
        done
        note "full logs preserved at ${WORK}"
    else
        rm -rf "${WORK}"
    fi
    rm -f "${SAMPLES_FILE}" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ── mint a dedicated origin cert (SAN covers MITM_HOST + localhost + IP) ──────
mint_origin_cert() {
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${ORIGIN_KEY}" -out "${ORIGIN_CERT}" -days 2 \
        -subj "/CN=${MITM_HOST}" \
        -addext "subjectAltName=DNS:${MITM_HOST},DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1 || return 1
    return 0
}

# ── /etc/hosts: map MITM_HOST → 127.0.0.1 (curl SNI + server libcurl) ────────
install_hosts() {
    cp /etc/hosts "${WORK}/hosts.bak" || return 1
    HOSTS_BACKED_UP=1
    printf '%s\n' "${HOSTS_LINE}" >>/etc/hosts || return 1
    return 0
}

# ── TLS origin (python3 http.server + wrap_socket) ───────────────────────────
# Serves files from WORK over TLS; the gateway server fetches via libcurl.
write_origin_py() {
    cat >"${WORK}/origin.py" <<'PY'
import http.server, os, ssl

ROOT = os.environ["MQ_ORIGIN_ROOT"]
PORT = int(os.environ["MQ_ORIGIN_PORT"])
CERT = os.environ["MQ_ORIGIN_CERT"]
KEY  = os.environ["MQ_ORIGIN_KEY"]


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
            "https://localhost:${ORIGIN_PORT}/" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "TLS origin did not become ready within timeout."
    return 1
}

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

# tproxy ingress WITH --mitm. Runs as root (uid 0); --tproxy-uid 0 exempts its
# own + the origin's traffic; curl runs as nobody (uid != 0) → IS captured.
start_client() {
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --tproxy "127.0.0.1:${TPROXY_PORT}" \
        --tproxy-mode redirect \
        --tproxy-dport "${ORIGIN_PORT}" \
        --setup-redirect \
        --tproxy-uid 0 \
        --mitm \
        --ca-cert "${MITM_CA_CRT_RUN}" \
        --ca-key "${MITM_CA_KEY_RUN}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
}

# Wait for: server+client alive, gwc tunnel established, nft REDIRECT installed.
# If the client died because the binary is not MITM-capable, SKIP (not FAIL).
wait_mitm_ready() {
    for _ in $(seq 1 120); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "server died during startup; see ${WORK}/server.log"
            return 1
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            if grep -q -- '--mitm unavailable' "${WORK}/client.log" 2>/dev/null; then
                note "SKIP: mqproxy binary built without BoringSSL — --mitm unavailable."
                exit "${SKIP}"
            fi
            note "client died during startup; see ${WORK}/client.log"
            return 1
        fi
        if grep -q "tunnel conn established" "${WORK}/client.log" 2>/dev/null \
            && grep -q "REDIRECT rules installed" "${WORK}/client.log" 2>/dev/null \
            && nft list table ip mqproxy >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    note "MITM client did not become ready within timeout."
    tail -10 "${WORK}/client.log" >&2 2>/dev/null
    return 1
}

# ── run ──────────────────────────────────────────────────────────────────────
note "minting runtime origin cert (SAN=${MITM_HOST},localhost,127.0.0.1) ..."
mint_origin_cert || { note "ERROR: could not mint origin cert."; exit 1; }

# Stage the world-readable MITM CA copy for the unprivileged curl.
cp "${MITM_CA_CRT}" "${MITM_CA_PUB}" || { note "ERROR: could not stage MITM CA copy."; exit 1; }
chmod 644 "${MITM_CA_PUB}"

# Stage euid-owned 0600 CA cert+key copies for --ca-cert/--ca-key.
cp "${MITM_CA_CRT}" "${MITM_CA_CRT_RUN}" || { note "ERROR: could not stage --ca-cert copy."; exit 1; }
chmod 600 "${MITM_CA_CRT_RUN}"
cp "${MITM_CA_KEY}" "${MITM_CA_KEY_RUN}" || { note "ERROR: could not stage --ca-key copy."; exit 1; }
chmod 600 "${MITM_CA_KEY_RUN}"

note "installing /etc/hosts entry (${HOSTS_LINE}) ..."
install_hosts || { note "ERROR: could not edit /etc/hosts."; exit 1; }

# Stage a real 4KB object (spec §5.3) so each fetch moves meaningful bytes.
head -c 4096 /dev/urandom >"${WORK}/4k.bin"

note "Starting TLS origin on 127.0.0.1:${ORIGIN_PORT} ..."
start_origin || { note "origin unavailable — cannot run MITM bench."; exit 1; }

note "Starting mqproxy server (gateway mode) on ${SERVER_IP}:${QUIC_PORT} ..."
start_server

note "Starting mqproxy MITM client (tproxy=127.0.0.1:${TPROXY_PORT}, --mitm) ..."
start_client
wait_mitm_ready || exit 1
note "MITM client + tunnel + nft REDIRECT rules ready."

MITM_URL="https://${MITM_HOST}:${ORIGIN_PORT}/4k.bin"

note "collecting ${N} MITM(H2) %{time_total} samples for ${MITM_URL} ..."
# `nobody` runs curl (uid != 0 → its TCP connection IS captured by the nft
# REDIRECT). The >>SAMPLES_FILE redirect is INTENTIONALLY performed by the (root)
# parent shell into the pre-chmod-666 samples file — root then reads it back for
# the percentile math (SC2024 is therefore expected here, not a bug).
# shellcheck disable=SC2024
for _ in $(seq 1 "${N}"); do
    sudo -u nobody curl -s --http2 --cacert "${MITM_CA_PUB}" \
        --max-time 20 -o /dev/null -w '%{time_total}\n' "${MITM_URL}" \
        >>"${SAMPLES_FILE}" || true
done

# Emit ABSOLUTE p50/p99/ratio (mitm_p50_ms / mitm_p99_ms / mitm_p99_over_p50).
# bench_pctile_or_skip emits insufficient_samples if <30 lines collected.
bench_pctile_or_skip mitm "${SAMPLES_FILE}" mitm '{}'
exit 0
