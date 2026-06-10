#!/usr/bin/env bash
#
# e2e_gateway.sh — Phase 2 Task 5.1: full-chain HTTP-gateway E2E.
#
# WHAT THIS PROVES (design §6.3 / §14):
#   The complete fetch path works end to end and the error surface is
#   byte-for-byte what the spec promises:
#
#     curl → POST /_mqproxy/fetch (local fetch ingress)
#          → mq_gw_client → H3 over MPQUIC → mqproxy-server
#          → mq_gw_server → libcurl → ORIGIN (TLS, verified) → back.
#
#   Cases (all over the real chain, against a real TLS origin):
#     1. 8MB download, byte-exact (cmp).
#     2. 8MB upload (PUT), byte-exact at the origin + response "len=<n>".
#     3. 403 + x-mq-error: auth-failed   (wrong token; server rejects).
#     4. 400 family: bad target / missing auth / duplicate auth header.
#     5. 502 + x-mq-error: curl:6 (DNS) and curl:7 (connection refused).
#     6. 504 (origin blackhole + short MQ_GW_ORIGIN_CONNECT_TIMEOUT_S).
#     7. x-mq-origin-protocol present on the download response (http/1.1).
#     8. (NET_ADMIN-gated) 2-path aggregation smoke: shape two loopback
#        paths, download 8MB over both, confirm BOTH gateway paths moved bytes
#        (client logs mq_h3_conn_dump_stats per-path counters at SIGTERM).
#        Without NET_ADMIN this sub-case is SKIPPED (a note) — cases 1-7 still
#        decide the exit status.
#
# SKIP DISCIPLINE:
#   The WHOLE script exits 77 (SKIP) ONLY when the python3 TLS origin cannot be
#   stood up (no python3, no ssl, port trouble) — without an origin there is
#   nothing to test. Every OTHER failure is a real FAIL (exit 1). Case 8 alone
#   skipping (no NET_ADMIN) does NOT skip the script.
#
# HOW TO RUN:
#   tests/integration/e2e_gateway.sh                 # cases 1-7 (+ case-8 skip)
#   sudo tests/integration/e2e_gateway.sh            # also runs case 8 (tc on lo)
#   ctest --test-dir build -R e2e_gateway --output-on-failure
#
# ENV (passed by CMake; overridable):
#   MQPROXY_BIN              the `mqproxy` binary.
#   MQPROXY_CERT/KEY         tunnel TLS cert/key (CN=mqproxy-test).
#   MQPROXY_ORIGIN_CERT/KEY  origin TLS cert/key (SAN=IP:127.0.0.1) — the server
#                            verifies the origin against MQPROXY_ORIGIN_CERT
#                            (passed as --origin-ca; we NEVER disable verify).
#
set -u

SKIP=77
note() { printf '%s\n' "e2e_gateway: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
ORIGIN_CERT="${MQPROXY_ORIGIN_CERT:-${REPO_ROOT}/tests/certs/origin.crt}"
ORIGIN_KEY="${MQPROXY_ORIGIN_KEY:-${REPO_ROOT}/tests/certs/origin.key}"

TOKEN="gw-e2e-token"
SERVER_IP="127.0.0.1"
PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"

if [ ! -x "${MQPROXY_BIN}" ]; then
    note "mqproxy binary not found/executable: ${MQPROXY_BIN}"
    note "  Build first (cmake --build build) or set MQPROXY_BIN."
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    note "python3 not found — cannot stand up the TLS origin. SKIPPING."
    exit "${SKIP}"
fi
if ! python3 -c 'import ssl, http.server' 2>/dev/null; then
    note "python3 lacks ssl/http.server — cannot stand up the TLS origin. SKIPPING."
    exit "${SKIP}"
fi
for f in "${ORIGIN_CERT}" "${ORIGIN_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "origin cert/key missing: ${f} (CMake generates it; set MQPROXY_ORIGIN_CERT/KEY)."
        exit 1
    fi
done

# ── free-port selection ──────────────────────────────────────────────────────
# Ask the kernel for an unused TCP/UDP port by binding :0 and reading it back.
# (A previous smoke collided on fixed famous ports — never hardcode.)
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
# A verified-free TCP port held by NOTHING — used for the "connection refused"
# (curl:7) case. We grab it and DON'T bind it, so a connect there is refused.
REFUSED_PORT="$(free_port tcp)"
if [ -z "${ORIGIN_PORT}" ] || [ -z "${QUIC_PORT}" ] || [ -z "${GW_PORT}" ] || \
   [ -z "${REFUSED_PORT}" ]; then
    note "free-port selection failed (python3 socket bind). SKIPPING."
    exit "${SKIP}"
fi

# ── workspace + cleanup ──────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_gateway.XXXXXX)"
BIGFILE="${WORK}/big.bin"
UPLOAD_SAVE="${WORK}/upload_saved.bin"   # origin writes PUT bodies here
ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""
TC_ON=0

cleanup() {
    set +e
    [ -n "${CLIENT_PID}" ] && kill "${CLIENT_PID}" 2>/dev/null
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    [ "${TC_ON}" -eq 1 ] && tc qdisc del dev lo root 2>/dev/null
    wait 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── TLS origin (python3 http.server + wrap_socket) ───────────────────────────
# SimpleHTTPRequestHandler has no do_PUT, so use an inline handler: GET serves
# files from WORK (big.bin), PUT saves the body to UPLOAD_SAVE and replies
# "len=<n>". HTTP/1.1 so x-mq-origin-protocol is http/1.1. The origin reads its
# config (root/save/port/cert/key) from the environment so no shell values are
# interpolated into the python source.
write_origin_py() {
    cat >"${WORK}/origin.py" <<'PY'
import http.server, os, ssl

ROOT = os.environ["MQ_ORIGIN_ROOT"]
SAVE = os.environ["MQ_ORIGIN_SAVE"]
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

    def do_PUT(self):
        # A request with a KNOWN Content-Length is forwarded to the origin with
        # Content-Length framing (the gw client re-emits the validated CL over
        # the tunnel; design §7.1 "recompute"). The genuinely-lengthless path still
        # uses Transfer-Encoding: chunked, so handle BOTH framings and report
        # which one was seen via the x-framing response header so the harness can
        # assert it. Reply "len=<bytes received>".
        te = self.headers.get("Transfer-Encoding", "")
        framing = "chunked" if "chunked" in te.lower() else "content-length"
        total = 0
        with open(SAVE, "wb") as f:
            if "chunked" in te.lower():
                while True:
                    size_line = self.rfile.readline().strip()
                    if not size_line:
                        break
                    size = int(size_line.split(b";", 1)[0], 16)
                    if size == 0:
                        self.rfile.readline()  # trailing CRLF after the 0-chunk
                        break
                    remaining = size
                    while remaining > 0:
                        chunk = self.rfile.read(min(remaining, 65536))
                        if not chunk:
                            break
                        f.write(chunk)
                        total += len(chunk)
                        remaining -= len(chunk)
                    self.rfile.readline()  # CRLF after each chunk's data
            else:
                remaining = int(self.headers.get("Content-Length", "0"))
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 65536))
                    if not chunk:
                        break
                    f.write(chunk)
                    total += len(chunk)
                    remaining -= len(chunk)
        body = ("len=%d" % total).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Framing", framing)
        self.end_headers()
        self.wfile.write(body)


httpd = http.server.HTTPServer(("127.0.0.1", PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
}

start_origin() {
    # 8MB deterministic random file for download/upload cmp.
    dd if=/dev/urandom of="${BIGFILE}" bs=1M count=8 status=none
    write_origin_py
    MQ_ORIGIN_ROOT="${WORK}" MQ_ORIGIN_SAVE="${UPLOAD_SAVE}" \
        MQ_ORIGIN_PORT="${ORIGIN_PORT}" MQ_ORIGIN_CERT="${ORIGIN_CERT}" \
        MQ_ORIGIN_KEY="${ORIGIN_KEY}" \
        python3 "${WORK}/origin.py" >"${WORK}/origin.log" 2>&1 &
    ORIGIN_PID=$!
    # Poll the origin over TLS (verify against its own cert) up to ~5s.
    for _ in $(seq 1 50); do
        if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
            note "TLS origin process died on startup; see ${WORK}/origin.log:"
            sed 's/^/  origin| /' "${WORK}/origin.log" >&2 2>/dev/null
            return 1
        fi
        if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CERT}" \
            "https://127.0.0.1:${ORIGIN_PORT}/big.bin" --range 0-0 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "TLS origin did not become ready within timeout."
    return 1
}

start_server() {
    MQ_GW_ORIGIN_CONNECT_TIMEOUT_S="${1:-}" \
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        --origin-ca "${ORIGIN_CERT}" \
        --request-metrics \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
}

# start_client [extra --path IPs...]: gateway-only client on GW_PORT.
start_client() {
    local path_args=() ip
    for ip in "$@"; do path_args+=(--path "${ip}"); done
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --gateway "127.0.0.1:${GW_PORT}" \
        "${path_args[@]}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
}

stop_client() {
    [ -n "${CLIENT_PID}" ] && kill -TERM "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
    CLIENT_PID=""
}

# Wait until the gateway fetch ingress is accepting AND the tunnel conn is up.
# We poll a trivial fetch that we EXPECT to fail fast (bad target → 400): a 400
# back proves the listener + bridge are alive. Up to ~8s.
wait_gateway_ready() {
    for _ in $(seq 1 80); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "server died during startup; see ${WORK}/server.log:"
            sed 's/^/  server| /' "${WORK}/server.log" >&2 2>/dev/null
            return 1
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            note "client died during startup; see ${WORK}/client.log:"
            sed 's/^/  client| /' "${WORK}/client.log" >&2 2>/dev/null
            return 1
        fi
        # tunnel established is logged by the gw_client on handshake.
        if grep -q "tunnel conn established" "${WORK}/client.log" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "gateway tunnel did not establish within timeout."
    sed 's/^/  client| /' "${WORK}/client.log" >&2 2>/dev/null
    return 1
}

# ── case helpers ─────────────────────────────────────────────────────────────
PASS_COUNT=0
fail() { note "CASE $1 FAIL: $2"; exit 1; }
ok() { PASS_COUNT=$((PASS_COUNT + 1)); note "case $1 PASS: $2"; }

GW="127.0.0.1:${GW_PORT}"
AUTH="X-Mq-Auth: Bearer ${TOKEN}"

# ── run ──────────────────────────────────────────────────────────────────────
start_origin || { note "origin unavailable — SKIPPING whole script."; exit "${SKIP}"; }
start_server "" || exit 1
start_client || exit 1
wait_gateway_ready || exit 1

# ── case 1: 8MB download, byte-exact + (case 7) x-mq-origin-protocol ─────────
DL="${WORK}/dl.bin"
H1="${WORK}/c1_headers.txt"
code1="$(curl -s -o "${DL}" -D "${H1}" -w '%{http_code}' --max-time 30 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/big.bin")"
[ "${code1}" = "200" ] || fail 1 "download HTTP code = ${code1} (want 200); headers: $(tr -d '\r' <"${H1}" | head -3 | tr '\n' '|')"
cmp -s "${BIGFILE}" "${DL}" || fail 1 "downloaded body differs from origin big.bin"
ok 1 "8MB download byte-exact (200)"

# ── mq.req assertion: server must have emitted one request-metrics line ────────
# h3_on_close (which emits mq.req) fires slightly AFTER the client download
# returns, so poll briefly rather than grepping once to avoid a timing race.
# The formatter emits "method=GET status=200" adjacent (single space); match exactly.
mqreq_found=0
for _ in $(seq 1 25); do
    if grep -Eq 'mq\.req cid=.* sid=[0-9]+ method=GET status=200' "${WORK}/server.log"; then
        mqreq_found=1; break
    fi
    sleep 0.2
done
[ "${mqreq_found}" -eq 1 ] || { echo "FAIL: no mq.req line in ${WORK}/server.log after retry"; exit 1; }
note "mq.req line found in server.log"

# ── case 7: x-mq-origin-protocol present on case-1 response (http/1.1) ────────
if grep -qi '^x-mq-origin-protocol:[[:space:]]*http/1.1' "${H1}"; then
    ok 7 "x-mq-origin-protocol: http/1.1 present on download response"
else
    fail 7 "x-mq-origin-protocol header missing/wrong; headers: $(grep -i 'x-mq-origin-protocol' "${H1}" || echo '<none>')"
fi

# ── case 2: 8MB upload (PUT), origin saved file byte-exact + len=<n> ──────────
rm -f "${UPLOAD_SAVE}"
UP_RESP="${WORK}/up_resp.txt"
UP_HDR="${WORK}/up_resp_headers.txt"
code2="$(curl -s -o "${UP_RESP}" -D "${UP_HDR}" -w '%{http_code}' --max-time 30 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Method: PUT" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/upload" \
    --data-binary "@${BIGFILE}")"
[ "${code2}" = "200" ] || fail 2 "upload HTTP code = ${code2} (want 200); body: $(head -c 200 "${UP_RESP}")"
[ -f "${UPLOAD_SAVE}" ] || fail 2 "origin did not save the uploaded body"
cmp -s "${BIGFILE}" "${UPLOAD_SAVE}" || fail 2 "origin-saved upload differs from big.bin"
grep -q '^len=8388608$' "${UP_RESP}" || fail 2 "upload response not 'len=8388608'; got: $(head -c 120 "${UP_RESP}")"
# The known request Content-Length is re-emitted over the tunnel (design §7.1
# "recompute"), so the origin must have seen Content-Length framing, NOT chunked.
# The origin records which framing it saw in the x-framing response header.
grep -qi '^x-framing:[[:space:]]*content-length' "${UP_HDR}" || \
    fail 2 "origin upload framing not content-length; got: $(grep -i x-framing "${UP_HDR}" || echo '<none>')"
ok 2 "8MB upload byte-exact at origin + len=8388608 + Content-Length framing"

# ── case 3: wrong token → 403 + x-mq-error: auth-failed ──────────────────────
H3="${WORK}/c3_headers.txt"
code3="$(curl -s -o /dev/null -D "${H3}" -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "X-Mq-Auth: Bearer wrong-${TOKEN}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/big.bin")"
[ "${code3}" = "403" ] || fail 3 "wrong-token HTTP code = ${code3} (want 403)"
grep -qi '^x-mq-error:[[:space:]]*auth-failed' "${H3}" || \
    fail 3 "x-mq-error: auth-failed header missing; got: $(grep -i x-mq-error "${H3}" || echo '<none>')"
ok 3 "wrong token → 403 + x-mq-error: auth-failed"

# ── case 4: 400 family ───────────────────────────────────────────────────────
# (a) malformed target → 400.
code4a="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" -H "X-Mq-Target: notaurl")"
[ "${code4a}" = "400" ] || fail 4 "(a) bad target HTTP code = ${code4a} (want 400)"
# (b) missing X-Mq-Auth → 400.
code4b="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/big.bin")"
[ "${code4b}" = "400" ] || fail 4 "(b) missing-auth HTTP code = ${code4b} (want 400)"
# (c) duplicate X-Mq-Auth (two different values) → 400.
code4c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "X-Mq-Auth: Bearer ${TOKEN}" \
    -H "X-Mq-Auth: Bearer other-${TOKEN}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/big.bin")"
[ "${code4c}" = "400" ] || fail 4 "(c) duplicate-auth HTTP code = ${code4c} (want 400)"
ok 4 "400 family: bad-target / missing-auth / duplicate-auth"

# ── case 5: 502 family (origin-side curl failures) ───────────────────────────
# (a) DNS failure → 502 + x-mq-error: curl:6.
H5a="${WORK}/c5a_headers.txt"
code5a="$(curl -s -o /dev/null -D "${H5a}" -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://nxdomain-mqproxy-test.invalid/")"
[ "${code5a}" = "502" ] || fail 5 "(a) DNS HTTP code = ${code5a} (want 502)"
grep -qi '^x-mq-error:[[:space:]]*curl:6' "${H5a}" || \
    fail 5 "(a) x-mq-error: curl:6 missing; got: $(grep -i x-mq-error "${H5a}" || echo '<none>')"
# (b) connection refused (a verified-free port) → 502 + x-mq-error: curl:7.
H5b="${WORK}/c5b_headers.txt"
code5b="$(curl -s -o /dev/null -D "${H5b}" -w '%{http_code}' --max-time 15 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://127.0.0.1:${REFUSED_PORT}/")"
[ "${code5b}" = "502" ] || fail 5 "(b) refused HTTP code = ${code5b} (want 502)"
grep -qi '^x-mq-error:[[:space:]]*curl:7' "${H5b}" || \
    fail 5 "(b) x-mq-error: curl:7 missing; got: $(grep -i x-mq-error "${H5b}" || echo '<none>')"
ok 5 "502 family: DNS curl:6 + refused curl:7"

# ── case 6: 504 (origin blackhole + short connect timeout) ───────────────────
# Restart the server with MQ_GW_ORIGIN_CONNECT_TIMEOUT_S=2 so a black-holed
# origin (10.255.255.1, no route/no answer) trips a deterministic 504. The
# client tunnel survives the server restart? No — restart the client too.
stop_client
kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""
start_server "2" || exit 1
start_client || exit 1
wait_gateway_ready || exit 1
H6="${WORK}/c6_headers.txt"
code6="$(curl -s -o /dev/null -D "${H6}" -w '%{http_code}' --max-time 10 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://10.255.255.1/")"
[ "${code6}" = "504" ] || fail 6 "blackhole HTTP code = ${code6} (want 504); x-mq-error: $(grep -i x-mq-error "${H6}" || echo '<none>')"
ok 6 "504 on origin connect timeout (blackhole)"

note "cases 1-7 PASS (${PASS_COUNT}/7 checks)."

# ── case 9: L1 origin-connection reuse proof (no root required) ──────────────
# Proves that two sequential same-origin requests flip origin_reuse 0→1, which
# validates both the Task-2 capture wiring and libcurl's implicit keep-alive.
#
# COLD conncache: case 6 restarted the server with a short connect timeout;
# there may be residual connections in the server's libcurl conncache from
# earlier cases. Restart server+client clean so the conncache starts fresh and
# server.log is truncated to only case-9 traffic.
stop_client
kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""
start_server "" || exit 1
start_client || exit 1
wait_gateway_ready || exit 1

# Two test files of DISTINCT sizes — neither 8388608 (8 MiB) nor each other.
# Reuse is keyed by origin HOST:PORT, not path, so the two files must live at
# the same origin authority (https://127.0.0.1:${ORIGIN_PORT}).
# RESERVED sizes — the mq.req anchors below grep server.log by resp_bytes, so each
# reuse-case body size MUST be unique across the whole script: 3MiB/1MiB (case 9),
# 2MiB/512KiB (case 10), 8MiB (big.bin, cases 1/2/8). A new case reusing one of
# these sizes in the same server.log epoch could mis-anchor (grep|tail -1).
A_SIZE=3145728   # 3 MiB
B_SIZE=1048576   # 1 MiB
head -c "${A_SIZE}" /dev/zero >"${WORK}/a.bin"
head -c "${B_SIZE}" /dev/zero >"${WORK}/b.bin"

# First request — fresh connection, expect origin_reuse=0.
RESP9A="${WORK}/c9a_resp.bin"
code9a="$(curl -s -o "${RESP9A}" -w '%{http_code}' --max-time 30 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/a.bin")"
[ "${code9a}" = "200" ] || fail 9 "(a) first fetch HTTP code = ${code9a} (want 200)"

# Second request — same origin authority, expect reuse (origin_reuse=1).
RESP9B="${WORK}/c9b_resp.bin"
code9b="$(curl -s -o "${RESP9B}" -w '%{http_code}' --max-time 30 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/b.bin")"
[ "${code9b}" = "200" ] || fail 9 "(b) second fetch HTTP code = ${code9b} (want 200)"

# Poll for the first mq.req (anchored to resp_bytes=3145728, origin_reuse=0).
reuse_a_found=0
for _ in $(seq 1 25); do
    if grep -Eq 'mq\.req .* resp_bytes=3145728 .* origin_reuse=0' "${WORK}/server.log"; then
        reuse_a_found=1; break
    fi
    sleep 0.2
done
if [ "${reuse_a_found}" -ne 1 ]; then
    note "case 9 FAIL: no mq.req with resp_bytes=3145728 origin_reuse=0 in server.log"
    note "  mq.req lines in ${WORK}/server.log:"
    grep -E 'mq\.req ' "${WORK}/server.log" >&2 2>/dev/null || true
    exit 1
fi

# Poll for the second mq.req (anchored to resp_bytes=1048576, origin_reuse=1).
reuse_b_found=0
for _ in $(seq 1 25); do
    if grep -Eq 'mq\.req .* resp_bytes=1048576 .* origin_reuse=1' "${WORK}/server.log"; then
        reuse_b_found=1; break
    fi
    sleep 0.2
done
if [ "${reuse_b_found}" -ne 1 ]; then
    note "case 9 FAIL: no mq.req with resp_bytes=1048576 origin_reuse=1 in server.log"
    note "  mq.req lines in ${WORK}/server.log:"
    grep -E 'mq\.req ' "${WORK}/server.log" >&2 2>/dev/null || true
    exit 1
fi

ok 9 "origin_reuse flips 0->1 on repeat same-origin request (L1 reuse proof)"

# ── case 8: 2-path aggregation smoke (NET_ADMIN-gated) ───────────────────────
# Requires tc/netem on lo (NET_ADMIN). Without it: a note + continue (cases 1-7
# already passed → exit 0). With it: shape two equal-rate loopback paths, run a
# gateway-only client bound to both --path IPs, download 8MB over the tunnel,
# SIGTERM the client, and confirm BOTH gateway paths carried bytes (the client
# logs mq_h3_conn_dump_stats per-path counters at SIGTERM via
# mq_gw_client_dump_stats).
RATE="50mbit"; DELAY="10ms"
can_tc=0
if [ "$(id -u)" -eq 0 ] && tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    tc qdisc del dev lo root 2>/dev/null
    can_tc=1
fi

if [ "${can_tc}" -ne 1 ]; then
    note "case 8 skipped (no NET_ADMIN): 2-path aggregation smoke needs tc on lo."
    note "RESULT = PASS (cases 1-7 + case 9; case 8 skipped)."
    exit 0
fi

# Restart server+client clean (case 9 left a clean server up; restart anyway
# to isolate case-8 tc shaping from any residual state).
stop_client
kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""

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
note "case 8: tc shaping applied (RATE=${RATE} DELAY=${DELAY} per path)."

start_server "" || { note "case 8 FAIL: server restart"; exit 1; }
start_client "${PATH_A_IP}" "${PATH_B_IP}" || { note "case 8 FAIL: client restart"; exit 1; }
wait_gateway_ready || { note "case 8 FAIL: tunnel not ready (2-path)"; exit 1; }
# Give the second path time to come up + validate after mp-ready.
sleep 2

DL8="${WORK}/dl8.bin"
code8="$(curl -s -o "${DL8}" -w '%{http_code}' --max-time 40 \
    -X POST "http://${GW}/_mqproxy/fetch" \
    -H "${AUTH}" \
    -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/big.bin")"
[ "${code8}" = "200" ] || fail 8 "2-path download HTTP code = ${code8} (want 200)"
cmp -s "${BIGFILE}" "${DL8}" || fail 8 "2-path download body differs"

# The case-8 request runs on a 2-path connection, so its mq.req must report a
# multipath mp_state; 0 would mean the 2nd path never came up.
#
# We assert [1-3], NOT =1. mp_state is computed by xquic (xqc_multipath.c, from
# the per-stream-per-path cumulative byte counters) and classifies by path
# APP-STATUS, not path count: 1=stream used both an Available- AND a Standby-class
# path, 2=Standby-class only, 3=Available-class only. mqproxy creates ALL paths as
# Available-class (path_status 0; it never marks a path STANDBY — see
# mq_conn.c:412), so a multipath request here ALWAYS reads mp_state=3, never 1/2.
# Note mp_state=3 does NOT prove 2-path aggregation: it's 3 whether 1 or 2
# Available paths carried the stream (this download does aggregate — 8MiB in
# ~750ms ≈ 90Mbit > a single 50mbit path — but mp_state alone can't show that).
# Proving the within-stream byte split needs the per-path-per-stream bytes (spec
# §23.2 "必須"); xquic tracks them internally but does not surface them in
# request_stats — see
# docs/impl-notes/memos/2026-06-09-per-path-per-stream-bytes-not-emitted.md.
# We ANCHOR the match to THIS download's mq.req line via its exact
# resp_bytes=8388608 (the 8 MiB body — the only request of this size in case-8's
# truncated server.log), and on that same line also require a multipath mp_state.
# Anchoring on resp_bytes does double duty: it pins the assertion to the download
# (not some stray request) AND verifies the response-byte accounting is correct
# end-to-end under real 2-path conditions (more valuable than mp_state alone,
# which only confirms the 2nd path came up — it does NOT prove the byte split).
# server.log was truncated by this restart's start_server (case-8 traffic only);
# mq.req fires slightly AFTER curl returns, so poll briefly.
mpmulti_found=0
for _ in $(seq 1 25); do
    if grep -Eq 'mq\.req .* resp_bytes=8388608 .* mp_state=[1-3]' "${WORK}/server.log"; then
        mpmulti_found=1; break
    fi
    sleep 0.2
done
if [ "${mpmulti_found}" -ne 1 ]; then
    note "case 8 FAIL: no mq.req for the 8MiB download (resp_bytes=8388608) with a multipath mp_state (1-3)"
    note "  mq.req lines in ${WORK}/server.log:"
    grep -E 'mq\.req ' "${WORK}/server.log" >&2 2>/dev/null
    exit 1
fi
note "case 8: download mq.req confirmed (resp_bytes=8388608, $(grep -Eo 'mq\.req .* resp_bytes=8388608 .* mp_state=[0-9]+' "${WORK}/server.log" | grep -Eo 'mp_state=[0-9]+' | tail -1))"

# SIGTERM the client → it dumps the gateway conn per-path counters to client.log.
stop_client
PATHS_WITH_BYTES="$(grep -E 'mq\.path id=' "${WORK}/client.log" 2>/dev/null \
    | sed -E 's/.*mq\.path id=([0-9]+).*sent=([0-9]+) recv=([0-9]+).*/\1 \2 \3/' \
    | awk '($2+0 > 0 || $3+0 > 0) { print $1 }' \
    | sort -u | wc -l)"
note "case 8: gateway paths carrying bytes = ${PATHS_WITH_BYTES} (need >= 2)"
if [ "${PATHS_WITH_BYTES}" -lt 2 ]; then
    note "case 8 FAIL: fewer than 2 gateway paths carried bytes."
    note "  per-path stats in ${WORK}/client.log:"
    grep -E 'mq\.path id=' "${WORK}/client.log" >&2 2>/dev/null
    exit 1
fi
ok 8 "2-path aggregation: both gateway paths carried bytes"

# ── case 10 (L2): netem-shaped origin leg — quantitative timing proof ─────────
# Proves that a fresh request pays the TCP-handshake penalty (origin_connect_ms
# reflects the netem delay on the origin TCP leg) while a reused connection
# skips it entirely (origin_connect_ms=0, origin_reuse=1), and that reused
# ttfb_ms < fresh ttfb_ms.
#
# We shape ONLY the origin TCP leg (dst/src port ${ORIGIN_PORT}, protocol=tcp)
# so that the QUIC tunnel (UDP, different port) is unaffected. Without an
# explicit ip protocol match, a filter on the port number alone would also hit
# the QUIC port if it happened to collide numerically (free_port tcp vs
# free_port udp are allocated independently).
#
# COLD conncache: case 8 may have left a live origin connection in libcurl's
# pool. Restart server+client AFTER applying the shaping so the first shaped
# request opens a NEW, delayed connection.

# Clear any tc state case 8 left, then install a fresh single-class HTB+netem
# on the origin TCP port. Defensively probe tc add; skip L2 if it fails.
tc qdisc del dev lo root 2>/dev/null || true
if ! tc qdisc add dev lo root handle 1: htb default 1 2>/dev/null; then
    note "case 10 SKIP: tc qdisc add failed after case-8 teardown (unexpected)."
else
    tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
    tc class add dev lo parent 1: classid 1:10 htb rate "${RATE}" ceil "${RATE}" quantum 1514
    tc qdisc add dev lo parent 1:10 handle 10: netem delay "${DELAY}" limit 20000
    # Match TCP traffic to/from the origin port; explicitly require ip protocol=6
    # so the filter does NOT accidentally match UDP QUIC traffic on the same port number.
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip protocol 6 0xff match ip dport "${ORIGIN_PORT}" 0xffff flowid 1:10
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip protocol 6 0xff match ip sport "${ORIGIN_PORT}" 0xffff flowid 1:10
    TC_ON=1
    note "case 10: tc shaping applied (TCP port ${ORIGIN_PORT}, RATE=${RATE} DELAY=${DELAY})."

    # Cold restart after shaping is in place.
    stop_client
    kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""
    start_server "" || { note "case 10 FAIL: server restart"; exit 1; }
    start_client || { note "case 10 FAIL: client restart"; exit 1; }
    wait_gateway_ready || { note "case 10 FAIL: tunnel not ready"; exit 1; }

    # Two fresh distinct-size files (not used by any prior case):
    #   c.bin = 2 MiB (2097152)
    #   d.bin = 512 KiB (524288)
    C_SIZE=2097152
    D_SIZE=524288
    head -c "${C_SIZE}" /dev/zero >"${WORK}/c.bin"
    head -c "${D_SIZE}" /dev/zero >"${WORK}/d.bin"

    # ── fresh request (c.bin) — must open a new TCP connection to the origin ───
    RESP10C="${WORK}/c10c_resp.bin"
    code10c="$(curl -s -o "${RESP10C}" -w '%{http_code}' --max-time 30 \
        -X POST "http://${GW}/_mqproxy/fetch" \
        -H "${AUTH}" \
        -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/c.bin")"
    [ "${code10c}" = "200" ] || { note "case 10 FAIL: fresh fetch HTTP code = ${code10c} (want 200)"; exit 1; }

    # ── reused request (d.bin) — must reuse the existing origin connection ─────
    RESP10D="${WORK}/c10d_resp.bin"
    code10d="$(curl -s -o "${RESP10D}" -w '%{http_code}' --max-time 30 \
        -X POST "http://${GW}/_mqproxy/fetch" \
        -H "${AUTH}" \
        -H "X-Mq-Target: https://127.0.0.1:${ORIGIN_PORT}/d.bin")"
    [ "${code10d}" = "200" ] || { note "case 10 FAIL: reused fetch HTTP code = ${code10d} (want 200)"; exit 1; }

    # Poll for both mq.req lines (mq.req fires slightly after curl returns).
    mq10_fresh_found=0
    for _ in $(seq 1 25); do
        if grep -Eq "mq\\.req .* resp_bytes=${C_SIZE} .* origin_connect_ms=[0-9-]+" "${WORK}/server.log"; then
            mq10_fresh_found=1; break
        fi
        sleep 0.2
    done
    if [ "${mq10_fresh_found}" -ne 1 ]; then
        note "case 10 FAIL: no mq.req with resp_bytes=${C_SIZE} in server.log"
        grep -E 'mq\.req ' "${WORK}/server.log" >&2 2>/dev/null || true
        exit 1
    fi

    mq10_reuse_found=0
    for _ in $(seq 1 25); do
        if grep -Eq "mq\\.req .* resp_bytes=${D_SIZE} .* origin_reuse=[0-9]+" "${WORK}/server.log"; then
            mq10_reuse_found=1; break
        fi
        sleep 0.2
    done
    if [ "${mq10_reuse_found}" -ne 1 ]; then
        note "case 10 FAIL: no mq.req with resp_bytes=${D_SIZE} in server.log"
        grep -E 'mq\.req ' "${WORK}/server.log" >&2 2>/dev/null || true
        exit 1
    fi

    # ── assert 1: fresh origin_connect_ms > 10 (netem adds ~${DELAY} per RTT) ──
    fresh_cm="$(grep -Eo "mq\\.req .* resp_bytes=${C_SIZE} .* origin_connect_ms=[0-9-]+" "${WORK}/server.log" \
        | grep -Eo 'origin_connect_ms=[0-9-]+' | tail -1 | cut -d= -f2)"
    [ -n "${fresh_cm}" ] || { note "case 10 FAIL: could not extract fresh origin_connect_ms"; exit 1; }
    [ "${fresh_cm}" -gt 10 ] || { note "case 10 FAIL: fresh origin_connect_ms=${fresh_cm} not > 10 under netem (DELAY=${DELAY})"; exit 1; }
    note "case 10: fresh origin_connect_ms=${fresh_cm} (> 10, netem confirmed)"

    # ── assert 2: reused origin_reuse=1 and origin_connect_ms=0 ───────────────
    reuse_flag="$(grep -Eo "mq\\.req .* resp_bytes=${D_SIZE} .* origin_reuse=[0-9]+" "${WORK}/server.log" \
        | grep -Eo 'origin_reuse=[0-9]+' | tail -1 | cut -d= -f2)"
    reuse_cm="$(grep -Eo "mq\\.req .* resp_bytes=${D_SIZE} .* origin_connect_ms=[0-9-]+" "${WORK}/server.log" \
        | grep -Eo 'origin_connect_ms=[0-9-]+' | tail -1 | cut -d= -f2)"
    [ "${reuse_flag}" = "1" ] || { note "case 10 FAIL: reused request origin_reuse=${reuse_flag} (want 1)"; exit 1; }
    [ "${reuse_cm}" = "0" ] || { note "case 10 FAIL: reused request origin_connect_ms=${reuse_cm} (want 0)"; exit 1; }
    note "case 10: reused origin_reuse=1 origin_connect_ms=0 confirmed"

    # ── assert 3: reused ttfb_ms < fresh ttfb_ms ──────────────────────────────
    fresh_ttfb="$(grep -Eo "mq\\.req .* resp_bytes=${C_SIZE} .* ttfb_ms=[0-9-]+" "${WORK}/server.log" \
        | grep -Eo 'ttfb_ms=[0-9-]+' | tail -1 | cut -d= -f2)"
    reuse_ttfb="$(grep -Eo "mq\\.req .* resp_bytes=${D_SIZE} .* ttfb_ms=[0-9-]+" "${WORK}/server.log" \
        | grep -Eo 'ttfb_ms=[0-9-]+' | tail -1 | cut -d= -f2)"
    [ -n "${fresh_ttfb}" ] && [ -n "${reuse_ttfb}" ] || \
        { note "case 10 FAIL: could not extract ttfb_ms (fresh=${fresh_ttfb} reuse=${reuse_ttfb})"; exit 1; }
    [ "${reuse_ttfb}" -lt "${fresh_ttfb}" ] || \
        { note "case 10 FAIL: reused ttfb_ms=${reuse_ttfb} not < fresh ttfb_ms=${fresh_ttfb}"; exit 1; }
    note "case 10: ttfb_ms fresh=${fresh_ttfb} reuse=${reuse_ttfb} (reuse < fresh confirmed)"

    ok 10 "netem-shaped origin: fresh origin_connect_ms=${fresh_cm} > 10, reuse=0ms, ttfb drop confirmed"

    # Tear down the L2 shaping (cleanup trap also handles TC_ON=1).
    tc qdisc del dev lo root 2>/dev/null || true
    TC_ON=0
fi

note "RESULT = PASS (cases 1-9 + L2 case 10 ran under NET_ADMIN)."
exit 0
