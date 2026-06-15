#!/usr/bin/env bash
#
# e2e_tproxy.sh — Phase 7 MITM Slice 0+1: transparent capture + opaque relay e2e.
#
# WHAT THIS PROVES (design §7 / §8):
#   Transparent TCP capture (REDIRECT mode via nft) + opaque relay through the
#   mqproxy QUIC tunnel works end-to-end, byte-exactly, with clean teardown.
#
#   The key falsifiability axis is OPACITY: curl is asked to verify the origin's
#   TLS certificate against the origin CA directly (--cacert origin.crt).  If
#   mqproxy were intercepting/MITM-ing the TLS session it would need to present its
#   OWN cert (test.crt, not trusted by the origin CA), and curl would REJECT it
#   with a certificate-verification error.  A clean TLS handshake that verifies
#   against the origin CA therefore proves the relay is OPAQUE — the TLS stream
#   passes through unmodified, with the origin's cert arriving intact.
#
# ARCHITECTURE OF THE TEST:
#   - TLS origin (python3 ssl/http.server) on 127.0.0.1:443 (root can bind 443).
#     dport=443 is hardcoded in --setup-redirect (mq_tproxy_setup.c).
#   - mqproxy server: UDP on a free ephemeral port (127.0.0.1).
#   - mqproxy client (running as root, uid 0):
#       --tproxy 127.0.0.1:<ephemeral-tcp>   transparent-capture listener
#       --tproxy-mode redirect                nft NAT OUTPUT hook
#       --setup-redirect                      installs nft rules on start, removes on exit
#       --tproxy-uid 0                        EXEMPT uid 0 (root) from capture
#     This means: connections from root are SKIPPED by the nft rule, so mqproxy
#     itself and the origin server (both root) can talk to each other directly.
#   - Test TLS check via curl running as nobody (uid 65534, typically):
#       sudo -u nobody curl https://127.0.0.1/ --cacert origin.crt
#     nobody's outbound TCP to 127.0.0.1:443 is caught by the nft REDIRECT rule,
#     diverted to the tproxy listener port, tunneled over QUIC to the server, and
#     the server relays it to 127.0.0.1:443 where the origin is actually listening.
#     curl sees the origin's cert because the relay is OPAQUE.
#
# UID STRATEGY:
#   The whole test script runs as root.  mqproxy client also runs as root (uid 0)
#   and sets --tproxy-uid 0 to exempt its own traffic.  curl is invoked via
#   "sudo -u nobody" so its uid differs from 0 — the nft skuid 0 return rule does
#   NOT exempt it, and its connection is captured and tunneled.
#
# WHAT IS NOT VERIFIED (no root in dev sandbox):
#   The happy path (case 1: TLS opacity proof, case 2: multipath smoke, case 3:
#   teardown assertion) cannot run without CAP_NET_ADMIN/root.  The script is
#   correct-by-construction, following e2e_gateway.sh and e2e_multipath.sh idioms
#   closely; see the NOTE comments for each uncertain step.
#
# TO VALIDATE AS ROOT (run this on a root-capable machine):
#   sudo MQPROXY_BIN=/path/to/build/mqproxy \
#        MQPROXY_CERT=/path/to/tests/certs/test.crt \
#        MQPROXY_KEY=/path/to/tests/certs/test.key \
#        MQPROXY_ORIGIN_CERT=/path/to/tests/certs/origin.crt \
#        MQPROXY_ORIGIN_KEY=/path/to/tests/certs/origin.key \
#        bash tests/integration/e2e_tproxy.sh
#
#   Or via ctest (registered with SKIP_RETURN_CODE 77):
#   sudo ctest --test-dir build -R e2e_tproxy --output-on-failure
#
# ENV (passed by CMake; overridable):
#   MQPROXY_BIN              the `mqproxy` binary.
#   MQPROXY_CERT/KEY         tunnel TLS cert/key (CN=mqproxy-test).
#   MQPROXY_ORIGIN_CERT/KEY  origin TLS cert/key (SAN=IP:127.0.0.1) — curl
#                            verifies against MQPROXY_ORIGIN_CERT.
#
set -u

SKIP=77
note() { printf '%s\n' "e2e_tproxy: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
ORIGIN_CERT="${MQPROXY_ORIGIN_CERT:-${REPO_ROOT}/tests/certs/origin.crt}"
ORIGIN_KEY="${MQPROXY_ORIGIN_KEY:-${REPO_ROOT}/tests/certs/origin.key}"

TOKEN="tproxy-e2e-token"
SERVER_IP="127.0.0.1"
# ORIGIN_PORT is a free TCP port chosen below; the client captures exactly that
# port via --tproxy-dport, so the test does not collide with anything already on
# :443 on the host.
ORIGIN_PORT=""

PATH_A_IP="127.0.0.2"
PATH_B_IP="127.0.0.3"

# ── SKIP GATE (must be FIRST, before any privileged operation) ───────────────
# Condition 1: must be root (CAP_NET_ADMIN for nft + IP_TRANSPARENT).
if [ "$(id -u)" -ne 0 ]; then
    note "SKIP: not root.  Transparent capture needs root for nft + IP_TRANSPARENT."
    note "  Run with: sudo $0"
    note "  Or via ctest: sudo ctest --test-dir build -R e2e_tproxy --output-on-failure"
    exit "${SKIP}"
fi

# Condition 2: nft must be available (nftables).
if ! command -v nft >/dev/null 2>&1; then
    note "SKIP: nft (nftables) not found.  Install nftables and re-run."
    exit "${SKIP}"
fi

# Condition 3: probe that we can actually install an nft table (catches container
# without CAP_NET_ADMIN even when running as root).
if ! nft add table ip mqproxy_probe 2>/dev/null; then
    note "SKIP: cannot add nft table (no CAP_NET_ADMIN?).  Needs full NET_ADMIN capability."
    exit "${SKIP}"
fi
nft delete table ip mqproxy_probe 2>/dev/null || true

# Condition 4: sudo must be available (for running curl as nobody).
if ! command -v sudo >/dev/null 2>&1; then
    note "SKIP: sudo not found.  Required to run curl as nobody for capture test."
    exit "${SKIP}"
fi

# Condition 5: nobody user must exist.
if ! id nobody >/dev/null 2>&1; then
    note "SKIP: user 'nobody' does not exist.  Required as the non-root curl uid."
    exit "${SKIP}"
fi

# ── binary + cert pre-flight (these are real errors, not skips) ──────────────
if [ ! -x "${MQPROXY_BIN}" ]; then
    note "ERROR: mqproxy binary not found/executable: ${MQPROXY_BIN}"
    note "  Build first (cmake --build build) or set MQPROXY_BIN."
    exit 1
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

# ── free-port selection (for the QUIC server and tproxy listener) ─────────────
# The tproxy listener can use any ephemeral TCP port; nft redirects :443 to it.
# The QUIC server uses an ephemeral UDP port.
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
# Back-to-back ephemeral binds can hand back the same number; ensure distinct.
while [ -n "${ORIGIN_PORT}" ] && [ "${ORIGIN_PORT}" = "${TPROXY_PORT}" ]; do
    ORIGIN_PORT="$(free_port tcp)"
done
if [ -z "${QUIC_PORT}" ] || [ -z "${TPROXY_PORT}" ] || [ -z "${ORIGIN_PORT}" ]; then
    note "ERROR: free-port selection failed (python3 socket bind)."
    exit 1
fi

# nobody uid — needed to assert that the skuid exemption works
NOBODY_UID="$(id -u nobody)"

# ── workspace + cleanup ───────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_tproxy.XXXXXX)"
# mktemp -d is 0700/root; the capture curl runs as `nobody` and must be able to
# traverse WORK to write its -o output file. Make WORK traversable; the specific
# output files are pre-created world-writable just before each `sudo -u nobody curl`.
chmod 755 "${WORK}"
ORIGIN_BODY="${WORK}/hello.txt"
ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""
TC_ON=0

cleanup() {
    set +e
    # Kill client FIRST so it runs --setup-redirect teardown (nft delete table).
    # Give it up to 3s to exit cleanly so nft cleanup runs via atexit.
    if [ -n "${CLIENT_PID}" ]; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        # Wait up to 3s for clean exit
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null
        wait "${CLIENT_PID}" 2>/dev/null
    fi
    [ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null
    [ -n "${ORIGIN_PID}" ] && kill "${ORIGIN_PID}" 2>/dev/null
    # Best-effort nft cleanup in case the client didn't remove it (e.g. SIGKILL).
    nft delete table ip mqproxy 2>/dev/null || true
    # Restore tc if case 2 (multipath) left shaping on lo.
    [ "${TC_ON}" -eq 1 ] && tc qdisc del dev lo root 2>/dev/null || true
    wait 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT INT TERM

# ── TLS origin (python3 http.server + wrap_socket on port 443) ───────────────
# Serves a fixed-body response (ORIGIN_MAGIC) for byte-exact checking.
# Runs as root (both origin and mqproxy server are root → exempt from capture).
# NOTE: binding port 443 requires root; that is satisfied by the skip gate above.
ORIGIN_MAGIC="tproxy-e2e-origin-body-$(date +%s)"
printf '%s\n' "${ORIGIN_MAGIC}" >"${ORIGIN_BODY}"

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
        path = os.path.join(ROOT, os.path.basename(self.path) or "hello.txt")
        if not os.path.isfile(path):
            # serve hello.txt for any path that doesn't map to a real file
            path = os.path.join(ROOT, "hello.txt")
        with open(path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

httpd = http.server.HTTPServer(("127.0.0.1", PORT), H)
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
    # Poll the origin over TLS (verify against its own cert) up to ~5s.
    # curl connects directly (root, not captured) to check the origin is up.
    for _ in $(seq 1 50); do
        if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
            note "TLS origin process died on startup; see ${WORK}/origin.log:"
            sed 's/^/  origin| /' "${WORK}/origin.log" >&2 2>/dev/null
            return 1
        fi
        if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CERT}" \
            "https://127.0.0.1:${ORIGIN_PORT}/" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    note "TLS origin did not become ready within timeout."
    sed 's/^/  origin| /' "${WORK}/origin.log" >&2 2>/dev/null
    return 1
}

start_server() {
    "${MQPROXY_BIN}" server \
        --listen "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
}

# start_client [extra --path IPs...]: starts mqproxy client with tproxy ingress.
#
# UID RATIONALE: the client runs as root (uid 0).  --tproxy-uid 0 installs the
# nft "meta skuid 0 return" rule that EXEMPTS root's own traffic from capture.
# This allows the mqproxy process itself (and the TLS origin server, also root)
# to communicate on port 443 without being loop-captured.  curl runs as nobody
# (non-root), so its traffic IS captured.
start_client() {
    local path_args=() ip
    for ip in "$@"; do path_args+=(--path "${ip}"); done
    "${MQPROXY_BIN}" client \
        --server "${SERVER_IP}:${QUIC_PORT}" \
        --token "${TOKEN}" \
        --tproxy "127.0.0.1:${TPROXY_PORT}" \
        --tproxy-mode redirect \
        --tproxy-dport "${ORIGIN_PORT}" \
        --setup-redirect \
        --tproxy-uid 0 \
        "${path_args[@]}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
}

stop_client() {
    [ -n "${CLIENT_PID}" ] && kill -TERM "${CLIENT_PID}" 2>/dev/null
    # Wait up to 3s for clean exit (so --setup-redirect teardown runs).
    for _ in $(seq 1 30); do
        kill -0 "${CLIENT_PID}" 2>/dev/null || break
        sleep 0.1
    done
    kill -KILL "${CLIENT_PID}" 2>/dev/null
    wait "${CLIENT_PID}" 2>/dev/null
    CLIENT_PID=""
}

# Wait for the tproxy client to be ready:
#   1. The process is alive.
#   2. The nft table "ip mqproxy" exists (rules are installed).
#   3. The QUIC tunnel to the server is established (the client logged its
#      "mqproxy client: server=..." startup line AND the server is alive).
# The REDIRECT rules are installed during client startup (mq_tproxy_setup_install
# is called before the event loop).  The QUIC handshake completes asynchronously;
# we poll for up to 8s total.
wait_tproxy_ready() {
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
        # The client logs "REDIRECT rules installed" once nft rules are in.
        # After that, give the QUIC handshake a moment.
        if grep -q "REDIRECT rules installed" "${WORK}/client.log" 2>/dev/null; then
            # nft table must also be visible to the kernel.
            if nft list table ip mqproxy >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.1
    done
    note "tproxy client did not become ready within timeout."
    note "  client.log tail:"
    tail -10 "${WORK}/client.log" >&2 2>/dev/null
    return 1
}

# ── case helpers ──────────────────────────────────────────────────────────────
PASS_COUNT=0
fail() { note "FAIL: $1"; exit 1; }
ok()   { PASS_COUNT=$((PASS_COUNT + 1)); note "PASS: $1"; }

# ── run ───────────────────────────────────────────────────────────────────────
note "Starting TLS origin on 127.0.0.1:${ORIGIN_PORT} ..."
start_origin || { note "origin unavailable — cannot run tproxy e2e."; exit 1; }
note "Origin ready."

note "Starting mqproxy server on ${SERVER_IP}:${QUIC_PORT} ..."
start_server

note "Starting mqproxy client (tproxy listener on 127.0.0.1:${TPROXY_PORT}, uid=${NOBODY_UID} not exempt, uid=0 exempt) ..."
start_client
wait_tproxy_ready || exit 1
note "Client + nft REDIRECT rules ready."

# After rules are installed, wait for the QUIC handshake to complete. The
# handshake is asynchronous and we have no gateway ping-probe here, so the capture
# curl below is wrapped in a retry loop (up to ~10s) rather than relying on a
# single fixed sleep — robust against slow/loaded CI without hanging.
sleep 1

# ── case 1: TLS opacity proof — byte-exact body + cert verification ───────────
#
# curl as nobody (uid ${NOBODY_UID}) connects to 127.0.0.1:443.  The nft rule:
#   meta skuid 0 return           (root traffic exempt)
#   tcp dport 443 redirect to :<TPROXY_PORT>  (everyone else captured)
# diverts nobody's connection to the tproxy listener, which tunnels it over
# QUIC to the server, which relays it to 127.0.0.1:443 (the actual origin).
#
# --cacert uses the ORIGIN cert (not the mqproxy tunnel cert).  If the relay
# were a TLS MITM (Slice 1 must NOT be), the server-side cert would be
# test.crt (not trusted by origin.crt) → curl would exit with CURLE_SSL_PEER_CERTIFICATE.
# A clean 200 + body match proves opaque relay.
#
# NOTE: sudo -u nobody inherits the environment; --cacert is a file path
# accessible to root.  If the sandbox enforces strict sudoers, this may need
# "sudo -u nobody env ..."; adjust if the root run sees "sudo: sorry, you
# must have a tty" or similar.  The test cert is world-readable (0644) after
# cmake generates it.

CURL_OUT="${WORK}/curl_out.txt"
CURL_CODE="${WORK}/curl_code.txt"
# Pre-create world-writable: `nobody` writes these inside root's WORK dir.
: >"${CURL_OUT}"; : >"${CURL_CODE}"; chmod 666 "${CURL_OUT}" "${CURL_CODE}"

note "case 1: running curl as nobody (uid ${NOBODY_UID}) to 127.0.0.1:${ORIGIN_PORT} ..."
code1="000"
for attempt in $(seq 1 10); do
    sudo -u nobody curl -s -o "${CURL_OUT}" -w '%{http_code}' \
        --max-time 15 \
        --cacert "${ORIGIN_CERT}" \
        "https://127.0.0.1:${ORIGIN_PORT}/" >"${CURL_CODE}" 2>/dev/null || true
    code1="$(cat "${CURL_CODE}" 2>/dev/null || echo 000)"
    [ "${code1}" = "200" ] && break
    note "case 1: attempt ${attempt}/10 got HTTP ${code1}; tunnel may still be handshaking, retrying ..."
    sleep 1
done
[ "${code1}" = "200" ] || fail "case 1: curl HTTP code = ${code1} (want 200); \
check ${WORK}/client.log and ${WORK}/server.log for relay errors"

body1="$(cat "${CURL_OUT}" 2>/dev/null)"
[ "${body1}" = "${ORIGIN_MAGIC}" ] || \
    fail "case 1: body mismatch: got '${body1}' want '${ORIGIN_MAGIC}'"

ok "case 1: TLS opacity proof — 200 + body byte-exact + origin cert verified (no MITM)"

# ── case 2: multipath smoke (NET_ADMIN-gated; same gate already passed above) ─
#
# Bring up a 2nd loopback path (tc netem shaping), restart the client with two
# --path IPs, repeat the capture check.  Proves aggregation does not corrupt
# the opaque byte stream.
#
# Rate and delay chosen low (50mbit / 10ms) to complete quickly in a short test.
RATE="50mbit"; DELAY="10ms"
can_tc=0
if tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    tc qdisc del dev lo root 2>/dev/null
    can_tc=1
fi

if [ "${can_tc}" -ne 1 ]; then
    note "case 2 skipped: cannot add tc qdisc on lo (no tc/netem — should not happen after gate)."
else
    # Shape two loopback paths (mirror e2e_gateway case 8).
    tc qdisc del dev lo root 2>/dev/null || true
    tc qdisc add dev lo root handle 1: htb default 1
    tc class add dev lo parent 1: classid 1:1  htb rate 10gbit ceil 10gbit
    tc class add dev lo parent 1: classid 1:10 htb rate "${RATE}" ceil "${RATE}" quantum 1514
    tc class add dev lo parent 1: classid 1:11 htb rate "${RATE}" ceil "${RATE}" quantum 1514
    tc qdisc add dev lo parent 1:10 handle 10: netem delay "${DELAY}" limit 20000
    tc qdisc add dev lo parent 1:11 handle 11: netem delay "${DELAY}" limit 20000
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip src "${PATH_A_IP}/32" flowid 1:10
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip dst "${PATH_A_IP}/32" flowid 1:10
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip src "${PATH_B_IP}/32" flowid 1:11
    tc filter add dev lo protocol ip parent 1: prio 1 u32 \
        match ip dst "${PATH_B_IP}/32" flowid 1:11
    TC_ON=1
    note "case 2: tc shaping applied (RATE=${RATE} DELAY=${DELAY} per path)."

    # Restart client with two paths.
    stop_client
    kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; SERVER_PID=""
    start_server
    start_client "${PATH_A_IP}" "${PATH_B_IP}"
    wait_tproxy_ready || { note "case 2 FAIL: tunnel not ready (2-path)"; exit 1; }
    # Give the second path time to join (mp-ready).
    sleep 2

    CURL_OUT2="${WORK}/curl_out2.txt"
    CURL_CODE2="${WORK}/curl_code2.txt"
    : >"${CURL_OUT2}"; : >"${CURL_CODE2}"; chmod 666 "${CURL_OUT2}" "${CURL_CODE2}"
    note "case 2: running 2-path curl as nobody ..."
    code2="000"
    for attempt in $(seq 1 10); do
        sudo -u nobody curl -s -o "${CURL_OUT2}" -w '%{http_code}' \
            --max-time 15 \
            --cacert "${ORIGIN_CERT}" \
            "https://127.0.0.1:${ORIGIN_PORT}/" >"${CURL_CODE2}" 2>/dev/null || true
        code2="$(cat "${CURL_CODE2}" 2>/dev/null || echo 000)"
        [ "${code2}" = "200" ] && break
        note "case 2: attempt ${attempt}/10 got HTTP ${code2}; retrying ..."
        sleep 1
    done
    [ "${code2}" = "200" ] || fail "case 2: 2-path curl HTTP code = ${code2} (want 200)"

    body2="$(cat "${CURL_OUT2}" 2>/dev/null)"
    [ "${body2}" = "${ORIGIN_MAGIC}" ] || \
        fail "case 2: 2-path body mismatch: got '${body2}' want '${ORIGIN_MAGIC}'"

    ok "case 2: 2-path multipath smoke — body byte-exact with tc shaping"

    # Tear down tc shaping (cleanup trap also handles TC_ON=1).
    tc qdisc del dev lo root 2>/dev/null || true
    TC_ON=0
fi

# ── case 3: teardown assertion — nft table gone after client stops ────────────
#
# After stop_client the client runs --setup-redirect teardown:
#   nft delete table ip mqproxy
# Assert the table is gone (redirect no longer active).
note "case 3: stopping client, asserting nft table is removed ..."
stop_client

# nft list table ip mqproxy should FAIL (table does not exist).
if nft list table ip mqproxy >/dev/null 2>&1; then
    fail "case 3: nft table 'ip mqproxy' still present after client exit (teardown failed)"
fi
ok "case 3: nft table 'ip mqproxy' gone after client exit (teardown confirmed)"

# ── summary ───────────────────────────────────────────────────────────────────
note "RESULT = PASS (${PASS_COUNT} checks passed: opacity proof + multipath smoke + teardown)."
exit 0
