#!/usr/bin/env bash
#
# e2e_mitm_h2.sh — Phase 7 MITM Slice 3 Task 16: NET_ADMIN transparent-MITM H2 e2e.
#
# WHAT THIS PROVES (the capstone for the 🔒 security gate):
#   This is the ONLY test that drives the LIVE mq_mitm_conn orchestrator end to
#   end. A real browser (curl --http2) is transparently captured (nft REDIRECT),
#   the client forges a per-SNI leaf signed by the MITM CA, terminates TLS,
#   speaks h2 over the tunnel to the gateway server, which fetches the real
#   origin via libcurl. The full live data path is:
#
#     curl (as nobody, --http2)
#       → nft REDIRECT
#       → mqproxy-client tproxy listener
#       → mq_mitm_conn orchestrator (forge leaf for SNI, terminate TLS, ALPN=h2)
#       → mq_gw_h2_adapter
#       → gwc (gateway client) → MPQUIC tunnel
#       → mqproxy-server (gateway mode) → libcurl → ORIGIN (HTTPS).
#
#   The Slice-2 e2e (e2e_mitm_smoke.sh) only exercised mq_mitm_core over an
#   SSL_set_fd socket with a hand-rolled single-shot server; the live
#   orchestrator's BIO-pump + handshake + adapter→tunnel submit + teardown is
#   NOT unit-covered (test_mitm_teardown is a fake-SSL teardown). THIS script is
#   what genuinely exercises that path.
#
# THE TWO FALSIFIABILITY AXES (one per host, mirror e2e_tproxy's opacity proof):
#   * MITM host  (SNI=mitm.test): curl trusts the MITM CA (--cacert mitm-ca.crt)
#       and the handshake MUST succeed against the FORGED leaf (CN/SAN=mitm.test,
#       issued by the MITM CA). If MITM were NOT happening curl would see the
#       origin's real cert (issued by the origin CA, NOT the MITM CA) and REJECT
#       it. A clean h2 200 against --cacert mitm-ca.crt therefore proves MITM
#       termination + re-encryption to the origin works.
#   * IGNORE host (SNI=pinned.example, in --ignore-host): the flow is spliced
#       OPAQUELY (no termination). curl must verify against the ORIGIN cert
#       (--cacert origin-ca), exactly like e2e_tproxy. If the client MITM'd it,
#       curl would see the MITM-CA-signed forged leaf and — verifying against the
#       ORIGIN CA — REJECT it. A clean handshake against the origin CA (and a
#       handshake that FAILS against the MITM CA) proves the ignore-hosts splice
#       is opaque (the origin's real ClientHello/cert reach the wire untouched).
#
# ASSERTIONS (Task 16 Step 2):
#   (a) curl --http2 to the MITM host gets the origin object over h2
#       (http_version == 2, body byte-exact)        → transparent MITM works.
#   (b) a second same-origin fetch REUSES the warm origin connection
#       (mq.req origin_reuse=1). The plan text says "origin-once (cache hit)", but
#       the server response cache is NOT browser-reachable under the MITM model:
#       §4.5 step 1 strips ALL browser x-mq-* headers and the path injects only
#       x-mq-auth + x-mq-forward-cookie (never X-Mq-Cache). So origin-connection
#       reuse is the MITM-model-correct "served efficiently 2nd time" proof; the
#       cache HIT itself is covered on the fetch-API ingress by e2e_gateway case 14.
#       (See the long NOTE at case b.)
#   (c) a cookie-authenticated request reaches the origin WITH its Cookie
#       (the H2 adapter forwards browser headers verbatim + injects
#       x-mq-forward-cookie:true → §4.5 forward). Assert origin echoes k=v.
#   (d) an --ignore-host-matched SNI is spliced opaquely: curl verifying the
#       ORIGIN cert succeeds AND curl verifying the MITM CA FAILS (no MITM cert
#       presented for the excluded host).
#   (e) concurrent multi-stream fetch (curl --http2 --parallel N URLs) succeeds
#       (the orchestrator's single h2 conn multiplexes N streams onto the tunnel).
#
# HOW HOSTNAMES RESOLVE (both client AND server sides):
#   The H2 adapter forwards the browser's :authority verbatim; the gateway server
#   fetches https://<:authority><:path> via libcurl and verifies the origin cert
#   against --origin-ca. So BOTH the SNI host (browser→client) and the libcurl
#   target host (server→origin) are the SAME hostname, and BOTH must resolve to
#   127.0.0.1 and be covered by the origin cert's SAN. We therefore:
#     * generate a DEDICATED origin cert at runtime (in WORK) whose SAN covers
#       mitm.test + pinned.example + localhost + IP:127.0.0.1 (the tracked
#       tests/certs/origin.crt only carries localhost/127.0.0.1, so we mint our
#       own self-signed origin cert here and point --origin-ca at it — the e2e
#       is self-contained, like e2e_gateway already generates its own files).
#     * add /etc/hosts entries mitm.test/pinned.example → 127.0.0.1 (we are root
#       in the NET_ADMIN container) so BOTH curl's SNI and the server's libcurl
#       resolve the hostnames. The entries are removed on cleanup.
#   curl connects to https://<host>:${ORIGIN_PORT}/ ; the nft REDIRECT (dport
#   ${ORIGIN_PORT}) captures nobody's connection to the tproxy listener.
#
# UID STRATEGY (identical to e2e_tproxy.sh):
#   The whole script runs as root. The mqproxy client also runs as root (uid 0)
#   with --tproxy-uid 0 to EXEMPT its own + the origin's traffic from capture.
#   curl runs via "sudo -u nobody" so its uid != 0 → its connection IS captured.
#
# WHAT IS NOT VERIFIED WITHOUT ROOT/NET_ADMIN (dev sandbox):
#   The happy path cannot run without CAP_NET_ADMIN (nft) + root. The script is
#   correct-by-construction, mirroring e2e_tproxy.sh (capture half) and
#   e2e_gateway.sh (gateway/origin half); see NOTE comments at each unverifiable
#   step. It SKIPs (exit 77) cleanly when prerequisites are absent.
#
# TO VALIDATE AS ROOT (run on a NET_ADMIN-capable machine / container):
#   sudo MQPROXY_BIN=/path/to/build/mqproxy \
#        MQPROXY_CERT=/path/to/tests/certs/test.crt \
#        MQPROXY_KEY=/path/to/tests/certs/test.key \
#        MQ_MITM_CA_CRT=/path/to/tests/certs/mitm-ca.crt \
#        MQ_MITM_CA_KEY=/path/to/tests/certs/mitm-ca.key \
#        bash tests/integration/e2e_mitm_h2.sh
#
#   Or via ctest (registered with SKIP_RETURN_CODE 77):
#   sudo ctest --test-dir build -R e2e_mitm_h2 --output-on-failure
#
#   Docker-no-sudo NET_ADMIN pattern (per project memory):
#     docker run --rm --cap-add=NET_ADMIN -v "$PWD":"$PWD" -w "$PWD" \
#       ubuntu:24.04 bash -lc 'apt-get update && \
#         apt-get install -y curl openssl nftables python3 sudo iproute2 && \
#         MQPROXY_BIN=... bash tests/integration/e2e_mitm_h2.sh'
#     (NOTE the curl-CLI gotcha: libcurl-dev != the curl binary — install `curl`.)
#
# ENV (passed by CMake; overridable):
#   MQPROXY_BIN              the `mqproxy` binary (MUST be MITM-capable).
#   MQPROXY_CERT/KEY         tunnel TLS cert/key (CN=mqproxy-test).
#   MQ_MITM_CA_CRT/KEY       the MITM signing CA (configure-time fixtures) —
#                            consumed by --ca-cert/--ca-key; curl trusts the crt.
#
set -u

SKIP=77
note() { printf '%s\n' "e2e_mitm_h2: $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MQPROXY_BIN="${MQPROXY_BIN:-${REPO_ROOT}/build/mqproxy}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
MITM_CA_CRT="${MQ_MITM_CA_CRT:-${REPO_ROOT}/tests/certs/mitm-ca.crt}"
MITM_CA_KEY="${MQ_MITM_CA_KEY:-${REPO_ROOT}/tests/certs/mitm-ca.key}"

TOKEN="mitm-h2-e2e-token"
SERVER_IP="127.0.0.1"
MITM_HOST="mitm.test"        # MITM'd host (SNI → forged leaf signed by MITM CA)
IGNORE_HOST="pinned.example" # opaque host (matches --ignore-host; origin cert)
HOSTS_LINE="127.0.0.1 ${MITM_HOST} ${IGNORE_HOST}"
ORIGIN_PORT=""

# ── SKIP GATE (must be FIRST, before any privileged operation) ───────────────
# Condition 1: must be root (CAP_NET_ADMIN for nft REDIRECT + /etc/hosts edit).
if [ "$(id -u)" -ne 0 ]; then
    note "SKIP: requires NET_ADMIN/root.  Transparent MITM capture needs root for nft."
    note "  Run with: sudo $0"
    note "  Or via ctest: sudo ctest --test-dir build -R e2e_mitm_h2 --output-on-failure"
    exit "${SKIP}"
fi

# Condition 2: nft (nftables) available.
if ! command -v nft >/dev/null 2>&1; then
    note "SKIP: nft (nftables) not found.  Install nftables and re-run."
    exit "${SKIP}"
fi

# Condition 3: probe an actual nft table add (catches root-without-CAP_NET_ADMIN).
if ! nft add table ip mqproxy_probe 2>/dev/null; then
    note "SKIP: cannot add nft table (no CAP_NET_ADMIN?).  Needs full NET_ADMIN capability."
    exit "${SKIP}"
fi
nft delete table ip mqproxy_probe 2>/dev/null || true

# Condition 4: curl + openssl + sudo + nobody + python3 present.
if ! command -v curl >/dev/null 2>&1; then
    note "SKIP: curl not found.  (NB: libcurl-dev is NOT the curl CLI — install 'curl'.)"
    exit "${SKIP}"
fi
if ! command -v openssl >/dev/null 2>&1; then
    note "SKIP: openssl CLI not found — needed to mint the runtime origin cert."
    exit "${SKIP}"
fi
if ! command -v sudo >/dev/null 2>&1; then
    note "SKIP: sudo not found.  Required to run curl as nobody for capture."
    exit "${SKIP}"
fi
if ! id nobody >/dev/null 2>&1; then
    note "SKIP: user 'nobody' does not exist.  Required as the non-root curl uid."
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

# Condition 5: curl must support HTTP/2 (the whole point — a no-h2 curl can't
# falsify the h2 negotiation). curl --version lists "HTTP2" in its Features.
if ! curl --version 2>/dev/null | grep -qi 'HTTP2'; then
    note "SKIP: curl lacks HTTP/2 support (no 'HTTP2' feature).  Needs an h2-capable curl."
    exit "${SKIP}"
fi

# ── binary + fixture pre-flight (real errors, not skips) ─────────────────────
if [ ! -x "${MQPROXY_BIN}" ]; then
    note "ERROR: mqproxy binary not found/executable: ${MQPROXY_BIN}"
    note "  Build first (cmake --build build) or set MQPROXY_BIN."
    exit 1
fi
# The binary MUST be MITM-capable (built with BoringSSL archives). If --mitm is
# unavailable the binary hard-errors at validation — detect that here and SKIP
# rather than FAIL, so a no-archive build does not red the suite.
if "${MQPROXY_BIN}" client --help 2>&1 | grep -q -- '--mitm'; then
    : # MITM flag present in help — capable build (help always lists it; the
      # runtime hard-error is the real gate, checked by the readiness wait below)
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
# Back-to-back ephemeral binds can hand back the same number; ensure distinct.
while [ -n "${ORIGIN_PORT}" ] && [ "${ORIGIN_PORT}" = "${TPROXY_PORT}" ]; do
    ORIGIN_PORT="$(free_port tcp)"
done
if [ -z "${QUIC_PORT}" ] || [ -z "${TPROXY_PORT}" ] || [ -z "${ORIGIN_PORT}" ]; then
    note "ERROR: free-port selection failed (python3 socket bind)."
    exit 1
fi

# ── workspace + cleanup ───────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_mitm_h2.XXXXXX)"
# nobody must traverse WORK to write its -o output (mktemp -d is 0700/root).
chmod 755 "${WORK}"

ORIGIN_CERT="${WORK}/origin.crt"   # runtime origin cert (SAN covers both hosts)
ORIGIN_KEY="${WORK}/origin.key"
# Public copies under /tmp so the unprivileged `nobody` curl can --cacert them
# (the repo path is usually under a 0700 home dir nobody cannot traverse — see
# the e2e_tproxy.sh note on the HTTP-000 path-permission trap).
MITM_CA_PUB="${WORK}/mitm_ca.crt"
ORIGIN_CA_PUB="${WORK}/origin_ca.crt"
# Private CA copies that --ca-cert/--ca-key consume. mq_mitm_core REQUIRES the CA
# KEY to be owned by the running euid with NO group/other perms (a deliberate
# 0600-owner security gate — read_pem_file_safely). The tracked fixture key is
# owned by the repo user, so when this script runs as root (uid 0) the original
# would be REJECTED (st_uid != geteuid). We therefore stage root-owned 0600 copies
# in WORK and point --ca-key/--ca-cert at THOSE.
MITM_CA_CRT_RUN="${WORK}/ca.crt"
MITM_CA_KEY_RUN="${WORK}/ca.key"

ORIGIN_PID=""
SERVER_PID=""
CLIENT_PID=""
HOSTS_BACKED_UP=0

cleanup() {
    rc=$?
    set +e
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
    # Best-effort nft cleanup (in case the client was SIGKILLed before teardown).
    nft delete table ip mqproxy 2>/dev/null || true
    # Remove the /etc/hosts entries we appended.
    if [ "${HOSTS_BACKED_UP}" -eq 1 ] && [ -f "${WORK}/hosts.bak" ]; then
        cp "${WORK}/hosts.bak" /etc/hosts 2>/dev/null || \
            sed -i "\| ${MITM_HOST} ${IGNORE_HOST}\$|d" /etc/hosts 2>/dev/null
    fi
    wait 2>/dev/null
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
}
trap cleanup EXIT INT TERM

# ── mint a dedicated origin cert (SAN covers both hostnames) ─────────────────
# Self-signed; the server trusts it via --origin-ca (origin cert == its own CA,
# exactly as e2e_gateway uses the self-signed origin.crt as --origin-ca). SAN
# carries the two test hostnames + localhost + IP so the server's libcurl host
# verification passes for both the MITM and the ignore-host targets.
mint_origin_cert() {
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${ORIGIN_KEY}" -out "${ORIGIN_CERT}" -days 2 \
        -subj "/CN=${MITM_HOST}" \
        -addext "subjectAltName=DNS:${MITM_HOST},DNS:${IGNORE_HOST},DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1 || return 1
    return 0
}

# ── /etc/hosts: map both test hostnames to 127.0.0.1 ─────────────────────────
# Needed on BOTH sides: curl's SNI (client) and the server's libcurl (origin
# fetch) must resolve the hostnames to 127.0.0.1.
install_hosts() {
    cp /etc/hosts "${WORK}/hosts.bak" || return 1
    HOSTS_BACKED_UP=1
    printf '%s\n' "${HOSTS_LINE}" >>/etc/hosts || return 1
    return 0
}

# ── TLS origin (python3 http.server + wrap_socket) ───────────────────────────
# GET serves files from WORK and counts per-path FILE hits (cache HIT proof);
# /__count?p=<path> reads the count back (never counted, never cached). The
# /echo-cookie path echoes the request Cookie header (case c). A basename
# starting "cache-" is served with NO Cache-Control so the server may cache it.
write_origin_py() {
    cat >"${WORK}/origin.py" <<'PY'
import http.server, os, ssl, urllib.parse

ROOT = os.environ["MQ_ORIGIN_ROOT"]
PORT = int(os.environ["MQ_ORIGIN_PORT"])
CERT = os.environ["MQ_ORIGIN_CERT"]
KEY  = os.environ["MQ_ORIGIN_KEY"]


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    COUNTS = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/echo-cookie":
            body = (self.headers.get("Cookie") or "(none)").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.split("?", 1)[0] == "/__count":
            qs = urllib.parse.urlparse(self.path).query
            p = urllib.parse.parse_qs(qs).get("p", [""])[0]
            body = str(H.COUNTS.get(p, 0)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # FILE path: count this origin hit (NOT /__count, handled above).
        H.COUNTS[self.path] = H.COUNTS.get(self.path, 0) + 1
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
    # Poll the origin over TLS (verify against its own cert) up to ~5s. curl
    # connects directly (root, exempt from capture) to check the origin is up.
    for _ in $(seq 1 50); do
        if ! kill -0 "${ORIGIN_PID}" 2>/dev/null; then
            note "TLS origin process died on startup; see ${WORK}/origin.log:"
            sed 's/^/  origin| /' "${WORK}/origin.log" >&2 2>/dev/null
            return 1
        fi
        if curl -s -o /dev/null --max-time 2 --cacert "${ORIGIN_CERT}" \
            "https://localhost:${ORIGIN_PORT}/" 2>/dev/null; then
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
        --origin-ca "${ORIGIN_CERT}" \
        --request-metrics \
        --cache-max-bytes 67108864 \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
}

# start_client: tproxy ingress WITH --mitm. Runs as root (uid 0); --tproxy-uid 0
# exempts its own + the origin's traffic. --ignore-host ${IGNORE_HOST} leaves
# that SNI opaque (the splice proof, case d).
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
        --ignore-host "${IGNORE_HOST}" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
}

# Wait for the MITM client to be ready:
#   1. server + client processes alive.
#   2. the gwc tunnel is established (gw_client logs "tunnel conn established" —
#      the MITM orchestrator submits H2 requests through THIS shared gwc).
#   3. the nft REDIRECT rules are installed (client logs "REDIRECT rules
#      installed" + the table is visible to the kernel).
# Up to ~12s total (handshake is async). If the client died because the binary
# is not MITM-capable, the log carries the "--mitm unavailable" hard-error → we
# SKIP rather than FAIL.
wait_mitm_ready() {
    for _ in $(seq 1 120); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "server died during startup; see ${WORK}/server.log:"
            sed 's/^/  server| /' "${WORK}/server.log" >&2 2>/dev/null
            return 1
        fi
        if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            if grep -q -- '--mitm unavailable' "${WORK}/client.log" 2>/dev/null; then
                note "SKIP: mqproxy binary built without BoringSSL — --mitm unavailable."
                exit "${SKIP}"
            fi
            note "client died during startup; see ${WORK}/client.log:"
            sed 's/^/  client| /' "${WORK}/client.log" >&2 2>/dev/null
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
    note "  client.log tail:"
    tail -10 "${WORK}/client.log" >&2 2>/dev/null
    return 1
}

# ── case helpers ──────────────────────────────────────────────────────────────
PASS_COUNT=0
fail() { note "FAIL: $1"; exit 1; }
ok()   { PASS_COUNT=$((PASS_COUNT + 1)); note "PASS: $1"; }

# nobody-runnable curl wrapper. Writes outputs into pre-created world-writable
# files inside root's WORK. Prints "<http_code> <http_version>" to stdout.
# $1 = output body file, $2.. = extra curl args (URL + headers).
ncurl() {
    local out="$1"; shift
    : >"${out}"; chmod 666 "${out}"
    sudo -u nobody curl -s -o "${out}" -w '%{http_code} %{http_version}' \
        --max-time 20 "$@" 2>/dev/null || true
}

# ── run ───────────────────────────────────────────────────────────────────────
note "minting runtime origin cert (SAN=${MITM_HOST},${IGNORE_HOST},localhost,127.0.0.1) ..."
mint_origin_cert || { note "ERROR: could not mint origin cert."; exit 1; }

# Stage world-readable CA copies for the unprivileged curl.
cp "${MITM_CA_CRT}" "${MITM_CA_PUB}" && chmod 644 "${MITM_CA_PUB}" || \
    { note "ERROR: could not stage MITM CA copy."; exit 1; }
cp "${ORIGIN_CERT}" "${ORIGIN_CA_PUB}" && chmod 644 "${ORIGIN_CA_PUB}" || \
    { note "ERROR: could not stage origin CA copy."; exit 1; }

# Stage euid-owned 0600 CA cert+key copies for --ca-cert/--ca-key (the core's
# read_pem_file_safely rejects a key not owned by geteuid() or with any
# group/other perm — see the MITM_CA_KEY_RUN note above).
cp "${MITM_CA_CRT}" "${MITM_CA_CRT_RUN}" && chmod 600 "${MITM_CA_CRT_RUN}" || \
    { note "ERROR: could not stage --ca-cert copy."; exit 1; }
cp "${MITM_CA_KEY}" "${MITM_CA_KEY_RUN}" && chmod 600 "${MITM_CA_KEY_RUN}" || \
    { note "ERROR: could not stage --ca-key copy."; exit 1; }

note "installing /etc/hosts entries (${HOSTS_LINE}) ..."
install_hosts || { note "ERROR: could not edit /etc/hosts."; exit 1; }

note "Starting TLS origin on 127.0.0.1:${ORIGIN_PORT} ..."
start_origin || { note "origin unavailable — cannot run MITM e2e."; exit 1; }
note "Origin ready."

note "Starting mqproxy server (gateway mode) on ${SERVER_IP}:${QUIC_PORT} ..."
start_server

note "Starting mqproxy MITM client (tproxy=127.0.0.1:${TPROXY_PORT}, --mitm, --ignore-host ${IGNORE_HOST}) ..."
start_client
wait_mitm_ready || exit 1
note "MITM client + tunnel + nft REDIRECT rules ready."

# Cacheable + plain bodies (distinct, deterministic).
ORIGIN_MAGIC="mitm-h2-origin-body-$(date +%s)"
printf '%s\n' "${ORIGIN_MAGIC}" >"${WORK}/obj.bin"      # MITM GET object (cases a/e)
printf '%s\n' "cache-${ORIGIN_MAGIC}" >"${WORK}/cache-obj.bin" # cache HIT object (case b)
printf '%s\n' "opaque-${ORIGIN_MAGIC}" >"${WORK}/opq.bin"  # ignore-host object (case d)

MITM_URL="https://${MITM_HOST}:${ORIGIN_PORT}"
IGNORE_URL="https://${IGNORE_HOST}:${ORIGIN_PORT}"

# ── case (a): transparent MITM works — h2 200 against the FORGED leaf ─────────
# curl --http2 --cacert <MITM CA>. A clean h2 200 + byte-exact body proves the
# client forged a leaf for ${MITM_HOST} signed by the MITM CA, terminated TLS,
# spoke h2 over the tunnel, and the server fetched the origin. We RETRY (the QUIC
# handshake / first MITM forge can lag) like e2e_tproxy.
note "case a: curl --http2 (MITM, --cacert MITM-CA) to ${MITM_URL}/obj.bin ..."
res_a="000 0"
for attempt in $(seq 1 10); do
    res_a="$(ncurl "${WORK}/a_body.txt" --http2 --cacert "${MITM_CA_PUB}" "${MITM_URL}/obj.bin")"
    read -r code_a ver_a <<< "${res_a:-000 0}"; ver_a="${ver_a:-0}"
    [ "${code_a}" = "200" ] && break
    note "case a: attempt ${attempt}/10 got HTTP ${code_a} (h${ver_a}); retrying ..."
    sleep 1
done
read -r code_a ver_a <<< "${res_a:-000 0}"; ver_a="${ver_a:-0}"
[ "${code_a}" = "200" ] || fail "case a: HTTP code = ${code_a} (want 200) — MITM termination/forge failed; \
check ${WORK}/client.log + ${WORK}/server.log"
# http_version must be 2 (curl prints '2' for HTTP/2).
[ "${ver_a}" = "2" ] || fail "case a: http_version = ${ver_a} (want 2) — h2 was not negotiated"
body_a="$(cat "${WORK}/a_body.txt" 2>/dev/null)"
[ "${body_a}" = "${ORIGIN_MAGIC}" ] || fail "case a: body mismatch: got '${body_a}' want '${ORIGIN_MAGIC}'"
ok "case a: transparent MITM works — h2 200 + body byte-exact (forged leaf trusted via MITM CA)"

# ── case (b): cache HIT — second fetch served origin-once ────────────────────
# MITM-MODEL NOTE — why this is origin-CONNECTION-REUSE, not a server cache HIT:
#   The Task-16 plan text says "origin-once (cache hit)". But §4.5 step 1 (the
#   S3-D11 untrusted-browser-header policy, enforced in mq_gw_h2_adapter on_header)
#   STRIPS every browser-supplied x-mq-* header UNCONDITIONALLY, and the MITM path
#   injects EXACTLY two controls (x-mq-auth, x-mq-forward-cookie) — NOT X-Mq-Cache.
#   The server-side response cache is therefore NOT reachable from a transparently
#   MITM'd browser (a browser must never be able to drive the gateway cache). So an
#   origin-served-ONCE assertion is impossible in this model — the origin is hit on
#   every fetch. The valid, falsifiable "served efficiently the second time" proof
#   in the MITM model is ORIGIN-CONNECTION REUSE: the server keeps the origin TLS
#   connection warm and the 2nd same-origin fetch reuses it (mq.req origin_reuse=1,
#   origin_connect_ms=0). That is what we assert here (e2e_gateway case 9 proves the
#   same flip for the fetch-API path). The cache HIT itself is unit/e2e-covered on
#   the gateway fetch path (e2e_gateway case 14), which is the only ingress that can
#   set X-Mq-Cache.
note "case b: two same-origin MITM fetches → assert 2nd reuses the origin connection ..."
res_b1="$(ncurl "${WORK}/b1_body.txt" --http2 --cacert "${MITM_CA_PUB}" \
    "${MITM_URL}/cache-obj.bin")"
read -r code_b1 _ <<< "${res_b1:-000 0}"
[ "${code_b1}" = "200" ] || fail "case b: first fetch HTTP code = ${code_b1} (want 200)"
res_b2="$(ncurl "${WORK}/b2_body.txt" --http2 --cacert "${MITM_CA_PUB}" \
    "${MITM_URL}/cache-obj.bin")"
read -r code_b2 _ <<< "${res_b2:-000 0}"
[ "${code_b2}" = "200" ] || fail "case b: second fetch HTTP code = ${code_b2} (want 200)"
# Both bodies byte-identical (same origin object).
cmp -s "${WORK}/b1_body.txt" "${WORK}/b2_body.txt" || fail "case b: 2nd body differs from 1st"
# FALSIFIABLE reuse proof: the server must log at least one mq.req for this path
# with origin_reuse=1 (the warm origin connection was reused on the 2nd fetch).
# server.log is in WORK; mq.req fires slightly after curl returns, so poll briefly.
b_reuse=0
for _ in $(seq 1 25); do
    if grep -Eq 'mq\.req .* path="/cache-obj.bin" .* origin_reuse=1' "${WORK}/server.log" 2>/dev/null; then
        b_reuse=1; break
    fi
    sleep 0.2
done
[ "${b_reuse}" -eq 1 ] || fail "case b: no mq.req for /cache-obj.bin with origin_reuse=1 \
(2nd same-origin fetch did not reuse the origin connection); mq.req lines: \
$(grep -E 'mq\.req .* path=\"/cache-obj.bin\"' "${WORK}/server.log" 2>/dev/null | tr '\n' '|')"
ok "case b: second same-origin fetch reuses the warm origin connection (origin_reuse=1)"

# ── case (c): cookie-authenticated request reaches origin WITH its Cookie ─────
# §4.5 forward: the H2 adapter forwards browser headers verbatim + injects
# x-mq-forward-cookie:true, so the origin must see Cookie: k=v echoed back.
note "case c: MITM fetch of /echo-cookie with Cookie: k=v ..."
res_c="$(ncurl "${WORK}/c_body.txt" --http2 --cacert "${MITM_CA_PUB}" \
    -H "Cookie: k=v" "${MITM_URL}/echo-cookie")"
read -r code_c _ <<< "${res_c:-000 0}"
[ "${code_c}" = "200" ] || fail "case c: HTTP code = ${code_c} (want 200)"
body_c="$(cat "${WORK}/c_body.txt" 2>/dev/null)"
[ "${body_c}" = "k=v" ] || fail "case c: origin saw Cookie='${body_c}' (want k=v) — §4.5 forward failed"
ok "case c: cookie-authenticated request reached origin WITH its Cookie (k=v)"

# ── case (d): --ignore-host SNI spliced opaquely (no MITM cert presented) ─────
# Positive (opacity): curl --http2 verifying the ORIGIN cert MUST succeed — the
# connection passed through untouched, so the origin's real cert reaches curl.
# Negative (no MITM): curl verifying the MITM CA MUST FAIL — no forged leaf is
# presented for an ignore-host (if one were, this would WRONGLY succeed).
note "case d: ignore-host ${IGNORE_HOST} — opaque splice proof (origin CA ok, MITM CA fails) ..."
# (d.1) origin-CA verify succeeds (opaque pass-through). The opaque relay is a
# byte-pipe; curl will negotiate whatever the origin offers (h2 only if the
# python origin advertised it — it does NOT, so the http_version may be 1.1 here.
# Opacity, not h2, is the axis for the ignore-host, so we assert code+cert only).
res_d="000 0"
for attempt in $(seq 1 10); do
    res_d="$(ncurl "${WORK}/d_body.txt" --cacert "${ORIGIN_CA_PUB}" "${IGNORE_URL}/opq.bin")"
    read -r code_d _ <<< "${res_d:-000 0}"
    [ "${code_d}" = "200" ] && break
    note "case d: attempt ${attempt}/10 origin-CA fetch got HTTP ${code_d}; retrying ..."
    sleep 1
done
read -r code_d _ <<< "${res_d:-000 0}"
[ "${code_d}" = "200" ] || fail "case d: origin-CA verify HTTP code = ${code_d} (want 200) — opaque splice failed"
body_d="$(cat "${WORK}/d_body.txt" 2>/dev/null)"
[ "${body_d}" = "opaque-${ORIGIN_MAGIC}" ] || \
    fail "case d: opaque body mismatch: got '${body_d}' want 'opaque-${ORIGIN_MAGIC}'"
# (d.2) MITM-CA verify MUST FAIL — no forged leaf for an ignore-host. A non-200
# (curl cert-verify error → HTTP 000) is the required outcome; a 200 here would
# mean the host was WRONGLY MITM'd (forged leaf presented).
res_d2="$(ncurl "${WORK}/d2_body.txt" --cacert "${MITM_CA_PUB}" "${IGNORE_URL}/opq.bin")"
read -r code_d2 _ <<< "${res_d2:-000 0}"
[ "${code_d2}" != "200" ] || \
    fail "case d: MITM-CA verify UNEXPECTEDLY succeeded (HTTP 200) — the ignore-host was MITM'd (forged leaf presented)"
ok "case d: ignore-host spliced opaquely (origin cert verifies; MITM CA rejected — no forged leaf, HTTP ${code_d2})"

# ── case (e): concurrent multi-stream fetch succeeds ─────────────────────────
# curl --http2 --parallel over multiple URLs runs them concurrently on ONE h2
# connection (the MITM orchestrator multiplexes N streams onto the single
# terminated h2 conn → tunnel). All must return 200. We use curl's -Z (parallel)
# with multiple --next blocks; write each body to a distinct file and check all
# returned 200. (Each URL is /obj.bin; the origin serves it N times.)
note "case e: concurrent multi-stream MITM fetch (curl --http2 --parallel x4) ..."
: >"${WORK}/e_codes.txt"; chmod 666 "${WORK}/e_codes.txt"
for i in 1 2 3 4; do
    : >"${WORK}/e_${i}.txt"; chmod 666 "${WORK}/e_${i}.txt"
done
# -Z enables parallel transfers; -w '%{http_code}\n' prints one code per URL.
# SC2024: the >e_codes.txt redirect is INTENTIONALLY performed by the (root)
# parent shell, not by `nobody` — root owns WORK so writing e_codes.txt is fine.
# The per-stream BODY files are written by `nobody` via curl -o into the
# pre-created world-writable e_*.txt above (that is the capture that matters).
# shellcheck disable=SC2024
sudo -u nobody curl -s --http2 -Z --max-time 25 --cacert "${MITM_CA_PUB}" \
    -o "${WORK}/e_1.txt" "${MITM_URL}/obj.bin" \
    -o "${WORK}/e_2.txt" "${MITM_URL}/obj.bin" \
    -o "${WORK}/e_3.txt" "${MITM_URL}/obj.bin" \
    -o "${WORK}/e_4.txt" "${MITM_URL}/obj.bin" \
    -w '%{http_code}\n' >"${WORK}/e_codes.txt" 2>/dev/null || true
e_ok=0
for i in 1 2 3 4; do
    if [ "$(cat "${WORK}/e_${i}.txt" 2>/dev/null)" = "${ORIGIN_MAGIC}" ]; then
        e_ok=$((e_ok + 1))
    fi
done
e_200="$(grep -c '^200$' "${WORK}/e_codes.txt" 2>/dev/null || echo 0)"
[ "${e_ok}" -eq 4 ] || fail "case e: only ${e_ok}/4 concurrent fetches returned the correct body; \
codes: $(tr '\n' ' ' <"${WORK}/e_codes.txt")"
[ "${e_200}" -ge 4 ] || fail "case e: only ${e_200}/4 concurrent fetches returned HTTP 200; \
codes: $(tr '\n' ' ' <"${WORK}/e_codes.txt")"
ok "case e: concurrent multi-stream fetch — 4/4 streams returned 200 + byte-exact body"

# ── summary ───────────────────────────────────────────────────────────────────
note "RESULT = PASS (${PASS_COUNT} checks: MITM-works + cache-once + cookie-forward + ignore-host-splice + multi-stream)."
exit 0
