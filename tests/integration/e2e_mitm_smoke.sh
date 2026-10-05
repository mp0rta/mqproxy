#!/usr/bin/env bash
#
# e2e_mitm_smoke.sh — Phase 7 MITM Slice 2 Task 8: openssl s_client cross-impl smoke.
#
# WHAT THIS PROVES (spec S2-D6):
#   The mq_mitm_core TLS termination path works against a NON-BoringSSL client.
#   The in-process unit suite (test_mitm_core) drives a BoringSSL client over a
#   memory BIO; this complements it with a real, separate TLS implementation (the
#   system `openssl s_client`) negotiating over an actual loopback socket. The
#   cross-implementation signal is the whole point.
#
#   The helper (mitm_smoke_server) loads the MITM CA, accepts ONE connection, and
#   terminates TLS through mq_mitm_core, forging a per-SNI leaf signed by the CA
#   and negotiating ALPN=h2. We assert s_client sees:
#     - "ALPN protocol: h2"            (h2 was negotiated)
#     - "Verify return code: 0 (ok)"   (the forged leaf chains to the CA we trust)
#
# TWO MODES:
#   * C helper (default; used by CTest): mitm_smoke_server terminates one connection.
#   * Rust binary (MQPROXY_RUST_BIN set): `mqproxy server` (gateway on) + `mqproxy
#     client --tproxy ... --mitm` with an nft REDIRECT for one unused destination
#     port; s_client connects to that port and is captured. Needs root + NET_ADMIN
#     + nft. The client's --tproxy-uid is a uid nobody runs, so root's s_client
#     is captured (the default exempts the client's own uid, i.e. root).
#
# ENV (passed by CMake; overridable):
#   MITM_SERVER_BIN   the mitm_smoke_server helper binary (C mode).
#   MQPROXY_RUST_BIN  the Rust `mqproxy` binary (selects the Rust mode).
#   MQPROXY_CERT/KEY  tunnel TLS cert/key for the Rust server (default tests/certs/test.*).
#   MITM_CA_CRT/KEY   the MITM CA cert/key (configure-time fixtures).
#
# SKIP semantics: exit 77 when `openssl` is absent, or (Rust mode) when root/nft/
# NET_ADMIN/python3 is missing. Any assertion failure is a hard failure (non-zero,
# not 77).
#
set -u

SKIP=77
note() { printf '%s\n' "e2e_mitm_smoke: $*" >&2; }

# ── SKIP GATE: openssl CLI required (the cross-impl client) ──────────────────
if ! command -v openssl >/dev/null 2>&1; then
    note "SKIP: openssl CLI not found — cannot run the cross-impl s_client smoke."
    exit "${SKIP}"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MITM_SERVER_BIN="${MITM_SERVER_BIN:-${REPO_ROOT}/build/mitm_smoke_server}"
RUST_BIN="${MQPROXY_RUST_BIN:-}"
MQPROXY_CERT="${MQPROXY_CERT:-${REPO_ROOT}/tests/certs/test.crt}"
MQPROXY_KEY="${MQPROXY_KEY:-${REPO_ROOT}/tests/certs/test.key}"
MITM_CA_CRT="${MITM_CA_CRT:-${REPO_ROOT}/tests/certs/mitm-ca.crt}"
MITM_CA_KEY="${MITM_CA_KEY:-${REPO_ROOT}/tests/certs/mitm-ca.key}"

# ── pre-flight (real errors, not skips) ──────────────────────────────────────
if [ -n "${RUST_BIN}" ]; then
    if [ ! -x "${RUST_BIN}" ]; then
        note "ERROR: Rust binary not found/executable: ${RUST_BIN}"
        exit 1
    fi
    if [ "$(id -u)" -ne 0 ] || ! command -v nft >/dev/null 2>&1 \
        || ! command -v python3 >/dev/null 2>&1 \
        || ! nft add table ip mqproxy_probe 2>/dev/null; then
        note "SKIP: Rust mode needs root + CAP_NET_ADMIN + nft + python3."
        exit "${SKIP}"
    fi
    nft delete table ip mqproxy_probe 2>/dev/null || true
elif [ ! -x "${MITM_SERVER_BIN}" ]; then
    note "ERROR: helper not found/executable: ${MITM_SERVER_BIN} (build mitm_smoke_server)."
    exit 1
fi
for f in "${MITM_CA_CRT}" "${MITM_CA_KEY}"; do
    if [ ! -f "${f}" ]; then
        note "ERROR: CA fixture missing: ${f} (CMake generates it)."
        exit 1
    fi
done

# ── free-port selection ──────────────────────────────────────────────────────
free_port() {
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${1:-tcp}" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if sys.argv[1] == "udp" else socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
    else
        # Fallback: pick a high port pseudo-randomly; the bind in the helper is the
        # real arbiter (it errors out if taken, and the readiness wait will fail).
        echo $(( (RANDOM % 20000) + 20000 ))
    fi
}

PORT="$(free_port tcp)"
if [ -z "${PORT}" ]; then
    note "ERROR: free-port selection failed."
    exit 1
fi

# ── workspace + cleanup ──────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_mitm_smoke.XXXXXX)"
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    rc=$?
    set +e
    # Client first: SIGTERM lets it remove its nft table (--setup-redirect).
    if [ -n "${CLIENT_PID}" ]; then
        kill -TERM "${CLIENT_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${CLIENT_PID}" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "${CLIENT_PID}" 2>/dev/null
        wait "${CLIENT_PID}" 2>/dev/null
        nft delete table ip mqproxy 2>/dev/null
    fi
    if [ -n "${SERVER_PID}" ]; then
        kill -KILL "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
    fi
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne "${SKIP}" ]; then
        if [ -s "${WORK}/client.log" ]; then
            note "──── client.log (tail) ────"
            tail -n 40 "${WORK}/client.log" | sed 's/^/  client| /' >&2
        fi
        if [ -s "${WORK}/server.log" ]; then
            note "──── server.log ────"
            sed 's/^/  server| /' "${WORK}/server.log" >&2
        fi
        if [ -s "${WORK}/sclient.out" ]; then
            note "──── s_client output (tail) ────"
            tail -n 40 "${WORK}/sclient.out" | sed 's/^/  client| /' >&2
        fi
        note "logs preserved at ${WORK}"
    else
        rm -rf "${WORK}"
    fi
}
trap cleanup EXIT INT TERM

if [ -n "${RUST_BIN}" ]; then
    # ── Rust mode: server + MITM client + nft REDIRECT for one unused port ────
    QUIC_PORT="$(free_port udp)"
    PORT="$(free_port tcp)"     # the redirected destination: nothing listens here
    TPROXY_PORT="$(free_port tcp)"
    while [ "${TPROXY_PORT}" = "${PORT}" ]; do TPROXY_PORT="$(free_port tcp)"; done
    # The key must be owned by the running uid with mode 0600 (Rust loader gate).
    cp "${MITM_CA_CRT}" "${WORK}/ca.crt" && cp "${MITM_CA_KEY}" "${WORK}/ca.key" \
        && chmod 600 "${WORK}/ca.crt" "${WORK}/ca.key" || { note "ERROR: staging CA failed."; exit 1; }
    note "launching Rust server (udp ${QUIC_PORT}) + MITM client (tproxy ${TPROXY_PORT}, dport ${PORT}) ..."
    "${RUST_BIN}" server --listen "127.0.0.1:${QUIC_PORT}" --token smoke-token \
        --cert "${MQPROXY_CERT}" --key "${MQPROXY_KEY}" >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!
    "${RUST_BIN}" client --server "127.0.0.1:${QUIC_PORT}" --token smoke-token \
        --tproxy "127.0.0.1:${TPROXY_PORT}" --tproxy-mode redirect \
        --tproxy-dport "${PORT}" --setup-redirect --tproxy-uid 65433 \
        --mitm --ca-cert "${WORK}/ca.crt" --ca-key "${WORK}/ca.key" \
        >"${WORK}/client.log" 2>&1 &
    CLIENT_PID=$!
    ready=0
    for _ in $(seq 1 120); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null || ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
            note "ERROR: server or client exited during startup."
            exit 1
        fi
        if grep -q "tunnel conn established" "${WORK}/client.log" 2>/dev/null \
            && grep -q "REDIRECT rules installed" "${WORK}/client.log" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [ "${ready}" -ne 1 ]; then
        note "ERROR: Rust client did not become ready within timeout."
        exit 1
    fi
else
    # ── launch the single-shot helper ────────────────────────────────────────────
    note "launching helper on 127.0.0.1:${PORT} ..."
    "${MITM_SERVER_BIN}" "${MITM_CA_CRT}" "${MITM_CA_KEY}" "${PORT}" \
        >"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!

    # ── wait for the listener to be ready (retry-connect, not a fixed sleep) ──────
    ready=0
    for _ in $(seq 1 100); do
        if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
            note "ERROR: helper exited before becoming ready; see ${WORK}/server.log:"
            sed 's/^/  server| /' "${WORK}/server.log" >&2 2>/dev/null
            exit 1
        fi
        # The helper prints "LISTENING" once it has bound+listen()ed.
        if grep -q "LISTENING" "${WORK}/server.log" 2>/dev/null; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [ "${ready}" -ne 1 ]; then
        note "ERROR: helper did not become ready within timeout."
        exit 1
    fi
fi

# ── drive openssl s_client (cross-impl TLS client) ───────────────────────────
# -alpn h2          offer only h2 (the helper's selector must pick it)
# -servername       SNI → the helper forges a leaf with this in the SAN
# -CAfile           trust the MITM CA → "Verify return code: 0 (ok)" iff chain OK
# Bounded by `timeout` so a hung handshake fails fast instead of hanging CI.
SCLIENT_OUT="${WORK}/sclient.out"
note "running openssl s_client to 127.0.0.1:${PORT} (SNI=host.example.com, alpn=h2) ..."
timeout 20 openssl s_client \
    -connect "127.0.0.1:${PORT}" \
    -servername host.example.com \
    -alpn h2 \
    -CAfile "${MITM_CA_CRT}" \
    </dev/null >"${SCLIENT_OUT}" 2>&1 || true

# Reap the single-shot helper now that the connection is done (C mode only).
helper_rc=0
if [ -z "${RUST_BIN}" ]; then
    wait "${SERVER_PID}" 2>/dev/null
    helper_rc=$?
    SERVER_PID=""
fi

# ── assertions ───────────────────────────────────────────────────────────────
fail=0

if grep -q "ALPN protocol: h2" "${SCLIENT_OUT}"; then
    note "PASS: ALPN protocol h2 negotiated."
else
    note "FAIL: 'ALPN protocol: h2' not found in s_client output."
    fail=1
fi

if grep -q "Verify return code: 0 (ok)" "${SCLIENT_OUT}"; then
    note "PASS: forged leaf chain verified against the MITM CA (Verify return code: 0)."
else
    note "FAIL: 'Verify return code: 0 (ok)' not found — chain did not verify."
    fail=1
fi

# Defensive: confirm the helper itself reported a clean ALPN=h2 termination.
if [ -z "${RUST_BIN}" ] && ! grep -q "ALPN=h2" "${WORK}/server.log" 2>/dev/null; then
    note "WARN: helper did not log ALPN=h2 (rc=${helper_rc}); see server.log."
fi

if [ "${fail}" -ne 0 ]; then
    note "──── s_client output (tail) ────"
    tail -n 40 "${SCLIENT_OUT}" | sed 's/^/  client| /' >&2
    note "RESULT = FAIL"
    exit 1
fi

note "RESULT = PASS (cross-impl s_client: h2 negotiated + chain verified)."
exit 0
