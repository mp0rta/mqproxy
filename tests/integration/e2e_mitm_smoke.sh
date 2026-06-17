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
# ENV (passed by CMake; overridable):
#   MITM_SERVER_BIN   the mitm_smoke_server helper binary.
#   MITM_CA_CRT/KEY   the MITM CA cert/key (configure-time fixtures).
#
# SKIP semantics: exit 77 ONLY when `openssl` is absent. Any assertion failure is
# a hard failure (non-zero, not 77).
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
MITM_CA_CRT="${MITM_CA_CRT:-${REPO_ROOT}/tests/certs/mitm-ca.crt}"
MITM_CA_KEY="${MITM_CA_KEY:-${REPO_ROOT}/tests/certs/mitm-ca.key}"

# ── pre-flight (real errors, not skips) ──────────────────────────────────────
if [ ! -x "${MITM_SERVER_BIN}" ]; then
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
        python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

PORT="$(free_port)"
if [ -z "${PORT}" ]; then
    note "ERROR: free-port selection failed."
    exit 1
fi

# ── workspace + cleanup ──────────────────────────────────────────────────────
WORK="$(mktemp -d /tmp/mqproxy_e2e_mitm_smoke.XXXXXX)"
SERVER_PID=""

cleanup() {
    rc=$?
    set +e
    if [ -n "${SERVER_PID}" ]; then
        kill -KILL "${SERVER_PID}" 2>/dev/null
        wait "${SERVER_PID}" 2>/dev/null
    fi
    if [ "${rc}" -ne 0 ] && [ "${rc}" -ne "${SKIP}" ]; then
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

# Reap the single-shot helper now that the connection is done.
wait "${SERVER_PID}" 2>/dev/null
helper_rc=$?
SERVER_PID=""

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
if ! grep -q "ALPN=h2" "${WORK}/server.log" 2>/dev/null; then
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
