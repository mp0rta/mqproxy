#!/usr/bin/env bash
# check_boringssl_isolation.sh — Phase 7 Slice 3 Task 3 build-verification gate.
#
# Asserts the BoringSSL the MITM core links against is *isolated* inside the
# mqproxy executable so it cannot interpose libcurl's system OpenSSL (libssl.so).
#
# SCOPE OF THE CANARIES: the three symbols below (SSL_new, SSL_CTX_new, X509_sign)
# are *representative canaries* for the BoringSSL SSL_*/X509_* surface — NOT an
# exhaustive enumeration. The actual isolation is enforced by --exclude-libs
# covering the WHOLE libssl.a/libcrypto.a archives (plus BoringSSL's own hidden
# visibility); the `nm` checks here only spot-validate non-export on these few.
#
# WHY THE THREE CHECKS LOOK ASYMMETRIC (symbol-presence ordering subtlety):
#   A static archive only contributes object files that resolve some *referenced*
#   undefined symbol. At THIS task nothing in cli/main.c references the MITM core
#   yet (Task 13 wires the caller), so whether BoringSSL SSL_*/X509_* objects are
#   pulled into the exe depends on the build flavor:
#     * STATIC build (MQPROXY_STATIC_XQUIC=ON): libxquic-static.a references
#       BoringSSL SSL_*/EVP_AEAD_* etc., so SSL_new IS present in the exe today.
#       The non-export gate (check ii) is therefore fully meaningful here NOW —
#       this is the strongest test of the isolation.
#     * DYNAMIC build (default): libxquic.so resolves its BoringSSL internally,
#       so SSL_new is NOT pulled into the exe until a caller references it (Task
#       13). Check (i) below will find NOTHING in the dynamic build right now.
#
#   Hence check (i) is tolerant of ABSENCE: a symbol that is simply not yet
#   referenced is acceptable. It fails ONLY on a lingering `U SSL_new` (undefined
#   = broken link, the archive was supposed to satisfy a reference but didn't),
#   or on a `t`/`T` defined symbol being exported (that is caught by check ii).
#   Check (ii) is the real export gate: it must return nothing (vacuously true
#   when the symbol is absent, meaningfully enforced when present). Check (iii)
#   confirms libcurl still dynamically needs system OpenSSL.
#
#   This makes the script: PASS in the dynamic build now (symbols absent →
#   vacuous), genuinely VALIDATE non-export in the static build now (symbols
#   present from xquic), and AUTOMATICALLY strengthen for the dynamic build once
#   Task 13 wires a MITM caller. Do NOT add a fake reference to force SSL_new to
#   appear in the dynamic build.
#
# Usage: check_boringssl_isolation.sh <path-to-mqproxy-exe>
set -euo pipefail

EXE="${1:?usage: check_boringssl_isolation.sh <mqproxy-exe>}"
if [[ ! -x "$EXE" ]]; then
    echo "FAIL: executable not found or not executable: $EXE" >&2
    exit 1
fi

fail=0

# ---- (i) No lingering undefined BoringSSL symbol (broken link guard) --------
# `nm` lists undefined symbols with type 'U'. A `U SSL_new` would mean the link
# expected the BoringSSL archive to satisfy a reference but it did not resolve.
# Absence of any SSL_new line (not referenced yet) is acceptable.
undef="$(nm "$EXE" 2>/dev/null | grep -E ' U (SSL_new|SSL_CTX_new|X509_sign)$' || true)"
if [[ -n "$undef" ]]; then
    echo "FAIL (i): undefined BoringSSL symbols remain (broken link):" >&2
    echo "$undef" >&2
    fail=1
else
    echo "OK (i): no undefined BoringSSL SSL_*/X509_* symbols."
fi

# Informational: report whether the symbols are present at all (helps debugging
# the static-vs-dynamic difference; not a pass/fail condition by itself).
defined="$(nm "$EXE" 2>/dev/null | grep -E ' [TtWw] (SSL_new|SSL_CTX_new|X509_sign)$' || true)"
if [[ -n "$defined" ]]; then
    echo "INFO: BoringSSL symbols are defined in the exe (expected in static build):"
    echo "$defined"
else
    echo "INFO: BoringSSL symbols not (yet) pulled into the exe (expected in dynamic build pre-Task13)."
fi

# ---- (ii) THE ISOLATION GATE: BoringSSL symbols must NOT be exported ---------
# `nm -D` lists *dynamic* (exported) symbols. If any BoringSSL SSL_*/X509_* shows
# up as a global 'T' or weak 'W' in the dynamic symbol table, it can interpose
# libcurl's libssl.so at runtime — exactly what --exclude-libs must prevent.
# Vacuously passes when the symbols are absent; meaningfully enforced when present.
exported="$(nm -D "$EXE" 2>/dev/null | grep -E ' (T|W) (SSL_new|SSL_CTX_new|X509_sign)$' || true)"
if [[ -n "$exported" ]]; then
    echo "FAIL (ii): BoringSSL symbols EXPORTED in dynamic symbol table (interposition risk):" >&2
    echo "$exported" >&2
    fail=1
else
    echo "OK (ii): no BoringSSL SSL_*/X509_* exported (isolation gate holds)."
fi

# ---- (iii) libcurl still dynamically needs system OpenSSL --------------------
# Confirms we did not accidentally sever libcurl's dependency on the system
# libssl.so (i.e. the static BoringSSL is additive/isolated, not a replacement).
if ldd "$EXE" 2>/dev/null | grep -q 'libssl\.so'; then
    echo "OK (iii): libcurl still dynamically needs system libssl.so."
else
    echo "FAIL (iii): libssl.so not in ldd output — libcurl's system OpenSSL link is gone." >&2
    fail=1
fi

if [[ "$fail" -ne 0 ]]; then
    echo "BoringSSL isolation check FAILED for $EXE" >&2
    exit 1
fi
echo "BoringSSL isolation check PASSED for $EXE"
exit 0
