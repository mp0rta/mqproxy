#!/bin/sh
# test_cli_help.sh — smoke test for the mqproxy CLI.
#
# Asserts that --help works at the top level and per subcommand (exit 0, output
# documents the flags), and that an unknown subcommand fails (non-zero). The
# mqproxy binary path is passed as $1 (configured via $<TARGET_FILE:mqproxy>).
#
# This does NOT start a live client/server — it only exercises argument parsing
# and the usage text, which must not require cert/key/network.
set -u

BIN="${1:-}"
if [ -z "$BIN" ]; then
    echo "usage: $0 <path-to-mqproxy>" >&2
    exit 2
fi
if [ ! -x "$BIN" ]; then
    echo "FAIL: mqproxy binary not executable: $BIN" >&2
    exit 2
fi

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# ── top-level --help / -h: exit 0, mentions both subcommands ──────────────────
for flag in --help -h; do
    out=$("$BIN" "$flag" 2>&1)
    rc=$?
    [ "$rc" -eq 0 ] || fail "top-level '$flag' exited $rc (want 0)"
    echo "$out" | grep -q "client" || fail "top-level '$flag' output missing 'client'"
    echo "$out" | grep -q "server" || fail "top-level '$flag' output missing 'server'"
done

# ── client --help: exit 0, documents the client flags ─────────────────────────
out=$("$BIN" client --help 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "'client --help' exited $rc (want 0)"
for flag in "--server" "--token" "--socks5" "--http-connect" "--gateway" "--path" \
            "--keepalive-idle" "--reconnect" "--no-reconnect" "--reconnect-max-backoff" \
            "--metrics-interval" "--config" \
            "--mitm" "--ca-cert" "--ca-key" "--ignore-host" "--ignore-hosts"; do
    echo "$out" | grep -q -- "$flag" || fail "'client --help' output missing '$flag'"
done
echo "$out" | grep -q "UDP ASSOCIATE supported" || \
    fail "'client --help' output missing 'UDP ASSOCIATE supported'"

# ── server --help: exit 0, documents the server flags ─────────────────────────
out=$("$BIN" server --help 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "'server --help' exited $rc (want 0)"
for flag in "--listen" "--token" "--origin-ca" "--no-gateway" "--udp-idle-timeout" "--no-udp" \
            "--metrics-interval" "--config"; do
    echo "$out" | grep -q -- "$flag" || fail "'server --help' output missing '$flag'"
done

# ── client with no ingress: non-zero exit, names all three ingress flags ──────
# --server/--token are present but none of --socks5/--http-connect/--gateway, so
# the client must reject the invocation with a clear "at least one ingress" error.
out=$("$BIN" client --server 127.0.0.1:4433 --token t 2>&1)
rc=$?
[ "$rc" -ne 0 ] || fail "client with no ingress exited 0 (want non-zero)"
echo "$out" | grep -q -- "--socks5" || fail "no-ingress error missing '--socks5'"
echo "$out" | grep -q -- "--http-connect" || fail "no-ingress error missing '--http-connect'"
echo "$out" | grep -q -- "--gateway" || fail "no-ingress error missing '--gateway'"

# ── MITM fail-closed validation (Slice 3 Task 15) ─────────────────────────────
# These run before any bind/CA load, so they're privilege-free regardless of
# whether the binary was built with or without BoringSSL: a no-archive build
# hard-errors "built without BoringSSL"; an archive build hits the
# --tproxy/--ca-cert/--ca-key requirements. Either way the exit is non-zero.

# --mitm with a non-tproxy ingress (gateway) must be rejected (requires --tproxy,
# or unavailable on a no-archive build).
out=$("$BIN" client --server 127.0.0.1:4433 --token t --gateway 127.0.0.1:8080 --mitm 2>&1)
rc=$?
[ "$rc" -ne 0 ] || fail "--mitm without --tproxy exited 0 (want non-zero)"

# --mitm + --tproxy but no CA must be rejected (requires --ca-cert/--ca-key, or
# unavailable on a no-archive build).
out=$("$BIN" client --server 127.0.0.1:4433 --token t --tproxy 127.0.0.1:18443 --mitm 2>&1)
rc=$?
[ "$rc" -ne 0 ] || fail "--mitm without CA exited 0 (want non-zero)"
# On an archive build this names the missing CA flags; tolerate the no-archive
# "built without BoringSSL" message by only asserting the error mentions mitm.
echo "$out" | grep -qi -- "mitm" || fail "--mitm-without-CA error missing 'mitm'"

# --mitm is a CLIENT-only flag; the server subcommand must reject it (unknown
# option) — getopt_long has no --mitm in the server longopts.
"$BIN" server --mitm >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] || fail "server --mitm exited 0 (want non-zero; --mitm is client-only)"

# ── unknown subcommand: non-zero exit ─────────────────────────────────────────
"$BIN" bogus-subcommand >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] || fail "unknown subcommand exited 0 (want non-zero)"

# ── no subcommand: non-zero exit ──────────────────────────────────────────────
"$BIN" >/dev/null 2>&1
rc=$?
[ "$rc" -ne 0 ] || fail "no subcommand exited 0 (want non-zero)"

echo "PASS: test_cli_help"
exit 0
