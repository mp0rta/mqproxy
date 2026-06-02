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
for flag in "--server" "--token" "--socks5" "--http-connect" "--path"; do
    echo "$out" | grep -q -- "$flag" || fail "'client --help' output missing '$flag'"
done

# ── server --help: exit 0, documents the server flags ─────────────────────────
out=$("$BIN" server --help 2>&1)
rc=$?
[ "$rc" -eq 0 ] || fail "'server --help' exited $rc (want 0)"
for flag in "--listen" "--token"; do
    echo "$out" | grep -q -- "$flag" || fail "'server --help' output missing '$flag'"
done

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
