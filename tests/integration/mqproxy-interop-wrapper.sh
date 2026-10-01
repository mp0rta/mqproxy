#!/usr/bin/env bash
set -eu
case "$1" in client) exec "$MQPROXY_CLIENT_BIN" "$@";; server) exec "$MQPROXY_SERVER_BIN" "$@";; *) exec "$MQPROXY_SERVER_BIN" "$@";; esac
