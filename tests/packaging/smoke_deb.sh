#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
# Run only on a disposable native systemd CI runner, as root.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'run as root on a disposable runner'; exit 1; }
DEB="${1:?deb path}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cleanup() {
  systemctl stop mqproxy-client@sp5client mqproxy-server@sp5server || true
  dpkg -r mqproxy || true
  rm -f /etc/mqproxy/sp5{server,client}.conf /etc/mqproxy/sp5test.{crt,key}
}
trap cleanup EXIT
# Reassert dpkg after dependency repair; broken maintainer scripts must fail.
dpkg -i "$DEB" || { apt-get -f install -y; dpkg -i "$DEB"; }
id mqproxy
test -d /etc/mqproxy
install -o mqproxy -g mqproxy -m 0644 "$ROOT/tests/certs/test.crt" /etc/mqproxy/sp5test.crt
install -o mqproxy -g mqproxy -m 0600 "$ROOT/tests/certs/test.key" /etc/mqproxy/sp5test.key
printf '[Interface]\nListen = 127.0.0.1:14433\n[TLS]\nCert = /etc/mqproxy/sp5test.crt\nKey = /etc/mqproxy/sp5test.key\n[Auth]\nKey = citoken\n' > /etc/mqproxy/sp5server.conf
printf '[Server]\nAddress = 127.0.0.1:14433\n[Auth]\nKey = citoken\n[Ingress]\nSocks5 = 127.0.0.1:11080\n' > /etc/mqproxy/sp5client.conf
chown mqproxy:mqproxy /etc/mqproxy/sp5{server,client}.conf
chmod 0600 /etc/mqproxy/sp5{server,client}.conf
systemctl daemon-reload
systemctl start mqproxy-server@sp5server mqproxy-client@sp5client
sleep 2
for unit in mqproxy-server@sp5server mqproxy-client@sp5client; do
  journalctl -u "$unit" --no-pager -n 30
  systemctl is-active "$unit"
done
# A real SOCKS request proves the two hardened services can relay traffic.
WORK=$(mktemp -d)
python3 -m http.server 18089 --bind 127.0.0.1 --directory "$WORK" > "$WORK/http.log" 2>&1 &
HTTP_PID=$!
trap 'kill "$HTTP_PID" 2>/dev/null || true; rm -rf "$WORK"; cleanup' EXIT
printf 'sp5 service relay\n' > "$WORK/probe"
for _attempt in {1..20}; do
  if curl --fail --silent --noproxy '' --socks5-hostname 127.0.0.1:11080 \
      --max-time 2 http://127.0.0.1:18089/probe > "$WORK/received"; then break; fi
  sleep 1
done
cmp "$WORK/probe" "$WORK/received"
echo 'OK: deb installation and hardened server/client relay'
