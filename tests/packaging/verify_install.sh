#!/usr/bin/env bash
# Verify a staged Rust installation (also usable after dpkg-deb --extract).
set -euo pipefail
STAGE="${1:?staged installation root}"
for f in \
  usr/bin/mqproxy \
  usr/lib/systemd/system/mqproxy-server@.service \
  usr/lib/systemd/system/mqproxy-client@.service \
  usr/lib/sysusers.d/mqproxy.conf \
  usr/lib/tmpfiles.d/mqproxy.conf \
  usr/share/doc/mqproxy/server.conf.example \
  usr/share/doc/mqproxy/client.conf.example \
  usr/share/doc/mqproxy/LICENSE \
  usr/share/doc/mqproxy/NOTICE \
  usr/share/doc/mqproxy/third-party/xquic.txt \
  usr/share/doc/mqproxy/third-party/boringssl.txt \
  usr/share/doc/mqproxy/third-party/RUST-DEPENDENCIES.txt; do
  test -s "$STAGE/$f" || { echo "MISSING: $f"; exit 1; }
done
# These are linked in-process or replaced by Rust libraries.
if readelf -d "$STAGE/usr/bin/mqproxy" | grep -Ei 'NEEDED.*(xquic|ssl|crypto|curl|event|nghttp2)'; then
  echo 'FAIL: unexpected shared protocol library'; exit 1
fi
for mode in server client; do
  grep -q "^ExecStart=/usr/bin/mqproxy $mode " "$STAGE/usr/lib/systemd/system/mqproxy-$mode@.service"
done
bash "$(dirname "$0")/../test_cli_help.sh" "$STAGE/usr/bin/mqproxy"
echo 'OK: Rust packaging install verified'
