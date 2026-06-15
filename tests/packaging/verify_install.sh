#!/usr/bin/env bash
# Verify packaging install layout + static self-containment.
# Usage: verify_install.sh <build-dir>
#
# Requires the build to have been configured with -DCMAKE_INSTALL_PREFIX=/usr
# (the @CMAKE_INSTALL_PREFIX@ in the unit ExecStart is baked at *configure* time,
# so a --prefix at install time would not match). On any other prefix this SKIPs.
set -euo pipefail
BUILD="${1:?build dir}"
[ -x "$BUILD/mqproxy" ] || { echo "SKIP: no mqproxy in $BUILD"; exit 77; }

PREFIX="$(sed -n 's/^CMAKE_INSTALL_PREFIX:[^=]*=//p' "$BUILD/CMakeCache.txt" 2>/dev/null || true)"
if [ "$PREFIX" != "/usr" ]; then
  echo "SKIP: packaging CTest expects -DCMAKE_INSTALL_PREFIX=/usr (got '${PREFIX:-unset}')"
  exit 77
fi

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
# No --prefix: honor the configured /usr so the staged tree matches the baked ExecStart.
DESTDIR="$STAGE" cmake --install "$BUILD" >/dev/null

fail=0
for f in \
  usr/bin/mqproxy \
  usr/lib/systemd/system/mqproxy-server@.service \
  usr/lib/systemd/system/mqproxy-client@.service \
  usr/lib/sysusers.d/mqproxy.conf \
  usr/lib/tmpfiles.d/mqproxy.conf \
  usr/share/doc/mqproxy/server.conf.example \
  usr/share/doc/mqproxy/client.conf.example \
  usr/share/doc/mqproxy/LICENSE ; do
  [ -e "$STAGE/$f" ] || { echo "MISSING: $f"; fail=1; }
done

# Self-containment: must not need libxquic. (libssl/libcrypto/libcurl/libevent are
# legitimate distro deps — do NOT broaden this grep to match them.)
if ldd "$STAGE/usr/bin/mqproxy" | grep -qi xquic; then
  echo "FAIL: staged binary links libxquic (expected static)"; fail=1
fi

grep -q '^ExecStart=/usr/bin/mqproxy server ' \
  "$STAGE/usr/lib/systemd/system/mqproxy-server@.service" \
  || { echo "FAIL: server ExecStart not substituted to /usr"; fail=1; }

[ "$fail" -eq 0 ] && echo "OK: packaging install verified"
exit "$fail"
