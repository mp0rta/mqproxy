#!/usr/bin/env bash
# Disposable test CA; never install it into a machine's trust store.
set -euo pipefail
cd "$(dirname "$0")"
if [[ -s mitm-ca.crt && -s mitm-ca.key ]]; then exit 0; fi
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out mitm-ca.key
openssl req -x509 -new -key mitm-ca.key -out mitm-ca.crt -days 3650 \
  -subj /CN=mqproxy-mitm-test-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
