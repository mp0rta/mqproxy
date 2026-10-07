#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqproxy contributors
# Test-only CA fixtures for crates/mq-proxy/src/client/mitm/ca.rs (SP4 spec §7.1).
# Run once (openssl 3); the outputs are committed. Every certificate lasts
# 36500 days so tests on the real clock never age out, except ca-expiring.
set -euo pipefail
cd "$(dirname "$0")"

D=36500
BC='basicConstraints=critical,CA:TRUE'
KU='keyUsage=critical,keyCertSign,cRLSign'

# ca <name> <-newkey arg> [extra req args...]
ca() {
  local n=$1 k=$2
  shift 2
  openssl req -x509 -newkey "$k" -nodes -keyout "$n.key" -out "$n.crt" -days "$D" \
    -subj "/CN=mqproxy test $n" -addext "$BC" -addext "$KU" "$@" 2>/dev/null
}

# Good CAs (openssl 3 writes PKCS#8 "PRIVATE KEY").
ca ca-p256 ec -pkeyopt ec_paramgen_curve:P-256
ca ca-p384 ec -pkeyopt ec_paramgen_curve:P-384
ca ca-ed25519 ed25519
ca ca-rsa2048 rsa:2048

# Keys in the wrong format.
openssl genrsa -traditional -out key-rsa-pkcs1.pem 2048 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out key-ec-sec1.pem
openssl pkcs8 -topk8 -in ca-p256.key -passout pass:test -v2 aes-256-cbc -out key-encrypted-pkcs8.pem
cat ca-p256.key ca-p384.key > two-keys.pem

# Certificates that fail checks, all self-signed with ca-p256.key so the only
# fault is the one named.
openssl req -new -key ca-p256.key -subj "/CN=mqproxy test v1" -out v1.csr
openssl x509 -req -in v1.csr -signkey ca-p256.key -days "$D" -out cert-v1.crt 2>/dev/null
rm v1.csr
openssl req -x509 -key ca-p256.key -out cert-ca-false.crt -days "$D" \
  -subj "/CN=mqproxy test ca-false" -addext 'basicConstraints=critical,CA:FALSE'
openssl req -x509 -key ca-p256.key -out cert-no-keycertsign.crt -days "$D" \
  -subj "/CN=mqproxy test no-keycertsign" -addext "$BC" -addext 'keyUsage=critical,digitalSignature'

# Edge cases.
P256=(ec -pkeyopt ec_paramgen_curve:P-256)
openssl req -x509 -newkey "${P256[@]}" -nodes -keyout ca-repeated-ou.key -out ca-repeated-ou.crt \
  -days "$D" -subj "/CN=mqproxy test repeated-ou/OU=one/OU=two" -addext "$BC" -addext "$KU" 2>/dev/null
ca ca-uri-constraint "${P256[@]}" -addext 'nameConstraints=critical,permitted;URI:.example.com'
ca ca-dns-constraint "${P256[@]}" \
  -addext 'nameConstraints=critical,permitted;DNS:.example.com,permitted;IP:192.168.0.0/255.255.0.0,excluded;DNS:bad.example.com'
# An empty dNSName subtree: SEQUENCE { [0|1] { SEQUENCE { [2] "" } } }.
ca ca-empty-permitted "${P256[@]}" -addext 'nameConstraints=critical,DER:30:06:a0:04:30:02:82:00'
ca ca-empty-excluded "${P256[@]}" -addext 'nameConstraints=critical,DER:30:06:a1:04:30:02:82:00'
D=10 ca ca-expiring "${P256[@]}"

cat ca-p256.crt ca-p384.crt > ca-plus-extra.crt
