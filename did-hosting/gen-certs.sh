#!/usr/bin/env bash
# Regenerates the dev-only CA + TLS server certificate used by the did-host
# container. The SAN covers every hostname that is aliased onto did-host.
#
# Run from the repo root:  bash did-hosting/gen-certs.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"
cd "$DIR"

SAN="DNS:secureissuer.solidcommunity.net,DNS:bboi.solidcommunity.net,DNS:secureapp.solidcommunity.net,DNS:secureapp-2.solidcommunity.net,DNS:raw.githubusercontent.com,DNS:did-host,DNS:localhost,IP:127.0.0.1"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=dkg-demo-did-ca" >/dev/null 2>&1

# Server key + CSR + signed cert
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=did-host" >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 3650 -extfile <(printf "subjectAltName=%s" "$SAN") >/dev/null 2>&1

rm -f server.csr ca.srl
echo "Wrote $DIR/{ca.crt,ca.key,server.crt,server.key}"
