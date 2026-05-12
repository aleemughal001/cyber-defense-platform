#!/usr/bin/env bash
set -e

docker run --rm -it openquantumsafe/oqs-ossl3:latest sh -lc '
OPENSSL=/opt/openssl/bin/openssl

$OPENSSL version
$OPENSSL list -providers || true
$OPENSSL list -kem-algorithms || true
$OPENSSL list -signature-algorithms || true

mkdir -p /tmp/pqc
cd /tmp/pqc

$OPENSSL req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -sha256 -days 1 -nodes -subj "/CN=localhost"

( $OPENSSL s_server -accept 4433 -cert cert.pem -key key.pem -www > /tmp/server.log 2>&1 & )
sleep 3

echo "GET /" | $OPENSSL s_client -connect localhost:4433 -tls1_3 || true
'
