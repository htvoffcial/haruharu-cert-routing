#!/bin/sh
# Generate two self-signed ECDSA P-256 certificates for the localhost demo.
# Both use CN=localhost but have different keys (and serials), like the live demo.
set -e
cd "$(dirname "$0")"
mkdir -p certs
for name in a b; do
  openssl ecparam -genkey -name prime256v1 -noout -out "certs/$name.key"
  openssl req -new -x509 -key "certs/$name.key" -out "certs/$name.pem" -days 365 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
done
echo "wrote certs/a.pem, certs/a.key, certs/b.pem, certs/b.key"
