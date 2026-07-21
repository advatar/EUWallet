#!/bin/sh
set -eu

vector_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:-$vector_dir}
fixture_ca_key="$vector_dir/../../../../x509/tests/vectors/ca.key"
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

openssl ecparam -name prime256v1 -genkey -noout -out "$temporary_dir/root-a.key"
openssl ecparam -name prime256v1 -genkey -noout -out "$temporary_dir/root-b.key"

openssl req -new -x509 -sha256 -days 3650 \
  -key "$temporary_dir/root-a.key" \
  -subj "/CN=Embedded mdoc Root A" \
  -config "$vector_dir/openssl.cnf" -extensions root_ca \
  -out "$temporary_dir/root-a.pem"
openssl req -new -x509 -sha256 -days 3650 \
  -key "$temporary_dir/root-b.key" \
  -subj "/CN=Embedded mdoc Root B" \
  -config "$vector_dir/openssl.cnf" -extensions root_ca \
  -out "$temporary_dir/root-b.pem"

# Re-certify the existing test CA public key under two roots. The resulting intermediates have
# the exact subject/key identifier expected by issuer.der, which creates two valid paths for the
# same mdoc issuer key without committing either new root private key.
openssl req -new -sha256 \
  -key "$fixture_ca_key" \
  -subj "/CN=EUDI Test RP-Access CA" \
  -out "$temporary_dir/bridge.csr"
openssl x509 -req -sha256 -days 3650 \
  -in "$temporary_dir/bridge.csr" \
  -CA "$temporary_dir/root-a.pem" -CAkey "$temporary_dir/root-a.key" \
  -set_serial 4101 \
  -extfile "$vector_dir/openssl.cnf" -extensions bridge_ca \
  -out "$temporary_dir/bridge-a.pem"
openssl x509 -req -sha256 -days 3650 \
  -in "$temporary_dir/bridge.csr" \
  -CA "$temporary_dir/root-b.pem" -CAkey "$temporary_dir/root-b.key" \
  -set_serial 4102 \
  -extfile "$vector_dir/openssl.cnf" -extensions bridge_ca \
  -out "$temporary_dir/bridge-b.pem"

mkdir -p "$output_dir"
for name in root-a root-b bridge-a bridge-b; do
  openssl x509 -in "$temporary_dir/$name.pem" -outform DER \
    -out "$temporary_dir/$name.der"
  openssl base64 -A -in "$temporary_dir/$name.der" \
    -out "$output_dir/$name.der.b64"
done
