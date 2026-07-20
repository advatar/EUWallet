#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config="$script_dir/openssl.cnf"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/euwallet-x509-strict.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

new_request() {
    name=$1
    subject=$2
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$work_dir/$name.key" -out "$work_dir/$name.csr" -subj "/CN=$subject" >/dev/null 2>&1
}

self_sign() {
    name=$1
    extensions=$2
    serial=$3
    openssl x509 -req -in "$work_dir/$name.csr" -signkey "$work_dir/$name.key" \
        -sha256 -days 3650 -set_serial "$serial" -extfile "$config" -extensions "$extensions" \
        -out "$work_dir/$name.crt" >/dev/null 2>&1
}

ca_sign() {
    name=$1
    ca=$2
    extensions=$3
    serial=$4
    openssl x509 -req -in "$work_dir/$name.csr" -CA "$work_dir/$ca.crt" \
        -CAkey "$work_dir/$ca.key" -sha256 -days 3650 -set_serial "$serial" \
        -extfile "$config" -extensions "$extensions" -out "$work_dir/$name.crt" >/dev/null 2>&1
}

emit() {
    name=$1
    output=${2:-$name}
    openssl x509 -in "$work_dir/$name.crt" -outform DER -out "$work_dir/$name.der"
    openssl base64 -A -in "$work_dir/$name.der" -out "$script_dir/$output.der.b64"
    printf '\n' >>"$script_dir/$output.der.b64"
}

new_request root-a "Strict Root A"
self_sign root-a root_ca 1001
new_request root-b "Strict Root B"
self_sign root-b root_ca 1002

# One intermediate key is cross-signed by two roots. Its SKI remains identical in both certs.
new_request intermediate "Strict Intermediate"
ca_sign intermediate root-a intermediate_ca 1101
cp "$work_dir/intermediate.crt" "$work_dir/intermediate-a.crt"
cp "$work_dir/intermediate.key" "$work_dir/intermediate-a.key"
ca_sign intermediate root-b intermediate_ca 1102
cp "$work_dir/intermediate.crt" "$work_dir/intermediate-b.crt"
cp "$work_dir/intermediate.key" "$work_dir/intermediate-b.key"
new_request leaf "Strict Leaf"
ca_sign leaf intermediate-a leaf 1201

new_request root-zero "Strict Root Zero"
self_sign root-zero root_zero 2001
new_request intermediate-zero "Strict Intermediate Zero"
ca_sign intermediate-zero root-zero intermediate_ca 2101
new_request leaf-zero "Strict Leaf Zero"
ca_sign leaf-zero intermediate-zero leaf 2201

new_request intermediate-no-keycert "Strict Intermediate No KeyCertSign"
ca_sign intermediate-no-keycert root-a ca_no_keycert 3101
new_request leaf-no-keycert-parent "Strict Leaf No KeyCertSign Parent"
ca_sign leaf-no-keycert-parent intermediate-no-keycert leaf 3201

new_request intermediate-missing-bc "Strict Intermediate Missing BasicConstraints"
ca_sign intermediate-missing-bc root-a ca_missing_basic_constraints 4101
new_request leaf-missing-bc-parent "Strict Leaf Missing BasicConstraints Parent"
ca_sign leaf-missing-bc-parent intermediate-missing-bc leaf 4201

new_request root-no-keycert "Strict Root No KeyCertSign"
self_sign root-no-keycert root_no_keycert 5001
new_request leaf-root-no-keycert "Strict Leaf Root No KeyCertSign"
ca_sign leaf-root-no-keycert root-no-keycert leaf 5101

new_request leaf-no-digital-signature "Strict Leaf No DigitalSignature"
ca_sign leaf-no-digital-signature intermediate-a leaf_no_digital_signature 6101
new_request leaf-unknown-critical "Strict Leaf Unknown Critical"
ca_sign leaf-unknown-critical intermediate-a leaf_unknown_critical 6201

# Same issuer DN as the real intermediate, but a different key/SKI: the leaf AKI cannot match the
# supplied real intermediate.
new_request intermediate-fake "Strict Intermediate"
ca_sign intermediate-fake root-a intermediate_ca 7101
new_request leaf-aki-mismatch "Strict Leaf AKI Mismatch"
ca_sign leaf-aki-mismatch intermediate-fake leaf 7201

# Build a genuine issuer-name/AKI cycle. The bootstrap and final Loop B certificates share the
# same subject key and SKI, so Loop A remains structurally linked to the final certificate.
new_request loop-b "Strict Loop B"
self_sign loop-b loop_ca 8001
cp "$work_dir/loop-b.crt" "$work_dir/loop-b-bootstrap.crt"
cp "$work_dir/loop-b.key" "$work_dir/loop-b-bootstrap.key"
new_request loop-a "Strict Loop A"
ca_sign loop-a loop-b-bootstrap loop_ca 8101
ca_sign loop-b loop-a loop_ca 8201
new_request loop-leaf "Strict Loop Leaf"
ca_sign loop-leaf loop-a leaf 8301

for name in root-a root-b leaf root-zero intermediate-zero leaf-zero \
    intermediate-no-keycert leaf-no-keycert-parent intermediate-missing-bc \
    leaf-missing-bc-parent root-no-keycert leaf-root-no-keycert leaf-no-digital-signature \
    leaf-unknown-critical leaf-aki-mismatch loop-a loop-b loop-leaf; do
    emit "$name"
done
emit intermediate-a intermediate-a
emit intermediate-b intermediate-b
