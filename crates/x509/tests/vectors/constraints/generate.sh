#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config="$script_dir/openssl.cnf"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/euwallet-x509-constraints.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

new_ec_request() {
    name=$1
    subject=$2
    curve=${3:-P-256}
    openssl req -new -newkey ec -pkeyopt "ec_paramgen_curve:$curve" -nodes \
        -keyout "$work_dir/$name.key" -out "$work_dir/$name.csr" \
        -subj "/CN=$subject" >/dev/null 2>&1
}

new_named_ec_request() {
    name=$1
    subject=$2
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$work_dir/$name.key" -out "$work_dir/$name.csr" \
        -subj "$subject" >/dev/null 2>&1
}

new_rsa_request() {
    name=$1
    subject=$2
    bits=$3
    exponent=${4:-65537}
    openssl req -new -newkey rsa -pkeyopt "rsa_keygen_bits:$bits" \
        -pkeyopt "rsa_keygen_pubexp:$exponent" -nodes -keyout "$work_dir/$name.key" \
        -out "$work_dir/$name.csr" -subj "/CN=$subject" >/dev/null 2>&1
}

new_ed25519_request() {
    name=$1
    subject=$2
    openssl req -new -newkey ed25519 -nodes -keyout "$work_dir/$name.key" \
        -out "$work_dir/$name.csr" -subj "/CN=$subject" >/dev/null 2>&1
}

self_sign() {
    name=$1
    extensions=$2
    serial=$3
    digest=${4:-sha256}
    openssl x509 -req -in "$work_dir/$name.csr" -signkey "$work_dir/$name.key" \
        "-$digest" -days 3650 -set_serial "$serial" -extfile "$config" \
        -extensions "$extensions" -out "$work_dir/$name.crt" >/dev/null 2>&1
}

ca_sign() {
    name=$1
    ca=$2
    extensions=$3
    serial=$4
    digest=${5:-sha256}
    openssl x509 -req -in "$work_dir/$name.csr" -CA "$work_dir/$ca.crt" \
        -CAkey "$work_dir/$ca.key" "-$digest" -days 3650 -set_serial "$serial" \
        -extfile "$config" -extensions "$extensions" -out "$work_dir/$name.crt" \
        >/dev/null 2>&1
}

self_sign_no_digest() {
    name=$1
    extensions=$2
    serial=$3
    openssl x509 -req -in "$work_dir/$name.csr" -signkey "$work_dir/$name.key" \
        -days 3650 -set_serial "$serial" -extfile "$config" -extensions "$extensions" \
        -out "$work_dir/$name.crt" >/dev/null 2>&1
}

ca_sign_no_digest() {
    name=$1
    ca=$2
    extensions=$3
    serial=$4
    openssl x509 -req -in "$work_dir/$name.csr" -CA "$work_dir/$ca.crt" \
        -CAkey "$work_dir/$ca.key" -days 3650 -set_serial "$serial" -extfile "$config" \
        -extensions "$extensions" -out "$work_dir/$name.crt" >/dev/null 2>&1
}

emit() {
    name=$1
    openssl x509 -in "$work_dir/$name.crt" -outform DER -out "$work_dir/$name.der"
    openssl base64 -A -in "$work_dir/$name.der" -out "$script_dir/$name.der.b64"
    printf '\n' >>"$script_dir/$name.der.b64"
}

# Supported DNS/URI/IP constraints and adversarial descendants.
new_ec_request constrained-root "Constraint Root"
self_sign constrained-root root_name_constraints 1001
for vector in allowed dns-outside dns-excluded uri-apex uri-no-authority uri-excluded \
    ip-outside ip-excluded; do
    new_ec_request "leaf-$vector" "Constraint Leaf $vector"
    ca_sign "leaf-$vector" constrained-root "leaf_$(printf '%s' "$vector" | tr - _)" \
        "20$(printf '%02d' "$(expr $(printf '%s' "$vector" | wc -c) % 90)")"
done

# Permitted subtrees from separate authorities intersect rather than overwrite one another.
new_ec_request intersection-root "Intersection Root"
self_sign intersection-root root_name_constraints 3001
new_ec_request intersection-intermediate "Intersection Intermediate"
ca_sign intersection-intermediate intersection-root intermediate_narrow 3002
for vector in team-allowed team-outside; do
    new_ec_request "leaf-$vector" "Intersection Leaf $vector"
    ca_sign "leaf-$vector" intersection-intermediate \
        "leaf_$(printf '%s' "$vector" | tr - _)" "31$(printf '%02d' "$(printf '%s' "$vector" | wc -c)")"
done

# Unsupported/non-conforming name-constraint forms stay parseable as anchors but fail every path.
new_ec_request email-constraint-root "Email Constraint Root"
self_sign email-constraint-root root_email_constraint 4001
new_ec_request noncritical-constraint-root "Noncritical Constraint Root"
self_sign noncritical-constraint-root root_noncritical_constraint 4002
new_ec_request illegal-constraint-leaf "Illegal Constraint Leaf"
ca_sign illegal-constraint-leaf constrained-root leaf_illegal_constraint 4003
new_ec_request plain-leaf "Plain Leaf"
ca_sign plain-leaf email-constraint-root leaf 4004
for vector in allowed outside excluded; do
    new_ec_request "email-$vector-leaf" "Email $vector Leaf"
    ca_sign "email-$vector-leaf" email-constraint-root "leaf_email_$vector" \
        "41$(printf '%02d' "$(printf '%s' "$vector" | wc -c)")"
done
new_named_ec_request directory-constraint-root "/C=DE/O=Example/CN=Directory Constraint Root"
self_sign directory-constraint-root root_directory_constraint 4201
new_named_ec_request directory-allowed-leaf "/C=DE/O=Example/OU=PID/CN=Allowed Wallet"
ca_sign directory-allowed-leaf directory-constraint-root leaf 4202
new_named_ec_request directory-outside-leaf "/C=DE/O=Other/OU=PID/CN=Outside Wallet"
ca_sign directory-outside-leaf directory-constraint-root leaf 4203
new_named_ec_request directory-excluded-leaf "/C=DE/O=Example/OU=Blocked/CN=Excluded Wallet"
ca_sign directory-excluded-leaf directory-constraint-root leaf 4204
new_ec_request noncritical-leaf "Noncritical Leaf"
ca_sign noncritical-leaf noncritical-constraint-root leaf 4005

# Certificate-only algorithm vectors. These deliberately mix child SPKI types and issuer
# signature families: compatibility is with the issuer key, not the child's key.
new_rsa_request rsa-root "RSA Root" 2048
self_sign rsa-root root_ca 5001 sha384
new_ec_request rsa-signed-ec-leaf "RSA-signed EC Leaf"
ca_sign rsa-signed-ec-leaf rsa-root leaf 5002 sha384
new_ec_request rsa-sha256-leaf "RSA SHA256 Leaf"
ca_sign rsa-sha256-leaf rsa-root leaf 5003 sha256
new_ec_request rsa-sha512-leaf "RSA SHA512 Leaf"
ca_sign rsa-sha512-leaf rsa-root leaf 5004 sha512

new_ec_request p256-sha384-root "P256 SHA384 Root"
self_sign p256-sha384-root root_ca 5101 sha384
new_rsa_request ec-signed-rsa-leaf "EC-signed RSA Leaf" 2048
ca_sign ec-signed-rsa-leaf p256-sha384-root leaf 5102 sha384

new_ec_request p384-root "P384 Root" P-384
self_sign p384-root root_ca 5111 sha384
new_ec_request p384-leaf "P384 Leaf" P-384
ca_sign p384-leaf p384-root leaf 5112 sha384

new_ed25519_request ed25519-root "Ed25519 Root"
self_sign_no_digest ed25519-root root_ca 5121
new_ed25519_request ed25519-leaf "Ed25519 Leaf"
ca_sign_no_digest ed25519-leaf ed25519-root leaf 5122

new_rsa_request weak-rsa-root "Weak RSA Root" 1024
self_sign weak-rsa-root root_ca 5201 sha256
new_rsa_request exponent-three-root "Exponent Three Root" 2048 3
self_sign exponent-three-root root_ca 5202 sha256
new_ec_request p521-root "P521 Root" P-521
self_sign p521-root root_ca 5203 sha384
new_ec_request sha1-leaf "SHA1 Leaf"
ca_sign sha1-leaf rsa-root leaf 5204 sha1

for vector in constrained-root leaf-allowed leaf-dns-outside leaf-dns-excluded leaf-uri-apex \
    leaf-uri-no-authority leaf-uri-excluded leaf-ip-outside leaf-ip-excluded intersection-root \
    intersection-intermediate leaf-team-allowed leaf-team-outside email-constraint-root \
    email-allowed-leaf email-outside-leaf email-excluded-leaf directory-constraint-root \
    directory-allowed-leaf directory-outside-leaf directory-excluded-leaf \
    noncritical-constraint-root illegal-constraint-leaf plain-leaf noncritical-leaf rsa-root \
    rsa-signed-ec-leaf rsa-sha256-leaf rsa-sha512-leaf p256-sha384-root ec-signed-rsa-leaf \
    p384-root p384-leaf ed25519-root ed25519-leaf weak-rsa-root exponent-three-root p521-root \
    sha1-leaf; do
    emit "$vector"
done
