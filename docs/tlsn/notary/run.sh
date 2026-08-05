#!/bin/sh
# launchd wrapper for the TLSNotary notary gateway. Loads the signing key from a chmod-600 file so it
# is never baked into the plist, then execs the gateway on loopback (Caddy terminates TLS in front).
#
# Install to /Users/johansellstrom/services/tlsn-notary/run.sh (chmod 0755) and point the launchd
# plist's ProgramArguments at it. Edit the --allow-host list to the domains you notarize (TLS 1.2
# targets only). See README.md.
set -eu

dir=/Users/johansellstrom/services/tlsn-notary
TLSN_NOTARY_SIGNING_KEY=$(cat "$dir/notary-signing-key.hex")
export TLSN_NOTARY_SIGNING_KEY

exec "$dir/tlsn-browser-demo" \
  --listen 127.0.0.1:7047 \
  --static-dir "$dir/static" \
  --wasm-pkg-dir "$dir/static/wasm" \
  --allow-host example.com \
  --allow-host www.google.com \
  --allow-port 443 \
  --verifier-max-sent-data 32768 \
  --verifier-max-recv-data 524288
