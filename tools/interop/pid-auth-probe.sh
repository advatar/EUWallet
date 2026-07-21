#!/usr/bin/env bash
# Live OpenID4VCI authorization-code probe against the EU reference PID issuer
# (issuer.eudiw.dev). It drives every MACHINE-TO-MACHINE step of a real PID issuance up to — but
# not through — the interactive eID/browser authentication, which by design needs a human at a
# browser with an eID. It:
#   1. fetches the live credential-issuer + authorization-server metadata,
#   2. generates a real PKCE verifier/challenge (RFC 7636 S256),
#   3. performs a Pushed Authorization Request (PAR) as a PUBLIC client with a wallet deep-link
#      redirect, and
#   4. prints the exact authorization URL a human opens to complete eID, plus the follow-on
#      token + credential requests to run with the returned `code`.
#
# It captures reproducible evidence and never fabricates a round-trip: it stops at the human step.
# No credentials or personal data are submitted by this script.
#
# Usage: tools/interop/pid-auth-probe.sh [credential_config_id]
set -euo pipefail

CONFIG_ID="${1:-eu.europa.ec.eudi.pid_vc_sd_jwt}"
CLIENT_ID="${WALLET_CLIENT_ID:-advatar-eudi-wallet}"
REDIRECT_URI="${WALLET_REDIRECT_URI:-eudi-openid4vci://authorize}"
ISSUER="https://issuer.eudiw.dev"
TMP="$(mktemp -d)"
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

echo "== 1) credential-issuer metadata =="
curl -fsS --max-time 20 "$ISSUER/.well-known/openid-credential-issuer" -o "$TMP/ci.json"
CRED_EP=$(jq -r '.credential_endpoint' "$TMP/ci.json")
echo "credential_endpoint = $CRED_EP"
jq -e --arg c "$CONFIG_ID" '.credential_configurations_supported[$c]' "$TMP/ci.json" >/dev/null \
  && echo "config '$CONFIG_ID' is offered" || { echo "config '$CONFIG_ID' NOT offered"; exit 1; }

echo "== 2) authorization-server metadata =="
curl -fsS --max-time 20 "$ISSUER/.well-known/oauth-authorization-server" -o "$TMP/as.json"
PAR_EP=$(jq -r '.pushed_authorization_request_endpoint' "$TMP/as.json")
AUTH_EP=$(jq -r '.authorization_endpoint' "$TMP/as.json")
TOKEN_EP=$(jq -r '.token_endpoint' "$TMP/as.json")
echo "PAR=$PAR_EP  AUTH=$AUTH_EP  TOKEN=$TOKEN_EP"

echo "== 3) PKCE (S256) + state =="
VERIFIER=$(openssl rand 32 | b64url)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | b64url)
STATE=$(openssl rand 16 | b64url)
echo "code_verifier (KEEP for the token step) = $VERIFIER"
echo "code_challenge (S256)                    = $CHALLENGE"
echo "state                                    = $STATE"

echo "== 4) Pushed Authorization Request (public client) =="
# authorization_details selects the credential configuration (OpenID4VCI 1.0).
AUTHZ_DETAILS=$(jq -cn --arg c "$CONFIG_ID" \
  '[{type:"openid_credential",credential_configuration_id:$c}]')
CODE=$(curl -sS --max-time 25 -o "$TMP/par.json" -w '%{http_code}' -X POST "$PAR_EP" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "authorization_details=$AUTHZ_DETAILS")
echo "PAR HTTP $CODE"; cat "$TMP/par.json"; echo
REQUEST_URI=$(jq -r '.request_uri // empty' "$TMP/par.json")
[ -n "$REQUEST_URI" ] || { echo "PAR did not return a request_uri"; exit 1; }

AUTH_URL="$AUTH_EP?client_id=$CLIENT_ID&request_uri=$REQUEST_URI"
cat <<EOF

== NEXT (human-in-the-loop; cannot be automated) ==
Open this URL in a browser and complete the eID authentication:

  $AUTH_URL

On success the browser is redirected to:
  $REDIRECT_URI?code=<AUTHORIZATION_CODE>&state=$STATE

Then exchange the code for a DPoP-bound access token (public client):

  curl -X POST "$TOKEN_EP" -H 'Content-Type: application/x-www-form-urlencoded' \\
    -H 'DPoP: <ES256 DPoP proof for POST $TOKEN_EP>' \\
    --data-urlencode 'grant_type=authorization_code' \\
    --data-urlencode "code=<AUTHORIZATION_CODE>" \\
    --data-urlencode "redirect_uri=$REDIRECT_URI" \\
    --data-urlencode "client_id=$CLIENT_ID" \\
    --data-urlencode "code_verifier=$VERIFIER"

and request the credential (proof-of-possession JWT over the issuer c_nonce):

  curl -X POST "$CRED_EP" -H 'Authorization: DPoP <access_token>' \\
    -H 'DPoP: <ES256 DPoP proof for POST $CRED_EP, ath=<token hash>>' \\
    -H 'Content-Type: application/json' \\
    -d '{"credential_configuration_id":"$CONFIG_ID","proof":{"proof_type":"jwt","jwt":"<device-key proof>"}}'

The token + credential legs are owned by the Rust core's OID4VCI/HAIP transport (WIA/KA, DPoP,
c_nonce reservation, ES256 proof signing) — this probe intentionally does not reimplement them.
EOF
rm -rf "$TMP"
