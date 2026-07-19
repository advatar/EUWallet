#!/usr/bin/env bash
# Interop probe against the EU Digital Identity Wallet reference environment.
#
# What this DOES (coded, reproducible): over the platform's TLS stack (curl), fetch the reference
# issuer's live OpenID4VCI metadata and validate its shape, confirm the reference verifier is
# reachable, and report the intersection with the credential formats this wallet supports.
#
# What this does NOT do: run the OpenID Foundation conformance suite or claim any conformance /
# certification result. That is a separate, external assessment (OIDF self-certification opened
# 2026-02-26) requiring their harness. This probe is reachability + wire-shape only.
#
# Usage: tools/interop/probe.sh   (needs network; exit code 0 = all checks passed)
set -uo pipefail

ISSUER="${ISSUER:-https://issuer.eudiw.dev}"
VERIFIER="${VERIFIER:-https://verifier.eudiw.dev}"
TMP="$(mktemp)"
fail=0

echo "EUDI reference-environment interop probe — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "issuer=$ISSUER  verifier=$VERIFIER"
echo

# 1) Issuer OpenID4VCI metadata: fetch + validate shape.
code=$(curl -sS -m 25 -o "$TMP" -w '%{http_code}' "$ISSUER/.well-known/openid-credential-issuer" || echo 000)
echo "[issuer] GET /.well-known/openid-credential-issuer -> HTTP $code"
if [ "$code" = "200" ]; then
  python3 - "$TMP" "$ISSUER" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1])); issuer = sys.argv[2]
cfgs = doc.get("credential_configurations_supported") or doc.get("credentials_supported") or {}
sdjwt = [k for k, v in cfgs.items() if isinstance(v, dict) and v.get("format") in ("dc+sd-jwt", "vc+sd-jwt")]
mdoc = [k for k, v in cfgs.items() if isinstance(v, dict) and v.get("format") == "mso_mdoc"]
ok = doc.get("credential_issuer") == issuer and len(cfgs) > 0 and len(sdjwt) > 0
print(f"          credential_issuer = {doc.get('credential_issuer')}")
print(f"          configurations    = {len(cfgs)}  (sd-jwt: {len(sdjwt)}, mso_mdoc: {len(mdoc)})")
print(f"          wallet-supported SD-JWT VC configs present: {'yes' if sdjwt else 'NO'}  e.g. {sdjwt[:3]}")
sys.exit(0 if ok else 1)
PY
  [ $? -ne 0 ] && { echo "  [issuer] metadata shape check FAILED"; fail=1; }
else
  echo "  [issuer] metadata unreachable"; fail=1
fi
echo

# 2) Verifier reachability.
vcode=$(curl -sS -m 25 -o /dev/null -w '%{http_code}' "$VERIFIER" || echo 000)
echo "[verifier] GET / -> HTTP $vcode"
[ "$vcode" = "200" ] || { echo "  [verifier] not reachable"; fail=1; }
echo

rm -f "$TMP"
if [ "$fail" = "0" ]; then
  echo "RESULT: PASS — reference issuer metadata valid + wallet-supported formats offered; verifier reachable."
else
  echo "RESULT: FAIL — see above (network or upstream change)."
fi
exit "$fail"
