#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${REFERENCE_INTEROP_OUT:-$ROOT/docs/certification-evidence/reference-interop}"
ISSUER="${REFERENCE_ISSUER:-https://issuer.eudiw.dev}"
VERIFIER="${REFERENCE_VERIFIER:-https://verifier.eudiw.dev}"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$OUT"

python3 - "$ROOT/tools/reference-interop/pinned-components.json" "$OUT/report.json" "$ISSUER" "$VERIFIER" "$STAMP" <<'PY'
import json, pathlib, subprocess, sys, urllib.error, urllib.request

pin = pathlib.Path(sys.argv[1])
report = pathlib.Path(sys.argv[2])
issuer_url, verifier_url, stamp = sys.argv[3:]
root = pin.parents[2]
def get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as response:
        body = response.read(256 * 1024)
        return response.status, response.headers.get_content_type(), body

def probe(url, parse_json=False):
    try:
        status, content_type, body = get(url)
        metadata = json.loads(body) if parse_json else {}
        return {"url": url, "status": status, "content_type": content_type,
                "reachable": True, "error": None, "metadata": metadata}
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        return {"url": url, "status": None, "content_type": None,
                "reachable": False, "error": str(error), "metadata": {}}

issuer = probe(issuer_url + "/.well-known/openid-credential-issuer", parse_json=True)
verifier = probe(verifier_url + "/")
metadata = issuer.pop("metadata")
configs = metadata.get("credential_configurations_supported", {}) if isinstance(metadata, dict) else {}
revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
payload = {
    "run_at": stamp,
    "source_revision": revision,
    "reference_issuer": {**issuer,
                          "credential_configurations": len(configs),
                          "formats": sorted({v.get("format") for v in configs.values() if isinstance(v, dict)})},
    "reference_verifier": {**verifier, "metadata": None},
    "scope": "reachability and metadata shape only; no conformance or certification claim",
    "pinned_components": json.load(pin.open())
}
report.parent.mkdir(parents=True, exist_ok=True)
json.dump(payload, report.open("w"), indent=2, sort_keys=True)
if not issuer["reachable"] or not verifier["reachable"]:
    raise SystemExit("reference endpoint probe blocked; see report for details")
PY

echo "Reference interoperability report: $OUT/report.json"
