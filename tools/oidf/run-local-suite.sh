#!/usr/bin/env bash
# Start the official OpenID Foundation conformance suite at a pinned release.
# This starts the test service only; it does not fabricate test plans or results.
set -euo pipefail

SUITE_TAG="${OIDF_SUITE_TAG:-release-v5.2.1}"
SUITE_COMMIT="${OIDF_SUITE_COMMIT:-932b46f1e507871eb0b34621aaef65ff04442e6f}"
WORKDIR="${OIDF_WORKDIR:-${TMPDIR:-/tmp}/openid-conformance-suite-${SUITE_TAG}}"
REPOSITORY="https://gitlab.com/openid/conformance-suite.git"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
command -v git >/dev/null || { echo "git is required" >&2; exit 2; }

if [[ ! -d "$WORKDIR/.git" ]]; then
  mkdir -p "$(dirname "$WORKDIR")"
  git clone --depth 1 --branch "$SUITE_TAG" "$REPOSITORY" "$WORKDIR"
fi
actual="$(git -C "$WORKDIR" rev-parse HEAD)"
[[ "$actual" == "$SUITE_COMMIT" ]] || {
  echo "OIDF suite revision mismatch: expected $SUITE_COMMIT, got $actual" >&2
  exit 1
}

IMAGE_TAG="$SUITE_TAG" docker compose -f "$WORKDIR/docker-compose-prebuilt.yml" up -d
echo "OIDF suite $SUITE_TAG ($actual) is starting at https://localhost:8443"
echo "Use the suite UI/API to create the OID4VCI issuer and OID4VP verifier plans."
