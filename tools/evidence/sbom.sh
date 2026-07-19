#!/usr/bin/env bash
# Regenerate the published CycloneDX SBOMs (docs/certification-evidence/sbom/).
# Reproducible from a clean checkout. See docs/certification-evidence/sbom/README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:$PATH"
command -v cargo-cyclonedx >/dev/null 2>&1 || cargo install cargo-cyclonedx --locked

cargo cyclonedx --format json --all
mkdir -p docs/certification-evidence/sbom
# shellcheck disable=SC2038
find crates -maxdepth 2 -name '*.cdx.json' -exec mv {} docs/certification-evidence/sbom/ \;

echo "SBOMs refreshed in docs/certification-evidence/sbom/ ($(ls docs/certification-evidence/sbom/*.cdx.json | wc -l | tr -d ' ') crates)"
