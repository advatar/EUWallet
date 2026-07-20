#!/usr/bin/env bash
# Generate run-specific CycloneDX SBOMs in docs/certification-evidence/sbom/.
# The output records its generation time, target, and checkout path. CI preserves the exact files
# from each run as an artifact. See docs/certification-evidence/sbom/README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:$PATH"
CARGO_CYCLONEDX_VERSION=0.5.9
if ! cargo cyclonedx --version 2>/dev/null | grep -q " $CARGO_CYCLONEDX_VERSION$"; then
  cargo install cargo-cyclonedx --version "$CARGO_CYCLONEDX_VERSION" --locked --force
fi

cargo cyclonedx --format json --all
mkdir -p docs/certification-evidence/sbom
# shellcheck disable=SC2038
find crates -maxdepth 2 -name '*.cdx.json' -exec mv {} docs/certification-evidence/sbom/ \;

echo "SBOMs refreshed in docs/certification-evidence/sbom/ ($(ls docs/certification-evidence/sbom/*.cdx.json | wc -l | tr -d ' ') crates)"
