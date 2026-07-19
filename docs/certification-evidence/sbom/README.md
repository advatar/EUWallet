# Software Bill of Materials (CycloneDX)

Published CycloneDX SBOMs for the wallet's Rust workspace, one per crate.

- **Format:** CycloneDX 1.3, JSON.
- **Tool:** `cargo-cyclonedx` v0.5.9.
- **Primary runtime SBOM:** [`wallet-core.cdx.json`](wallet-core.cdx.json) — the sans-IO
  facade transitively pulls in every protocol crate plus the `aws-lc-rs` cryptographic backend,
  so its component graph (111 components) is the wallet's runtime dependency set. The remaining
  files are per-crate SBOMs for finer-grained review.
- **Generated:** 2026-07-19, against workspace commit recorded alongside in the verification report.

## Regenerate

```
tools/evidence/sbom.sh        # or:
cargo cyclonedx --format json --all
mv crates/*/*.cdx.json docs/certification-evidence/sbom/
```

CI also generates the SBOM in the `supply-chain` job (`.github/workflows/ci.yml`); this directory
is the published, in-repo copy so reviewers do not need to run the pipeline.

## Scope & honesty

This is the dependency inventory of the **Rust core workspace**. The iOS shell's Swift package
dependencies (the generated UniFFI bindings and Apple frameworks) are not enumerated here; the
shell contains no third-party Swift packages beyond the SDK. Signed provenance / attestation of
release binaries is a separate, not-yet-published step (see the operational-assurance notes).
