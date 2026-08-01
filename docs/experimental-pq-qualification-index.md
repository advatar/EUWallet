# Experimental hybrid-PQ qualification index

Issue #95. This index covers the opt-in research profile only. It is not evidence of standards
approval, EUDI certification, or production enablement. A gate is complete only when the cited
artifact exercises the same scope as the requirement.

## Construction and fail-closed policy

| Requirement | Authoritative implementation/evidence | State |
|---|---|---|
| Atomic ES256 **and** ML-DSA-65 verification | `hybrid_pq::HybridVerifier`, `verify_credential_wrapper`, complete 2×2 matrix | Complete |
| Same profile, purpose, identity, generation, and TBS | `HybridContextV1`, `HybridTbsV1`, wrapper binding tests, Lean/Tamarin models | Complete |
| No classical-only fallback when hybrid is required | rollout policy tests, adversarial matrix, Lean/Tamarin downgrade lemmas | Complete |
| Hybrid ECDH + ML-KEM key establishment | `HybridKeyAgreement`, transcript/KDF and implicit-rejection vectors | Complete |
| Private keys remain wrapped and generation-bound | Rust wrapped-seed APIs and `ExperimentalHybridKeyCustody` | Complete in code; interactive hardware cases open |

## Cross-repository issuance and acquisition

| Requirement | Authoritative implementation/evidence | State |
|---|---|---|
| Byte-identical issuer/wallet corpus | `docs/test-vectors/hybrid-pq-v1-*`; VCIssuer issue #26 source corpus | Complete |
| Live payload semantics | Canonical seven-field CBOR: issuer, lifetime, VCT, holder JWK, disclosure hashes, development marker | Complete |
| Holder binding | RFC 7638 P-256 JWK thumbprint equals signed `wallet_identity` | Complete |
| Atomic real-backend acceptance | `HybridProviderIntegrationTests` drives frozen issuer bytes through Swift and the production Rust verifier | Complete |
| Certified-path exclusion | `ExperimentalCredentialCatalogue`; PID and mDL production-request assertions | Complete |

## Automated qualification

| Gate | Evidence | State |
|---|---|---|
| NIST/KAT and independent implementations | `experimental-pq-primitives`, `hybrid_component_vectors`, `hybrid_wrapper_vectors` | Complete |
| Unit/property/adversarial/fuzz/Kani | workspace tests, `docs/experimental-pq-adversarial-matrix.md`, Tier 1 CI | Complete |
| Swift and serial simulator | Swift package suite, `CoreOnSimulatorTests`, `HybridProviderIntegrationTests` | Complete |
| UniFFI and XCFramework | generated bindings, `ios/build-rust-xcframework.sh`, `ios/verify-rust-xcframework.sh` | Complete |
| Formal verification | `HybridPqModel.lean`, `hybrid_pq_and_verification.spthy`, Tier 2/3 CI | Complete |
| Dependency/SBOM/threat/ADR/certification boundary | dependency qualification, CycloneDX SBOM, threat model, ADR 0001, hybrid-PQ boundary | Complete |

## Physical-device qualification

The retained iPhone 15 Pro run and its digest are documented in
`docs/experimental-pq-physical-evidence.md`. Real backend correctness, latency/CPU/memory,
four-way bounded concurrency, Secure Enclave/Keychain generation and rotation, ciphertext-only
backup-excluded persistence, missing-key rejection, and rollback rejection passed.

The following gates remain open and must not be inferred from simulator or unattended evidence:

- biometric approval;
- biometric cancellation;
- protected-key access while the iPhone is locked;
- the sustained battery/thermal snapshot.

The executable cases live in `PhysicalHybridPqEvidenceTests`. Retain the final `.xcresult`, record
its SHA-256, update the physical evidence report, reconcile the #86 custody gate, and only then
close issues #91, #93, and #95.
