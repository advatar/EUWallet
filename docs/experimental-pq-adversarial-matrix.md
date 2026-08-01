# Experimental hybrid-PQ adversarial matrix

Issue #91 consolidates the regression evidence for the private profile. Test inputs use generated
ephemeral keys or fixed synthetic bytes only; no production key, credential, or ciphertext is an
input artifact.

| Threat / case | Evidence |
|---|---|
| Classical/PQ valid-valid, invalid-valid, valid-invalid, invalid-invalid | `atomic_verifier_covers_the_complete_two_by_two_validity_matrix` |
| Missing, truncated, oversized, duplicate, unsorted and unknown fields | `hybrid_pq::envelope` malformed/canonicality suites and `hybrid_pq_envelopes` fuzz target |
| Unknown profile and classical fallback | atomic verifier rejection and `hybrid_negotiation_rejects_every_fallback_shape` |
| Mixed identity or generation | atomic verifier mismatch suite and Swift custody mixed-generation suite |
| Altered purpose, context, audience, nonce, time and replay | TBS purpose/context suites and atomic verifier policy suite |
| Algorithm/key substitution and component swapping | exact-size typed constructors plus cross-key component regression |
| Transcript/share/ciphertext alteration | authenticated key-establishment transcript regression |
| ML-KEM invalid ciphertext | implicit-rejection regression |
| Rotation and rollback | `ExperimentalPqCustodyTests` rotation, rollback and failed-anchor-commit suites |
| Biometric cancellation, missing key and device lock | `ExperimentalPqCustodyTests` fail-closed custody suite |
| Atomic callback and partial failure | Rust callback contract and Swift effect/custody suites |
| Secret leakage | Rust debug-redaction audit and Swift diagnostic/ciphertext audit |
| Deterministic interoperability anchors | public-key, TBS and combiner vectors; component KAT/cross-library work in #105 |

## Executed suite evidence (2026-08-01, local Apple Silicon, Rust 1.97.1)

- Deterministic/cross-implementation vectors: `cargo test -p crypto-backend --features
  experimental-pq-primitives` — all suites green, including `hybrid_component_vectors`
  (byte-identical #105 corpus: real ES256 verified with AWS-LC, real ML-DSA-65 verified with
  RustCrypto, all twelve structural mutations rejected).
- Hybrid crate suites: `cargo test -p hybrid-pq --all-features` — 33 unit + 2 doc tests green.
- Fuzz: `hybrid_pq_envelopes` seeded with the checked-in public-key and signature envelope
  vectors, `-max_len=8300`; coverage rose from 40 to 203 edges, ≈ 22 M total executions across
  runs, zero crashes/OOMs/timeouts (corpus retained locally; corpus directories are gitignored).
- Swift: `swift test` in `ios/` — 158 tests, 0 failures, including `ExperimentalPqCustodyTests`.
- Simulator and full-gate evidence: every PR runs the iOS shell (swift build + test + native UI
  tests), Tier 1 (bounded fuzz + Kani), Tier 2 (Lean + oracle replay) and Tier 3 (Tamarin) CI
  gates; hybrid-PQ merges #115–#120 are green on `origin/main`.

The physical-device latency/memory matrix is not replaced by simulator evidence. It remains an
explicit closure dependency on issue #86. Issue #91 must stay open until that evidence and the
physical-device performance evidence are integrated.
