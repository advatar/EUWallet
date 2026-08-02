# Known-answer and interoperability tests

## Covered vector families

| Family | Assertion | Evidence location |
|---|---|---|
| ES256 / JOSE / COSE | Real-backend sign/verify, malformed signatures, algorithm/key mismatch, canonical signed bytes | `crates/crypto-backend/tests`, `crates/cose/tests`, `crates/sdjwt/tests` |
| SD-JWT VC | Draft/profile parsing, disclosure digests, recursive object/array disclosure, tamper and key-binding checks | `crates/sdjwt/tests` and wallet-core ingestion/presentation tests |
| mdoc / CBOR | Canonical encoding, IssuerSigned digest validation, COSE/x5chain handling, malformed/truncation cases | `crates/mdoc/tests`, `crates/cose/tests`, `fuzz/` |
| X.509 | Path construction, constraints, policies, names, key usage, signature/SPKI compatibility, adversarial chains | `crates/x509/tests/vectors` and `crates/x509/tests` |
| ML-DSA-65 / ML-KEM-768 | NIST/upstream anchors, malformed keys/ciphertexts/signatures, envelope limits, cross-library verification | `crates/hybrid-pq`, `crates/crypto-backend/tests`, and shared corpus tooling |
| Hybrid protocol artifacts | Canonical TBS/envelopes, AND verification, downgrade/mix-and-match/replay rejection, VCIssuer shared corpora | `crates/hybrid-pq`, `tools/check-identity-bridge-corpus.py`, and `docs/experimental-*` |

Tests distinguish deterministic codec fixtures and test doubles from cryptographic assurance: real
backend integration tests must pass for an algorithm to be claimed. Corpus digests pin shared
cross-repository inputs so a locally regenerated, incompatible vector cannot silently pass.

## Reproduction

Run `cargo test --workspace --locked` for workspace vectors and integrations. The CI workflow also
runs bounded fuzzing, Kani, Lean trace generation/replay, Tamarin proofs, native shell suites,
supply-chain checks, and generated-binding verification. Experimental hybrid suites require their
documented opt-in features; the final evidence run must record the exact commit and commands.

## Remaining qualification gates

The current evidence does not claim final official EUDI algorithm/certificate profiles, a complete
PKITS/OIDF/FCAF/German-sandbox pass, production certificate chains, or connected-device custody and
performance qualification. Those dependencies remain explicit in `STATUS.md`; results must be
added here with provenance and immutable artifacts before a production/certification claim.
