# EUWallet pre-launch security audit package

No independent security audit has been completed. Production release remains
blocked until an external review, remediation, independent re-review, and
sanitized report are complete.

## Interim AI-assisted review

Claude and Codex may perform reciprocal adversarial reviews of each release
candidate, recording commit, scope, findings, reproductions, fixes, and
limitations. This is useful engineering evidence, but is not an independent
audit and cannot satisfy legal, ARF, certification, regulator, or app-store
assurance requirements.

## Required external review

The eventual auditor must be independent and experienced in Rust, cryptographic
and PQ systems, iOS/Android key storage, native FFI, and OpenID4VCI/OpenID4VP
or ISO 18013-5 wallets.

## Scope

- `crates/wallet-core`: state transitions, durable checkpoints, transaction
  recovery, operation IDs, consent hashes, replay, and cancellation.
- `crates/oid4vci`, `crates/oid4vp`, `crates/sdjwt`, `crates/iso18013-5`:
  issuance, presentation, DCQL, disclosure, issuer binding, status, redirects,
  SSRF defenses, and trust decisions.
- `crates/crypto-backend`, `crates/cose`, `crates/jwe`, `crates/x509`,
  `crates/trust`, `crates/wua`: key lifecycle, algorithms, certificate paths,
  revocation freshness, and hybrid-PQ boundaries.
- UniFFI/C ABI, generated bindings, Swift/Android shells, Secure Enclave,
  Keychain, Keystore/StrongBox, recovery, process death, deep links, and
  opt-in platform integrations.
- CI, pinned toolchains/actions, dependencies/SBOM, release signing,
  endpoints, privacy, incident response, and reference-wallet interop.

Formal models, fuzzing, conformance results, vectors, reports, and reproducible
build manifests are evidence inputs—not substitutes for the external audit.
Critical/high findings block production and every fix requires regression tests
and re-review.
