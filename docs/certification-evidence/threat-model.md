# Threat model

## Scope and trust boundary

The target of evaluation represented by this repository is the Rust wallet core, its iOS and
Android shell contracts, local credential storage adapters, protocol codecs/state machines, and
the build and evidence automation checked into this repository. Issuers, relying parties, trust
list operators, app stores, operating systems, secure hardware, remote wallet-provider services,
and certification authorities are external dependencies. A passing repository test is not proof
that one of those external services or devices is trustworthy.

The core is intentionally sans-I/O. Native shells perform network, storage, clock, signing, trust
resolution, and rendering effects and return correlated typed results. The core rejects stale,
duplicate, mismatched, or unexpected results. Production assurance therefore depends on both the
state-machine checks and the platform adapter selected by the shipping application.

## Protected assets

- credential plaintext, selective-disclosure material, holder keys, wrapped PQ seeds, and export
  recovery secrets;
- consent meaning, authorization hashes, transaction data, payment/QES intent, and audit integrity;
- issuer, relying-party, status-list, WUA/WIA, and credential-policy trust decisions;
- freshness values, operation identifiers, nonces, replay state, key generations, and rollback
  counters;
- release artifacts, generated bindings, dependency provenance, and formal/test evidence.

## Adversaries and principal controls

| Adversary or failure | Security objective | Implemented control/evidence |
|---|---|---|
| Malicious issuer or verifier input | No parser panic, ambiguity, type confusion, or over-disclosure | Bounded canonical codecs and negative/property/fuzz tests in `crates/*`; DCQL selection and consent binding in `crates/oid4vp`, `crates/presenter`, and `crates/wallet-core` |
| Network attacker, redirector, or SSRF target | No transport downgrade or unintended endpoint access | HTTPS-only bounded transport profiles, redirect rejection, host/address policy, and media-type checks in `crates/shell-io` and native shells |
| Compromised or confused native shell | No semantic success from forged, stale, or cross-flow callbacks | Typed `Effect`/`Event` contracts, operation correlation, authorization hashes, and cascade limits in `crates/wallet-core` and shell contract tests |
| Lost/stolen device or local storage reader | No plaintext key export; fail closed when custody policy is unavailable | Secure Enclave/Keychain adapters, generation binding, AES-GCM wrapped PQ custody, and encrypted-export logic under `ios/` and `crates/wallet-core` |
| Credential substitution or stale trust/status | Only authenticated, current, policy-matching credentials are usable | Central ingestion, certificate-path validation, issuer/service binding, status freshness, and presentation-time revalidation |
| Dependency/build compromise | Detect unapproved dependencies and stale generated artifacts | locked dependencies, `cargo-deny`, `cargo-audit`, SBOM generation, generated-binding verification, and CI workflows |
| Classical cryptographic compromise in the experimental profile | Hybrid-required operations need both classical and PQ components | atomic hybrid envelopes, AND verification, downgrade-resistant negotiation, Lean/Tamarin models, and cross-implementation corpora |

## Security invariants

1. Untrusted bytes are bounded before allocation-intensive processing and malformed input fails
   without a panic or partial state transition.
2. Consent is computed from authenticated, fully resolved values and approval is bound to the exact
   operation and authorization hash.
3. Credentials enter durable holdings only through authenticated ingestion with exact type,
   issuer, holder-binding, validity, and status policy.
4. Network, signature, storage, trust, and rendering failure never become semantic success.
5. Experimental hybrid behavior is structurally separated, default-off, and cannot silently fall
   back when hybrid-required policy applies.

## Residual risks and open gates

`STATUS.md` is authoritative. Material open risks include final EUDI certificate/algorithm
profiles and official conformance vectors; DNS validation-to-connect binding in native transports;
production persistence and client lifecycle completion; connected-device biometric, locked-device,
battery, and thermal evidence; provider-platform operations; accessibility/privacy operational
validation; penetration testing; independent audit; and certification/listing. These are not
claimed complete by this document.

## Review evidence

See `docs/SECURITY_AUDIT.md`, `docs/certification-evidence/verification-report.md`,
`docs/certification-evidence/algorithm-allow-list.md`, and the traceability and formal-model
artifacts. Reassess this model for every release candidate and whenever a trust boundary,
cryptographic profile, platform adapter, or remote service changes.
