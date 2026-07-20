# Hybrid post-quantum boundary

Status: **design and evidence gate; not an EUDI-certified algorithm profile**.

## Non-negotiable interoperability rule

The certified EUDI mode keeps the exact ARF, HAIP, OpenID4VCI, OpenID4VP,
COSE/JOSE, mdoc, SD-JWT VC, trust-list, WUA/WIA and QTSP algorithms that are
currently pinned in `docs/normative-baselines.md`. Classical signatures remain
authoritative at every issuer, verifier, relying-party and trust-list boundary.
No peer is required to parse or validate a PQ field in certified mode.

## Permitted additive work

Hybrid protection may be introduced behind separate interfaces for:

- local checkpoint/export and recovery-key wrapping;
- provider links whose peer has an explicitly versioned private profile; and
- an opt-in experimental profile that is disabled by default and cannot issue or
  present a production EUDI credential.

Each hybrid construction must use a reviewed KEM-combiner/key-derivation design,
approved symmetric encryption, domain separation, downgrade detection, bounded
key sizes, and independent known-answer tests. PQ material must never enter
diagnostics, analytics, wallet history, or identifiers.

## Prohibited until profile and certification approval

Do not replace or extend production `alg`/`crv` fields, COSE/JOSE signatures,
X.509 trust-list certificates, HAIP profiles, qualified signatures, or wallet
attestations with an unregistered PQ algorithm. Do not claim EUDI, OIDF, FCAF,
German recognition, or CAB/BSI conformity for the experimental profile.

## Required gates before enabling anything in production

1. Pin the candidate algorithms and versions; obtain a cryptographic review and
   KAT/negative-test evidence.
2. Define the exact threat model, downgrade behavior, data-retention impact, and
   device support for iOS and Android.
3. Obtain written profile/CAB approval and rerun applicable OIDF/EU suites.
4. Version the profile and migration/rollback path; keep certified classical
   fallback available until the ecosystem has an approved replacement.

Until all four gates are closed, hybrid PQ remains internal research or an
explicitly opt-in experiment and is excluded from the launch certification claim.
