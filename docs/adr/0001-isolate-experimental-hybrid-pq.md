# ADR 0001: Isolate experimental hybrid post-quantum cryptography

- Status: Accepted for experimental implementation
- Date: 2026-07-31
- Decision owners: EUWallet maintainers
- Tracking: [#79](https://github.com/advatar/EUWallet/issues/79)

## Context

The wallet's certified protocol boundary currently admits only the algorithms pinned by its EUDI,
HAIP, OpenID4VCI, OpenID4VP, COSE/JOSE, mdoc, SD-JWT VC, X.509, trust-list, WUA/WIA and QES
profiles. `crypto_traits::Alg` represents that closed protocol set, and
`KeyAgreement::ecdh_es_p256` represents the current standardized OpenID4VP encryption operation.

Post-quantum migration needs a period in which neither the established classical primitive nor the
new post-quantum primitive is trusted alone. Hybrid signatures must therefore require successful
ES256 and ML-DSA-65 verification over one common message. Hybrid key establishment must combine
P-256 ECDH and ML-KEM-768 with a reviewed combiner and downgrade-resistant transcript binding.

Adding PQ variants directly to the certified enums would make an unapproved experimental algorithm
selectable by existing protocol code. Encoding two independent optional signatures would also make
component removal and classical-only downgrade easy to implement accidentally.

## Decision

The wallet will implement `euwallet-hybrid-pq-v1` behind separate experimental types, traits,
containers, feature flags and runtime policy.

The following invariants are architectural:

1. A hybrid signature is one atomic object containing mandatory ES256 and ML-DSA-65 components.
2. Both components sign the exact same versioned, domain-separated to-be-signed bytes.
3. Acceptance requires both components, their keys, their logical generation and the selected
   profile to validate.
4. Hybrid key establishment uses a separately reviewed P-256 ECDH + ML-KEM-768 combiner and binds
   the complete negotiation into the authenticated transcript.
5. A `hybrid-required` operation never falls back silently to a classical profile.
6. `crypto_traits::Alg`, certificate-only algorithm types and the existing `KeyAgreement`
   interface remain unchanged.
7. Standard SD-JWT VC, mdoc, COSE/JOSE, X.509, WUA/WIA, trust-list, QES and production issuer
   encodings remain unchanged until an applicable approved profile exists.
8. Experimental artifacts cannot satisfy production issuance or presentation requests.

The initial profile may be used only for local export/recovery artifacts, explicitly configured
private-profile peers and test-only credential wrappers.

Its exact algorithms, parameters, wire encodings, identifiers, purposes, versioning rule and
production exclusion boundary are frozen in
[`experimental-hybrid-pq-profile-v1.md`](../experimental-hybrid-pq-profile-v1.md). Any incompatible
change requires a new profile ID.

The adversaries, mandatory security properties, evidence obligations, non-claims and residual risks
are maintained in
[`experimental-hybrid-pq-threat-model.md`](../experimental-hybrid-pq-threat-model.md).

## Key custody consequence

The P-256 signing component remains a non-exportable Secure Enclave key. Current Apple hardware
does not execute ML-DSA or ML-KEM, so the PQ component cannot make the same non-exportability
claim. Its private material must be encrypted at rest under a biometric-gated `ThisDeviceOnly`
wrapping key, loaded only for one operation and zeroized immediately afterward. Both components
form one logical key generation; rotating either rotates the whole identity.

## Consequences

Positive consequences:

- Certified callers cannot select experimental algorithms accidentally.
- The `AND` acceptance rule is enforced by types and container structure.
- Experimental profiles can be removed or revised without reinterpreting standard artifacts.
- Downgrade, migration and certification boundaries remain explicit and testable.

Costs and limitations:

- Separate codecs, traits, FFI DTOs, key custody and conformance evidence are required.
- PQ operations increase binary size, memory, latency and wire size.
- PQ private-key operations occur in process memory and require explicit side-channel review.
- Private-profile interoperability requires EUWallet and VCIssuer to share exact schemas and
  vectors.

## Rejected alternatives

### Add ML-DSA or ML-KEM to existing certified enums

Rejected because this would make unapproved algorithms available to standard protocol code and
blur certification claims.

### Accept either the classical or PQ component

Rejected because `OR` semantics allow component stripping and downgrade, and lose the assurance of
the remaining primitive when one component is compromised.

### Put an optional PQ field beside an otherwise standard credential

Rejected because legacy or permissive parsers could ignore the field and accept the classical
credential as if hybrid protection had succeeded.

### Invent local PQ primitives or an ad-hoc KEM combiner

Rejected. Primitive implementations must be vetted dependencies behind `crypto-traits`, and key
combination must follow a pinned reviewed construction.

## Follow-up

The authoritative delivery order and acceptance gates are in
[`docs/experimental-hybrid-pq-implementation-plan.md`](../experimental-hybrid-pq-implementation-plan.md).
Production enablement remains blocked by external standards, profile, CAB and conformance
approval.
