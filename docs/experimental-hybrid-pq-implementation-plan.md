# Experimental hybrid post-quantum implementation plan

Status: **approved implementation plan; experimental profile only**.

This plan turns the boundary in
[`docs/certification-evidence/hybrid-pq-boundary.md`](certification-evidence/hybrid-pq-boundary.md)
into an ordered delivery programme. It does not register a new EUDI algorithm profile and does not
authorize post-quantum fields in production EUDI credentials.

## Security invariant

For a hybrid signature, acceptance is:

```text
exact profile supported
AND canonical encoding valid
AND classical key authorized
AND post-quantum key authorized
AND ES256 signature valid
AND ML-DSA-65 signature valid
AND downgrade policy satisfied
```

Both signatures cover the same domain-separated bytes. A missing, malformed, unsupported or
invalid component fails closed. There is no `classical OR post-quantum` acceptance path.

For hybrid key establishment, both P-256 ECDH and ML-KEM-768 operations contribute to the exact
reviewed combiner. The negotiated profile and both shares are authenticated by the transcript. A
`hybrid-required` session never retries silently as classical-only.

## Initial profile

The frozen algorithms, parameters, encodings, identifiers, purposes and exclusion rules are
normatively defined in
[`docs/experimental-hybrid-pq-profile-v1.md`](experimental-hybrid-pq-profile-v1.md).

The first release may protect local export/recovery artifacts, explicitly configured private
provider links and test-only credential wrappers. It must not modify standard SD-JWT VC, mdoc,
COSE/JOSE, X.509, WUA/WIA, trust-list, QES or production issuer behavior.

## Delivery order

The numbered sections are separate GitHub issues. Dependencies are hard gates unless an issue
explicitly says that work can run incrementally.

### 1. Freeze the experimental profile scope

Issue: [#78](https://github.com/advatar/EUWallet/issues/78)

- Pin the profile ID, algorithms, parameters, encoding and purpose identifiers.
- Enumerate every certified surface that remains unchanged.
- Restrict initial use to local artifacts, private-profile peers and test-only credentials.
- Make experimental artifacts structurally incapable of satisfying production requests.

Done when the profile is unambiguous, versioned, non-production and reflected in the ADR and
certification boundary. Completed by the frozen
[`euwallet-hybrid-pq-v1`](experimental-hybrid-pq-profile-v1.md) specification.

### 2. Establish governance, ADR and delivery tracking

Issue: [#79](https://github.com/advatar/EUWallet/issues/79)

- Add an ADR explaining why hybrid interfaces remain separate from `crypto_traits::Alg` and the
  certified `KeyAgreement` interface.
- Track each issue in `STATUS.md`.
- Use exactly one implementation branch per issue.
- Define review, evidence, merge, origin-main reachability and branch-retirement gates.

Done when the plan, ADR, status register and GitHub issue graph agree.

### 3. Define the threat model and security properties

Issue: [#80](https://github.com/advatar/EUWallet/issues/80)

Cover:

- quantum compromise of P-256;
- unexpected cryptanalytic or implementation failure of ML-DSA/ML-KEM;
- component removal, substitution, reordering or truncation;
- profile downgrade and classical-only fallback;
- mixed identities and mixed key generations;
- cross-purpose, cross-audience and cross-session replay;
- malformed/noncanonical encodings and resource exhaustion;
- cancellation or process death between component operations;
- key rollback, leakage through persistence/logging and mobile side channels.

Every threat must map to a test, formal property or explicit residual-risk statement. Do not claim
Secure-Enclave-native PQ execution or reviewed side-channel resistance.

The normative adversaries, properties, evidence mappings, non-claims and residual risks are in
[`docs/experimental-hybrid-pq-threat-model.md`](experimental-hybrid-pq-threat-model.md).

### 4. Add isolated hybrid cryptographic interfaces

Issue: [#81](https://github.com/advatar/EUWallet/issues/81)

Add separate experimental types such as:

```rust
pub enum HybridSignatureProfile {
    Es256MlDsa65V1,
}

pub struct HybridPublicKey {
    pub profile: HybridSignatureProfile,
    pub classical: Vec<u8>,
    pub post_quantum: Vec<u8>,
}

pub struct HybridSignature {
    pub profile: HybridSignatureProfile,
    pub classical: Vec<u8>,
    pub post_quantum: Vec<u8>,
}
```

Add separate hybrid signer, verifier and key-agreement traits. Keep `crypto_traits::Alg` unchanged.
Use typed errors for unsupported profiles, malformed components, component failures, identity or
generation mismatch, noncanonical input, resource limits and downgrade detection. Add compile-fail
or equivalent tests proving the experimental types cannot enter certified JOSE/COSE APIs.

Implemented in the isolated, zero-dependency `crates/hybrid-pq` crate. Codec and primitive behavior
remain gated on the following issues.

### 5. Specify common domain-separated signed bytes

Issue: [#82](https://github.com/advatar/EUWallet/issues/82)

Both algorithms sign one injective construction:

```text
HybridTBS =
    "EUWALLET-HYBRID-SIGNATURE-V1"
    || length(profile_id) || profile_id
    || length(purpose)    || purpose
    || length(context)    || context
    || length(payload)    || payload
```

Define purposes for wallet export, recovery envelope, provider message, experimental SD-JWT
wrapper and experimental mdoc wrapper. Context rules must bind applicable wallet/issuer identity,
logical key generation, transaction/session ID, audience, nonce, creation/expiry and transcript
hash. Publish stable positive and cross-purpose/cross-profile negative vectors.

The normative construction, binding rules and published vectors are in
[`docs/experimental-hybrid-pq-tbs-v1.md`](experimental-hybrid-pq-tbs-v1.md) and implemented by the
single-construction API in `crates/hybrid-pq`.

### 6. Implement the canonical hybrid envelope codec

Issue: [#83](https://github.com/advatar/EUWallet/issues/83)

Create an isolated `crates/hybrid-pq` codec/policy crate responsible for:

- deterministic canonical CBOR;
- strict version/profile parsing;
- hybrid public-key and signature containers;
- TBS construction;
- exact per-field and aggregate limits.

It must not implement cryptographic primitives. Both signature components are mandatory. Reject
duplicate keys, indefinite values, noncanonical integers, trailing bytes, unknown critical fields,
unsupported versions and oversized inputs. Add property tests, an independent CBOR cross-check and
parser fuzz targets.

Implemented by the strict, magic-prefixed schemas in
[`docs/experimental-hybrid-pq-envelope-v1.md`](experimental-hybrid-pq-envelope-v1.md) and
`crates/hybrid-pq/src/envelope.rs`.

### 7. Select and qualify ML-DSA/ML-KEM dependencies

Issue: [#84](https://github.com/advatar/EUWallet/issues/84)

Compare candidate FIPS 203/FIPS 204 implementations for:

- ML-KEM-768 and ML-DSA-65 KAT compatibility;
- constant-time claims, audits and vulnerability handling;
- Rust 1.97 and iOS static-library support;
- `unsafe` and transitive dependency footprint;
- license and maintenance health;
- secret zeroization and strict key/signature parsing.

Record the decision in the dependency budget, deny policy, SBOM, ADR and experimental algorithm
allow-list. If no candidate passes, stop primitive implementation at the traits/codec boundary.
Never implement ML-DSA or ML-KEM in-tree.

RustCrypto `ml-kem` 0.3.2 and `ml-dsa` 0.1.1 are qualified for the default-off experimental feature
in [`docs/experimental-pq-dependency-qualification.md`](experimental-pq-dependency-qualification.md).
Their lack of independent audit remains a production blocker.

### 8. Implement ML-DSA and ML-KEM backend primitives

Issue: [#85](https://github.com/advatar/EUWallet/issues/85)

Implement key generation, ML-DSA-65 sign/verify and ML-KEM-768 encapsulate/decapsulate only inside
`crypto-backend`. Enforce exact standardized lengths before backend calls. Production randomness
must use the system CSPRNG. Secret wrappers are non-cloneable, zeroized immediately and excluded
from `Debug`, diagnostics and analytics. Qualify with NIST KATs, cross-implementation vectors and
malformed/oversized negative cases.

### 9. Implement iOS post-quantum key custody

Issue: [#86](https://github.com/advatar/EUWallet/issues/86)

The classical P-256 key remains non-exportable in the Secure Enclave. Because the enclave does not
perform ML-DSA/ML-KEM:

1. Generate the PQ key in the Rust backend with system randomness.
2. Encrypt it immediately with an AES-256 wrapping key.
3. Store the encrypted PQ key as application data.
4. Store the wrapping key in a biometric-gated `ThisDeviceOnly` Keychain item.
5. Decrypt only for one operation and zeroize all plaintext buffers afterward.

Represent the components as one logical key reference containing profile, generation, both key
references and both public-key hashes. Rotating either component rotates the logical key. Reject
mixed generations. PQ private material must never enter exports, checkpoints, backups, logs,
analytics or crash details. Test on a physical device for lock state, biometric cancellation,
missing keys, rotation and rollback.

### 10. Add atomic hybrid sign effects across Rust and Swift

Issue: [#87](https://github.com/advatar/EUWallet/issues/87)

Add separate experimental DTOs:

```rust
Effect::HybridSign {
    operation_id,
    profile,
    key_ref,
    purpose,
    payload,
}

Event::HybridSignatureProduced {
    operation_id,
    profile,
    classical_signature,
    post_quantum_signature,
}
```

The Swift shell authenticates once and returns both signatures together. It emits no successful
event if either operation fails. The core rejects wrong, duplicate or stale operation IDs, profile
mismatch, mixed key generation and callbacks after cancellation. Update FFI contract tests,
Swift executors and test doubles. Regenerate and verify the UniFFI Swift/header bindings and
`ios/WalletCore.xcframework`.

### 11. Enforce atomic hybrid verification

Issue: [#88](https://github.com/advatar/EUWallet/issues/88)

One verification entry point must:

1. parse within strict limits;
2. require canonical encoding;
3. require the exact supported profile;
4. reconstruct TBS internally;
5. resolve one authorized logical hybrid identity/generation;
6. verify ES256;
7. verify ML-DSA-65;
8. apply nonce, audience, expiry, replay and downgrade policy.

Return success only after every step. Do not expose a partial-success object to protocol code.
External failures remain generic; local component diagnostics remain bounded and testable.

### 12. Implement downgrade-resistant hybrid key establishment

Issue: [#89](https://github.com/advatar/EUWallet/issues/89)

Add a separate `HybridKeyAgreement` interface. Use the exact pinned, reviewed ECDHE-MLKEM
combiner—never a locally invented alternative:

```text
Z_classical = P-256 ECDH(...)
Z_pq        = ML-KEM-768(...)
combined    = ReviewedCombiner(profile, transcript_hash, Z_classical, Z_pq)
traffic_key = HKDF-Expand(combined, domain || transcript_hash)
```

Both shares, identities, context and the selected profile are authenticated by the transcript.
Enforce exact key/ciphertext limits and standardized ML-KEM implicit rejection. Hybrid-required
policy must reject classical-only offers and must not silently retry.

### 13. Integrate experimental use cases in increasing-risk order

Issue: [#90](https://github.com/advatar/EUWallet/issues/90)

Deliver in this order:

1. test-only primitives and codecs;
2. hybrid-signed wallet export using a new version, without reinterpreting existing exports;
3. hybrid recovery encryption with profile/schema/generation in AAD;
4. allow-listed private provider links with downgrade-resistant negotiation;
5. experimental credential wrappers in a separate catalogue namespace;
6. standards-based production adoption only after external profile, CAB and conformance approval.

Each slice needs independent enablement, migration, rollback and negative certification-boundary
tests.

### 14. Build the complete adversarial test matrix

Issue: [#91](https://github.com/advatar/EUWallet/issues/91)

At minimum:

| Classical | Post-quantum | Profile | Expected |
|---|---|---|---|
| valid | valid | exact | accept |
| invalid | valid | exact | reject |
| valid | invalid | exact | reject |
| invalid | invalid | exact | reject |
| missing | valid | exact | reject |
| valid | missing | exact | reject |
| valid | valid | unknown | reject |
| valid | valid | classical-only downgrade | reject when hybrid required |
| valid A | valid B | mixed generation | reject |
| valid | valid | altered purpose/context | reject |

Also test KATs, cross-implementation vectors, truncation/oversize, differential canonical CBOR,
field duplication/order, algorithm/key substitution, signature swapping, replay, process death,
biometric cancellation, rotation/rollback, fuzzing, physical-device memory/latency and absence of
secret material in logs.

### 15. Extend formal models

Issue: [#92](https://github.com/advatar/EUWallet/issues/92)

Model:

```text
HybridAccept(message, classical_key, pq_key)
    iff VerifyClassical(message, classical_key)
    and VerifyPQ(message, pq_key)
    and SameHybridIdentity(classical_key, pq_key)
    and HybridRequired(session)
```

Prove or model-check that one component, component removal/substitution, mixed identities,
profile downgrade, cross-purpose replay and partial completion cannot produce acceptance.

### 16. Establish performance and resource budgets

Issue: [#93](https://github.com/advatar/EUWallet/issues/93)

Measure and cap key generation, sign/verify, encapsulate/decapsulate, peak memory, binary growth,
wire sizes/fragmentation, durable storage, battery impact and concurrency. Test supported physical
iPhones. Run agent-initiated simulator tests serially with
`-parallel-testing-enabled NO` and
`-maximum-concurrent-test-simulator-destinations 1`; clean only the disposable XCTest clone set
after all runs finish.

### 17. Add compile-time and runtime rollout controls

Issue: [#94](https://github.com/advatar/EUWallet/issues/94)

Add the compile-time feature `experimental-hybrid-pq` and runtime modes:

```text
Disabled
ExperimentalLocalOnly
PrivateProfileAllowed
HybridRequired
```

Release builds default to `Disabled`. Remote configuration alone cannot enable PQ.
`HybridRequired` never falls back silently. Telemetry may contain only profile/version,
success/failure class and latency buckets. A kill switch may stop new operations but must preserve
the ability to open existing user artifacts. Versioned decoders provide explicit read/migrate
behavior.

### 18. Close qualification, evidence and integration gates

Issue: [#95](https://github.com/advatar/EUWallet/issues/95)

Completion requires:

- structural `classical AND PQ` enforcement and downgrade tests;
- NIST, cross-library, Rust unit/integration/property/fuzz, Swift, serial simulator and
  physical-device tests;
- regenerated and verified UniFFI bindings and XCFramework;
- updated dependency budget, SBOM, threat model, ADR and certification evidence;
- proof that experimental artifacts cannot enter certified issuance/presentation;
- intended commits reachable from `origin/main`;
- immediate deletion of merged source branches.

## Release boundary

Production adoption remains blocked until applicable COSE/JOSE and credential profiles are final,
the EUDI profile and CAB approve the construction, trust/certificate profiles support it,
conformance suites are available and migration/rollback rules are externally agreed. Until then,
the implementation remains explicitly opt-in research and is excluded from every certification
claim.
