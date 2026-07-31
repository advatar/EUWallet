# Experimental hybrid post-quantum threat model

Status: **approved for experimental implementation**

Applies to profile: [`euwallet-hybrid-pq-v1`](experimental-hybrid-pq-profile-v1.md)

Tracking: [#80](https://github.com/advatar/EUWallet/issues/80)

## Scope and security objective

This model covers only the isolated experimental hybrid signature and key-establishment system. It
does not expand the wallet's certified EUDI boundary.

The objective is to preserve authenticity when either the classical or post-quantum signature
primitive remains secure, and to preserve key-establishment confidentiality when the reviewed
hybrid combiner's assumptions hold and at least one component secret remains unknown. Hybrid mode
does not preserve security if an attacker compromises both component private keys, bypasses trusted
local policy, or controls an endpoint before the hybrid operation begins.

The signature acceptance invariant is:

```text
Accept =
    exact_profile_supported
    AND canonical_container
    AND purpose_allowed
    AND context_fresh_and_authorized
    AND same_logical_identity_and_generation
    AND classical_key_authorized
    AND post_quantum_key_authorized
    AND ES256_valid(HybridTBS)
    AND ML_DSA_65_valid(HybridTBS)
```

There is no partial, degraded or `OR` success state. Both signatures authorize the exact same
versioned, domain-separated `HybridTBS` bytes.

For key establishment, a session configured as `hybrid-required` accepts only the exact
`p256-ml-kem-768` suite, authenticates the complete negotiation and both component shares in its
transcript, and derives a traffic key only after both component operations and the reviewed
combiner succeed. It never retries or continues as classical-only.

## Assets

- classical and post-quantum private keys and their wrapping keys;
- the binding between both component keys, logical identity and key generation;
- signed payloads, purposes, audiences, nonces, session identifiers and validity windows;
- KEM decapsulation keys, ECDH ephemeral secrets, component shared secrets and derived traffic keys;
- profile/policy configuration, peer allow-lists and compile-time enablement;
- canonical artifacts, audit events and non-sensitive failure telemetry;
- production/certification separation enforced by types, codecs and protocol routing.

## Trust boundaries and assumptions

Trusted:

- reviewed Rust/Swift code and its dependency lockfiles;
- the operating system cryptographic random-number generator;
- Secure Enclave enforcement for its P-256 key and biometric-gated Apple key-wrapping operation;
- trusted local policy that selects the purpose, peer and `hybrid-required` mode;
- authenticated software updates and the integrity of the application binary.

Untrusted:

- serialized artifacts, credential payloads, network messages, QR/deep-link input and peer claims;
- issuer/verifier/provider input until authenticated and authorized;
- storage containing encrypted PQ key material;
- cancellation, retry, process-death and restoration timing;
- lengths, CBOR structure, profile IDs, key IDs, generation IDs and negotiation offers supplied by a
  peer or artifact.

The network attacker can intercept, replay, delay, reorder, truncate, replace and synthesize
messages. A local attacker may read or roll back ordinary application storage, trigger repeated
operations and observe coarse timing, memory or power behavior. A quantum-capable attacker may
break P-256/ECDSA/ECDH. Separately, the model considers an unexpected cryptanalytic or
implementation failure of ML-DSA/ML-KEM.

## Mandatory properties

| ID | Property |
| --- | --- |
| P01 | Hybrid signature acceptance is exactly `classical_valid AND pq_valid`; every other component matrix rejects. |
| P02 | Both components sign the identical, injective, versioned and purpose-separated `HybridTBS`. |
| P03 | Profile, purpose, context, identity, logical generation and both authorized public keys are bound before verification succeeds. |
| P04 | Canonical parsing is strict, bounded and complete before cryptographic acceptance; alternate encodings cannot represent the same accepted artifact. |
| P05 | A hybrid operation exposes only atomic success or failure across Rust/Swift effect boundaries and after cancellation or process death. |
| P06 | A `hybrid-required` session never accepts, retries or resumes as classical-only. |
| P07 | The authenticated key-establishment transcript commits to offered/selected profile, roles, identities, both shares, session/audience and fresh nonces. |
| P08 | Both component keys form one logical generation; rotating, deleting or restoring either invalidates the pair. |
| P09 | PQ secret material is encrypted at rest, unwrapped for one bounded operation, never logged or serialized into an artifact, and zeroized on all exits. |
| P10 | Experimental artifacts and types cannot satisfy or enter production issuance, presentation, credential or trust flows. |
| P11 | Unsupported algorithms, versions, fields, purposes and peers fail closed without attacker-controlled fallback. |
| P12 | Failure reporting does not expose secret-dependent detail or a decapsulation oracle. |

## Threat and evidence matrix

Evidence labels refer to the delivery issues in the
[implementation plan](experimental-hybrid-pq-implementation-plan.md). A mapped test/property is a
required future acceptance test, not evidence that implementation already exists.

| ID | Threat / failure mode | Required control | Required evidence |
| --- | --- | --- | --- |
| T01 | Quantum attacker forges ES256 or derives P-256 secrets | Require the authorized ML-DSA signature; feed both ECDH and ML-KEM results to the reviewed combiner | #91 component matrix with forged classical component; #92 authenticity/secrecy property under classical compromise |
| T02 | Novel PQ break or backend defect permits ML-DSA forgery or reveals ML-KEM secret | Retain mandatory authorized ES256; combiner must retain security from the classical secret | #84 KAT/dependency qualification; #91 forged-PQ matrix; #92 property under PQ compromise |
| T03 | Attacker removes either signature, share, key ID or suite field | Mandatory fixed schema; no optional component; transcript/TBS binds suite and components | #83 parser negatives; #88 verification matrix; #89 downgrade tests; #92 component-removal trace |
| T04 | Component substitution or reordering creates a valid mixed artifact | Bind profile, purpose, context, identity, generation and both keys into the verified construction; fixed keyed schema | #82 cross-key vectors; #83 canonical codec tests; #91 substitution/reordering matrix |
| T05 | Classical signature and PQ signature authorize different messages | Construct `HybridTBS` once and pass identical immutable bytes to both signers/verifiers | #82 stable vectors; #87 signer effect tests; #88 mutation tests; #92 same-message agreement property |
| T06 | Negotiation is downgraded or a hybrid-required session falls back to classical-only | Trusted local policy fixes `hybrid-required`; authenticate offer, selection and both shares; no retry downgrade | #89 active-downgrade tests; #92 no-classical-acceptance trace |
| T07 | Keys from different identities or generations are combined | One logical pair record with identity/generation binding; rotate/delete both atomically | #86 rollback/rotation tests; #87 mixed-generation signing tests; #88 mixed-key rejection tests |
| T08 | Artifact is replayed across purpose, audience, protocol, wallet, issuer or session | Domain-separated purpose plus context binding for identities, audience, nonce, session, validity and transcript | #82 cross-purpose/profile vectors; #91 replay matrix; #92 injectivity/authentication lemmas |
| T09 | Stale artifact is accepted after expiry, rotation, revocation or recovery | Validate trusted time/freshness and current logical generation before cryptography succeeds | #88 expiry/generation tests; #91 replay-after-rotation cases |
| T10 | Noncanonical CBOR, duplicate keys or parser differentials create ambiguous signed bytes | Strict deterministic CBOR, re-encode equality or equivalent canonical check, reject duplicates/trailing/unknown critical data | #83 property/differential/fuzz tests; #91 malformed corpus |
| T11 | Oversized lengths, nesting or component values exhaust CPU/memory | Exact component sizes, aggregate/depth limits and bounded parse before expensive cryptography | #83 boundary/property/fuzz tests; #91 resource-exhaustion tests; #93 measured budgets |
| T12 | Truncation or partial network/storage write yields classical-only acceptance | Atomic container and persistence; both fixed-size components required before acceptance | #83 truncation corpus; #87 cancellation/persistence tests; #88 component matrix |
| T13 | Cancellation or process death occurs between component signatures | Closed effect protocol stages results privately and publishes only the complete artifact; erase partial state | #87 cancellation at every transition; #92 atomic-success state invariant |
| T14 | Cancellation or process death occurs during key establishment | Never persist component shared secrets/session key as resumable partial state; restart the full handshake | #89 interrupted-handshake tests; #92 no-partial-session-key invariant |
| T15 | Storage rollback restores an old PQ key or mismatched pair | Authenticated pair metadata, monotonic/current generation check and joint rotation/deletion | #86 backup/rollback/process-death tests; residual R03 |
| T16 | Encrypted PQ private key or wrapping metadata leaks | ThisDeviceOnly biometric-gated wrapping, least-lifetime unwrapping, zeroization and no secret telemetry | #86 at-rest/lifecycle/log tests; dependency zeroization review in #84; residual R01/R02 |
| T17 | Timing, cache, memory, power or repeated-error observation leaks PQ secrets | Qualified constant-time backend, bounded uniform errors, standardized ML-KEM implicit rejection, mobile side-channel review | #84 backend review/KATs; #85 malformed-input tests; #93 device measurements; residual R01 |
| T18 | Attacker turns verification/decapsulation failures into an oracle | Uniform typed public failure, no unauthenticated secret-dependent detail, attempt/rate policy at integration boundary | #85 negative KATs; #88 uniform verification errors; #89 decapsulation-failure tests |
| T19 | Weak, repeated or attacker-influenced randomness compromises keys/nonces | OS CSPRNG only; backend RNG contract review; forbid caller-provided production randomness | #84 dependency/RNG review; #85 deterministic test RNG confined to tests; #91 repetition/nonce tests |
| T20 | Experimental values enter certified JOSE/COSE/mdoc/SD-JWT or production protocol negotiation | Separate crates/types/codecs, magic prefix, no conversions, feature plus runtime allow-list | #81 compile-fail boundaries; #83 framing negatives; #90 production-routing tests; #94 disabled-build tests |
| T21 | Unknown version, algorithm, purpose or critical field is ignored | Closed enums/registry and fail-closed parsing; incompatible changes get a new profile ID | #83 unknown-value tests; #88 unsupported-profile tests |
| T22 | Attacker changes local enablement, purpose or peer policy through artifact/network input | Policy is trusted local configuration and cannot be widened by received data | #90 unconfigured-peer/purpose tests; #94 feature/policy matrix |
| T23 | Logs, crash reports, metrics or error strings expose keys, payloads or component-specific oracle detail | Explicit redaction types and structured non-secret error taxonomy | #85/#86 logging tests; #91 secret-scanning assertions; residual R04 |
| T24 | Dependency compromise, unsafe bug or supply-chain substitution defeats both components | Pin/deny/audit/SBOM, isolate backends, KAT startup/build evidence and vulnerability response | #84 qualification and supply-chain gates; #95 independent review; residual R05 |

## Formal model requirements

Issue #92 must extend the existing formal work with at least these claims:

1. no acceptance trace exists with fewer than both valid component signatures;
2. acceptance implies agreement on profile, purpose, context, payload, identity, generation and both
   authorized keys;
3. removing, substituting or reordering a component cannot preserve acceptance;
4. a hybrid-required session has no trace ending in a classical-only accepted state;
5. negotiated endpoints agree on roles, profile, both shares, transcript and derived-session
   identity;
6. compromise of only the classical or only the PQ primitive does not yield hybrid signature
   acceptance;
7. cancellation/process death has no state in which a partial signature or partial session key is
   externally accepted.

Computational proofs of the eventual KEM combiner are outside the current symbolic model unless
issue #89 adopts a construction with applicable published proofs. The model must state its
abstractions and compromise events explicitly.

## Non-claims

This experiment does **not** claim:

- EUDI, HAIP, national scheme, CAB, Common Criteria or FIPS module certification;
- interoperability with standard wallets, issuers or verifiers;
- Secure-Enclave-native execution or hardware non-exportability for ML-DSA/ML-KEM;
- resistance after both classical and post-quantum components are compromised;
- protection on a rooted/jailbroken device or against a fully compromised OS during use;
- reviewed resistance to fine-grained timing, cache, electromagnetic or power analysis;
- availability against an attacker able to exhaust device/network resources within enforced
  limits;
- metadata confidentiality, traffic-flow confidentiality or anonymity;
- long-term security from merely naming component algorithms before dependency, combiner,
  implementation and operational reviews pass.

## Residual risks

| ID | Residual risk | Treatment / review trigger |
| --- | --- | --- |
| R01 | PQ private operations occur in application memory and may leak through mobile side channels | Block production; measure on representative devices in #93; re-review backend, compiler or device-class changes |
| R02 | A compromised OS can capture PQ plaintext while unwrapped and can misuse authorized UI flows | Keep operation lifetime minimal; require biometric/user-presence policy; exclude compromised-device assurance |
| R03 | Apple platforms do not expose a universally reliable monotonic counter for arbitrary app state, so complete storage rollback prevention may require server/account state | Define the strongest local binding in #86; require online authority for any use case that needs rollback proof |
| R04 | Crash reporters and platform diagnostics are not fully controlled by cryptographic types | Disable/redact sensitive diagnostics around operations and verify release configuration before #90 integration |
| R05 | A shared dependency/runtime/compiler defect could affect both components or their orchestration | Diversity is not assumed; maintain qualification, SBOM, vulnerability response and independent review gates |
| R06 | Future standards may select different hybrids, combiners, encodings or parameters | Keep the profile private and versioned; never reinterpret v1; create a new profile after external approval |
| R07 | Resource caps reduce but cannot eliminate battery, thermal and scheduling denial of service | Benchmark in #93 and rate-limit at use-case boundaries; availability remains a non-claim |

## Review triggers

Re-open this threat model when any of the following changes:

- an algorithm, parameter, encoding, purpose, combiner or domain-separation construction;
- a PQ backend, major dependency version, compiler toolchain or unsafe-code footprint;
- key custody, backup/recovery, biometric or synchronization behavior;
- a protocol/use case, peer trust assumption or production/certification boundary;
- a vulnerability, cryptanalytic result or applicable standards profile;
- measured timing, memory, wire-size or side-channel behavior outside the approved budget.

Every implementation issue must cite the applicable property and threat IDs in its tests or
evidence. Unmapped behavior is not qualified behavior.
