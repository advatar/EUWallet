# Experimental hybrid PQ credential wrapper v1

Status: frozen for experimental use (issue #119). Non-EUDI, development-only.
This container never satisfies a production credential request and is not a
registered credential format.

`HybridCredentialWrapperV1` is the byte-exact credential wrapper for the
`euwallet-hybrid-pq-v1` profile, jointly frozen with VCIssuer. It carries an
canonical experimental credential payload, its disclosures, both component key
identifiers, the logical key generation, and both mandatory signatures.

## Framing

```text
ASCII("EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1") || 0x00 || deterministic_cbor_map
```

The map uses definite lengths, minimal-width arguments, and strictly ascending
unsigned integer keys. Exactly the eleven keys below must be present; unknown,
duplicate, reordered, indefinite-length, non-minimal, or trailing input fails
closed. The total wrapper must not exceed 65 536 bytes.

## Closed schema

| Key | Field | Type / bound |
|---:|---|---|
| 1 | version | uint, must be `1` |
| 2 | profile | text, must be `euwallet-hybrid-pq-v1` |
| 3 | purpose | text, `test-sd-jwt-wrapper-v1` or `test-mdoc-wrapper-v1` only |
| 4 | credential format | text, must be `dev-hybrid-pq+cbor` |
| 5 | credential payload | bytes, 1..=4096 |
| 6 | disclosures | array of nonempty byte strings, each <= 4096 bytes |
| 7 | classical key ID | text, 1..=128 bytes |
| 8 | PQ key ID | text, 1..=128 bytes |
| 9 | logical key generation | uint, >= 1 |
| 10 | ES256 signature | bytes, exactly 64 |
| 11 | ML-DSA-65 signature | bytes, exactly 3309 |

## Signed bytes

Both signatures cover the frozen `HybridTbsV1` construction with the wrapper
purpose, the issuance `HybridContextV1`, and the committed payload map

```text
deterministic_cbor({1: payload, 2: [disclosures]})
```

bounded at 4096 bytes, so payload and disclosure mutation (including
reordering) fails closed. The key identifiers (keys 7 and 8) and the
generation field (key 9) are **not** signed: verifiers must bind them to the
trusted logical identity resolved out of band, and the generation must equal
the context `key_generation`. `wrapper::verify_credential_wrapper` implements
that atomic rule; acceptance requires both component signatures over the
identical bytes with no classical-only or PQ-only path.

## Shared corpus

`docs/test-vectors/` carries the cross-repository wrapper corpus, byte-identical
in VCIssuer (`rust/issuer-service/tests/vectors/`):

- `hybrid-pq-v1-wrapper-envelope.hex` — positive wrapper over the issue #105
  component fixture; its committed TBS is exactly
  `hybrid-pq-v1-component-tbs.hex`, so the wrapper reuses the corpus keys and
real signatures.
- `hybrid-pq-v1-wrapper-mutations.json` — twenty-one structural, downgrade,
  binding, and signature rejection mutations, plus the fixture context and
  binding values needed to reproduce verification.

Fixture seeds and randomness are test-vector material only and must never be
production keys. `crates/crypto-backend/tests/hybrid_wrapper_vectors.rs`
verifies the positive vector with independent backends (aws-lc ES256,
RustCrypto ML-DSA-65) and rejects every mutation.

The positive payload is the same seven-field canonical CBOR shape emitted by
VCIssuer: issuer origin, creation/expiry, experimental VCT, holder JWK,
disclosure hashes, and the mandatory development-only marker. The signed
context wallet identity is the RFC 7638 thumbprint of that holder JWK.
`HybridProviderIntegrationTests` drives the frozen bytes through the Swift
acquisition coordinator and real Rust verifier, then proves the accepted value
exists only in the experimental namespace and cannot satisfy PID or mDL
production requests.

## Non-goals

The wrapper does not define a standards-track issuance format, revocation, or
any production trust decision. Production adoption
remains blocked behind the staged use-case gates
(`docs/experimental-pq-use-case-isolation.md`) and external approval.
