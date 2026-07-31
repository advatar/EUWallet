# Experimental hybrid post-quantum profile v1

Status: **frozen for experimental implementation**

Profile ID: `euwallet-hybrid-pq-v1`

This document is the normative scope definition for the first EUWallet hybrid post-quantum
experiment. The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT** and
**MAY** are to be interpreted as described by RFC 2119 and RFC 8174.

This profile is private, non-EUDI and non-production. It does not define an algorithm extension for
SD-JWT VC, mdoc, COSE, JOSE, X.509, OpenID4VCI, OpenID4VP, WUA/WIA, trust lists or QES.

## Frozen algorithm suite

| Function | Frozen choice | Parameters and encoding |
| --- | --- | --- |
| Classical signature | ES256 | ECDSA over NIST P-256 with SHA-256; 64-byte fixed-width `r || s` signature; 65-byte SEC 1 uncompressed public key (`0x04 || X || Y`) |
| Post-quantum signature | ML-DSA-65 | FIPS 204 ML-DSA-65; 1,952-byte public key; 4,032-byte private key; 3,309-byte signature |
| Classical key establishment | ECDH over NIST P-256 | 65-byte SEC 1 uncompressed public share; reject infinity, non-curve points and non-canonical encodings |
| Post-quantum key establishment | ML-KEM-768 | FIPS 203 ML-KEM-768; 1,184-byte encapsulation key; 2,400-byte decapsulation key; 1,088-byte ciphertext; 32-byte shared secret |
| Extract-and-expand KDF | HKDF-SHA-256 | 32-byte output; exact private combiner inputs, labels, and transcript encoding are pinned in `experimental-pq-key-establishment.md` |
| Content encryption | AES-256-GCM | 32-byte key; 12-byte nonce; 16-byte authentication tag |
| Hash | SHA-256 | 32-byte digest |

Implementations MUST use the exact FIPS 203 and FIPS 204 final standards, not earlier Kyber,
Dilithium or draft encodings. Secret-key encodings are backend-internal and MUST NOT appear in an
artifact. Strict parsing and standardized ML-KEM implicit rejection are required.

The key-establishment row is implemented only by the reviewed, private construction pinned in
`experimental-pq-key-establishment.md`. Other combiners remain unavailable. Changing its combiner,
transcript, or test vectors requires a new profile ID.

## Frozen identifiers

Identifiers are case-sensitive ASCII and MUST be encoded exactly as shown.

| Identifier class | Value |
| --- | --- |
| Profile | `euwallet-hybrid-pq-v1` |
| Signature suite | `es256-ml-dsa-65` |
| Key-establishment suite | `p256-ml-kem-768` |
| KDF | `hkdf-sha-256` |
| Content cipher | `aes-256-gcm` |
| Container version | unsigned integer `1` |

The closed purpose registry is:

| Purpose ID | Permitted use |
| --- | --- |
| `wallet-export-v1` | Locally exported wallet backup artifact |
| `wallet-recovery-v1` | Local wallet recovery envelope |
| `private-provider-message-v1` | Message on an explicitly configured private-profile provider link |
| `test-sd-jwt-wrapper-v1` | Opaque wrapper around a non-production SD-JWT test fixture |
| `test-mdoc-wrapper-v1` | Opaque wrapper around a non-production mdoc test fixture |

Unknown purpose IDs MUST be rejected. A purpose MUST be selected by trusted local policy; an
untrusted artifact cannot choose or broaden its permitted purpose. Adding or changing a purpose
requires a new profile version and review of cross-purpose replay tests.

## Container and canonical encoding

Every serialized artifact MUST have this framing:

```text
ASCII("EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1") || 0x00 || canonical_cbor
```

The magic prefix and NUL separator are mandatory. The CBOR item MUST be a definite-length map using
only unsigned integers, byte strings, UTF-8 text strings, arrays and maps. Floats, tags, simple
values other than `false`/`true`, indefinite-length items and duplicate map keys are forbidden.

CBOR MUST satisfy the Core Deterministic Encoding Requirements in RFC 8949 section 4.2.1:

- shortest-form arguments;
- no indefinite-length items;
- map keys sorted first by deterministic encoding length and then by bytewise lexical order.

Parsers MUST reject trailing bytes, invalid UTF-8, non-deterministic encodings, unknown critical
fields, unsupported versions and any component whose exact length does not match the frozen suite.
The detailed integer-key schema and aggregate resource limits are delivered by issue #83; changing
the framing, profile ID, suite identifiers or component representations requires a new profile ID.

Both signature components MUST occur in one container and MUST cover the same domain-separated
to-be-signed bytes. Missing, duplicated, malformed or invalid components fail the whole operation.
There is no classical-only or post-quantum-only success state.

## Permitted surfaces

Version 1 is limited to:

1. local wallet export and recovery artifacts;
2. messages exchanged with peers that are explicitly configured for this exact private profile;
3. wrappers around credentials marked and generated exclusively as non-production test fixtures.

Enablement requires both a compile-time experimental feature and a local runtime allow-list for the
exact purpose and peer. It MUST default off. A received artifact cannot enable the feature, add a
peer or relax the purpose policy.

## Production exclusion boundary

The following production and certification surfaces MUST remain byte-for-byte and behaviorally
unchanged:

- SD-JWT VC issuance, storage, presentation and verification;
- ISO/IEC 18013-5 mdoc and device-response encoding and verification;
- COSE algorithms, headers, keys and signature structures;
- JOSE algorithms, headers, JWKs, JWTs and JWS/JWE structures;
- X.509 certificate profiles, path validation and certificate-only algorithm types;
- OpenID4VCI and OpenID4VP metadata, negotiation, requests and responses;
- WUA/WIA, trust-list, PID provider and remote QES flows;
- production issuer, verifier and wallet-unit attestation paths;
- existing `crypto_traits::Alg` and `KeyAgreement` APIs.

Experimental artifacts are structurally disjoint from those surfaces:

- the mandatory magic prefix prevents an artifact from being a JWT, SD-JWT, COSE object or mdoc;
- experimental Rust/Swift types and codecs MUST NOT implement conversion into certified credential,
  JOSE, COSE or mdoc types;
- production parsers MUST NOT dispatch on the experimental prefix or profile ID;
- test wrappers carry their credential bytes as opaque payload and MUST NOT be accepted as a
  production credential or presentation;
- private-profile negotiation MUST occur outside standard OpenID4VCI/OpenID4VP metadata and MUST
  fail closed unless both endpoints are preconfigured for this exact profile;
- no experimental key, signature, header, claim or algorithm identifier may enter a production
  issuance or presentation request.

Conformance tests MUST prove these negative boundaries before any use-case integration is enabled.

## Versioning rule

The profile is immutable once implementations or fixtures depend on it. Any change to algorithms,
parameters, sizes, public encodings, framing, canonicalization, identifiers, purpose semantics or
the production exclusion boundary requires a new profile ID. Clarifications that do not change
accepted bytes or behavior MAY update this document with an issue-linked rationale.

The implementation and qualification sequence is maintained in
[`experimental-hybrid-pq-implementation-plan.md`](experimental-hybrid-pq-implementation-plan.md).
The architectural isolation decision is recorded in
[`adr/0001-isolate-experimental-hybrid-pq.md`](adr/0001-isolate-experimental-hybrid-pq.md).
