# Experimental hybrid PQ to-be-signed construction v1

Status: **frozen for experimental implementation**

Tracking: [#82](https://github.com/advatar/EUWallet/issues/82)

This document specifies the one byte string supplied without alteration to both ES256 and
ML-DSA-65. A signer or verifier MUST build it once and pass the same immutable bytes to both
component operations. Component-specific messages, prehashes or context encodings are forbidden.

For a wallet export larger than the 4 KiB payload bound, the common payload is the canonical
`EUWALLET-HYBRID-EXPORT-COMMITMENT-V1` manifest: checkpoint generation (`u64`), exact checkpoint
length (`u64`) and SHA-256 digest (32 bytes). This is one shared application-level commitment—not
a component-specific prehash. Both algorithms sign its identical bytes, and the version-2 import
path recomputes the length and digest over the complete carried checkpoint before accepting it.

## Primitive encoding

`u32be(n)` and `u64be(n)` are unsigned big-endian fixed-width integers. `len32(value)` is:

```text
u32be(byte_length(value)) || value
```

All text constants and identifiers are their exact case-sensitive ASCII bytes. There is no NUL
terminator or Unicode normalization. Identifier enums admit only the values frozen by
[`experimental-hybrid-pq-profile-v1.md`](experimental-hybrid-pq-profile-v1.md).

## Hybrid context

Context fields are encoded in fixed tag order:

```text
HybridContextV1 =
    ASCII("EUWALLET-HYBRID-CONTEXT-V1")
    || field(1, wallet_identity)
    || field(2, issuer_identity_or_empty)
    || field(3, u64be(key_generation))
    || field(4, transaction_id_or_empty)
    || field(5, session_id_or_empty)
    || field(6, audience_or_empty)
    || field(7, nonce)
    || field(8, u64be(created_at_epoch_seconds))
    || field(9, u64be(expires_at_epoch_seconds))
    || field(10, transcript_hash_or_empty)

field(tag, value) = one_byte_tag || len32(value)
```

All identities and identifiers are opaque bytes interpreted by the use-case policy. Present values
MUST be non-empty and at most 4,096 bytes. `wallet_identity` is always required.
`key_generation` is non-zero and identifies the atomic classical/PQ key pair. `nonce` is 16–64
bytes. Creation and expiry are unsigned Unix seconds and creation MUST precede expiry. A transcript
hash, when present, is exactly the 32-byte SHA-256 digest of the complete authenticated handshake
transcript defined by issue #89. Payloads are limited to 4,096 bytes at this interface; envelope
limits are further constrained by issue #83.

The fixed tags and lengths make the construction injective over valid contexts. Empty optional
values are forbidden so absence has only one encoding.

## Purpose policy

| Purpose | Required bindings | Forbidden bindings |
| --- | --- | --- |
| `wallet-export-v1` | wallet identity, key generation, nonce, creation, expiry | issuer, transaction, session, audience, transcript |
| `wallet-recovery-v1` | wallet identity, key generation, nonce, creation, expiry | issuer, transaction, session, audience, transcript |
| `private-provider-message-v1` | wallet identity, key generation, session, audience, nonce, creation, expiry, transcript | none; issuer and transaction are optional |
| `test-sd-jwt-wrapper-v1` | wallet identity, issuer, key generation, transaction, audience, nonce, creation, expiry | none; a present session also requires transcript |
| `test-mdoc-wrapper-v1` | wallet identity, issuer, key generation, transaction, audience, nonce, creation, expiry | none; a present session also requires transcript |

Trusted local policy supplies the purpose. Artifact input cannot change it. The verifier reconstructs
the context from authenticated local/session state and compares the resulting signature; it MUST
NOT treat attacker-supplied context as authorization.

## Hybrid TBS

```text
HybridTBSV1 =
    ASCII("EUWALLET-HYBRID-SIGNATURE-V1")
    || len32(ASCII("euwallet-hybrid-pq-v1"))
    || len32(ASCII(purpose_id))
    || len32(HybridContextV1)
    || len32(payload)
```

The Rust implementation is [`crates/hybrid-pq/src/tbs.rs`](../crates/hybrid-pq/src/tbs.rs).

## Published vectors

The common vector input is:

```text
wallet_identity: wallet-123
issuer_identity: absent
key_generation: 7
transaction_id: absent
session_id: absent
audience: absent
nonce: 000102030405060708090a0b0c0d0e0f
created_at_epoch_seconds: 1700000000
expires_at_epoch_seconds: 1700003600
transcript_hash: absent
payload: payload
```

- Positive export bytes:
  [`test-vectors/hybrid-pq-v1-export-tbs.hex`](test-vectors/hybrid-pq-v1-export-tbs.hex)
- Cross-purpose recovery bytes:
  [`test-vectors/hybrid-pq-v1-recovery-tbs.hex`](test-vectors/hybrid-pq-v1-recovery-tbs.hex)
- Negative unsupported-profile mutation:
  [`test-vectors/hybrid-pq-v2-invalid-profile-tbs.hex`](test-vectors/hybrid-pq-v2-invalid-profile-tbs.hex)

The export and recovery vectors differ because the purpose identifier is signed. A signature over
one MUST fail for the other. The negative vector changes only the profile suffix from `v1` to `v2`;
the closed profile registry MUST reject it before signature verification.

Any change to accepted bytes requires a new profile ID and replacement vectors. Clarifications that
do not change bytes may retain these vectors.
