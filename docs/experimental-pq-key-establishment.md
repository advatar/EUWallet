# Experimental hybrid-PQ key establishment

Issue #89 freezes the private, default-off `P256MlKem768V1` construction used by the
experimental profile. It is not an IETF or EU Wallet standard and must not be negotiated outside
the research boundary.

## Components and negotiation

- Classical component: ephemeral P-256 ECDH with an uncompressed 65-byte public share.
- Post-quantum component: ML-KEM-768 with a 1,184-byte encapsulation key and 1,088-byte ciphertext.
- Negotiation accepts exactly one `euwallet-p256-mlkem768-v1` offer in hybrid-required mode.
  Missing, duplicate, unknown, mixed classical, and optional-mode offers fail with a downgrade
  error. There is no classical fallback in this API.
- Sender and recipient release only the final 32-byte `HybridTrafficKey`; component secrets are
  non-cloneable, debug-redacted, and zeroized.

## Transcript commitment

The transcript starts with the ASCII domain `EUWALLET-HYBRID-KEM-TRANSCRIPT-V1`. Each following
field is encoded as a four-byte unsigned big-endian length followed by its bytes, in this order:

1. profile identifier
2. sender identity (UTF-8)
3. recipient identity (UTF-8)
4. recipient key generation (eight-byte unsigned big-endian)
5. authenticated protocol context
6. recipient P-256 public key
7. recipient ML-KEM encapsulation key
8. sender P-256 ephemeral public key
9. ML-KEM ciphertext

SHA-256 of that encoding is the transcript commitment. Decapsulation requires the commitment both
inside the wire object and separately from the caller's authenticated protocol transcript. A
wire-carried hash alone is not authentication.

## Pinned combiner

The construction follows the input ordering of `UniversalCombiner` in
[draft-irtf-cfrg-hybrid-kems-11](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-11),
with the classical KEM ciphertext represented by the P-256 ephemeral share. The precise private
mapping is pinned here because that draft is not a final standard:

```text
IKM = ss_MLKEM || ss_P256 || ct_MLKEM || ephemeral_P256 ||
      ek_MLKEM || ek_P256 || "EUWALLET-UG-P256-MLKEM768-HKDF-SHA256-V1" ||
      transcript_hash

combined = HKDF-SHA256(
  ikm=IKM,
  salt="EUWALLET-UG-P256-MLKEM768-HKDF-SHA256-V1",
  info="EUWALLET-HYBRID-UNIVERSAL-COMBINER-EXTRACT-V1",
  L=32)

traffic_key = HKDF-SHA256(
  ikm=combined,
  salt=transcript_hash,
  info="EUWALLET-HYBRID-TRAFFIC-KEY-V1" || transcript_hash,
  L=32)
```

The fixed-input interoperability anchor for the final key is
`3fa0d7cfe4f8857e42bacb9fc2ec2bd88d64ca29b6cd3eb5451cf6953e712ea7`.

The related TLS hybrid design is informative only; TLS transcript guarantees do not transfer
automatically to this protocol. See
[draft-ietf-tls-ecdhe-mlkem-05](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05).

## Failure behavior

Both component operations must succeed before the sender publishes any result. ML-KEM
decapsulation preserves FIPS 203 implicit rejection: a correctly sized invalid ciphertext produces
a pseudorandom component secret rather than a validity error. Authentication with the derived key
therefore fails later without creating a ciphertext-validity oracle. Wrong sizes, identities,
generations, profiles, contexts, or authenticated commitments fail before a traffic key is exposed.
