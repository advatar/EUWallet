# Experimental atomic hybrid verification

Status: **implemented behind `experimental-pq-primitives`**

Issue: [#88](https://github.com/advatar/EUWallet/issues/88)

`verify_hybrid_signature_atomic` is the only backend entry point that can accept an experimental
hybrid signature. It receives complete deterministic-CBOR signature and public-key envelopes, a
trusted resolved logical key reference, the protocol-authorized reference, the expected profile
and purpose, the semantic context and payload, and the current replay/time/downgrade policy facts.

The function performs one fail-closed sequence:

1. bounded strict parsing and byte-for-byte canonical re-encoding of both envelopes;
2. exact `euwallet-hybrid-pq-v1` profile and purpose matching;
3. resolved-versus-authorized wallet identity and generation matching;
4. context identity, audience, nonce, creation, expiry, replay and downgrade checks;
5. internal reconstruction of the one domain-separated `HybridTbs`;
6. ES256 verification followed by ML-DSA-65 verification over those same bytes.

No component-success value exists. Any failure returns the same external message, `hybrid
signature rejected`. Device-local tests and bounded telemetry may inspect only the stable
`HybridErrorClass`; backend details, key bytes, payloads and partial verification state are never
attached.

The tests use fresh real P-256 and ML-DSA keys and reject corrupted/missing envelopes, either
invalid signature component, mixed identities or generations, replay, expiry and downgrade. The
strict envelope decoder's existing property suite covers truncation, duplicate/unsorted fields,
non-minimal CBOR, unknown values, oversized inputs and trailing bytes.
