# Experimental PQ backend validation

Status: **implemented behind a default-off experimental feature; not production-approved**

Tracking: [#85](https://github.com/advatar/EUWallet/issues/85)

The ML-DSA-65 and ML-KEM-768 implementation is confined to
`crypto-backend/experimental-pq-primitives`. `hybrid-pq` owns only profiles, TBS construction and
strict envelopes; protocol crates have no direct primitive dependency.

## Boundary properties

- All public keys, signatures and ciphertexts are checked against the frozen fixed widths before
  backend parsing. Oversized and truncated inputs return typed, non-secret errors.
- Signing keys, decapsulation keys and shared secrets are non-cloneable wrapper types with redacted
  `Debug`; shared secrets explicitly zeroize on drop. The selected backend's secret keys use its
  enabled `zeroize` implementations.
- Key generation uses the platform CSPRNG. Deterministic seed import exists only for restoring the
  FIPS-preferred private-key representations and for reproducible tests.
- ML-KEM preserves FIPS 203 implicit rejection: a malformed-length ciphertext is rejected at the
  boundary, while a corrupted correctly-sized ciphertext produces a distinct pseudorandom shared
  secret without an oracle-style error.

## Verification evidence

- Local tests cover ML-DSA sign/verify, wrong-message rejection, ML-KEM agreement, implicit
  rejection, exact-length rejection, redacted formatting and compile-fail non-cloneability.
- Fixed seeds `00..1f` and `00..3f` pin SHA-256 public-key anchors
  `d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9` (ML-DSA-65) and
  `0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9` (ML-KEM-768).
- The exact selected upstream releases passed their NIST ACVP and Google Wycheproof suites,
  including ML-DSA-65 and ML-KEM-768, as recorded in
  [`experimental-pq-dependency-qualification.md`](experimental-pq-dependency-qualification.md).
  Those independently maintained vectors provide the cross-implementation and negative-vector
  evidence; the local anchors additionally detect integration drift at this boundary.
