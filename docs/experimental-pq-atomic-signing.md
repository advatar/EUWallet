# Experimental atomic hybrid signing

Status: **implemented behind the default-off hybrid-PQ profile**

Issue: [#87](https://github.com/advatar/EUWallet/issues/87)

`hybridSign` is a separate sans-I/O effect. It carries one positive monotonic operation ID, the
exact `euwallet-hybrid-pq-v1` profile, a logical custody key ID, a closed purpose discriminator and
the already-domain-separated payload. It does not replace the certified `sign` effect.

The iOS executor resolves the current rollback-anchored logical generation, prompts once for its
biometric-gated wrapping key, revalidates the Secure Enclave public-key binding, and then produces
ES256 and ML-DSA-65 components within that single unlocked operation. Rust authenticates and
decrypts the wrapped PQ seed only for the ML-DSA call and zeroizes the recovered plaintext. Swift
returns a `hybridSignatureProduced` event only after both exact-size components exist. Failure or
cancellation of either component returns only `operationFailed` or `operationCancelled`; no
partial-success DTO exists.

Core retains only secret-free correlation state. It accepts the pair once and only when the live
operation ID, active flow, expected result type, exact profile and component lengths all match.
Wrong, duplicate, stale, malformed, invalid-profile and post-restart callbacks fail closed without
consuming a valid pending operation. Pending signing operations are deliberately not restored after
process death, so a delayed native callback cannot authorize a new process or later operation.

The generated UniFFI surface exposes the narrow PQ component operation; it never returns seeds or
unwrapped private material. The tracked Swift/header bindings, both XCFramework slices, contract
symbol checks and CycloneDX SBOMs are regenerated whenever that function changes.
