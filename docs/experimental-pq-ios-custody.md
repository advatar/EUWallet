# Experimental hybrid-PQ custody on iOS

Status: **implemented; physical-device execution evidence pending**

Tracking: [#86](https://github.com/advatar/EUWallet/issues/86)

The P-256 component remains a non-exportable, biometric-gated Secure Enclave key. Apple Secure
Enclave does **not** execute ML-DSA-65 or ML-KEM-768. The PQ components therefore use software
execution in the qualified Rust backend and the following custody path:

1. Swift creates a random 256-bit wrapping key as a
   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` generic-password item protected by
   `biometryCurrentSet`.
2. Swift transfers that wrapping key to one Rust call. Rust generates both PQ keypairs using the
   system CSPRNG, encodes the preferred FIPS seeds, AES-256-GCM wraps them immediately, and
   zeroizes the wrapping key and plaintext seed bundle before returning.
3. Only nonce, authenticated ciphertext and public keys cross back through UniFFI. The ciphertext
   file uses complete file protection, atomic replacement and backup exclusion.
4. A separate `ThisDeviceOnly` Keychain anchor binds a monotonically increasing generation to the
   ciphertext record hash. The logical reference also binds profile, Secure Enclave reference,
   PQ wrapping-key reference and all three public-key hashes.
5. Rotation creates new classical and PQ components. The prior record stays authoritative until
   ciphertext and Keychain-anchor commits both succeed; mixed, missing or rolled-back generations
   fail closed.

PQ seed material is not part of Core state, durable checkpoints, wallet exports, diagnostics,
analytics or crash text. Swift diagnostic representations redact ciphertext as well. Operations
that unlock a generation must clear the returned wrapping-key `Data` with
`clearSensitiveBytes()` in a `defer` block.

## Automated evidence

- Rust tests decrypt the returned ciphertext only inside the test and prove that both recovered
  seeds derive the returned public keys; wrong wrapping-key lengths are rejected.
- Swift policy tests cover first generation, rotation, candidate rollback, mixed generation,
  stale-record rollback, missing wrapping key, biometric cancellation (`errSecUserCanceled`),
  locked/ineligible interaction (`errSecInteractionNotAllowed`), malformed backend material,
  redacted diagnostics, ciphertext-only disk storage and backup exclusion.
- `ios/verify-rust-xcframework.sh` verifies the generated wrapped-key function and checksum in both
  physical-device and simulator static-library slices.

## Required physical-device evidence

Run the following matrix on a passcode-enabled iPhone with enrolled biometrics. This cannot be
represented honestly by simulator or host mocks; record device model, OS build, timestamp and
result in this document before closing #86.

| Case | Procedure | Required result | Status |
| --- | --- | --- | --- |
| Initial generation | Unlock device, authenticate, rotate a new logical key | Secure Enclave P-256 and wrapped PQ generation 1 created; no plaintext seed in app container | Pending |
| Locked device | Lock device and request generation load before first unlock | Fails closed with interaction/protection error; no operation callback | Pending |
| Biometric cancellation | Cancel the authentication sheet | `errSecUserCanceled`; no signature/decapsulation result | Pending |
| Missing wrapping key | Remove only the test wrapping-key item and load the generation | `missingWrappingKey`; ciphertext is not treated as recoverable | Pending |
| Rotation | Authenticate and rotate twice | Both references and all public hashes change; generation advances exactly once | Pending |
| Rollback | Restore the prior ciphertext test fixture while current anchor remains | `rollbackDetected`; prior material is never used | Pending |
