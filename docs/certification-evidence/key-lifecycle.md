# Key lifecycle

## Key classes

| Key material | Creation and custody | Use and binding | Retirement |
|---|---|---|---|
| Classical holder/signing keys | Platform secure-hardware adapter where supported; references cross the core boundary, not private key bytes | Bound to holder proof, logical key reference, credential, operation, and algorithm | Platform deletion plus credential/persistence cleanup; failure is terminal and auditable |
| Experimental ML-DSA seed | Generated in Rust, immediately encrypted with AES-256-GCM under a device-only, biometric-gated wrapping key | Bound to logical identity, profile, public-key hash, and monotonically checked generation | Rotation advances the generation; stale, missing, mixed, or rolled-back records are rejected; wrapping keys and ciphertext are deleted on retirement |
| Experimental ML-KEM material | Created by the qualified backend and confined to the hybrid establishment/recovery flow | Both P-256 and ML-KEM contributions plus the authenticated transcript are required before deriving output | Transient secrets are zeroized; versioned artifacts are never reinterpreted as legacy material |
| Export/recovery keys | Derived only through the versioned authenticated recovery construction | Bound to artifact version, profile, generation, and AEAD associated data | Transient values are cleared; invalid/tampered artifacts fail closed |
| Issuer/RP/status trust keys | Received as bounded authenticated certificate/path evidence or pinned test corpus | Scoped to service type, identity, algorithm, validity, and policy | Revalidated at security-sensitive use; stale/revoked evidence is refused |

## Lifecycle invariants

1. Secret key bytes are never logged or placed in errors, telemetry, audit entries, or generated
   FFI DTOs intended for general application use.
2. A key reference is insufficient by itself: operations bind identity, generation, purpose,
   algorithm/profile, and the exact bytes authorized by the core.
3. Rotation is atomic. Mixed classical/PQ generations, rollback, missing components, duplicate
   callbacks, or partial hybrid signatures cannot succeed.
4. Backup/export is explicit and versioned; ordinary device-only keys are not silently made
   portable.
5. Cancellation, custody failure, or deletion failure does not become a successful wallet event.

## Evidence and operational gaps

Implementation and tests are under `crates/hybrid-pq`, `crates/crypto-backend`, `crates/wallet-core`,
`ios/Sources/WalletShell`, and the hybrid custody test suites. The generated UniFFI surface and
local XCFramework are verified by `ios/verify-rust-xcframework.sh` and CI.

Production closure still requires the connected-device biometric approve/cancel and locked-device
matrix, sustained battery/thermal evidence, production encrypted-persistence lifecycle testing,
provider/HSM operating procedures, recovery ceremonies, role separation, compromise response,
certificate/status key rotation procedures, and independently reviewed retention/destruction
evidence. Exact open gates are tracked in `STATUS.md`.
