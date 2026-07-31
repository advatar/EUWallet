# Experimental PQ dependency qualification

Status: **accepted for the isolated experimental feature; not production-approved**

Decision date: 2026-07-31

Tracking: [#84](https://github.com/advatar/EUWallet/issues/84)

## Decision

Pin RustCrypto [`ml-kem` 0.3.2](https://crates.io/crates/ml-kem/0.3.2) and
[`ml-dsa` 0.1.1](https://crates.io/crates/ml-dsa/0.1.1), with default features disabled and only
`getrandom` plus `zeroize` enabled. They are optional dependencies admitted solely by the
`hybrid-pq/experimental-pq-primitives` feature. The default and certified protocol graphs do not
enable them.

The authoritative package/version/checksum list is
[`experimental-pq-dependency-allow-list.toml`](experimental-pq-dependency-allow-list.toml).

## Candidate comparison

| Candidate | FIPS/vector evidence | Platform/safety | Decision |
| --- | --- | --- | --- |
| RustCrypto `ml-kem` 0.3.2 + `ml-dsa` 0.1.1 | Final FIPS 203/204 APIs; upstream NIST ACVP and Wycheproof suites pass at the pinned release tags | Pure Rust; Rust 1.85 declared MSRV; crates deny/forbid unsafe; optional zeroization; aarch64 iOS build passes | **Selected for experimental use** because one maintained ecosystem provides both algorithms, strict typed encodings and the smallest integration delta |
| IntegrityChain `fips203` 0.4.3 + `fips204` 0.4.6 | Final standards, KAT/fuzz and dudect infrastructure; source-level constant-time claims | Pure safe Rust; Rust 1.70 MSRV; smaller maintainer/user base; separate APIs/ecosystem | Qualified fallback, not admitted. Revisit if independent review favors it or RustCrypto regresses |
| `libcrux-ml-kem` 0.0.10 | Formally verified ML-KEM correctness/secret-independence claims | No matching ML-DSA package in the same selected boundary; larger generated/SIMD graph and no declared crates.io MSRV | Rejected for v1 because it does not cover the complete suite and increases integration diversity |
| AWS-LC 1.17.3 / `aws-lc-sys` | Underlying AWS-LC includes ML-KEM/ML-DSA identifiers and implementations | Existing high-level `aws-lc-rs` API does not expose the required primitives; direct sys calls require new unsafe FFI | Rejected until safe high-level Rust APIs exist |
| In-tree implementation | None | Would make the wallet responsible for primitive cryptography | Permanently prohibited |

## Verification evidence

The exact RustCrypto release tags and Wycheproof submodules were checked out and tested:

- `RustCrypto/KEMs` tag `ml-kem/v0.3.2`, commit
  `440768245bba59784b504269cb3087a6c21af45c`:
  21 unit tests, NIST ACVP key-generation and encapsulation/decapsulation tests, and 12
  Wycheproof groups passed.
- `RustCrypto/signatures` tag `ml-dsa/v0.1.1`, commit
  `f75d5b829948988f18d9463f286805fb9410bcdd`:
  37 unit tests, nine property tests, NIST ACVP key-generation/sign-generation/sign-verification
  tests, and six Wycheproof groups passed, including ML-DSA-65.
- Feature-enabled workspace host check passed on Rust 1.97.1.
- Feature-enabled release build passed for `aarch64-apple-ios` with the pinned rustup Rust 1.97.1
  compiler and installed iOS standard library.
- `cargo audit` reported zero vulnerabilities. Its only warnings are the two already-documented
  UniFFI build-time unmaintained crates (`bincode` and `paste`).

RustCrypto's ML-KEM release emits two `unstable_name_collisions` warnings only when compiling its
own internal tests; the wallet dependency and iOS builds are warning-free.

## Security assessment and blockers

Both selected upstream READMEs explicitly state that the implementations have not been independently
audited. The versions selected here include the ML-DSA constant-time division fix and tests for its
Barrett-reduction boundaries. Both crates forbid/deny unsafe code in their own manifests and their
zeroization features clear their secret key structures on drop. Randomness comes from `getrandom`
through `rand_core`; deterministic/hazmat APIs are not enabled.

These facts support research implementation, KATs and private-profile interoperability; they do not
support a production or certification claim. Production remains blocked on independent review,
side-channel measurements on supported mobile devices, vulnerability-response evidence and the
external standards/certification gates in #95.

Any version, feature, checksum, source, transitive cryptographic implementation or unsafe-footprint
change requires a new issue, repeated ACVP/Wycheproof/iOS/audit checks, and an updated allow-list.
