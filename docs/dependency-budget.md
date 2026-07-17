# Dependency budget

The wallet minimises **software libraries**, not standards (register: minimum-dependency
conclusion). Every external crate in the core must appear here with a justification and pass
`cargo deny check`. Cryptographic algorithms are never implemented in-tree and never pulled in
directly by a protocol/codec crate — they are reached only through `crypto-traits`.

## Runtime dependencies (per crate)

| Crate | External runtime deps | Why permitted |
|---|---|---|
| `crypto-traits` | — | Pure trait definitions; the crypto boundary. |
| `crypto-backend` | `aws-lc-rs` | The real (FIPS-capable) implementation of `crypto-traits`: verify/digest/HKDF/AES-GCM/random + a software ECDSA signer for tests/issuers. The ONLY crate that links a crypto primitive. Codecs never depend on it. |
| `cose` | — | Canonical CBOR + COSE_Sign1 are hand-written; crypto via `crypto-traits`. |
| `mdoc` | `cose` (path) | mdoc structures over the shared CBOR/COSE codec. |
| `sdjwt` | `serde_json`, `base64ct` | Strict JSON parsing and base64url are not worth hand-rolling; both are small, vetted, and in the budget. Signatures via `crypto-traits`. |
| `x509` | `der`, `x509-cert` | Vetted RustCrypto DER/X.509 parsers. Parsing + profile evaluation are *logic*, not crypto; certificate-signature verification goes through `crypto-traits`. |
| `oid4vp` | `serde_json`, `base64ct` | Parses the JOSE request object and builds the key-binding JWT (JSON + base64url). Signatures via `crypto-traits`. |
| `presenter` | `cose` (path) | Canonical consent hashing via the shared CBOR codec. |
| `oid4vci`,`iso18013-5`,`trust`,`status`,`wua` | (path deps only, so far) | Protocol/trust logic over the codecs + crypto boundary. |
| `wallet-core` | (path deps only) | Facade; will add `uniffi` at the FFI step (Section 3). |

## Approved shared crates (`[workspace.dependencies]`)

- `serde`, `serde_json` — serialization (serde_json is std; used at runtime only where JSON is the wire format, i.e. `sdjwt`).
- `base64ct` — constant-time, no_std base64url.
- `ciborium` — reserved as an independent CBOR cross-check in tests only (our own canonical encoder is authoritative).
- `hex`, `thiserror` — small ergonomics.
- `aws-lc-rs` — the FIPS-capable backend that will implement `crypto-traits` at the platform-crypto step. Never called directly by protocol/codec crates.
- `uniffi` — FFI bindings (Section 3).

## Dev-only dependencies (never shipped)

- `proptest` — property testing (`cose`, `mdoc`).
- `sha2` — a real SHA-256 behind the `Digest` trait so tests can check disclosure/digest math against published vectors (`sdjwt`).
- `serde_json` (dev) — parsing the Lean oracle's trace JSON (`oid4vp`).

## Enforcement

`deny.toml` denies wildcard crates.io versions (intra-workspace path deps are allowed),
restricts registries/sources, and constrains licenses. `cargo audit` runs in CI for advisories.
Any new entry here must be justified in the PR that adds it.
