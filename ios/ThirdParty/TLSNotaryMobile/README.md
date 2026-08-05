# TLSNotaryMobile

> **Vendored into EUWallet** from `advatar/tlsn` `packages/TLSNotaryMobile`. Powers the wallet's
> embedded "Add web evidence" browser (native prover). The `Artifacts/TLSNMobile.xcframework` binary
> is **gitignored** (large, like `WalletCore.xcframework`); regenerate it locally:
>
> ```sh
> ./build-xcframework.sh        # upstream: static-library-style slices
> ./repack-framework-style.sh   # REQUIRED: convert to framework-style (see below)
> ```
>
> `repack-framework-style.sh` is mandatory — the upstream static-library xcframework's
> `Headers/module.modulemap` collides with `WalletCore.xcframework`'s in the shared products
> `include/` ("Multiple commands produce … module.modulemap"). Framework-style keeps the module map
> inside `TLSNMobileFFI.framework/Modules/`, so it never collides. The wallet links this package only
> via the git-ignored `ios/project.local.yml`; the base `ios/project.yml` (CI) uses the hosted
> web-app fallback in `AddWebEvidenceView`.

`TLSNotaryMobile` is an experimental Swift Package backed by a Rust static
library. It provides an iPhone vertical slice for selecting an HTTPS page,
running its current GET through a native TLSNotary prover, constructing a W3C
VC-shaped evidence payload, and binding that payload to a holder P-256 key.

## Build

The installed Rust toolchain needs these targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
./packages/TLSNotaryMobile/build-xcframework.sh
cd packages/TLSNotaryMobile
swift test
```

Add `packages/TLSNotaryMobile` as a local package in Xcode. The package exposes
`TLSNotaryMobileClient`, `EvidenceRequest`, `SecureEnclaveHolderKey`, and an
iOS-only `WebEvidenceView`.

Configure the client with the URL of the companion browser-demo notary/relay:

```swift
let client = try TLSNotaryMobileClient(
    notary: NotaryConfiguration(
        baseURL: URL(string: "https://notary.example")!,
        trustedPublicKeyX963: pinnedNotaryPublicKey
    ),
    issuer: IssuerConfiguration(
        baseURL: URL(string: "https://issuer.example")!
    ),
    holderKey: try SecureEnclaveHolderKey()
)
WebEvidenceView(client: client)
```

## Current security boundary

The Rust engine executes `tlsn-sdk-core` against the verifier and TCP relay,
reveals the complete HTTP exchange, verifies the notary's portable ES256
artifact against `trustedPublicKeyX963`, and embeds it before applying the
holder signature. WKWebView cookies are copied into the
notarized GET, so those cookies and all revealed response data are disclosed to
the configured verifier. Use a trusted notary and narrowly scoped cookies.

The notary service must keep a stable signing key using
`TLSN_NOTARY_SIGNING_KEY` (a 64-character hex P-256 secret scalar). Obtain its
base64url public key from `/api/health`, decode it to SEC1 bytes, and pin those
bytes in the app. An ephemeral development key is generated when the variable
is absent; credentials from that key will not remain anchored across restarts.

The configured VCIssuer validates the embedded artifact at
`/evidence-offers/tlsnotary` and returns an OpenID4VCI authorization-code
`deep_link` for EUWallet or another compatible wallet. The resulting
`dev.advatar.tlsn.evidence.1` credential remains development TLSNotary
evidence; it is not promoted to PID or (Q)EAA.

## Source pin (build from GitHub, not a sibling checkout)

`TLSNMobile.xcframework` MUST be rebuilt from the TLSNotary fork **on GitHub**, not a local
`../tlsn` checkout. `build-xcframework.sh` clones `advatar/tlsn` at a pinned ref into a git-ignored
`.tlsn-src/` and builds from there:

- **Repo:** `https://github.com/advatar/tlsn.git` (override `TLSN_REPO`)
- **Ref:** `fix/artifact-wire-format-tests` (override `TLSN_REF`; switch to `main` once the fix merges)

Building from GitHub guarantees the artifact-signing fix (canonical sorted-key signing bytes,
commit `89a638f6a`) is included and avoids the `serde_json/preserve_order` divergence that vendoring
a sibling copy can introduce. After building, run `repack-framework-style.sh`.
