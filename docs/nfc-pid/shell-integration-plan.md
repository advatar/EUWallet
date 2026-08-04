# NFC-sourced PID — shell integration plan (N6 iOS / N7 Android)

Status: **plan** (native code not yet landed). The Rust/backend halves are done and
green: VCIssuer's proved NFC-PID gate + endpoint (advatar/VCIssuer#35, merged) and the
CI-safe `nfc-bridge` (branch `feat/nfc-reader-bridge`). This document turns the survey
map into the concrete shell work. It is written so a device-equipped session — the one
thing this environment lacks — can execute it directly.

## Why this is shell work, not wallet-core work

`wallet-core` stays **reader-free**: it is a default Cargo-workspace member, so it must
never depend on the excluded `nfc-bridge`/reader crates (that would drag the private
iProov submodule into advatar's GitHub-hosted CI). The chip read, the WebSocket, camera
OCR, and native iProov all live in the shells. wallet-core only sees the *outcome* as
ordinary events, and mints the PID via the **existing OID4VCI issuance path** — no core
change (confirmed: the minted PID's `vct` `eu.europa.ec.eudi.pid.1` is already in the
catalogue, so trust + device-binding + ingest work unchanged).

## End-to-end flow

1. **Camera OCR → MRZ** (shell). Vision `VNRecognizeText` (iOS) / ML Kit `TextRecognition`
   (Android) → raw MRZ text → `chipmunk_mrz::parse_ocr`. Gate the tap on
   `all_check_digits_valid`.
2. **Reader token** (wallet backend). `POST /v1/reader-token` to service-nfc with
   `shipEncrypted=true`, `encPubkeyDerHex` = VCIssuer's HPKE recipient key,
   `returnResultToken=false` → the read result is HPKE-encrypted directly to VCIssuer.
3. **NFC relay** (shell). Drive the reader over `wss://<host>/channel` + CoreNFC/IsoDep.
   Two options — pick one:
   - **A (native SDK, fastest):** embed `reader-ios/ChipmunkNFC` (`NFCPassportReader`) /
     `reader-android` (`NfcPassportReader`); it owns socket + NFC + relay loop. Call
     `readDocument(credentials:options:)`.
   - **B (Rust FFI, one codec):** build `reader-rust/crates/ffi` via `build-ios.sh` /
     `build-android.sh` into `ChipmunkReaderFFI.xcframework` / jniLibs, drive its
     `ReaderProtocol` (`FfiEffect::{Send,Transceive,…}`) with a `ReaderEffectExecutor`
     that maps `Send`→the WebSocket task and `Transceive`→`NFCISO7816Tag.sendCommand` /
     `IsoDep.transceive`. Reference: `ChipmunkNFC/NFC/TagReader`, `WebSocket/ConnectionManager`,
     `Relay/APDURelay`.
4. **Liveness** (shell). Native iProov SDK capture (per `docs/delegation/happ-liveness-nfc-strategy.md`)
   → assurance result bound to the DG2 portrait + the issuance nonce.
5. **Evidence attestation** (service-nfc + iProov backend). The trusted reader/liveness
   backend signs the eMRTD evidence attestation JWS (AuthAudit verdicts + DG1 identity +
   liveness) that VCIssuer's `verify_emrtd_evidence` expects.
6. **Mint** (wallet-core, unchanged). Standard OID4VCI issuance against VCIssuer's
   `PID_FROM_EMRTD_SD_JWT` scope; the shell's issuer client puts `emrtd_evidence` in the
   `/credential` request body (see below). VCIssuer runs the proved chip+liveness gate and
   returns a device-bound PID; wallet-core ingests via the existing authenticated path.

## Concrete seams

### iOS (`ios/`) — N6
- **Issuer request body:** `ios/Sources/WalletShell/IssuerClient.swift` builds
  `{credential_configuration_id, proofs:{jwt:[…]}}` (~L395). Add an optional
  `emrtd_evidence` object when issuing the NFC-PID configuration id. **This is the one
  small, `swift build`-verifiable change** and the correct first step.
- **Camera OCR:** new `MRZScannerView` (Vision) parallel to `ios/App/QRScannerView.swift`
  (VisionKit, QR-only today). Reference `reader-ios/SvipeMRZ/SvipeMRZScannerView.swift`.
- **NFC + socket:** reuse `ChipmunkNFC` (`NFCSessionManager`, `TagReader`,
  `ConnectionManager`, `APDURelay`). Entitlements already present
  (`ios/App/EUWalletDemo.entitlements`: `nfc.readersession.formats=TAG`,
  `iso7816.select-identifiers` — **verify the eMRTD AID `A0000002471001` is listed**, else
  CoreNFC silently drops the tag) and usage strings (`NFCReaderUsageDescription`,
  `NSCameraUsageDescription`).
- **iProov:** insert native capture before the mint; bind its result into the
  approval-before-signing gate (`WalletModel.approve()`) as `HappEvidence{fresh,tier}`.
- **wss SSRF:** the relay socket must NOT go through the hardened HTTPS `URLSessionHttpClient`
  / `ProductionURLPolicy`; use a separate `URLSessionWebSocketTask` with its own pinned-host
  allow-list (as `ConnectionManager` does). Security-review this path.

### Android (`android/`) — N7
- **Groundwork first:** `wallet-app/.../EUWalletApp.kt` is still a UI mock (Scan button
  `onClick={}`). Stand up the engine + `EffectExecutor` composition iOS already has,
  plus `NfcAdapter.enableReaderMode` foreground dispatch, before the relay.
- Mirror the iOS seams: ML Kit MRZ (`reader-android/.../MrzScannerScreen.kt`), IsoDep relay
  (`reader-android/.../TagReader.java`, `ApduRelay.java`) or `NfcPassportReader`, OkHttp
  WebSocket, native iProov, and the `emrtd_evidence` request-body field in the Kotlin
  issuer client.

## CI safety (do not regress)
The reader crates/SDK build **only** where the iProov submodule / reader package is present
(local, or a runner with the `github.com-iproov` SSH alias). advatar's GitHub-hosted CI must
never fetch the submodule or add iProov secrets. Keep any reader-dependent Rust out of the
default Cargo workspace (see root `Cargo.toml` `exclude`); package the reader FFI as its own
`.xcframework` / jniLibs, not through `wallet-core`'s.

## Open items (from the ADR)
- iProov assurance token format ↔ OpenID4VP `consent_hash` binding (WYSIWYS).
- Camera + biometrics entitlement / licensing review.
- Reconcile NFC-session ownership if PID-via-German-eID (AusweisApp2 SDK) and
  PID-via-passport-chip (raw APDU relay) both ship — one CoreNFC/IsoDep session.
- Privacy posture: the relay sends chip/MRZ data to service-nfc for BAC/PACE/PA — confirm
  this matches the intended architecture vs. an on-device reader.
