# Android wallet shell foundation

This directory is a reproducible Android library project for the first production shell boundary.
It is deliberately an AAR rather than a pretend application: the repository does not yet contain
an Android UI, a generated UniFFI/JNI bridge, or approved national-wallet service adapters.

## What is implemented

- A pinned Gradle 9.6.1 wrapper (including the distribution checksum), Android Gradle Plugin 9.3.0,
  Kotlin/JVM 17 configuration, `compileSdk 36`, and `minSdk 31`.
- A narrow `WalletEngineDriving` JSON boundary and closed Kotlin mirrors of every current Rust
  `Effect` and `ScreenDescription` variant. `WalletEventJson` covers every current Rust `Event`.
- A `StatusListResolver` boundary that returns the provider certificate chain and enforces the
  Rust core's two-MiB Token Status List cap before forwarding an authenticated-status event.
- `EffectExecutor`, which drains effect cascades and converts only successful operations into
  follow-up events. Core invocation/decoding, trust, rendering, storage, signing, transport,
  non-2xx status, missing adapters, and unsupported effects are terminal typed failures. No
  infrastructure failure becomes `userDeclined` or `presentationDelivered`.
- Explicit cascade outcomes distinguish idle work, input prompts, acknowledged success, user
  decline and abort. Empty queues, close-only responses and effects after close are never success.
- `AndroidKeystoreP256Signer`, which generates signing-only P-256 keys, checks the resulting
  `KeyInfo`, and returns 64-byte JOSE ES256 signatures. StrongBox is preferred and required by
  default. TEE use requires `HardwareKeyPolicy(allowTrustedEnvironment = true)` and is still
  accepted only when `KeyInfo.securityLevel` proves `TRUSTED_ENVIRONMENT`. Software and unknown
  security levels, extractable keys, mismatched authorization, and known emulators are rejected.
- `AndroidDurableStateStore`, a narrow encrypted load/compare-and-swap boundary for one canonical
  Core checkpoint. Its binary schema is exact and versioned, its total envelope is capped at 32
  MiB, and package identity, caller context, schema, generation and journal slot are authenticated.
  A generation-zero anchor makes interrupted first commits distinguishable from committed state.
- A production two-slot journal under `noBackupFilesDir`. Each commit writes and fsyncs a bounded
  fixed-name temporary slot, atomically renames it, fsyncs the app-owned directory, then advances a
  separately encrypted generation/envelope-digest anchor using the same durable sequence. Loads
  follow only the authenticated anchor and never fall back to an older slot.
- A non-exportable AES-256-GCM AndroidKeyStore key with the same StrongBox-first policy decision as
  signing. TEE use requires explicit `HardwareKeyPolicy(allowTrustedEnvironment = true)`. KeyInfo
  must prove the exact AES/GCM/encrypt-decrypt/user-authentication capabilities; software,
  emulator, unknown, imported, extractable, over-capable and policy-mismatched keys fail closed.
- A process lock plus advisory file lock, 0700/0600 permissions, bounded deterministic temp
  cleanup, pinned app-owned root identity, no-follow opens, and rejection of symlinks, special
  files, hard links, wrong owners and unexpected permissions. Release code has no demo, software
  key or in-memory persistence fallback.
- `EmulatorOnlyTestSigner`, a software P-256 signer that exists only in the debug source set and
  refuses to run unless its detector identifies an emulator. It is absent from release artifacts.
- A blocking, redirect-disabled, HTTPS-only `UrlConnectionHttpClient` with finite timeouts and a
  one-MiB response limit. Run the executor on a worker thread.
- A pure `WalletIngressParser` for bounded OpenID4VCI offer and OpenID4VP by-reference QR/deep-link
  inputs. Registered schemes require the exact empty-authority/path form; HTTPS links require an
  explicitly configured canonical origin; duplicate, conflicting, unsupported, malformed and
  oversized security inputs fail closed. `AndroidWalletIngress` extracts only unambiguous
  browsable `ACTION_VIEW` data from a host-provided `Intent`.

This module is still an AAR and intentionally declares no Activity or intent filter. The host app
must configure Android-verified App Links for every HTTPS origin it passes to
`WalletIngressParser`, route external intents through `AndroidWalletIngress`, and pass QR scanner
text directly to the pure parser. Origin allowlisting inside the library complements platform link
verification; it does not claim that an arbitrary explicit Intent was verified by Android.

The production signing policy requires hardware-enforced user authentication with a 30-second
validity window by default. The host application must complete an allowed biometric or device-
credential authentication before signing. Any German national-wallet policy decision to permit
TEE, alter that window, or require operation-bound authentication must be explicit and reviewed.
The durable-state key uses that same reviewed authentication window/types and additionally requests
Android unlocked-device protection. A load or commit therefore fails closed until the configured
strong biometric or device credential authorization is available.

## Durable-state security boundary

`DurableStateContext.binding` must be stable for the installation/profile and should bind the Core
checkpoint to its device-key reference. Callers advance generations strictly by one and reconcile
an interrupted commit by calling `load`: an interruption before anchor rename exposes the previous
generation, while one after atomic anchor rename may expose the new generation even if `commit`
reported an I/O error. This is the normal ambiguity boundary of crash-safe atomic persistence.

The journal detects corruption, partial writes, replaced keys, stale or substituted slot files and
local rollback while the separately authenticated anchor remains current. It intentionally lives
under `noBackupFilesDir`, so Android backup/restore must not migrate it to another installation.

This local construction does **not** prove rollback resistance if an attacker or platform can roll
back the complete application-data snapshot, including the authenticated anchor, together with a
usable historical AndroidKeyStore state. An old but internally consistent generation remains
cryptographically valid; the JVM suite includes that limitation as an explicit assurance test.
Before national-wallet launch, the Wallet Provider must pin generations with monotonic receipts or
another evaluated platform monotonic anchor and define recovery when that service is unavailable.
Physical-device evidence must also confirm the accepted StrongBox/KeyMint implementations and
filesystem durability behavior.

`DurableLifecycleCoordinator` is the pure host seam for the next layer: it prepares a fresh Core
with current clock/trust/device/WUA inputs before restore and compare-and-swap commits every Core
event before returning its effects to `EffectExecutor`. A failed commit retains the exact event,
checkpoint and effect batch for a retry that does not invoke Core again. Process death deliberately
drops such an uncommitted batch and restores only the last anchored checkpoint; protocol sessions
and pending effects are not a durable outbox. This gives at-most-once effect release after local
persistence, not exactly-once external delivery. The AAR still has no generated Rust adapter or
application lifecycle composition, so production integration remains open.

## Build and verify

Install Android SDK platform 36 and use JDK 17. From this directory:

```sh
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
./gradlew :wallet-shell:testDebugUnitTest
./gradlew :wallet-shell:lint
./gradlew :wallet-shell:assembleRelease
```

The project does not require `local.properties`; CI should supply `ANDROID_HOME` or `sdk.dir` by
its normal secure mechanism.

## Required production integration

This foundation does not make the Android wallet launch-ready. The host application still needs:

- the generated Rust bridge, its `DurableWalletEngineDriving` adapter and application ownership of
  the lifecycle coordinator (with no direct Core bypass);
- restart/process-death orchestration, schema migration policy, crash-window product behavior and
  Wallet Provider monotonic generation receipts;
- RP/issuer trust resolution, OpenID4VCI endpoint adapters, PAR/browser/transaction-code handling,
  and wallet-to-wallet transport;
- national-wallet key enrollment/attestation and device-integrity policy in addition to local
  `KeyInfo` checks;
- biometric/device-credential UX, Android UI and accessibility, deep-link Activity and verified
  App Link routing, secure backup/migration policy, telemetry/privacy controls, and physical-device
  interoperability/conformance testing.

Until those adapters exist, unsupported effects throw instead of fabricating progress.
