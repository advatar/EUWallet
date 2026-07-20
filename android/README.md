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
- `EmulatorOnlyTestSigner`, a software P-256 signer that exists only in the debug source set and
  refuses to run unless its detector identifies an emulator. It is absent from release artifacts.
- A blocking, redirect-disabled, HTTPS-only `UrlConnectionHttpClient` with finite timeouts and a
  one-MiB response limit. Run the executor on a worker thread.

The production signing policy requires hardware-enforced user authentication with a 30-second
validity window by default. The host application must complete an allowed biometric or device-
credential authentication before signing. Any German national-wallet policy decision to permit
TEE, alter that window, or require operation-bound authentication must be explicit and reviewed.

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

- the generated Rust bridge and lifecycle-safe engine adapter;
- approved durable anti-replay storage (there is intentionally no in-memory production fallback);
- RP/issuer trust resolution, OpenID4VCI endpoint adapters, PAR/browser/transaction-code handling,
  and wallet-to-wallet transport;
- national-wallet key enrollment/attestation and device-integrity policy in addition to local
  `KeyInfo` checks;
- biometric/device-credential UX, Android UI and accessibility, deep links, secure backup/migration
  policy, telemetry/privacy controls, and physical-device interoperability/conformance testing.

Until those adapters exist, unsupported effects throw instead of fabricating progress.
