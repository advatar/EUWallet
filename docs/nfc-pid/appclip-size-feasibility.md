# C0 — PID Capture App Clip size feasibility spike

**Question.** Can the standalone PID Capture companion — iProov Biometrics SDK **+** ChipmunkNFC
reader **+** CaptureKit — ship as an **App Clip** under Apple's size budget, or must cross-wallet
capture ship only as the full standalone app (C3)?

## The budget (what actually counts)

- **iOS 16+: 15 MB.** (10 MB on iOS 15 and earlier.) The companion targets iOS 17 (matching the
  wallet), so **15 MB** is the ceiling.
- The limit is on the **thinned, uncompressed** App Clip binary+assets for a **single device
  slice** — *not* the universal `.ipa`, and *not* the full app. This is the number Apple reports in
  the **App Thinning Size Report**, not the archive size on disk. Per-device thinning (one arch, one
  set of `@Nx` assets, bitcode stripped) is what makes the budget survivable.
- Swift standard library and Apple frameworks (CoreNFC, Vision, AVFoundation, CryptoKit) are **not**
  counted meaningfully — they are in the OS or dynamically linked. What counts is **our code + the
  two third-party SDKs + our assets**.

## Component estimates (thinned, arm64, per-device)

| Component | Estimated thinned size | Notes |
|---|---|---|
| iProov Biometrics SDK (GPA) | **the dominant risk — measure it** | Ships as an `xcframework` with Metal shaders and on-device liveness assets. This is the one line item that can blow the budget on its own. |
| ChipmunkNFC reader | small (~1–2 MB) | In the **relay** model the heavy eMRTD crypto (BAC/PACE, secure messaging, Passive/Chip/Active Auth) runs on the `service-nfc` server, so the on-device package is a thin CoreNFC + WebSocket relay + MRZ helper. Keep it in relay mode for the clip. |
| CaptureKit + app/clip code | < 1 MB | SwiftUI + URLSession session client. Negligible. |
| Assets (app icon, launch, one accent) | < 0.5 MB | Slice with an asset catalog; ship **no** marketing imagery in the clip. |

**Conclusion: feasibility hinges entirely on the thinned iProov slice.** ChipmunkNFC + CaptureKit +
assets comfortably leave ~11–12 MB of headroom; whether the clip fits is decided by iProov alone.

## Measure it precisely (do this before committing to the clip)

The estimates above are not a shipping decision. Get the real number from Apple's thinning report:

```bash
# 1) Archive the PIDCaptureClip scheme for a real device (Release, thinned).
xcodebuild -project ios/EUWalletDemo.xcodeproj -scheme PIDCaptureClip \
  -configuration Release -archivePath /tmp/PIDCaptureClip.xcarchive \
  -destination 'generic/platform=iOS' archive

# 2) Export with thinning for a specific device to get App Thinning Size Report.txt.
xcodebuild -exportArchive -archivePath /tmp/PIDCaptureClip.xcarchive \
  -exportPath /tmp/PIDCaptureClip-export \
  -exportOptionsPlist ios/ExportOptions-thinning.plist   # thinDeviceVariants / <thin>iPhone16,1</thin>

# 3) Read the per-device App Clip size from the report.
cat "/tmp/PIDCaptureClip-export/App Thinning Size Report.txt"
```

App Store Connect also shows the definitive App Clip size once a build is processed (Build ▸ App
Clip ▸ size). Treat **that** as authoritative for the release gate.

## Mitigations if the thinned iProov slice overflows 15 MB

Apply in order; re-measure after each:

1. **On-Demand Resources / clip-only asset stripping** — ensure no wallet assets, fonts, or sample
   data are linked into the clip target. The clip links CaptureKit only, never WalletShell/WalletCore.
2. **Trim iProov to GPA-only** — if the SDK exposes feature/module flags (e.g. exclude enrolment-only
   or LA-only paths), link only what genuine-presence capture needs.
3. **Keep ChipmunkNFC in relay mode** — never bundle a self-contained eMRTD verifier in the clip;
   Passive Auth stays server-side (it already does, and VCIssuer re-runs it authoritatively).
4. **Strip symbols / dead-code** — `DEAD_CODE_STRIPPING=YES`, `STRIP_INSTALLED_PRODUCT=YES`,
   `SWIFT_OPTIMIZATION_LEVEL=-Osize` for the clip.

## Decision

- **Build both targets** (this epic does): `PIDCapture` (full standalone app, **no size budget**) and
  `PIDCaptureClip` (App Clip, 15 MB budget).
- **The full app is the guaranteed path.** Cross-wallet capture works via the standalone app
  regardless of the clip outcome — the QR falls back to an App Store / TestFlight link.
- **The App Clip is the frictionless path, gated on measurement.** Ship the clip **only after** the
  thinned iProov slice is measured under 15 MB with the mitigations above. If it overflows and cannot
  be trimmed, the clip is dropped and the standalone app carries the flow — no functional loss, only
  the tap-to-launch convenience.

**Status:** analysis complete; the empirical measurement is a device+SDK task (needs the licensed
iProov xcframework + ChipmunkNFC linked via `project.local.yml`) and is the go/no-go gate for
shipping the clip. Targets are scaffolded so the measurement can be run as soon as the SDKs are
present.
