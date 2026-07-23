# Shipping the demo to TestFlight

`testflight.sh` archives the app (Release, device), exports a signed `.ipa`, and uploads it to
App Store Connect. The Rust core already cross-compiles a device slice
(`WalletCore.xcframework/ios-arm64`), so nothing in the core blocks this — the gates are all Apple
account setup, which can't be committed to the repo.

## What TestFlight is (and isn't) good for here

- **Good for:** getting the app onto real hardware — the **actual Secure Enclave** signing path (the
  simulator uses a software fallback), real camera/QR capture, on-device performance, and putting a
  tangible build in a stakeholder's hands.
- **Not yet:** a real-interoperability pilot. The build talks to **in-repo demo counterparties** (a
  stub issuer and a canned verifier), so a tester can exercise the wallet's own machinery but cannot
  obtain a real PID or present to a real relying party. That's the "live eudiw.dev round-trip" item,
  which is gated on external services.
- **Naming:** the display name is **"Advatar Wallet"** and the bundle identifier is
  `eu.advatar.wallet`. The app does not claim official EU endorsement or certification.

## One-time setup

1. **Apple Developer Program** membership. Note your 10-character **Team ID** (Apple Developer →
   Membership).
2. **App record** in App Store Connect for bundle id `eu.advatar.wallet` (My Apps → + → New App).
3. **App Store Connect API key** (Users and Access → Integrations → App Store Connect API → +):
   download the `AuthKey_<KEY_ID>.p8` once, and note the **Key ID** and **Issuer ID**.
4. The generated project preserves **Data Protection**, **NFC Tag Reading**, and the Apple
   **Digital Credentials API – Mobile Document Provider** entitlement (EU age verification,
   photo ID, mDL and EU PID). Automatic signing must use a profile that contains these entitlements.

## Run

```sh
export DEVELOPMENT_TEAM=ABCDE12345          # your Team ID
# optional — set all three to upload automatically:
export ASC_KEY_ID=XXXXXXXXXX
export ASC_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export ASC_KEY_PATH=~/Downloads/AuthKey_XXXXXXXXXX.p8

./ios/testflight.sh
```

Without the `ASC_*` vars the script stops after producing the `.ipa`, which you can drag into the
**Transporter** app instead. Internal testers get the build immediately; external testers require a
one-time TestFlight beta review.
