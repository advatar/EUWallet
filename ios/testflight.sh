#!/usr/bin/env bash
# Archive the EUDI wallet demo for iOS and upload it to TestFlight (App Store Connect).
#
# This is a TEMPLATE — it needs YOUR Apple Developer credentials, which are never committed.
# See TESTFLIGHT.md for the one-time setup. Nothing here runs without a Team ID.
#
# Required:
#   DEVELOPMENT_TEAM   your 10-character Apple Team ID (archive + signing)
# Optional (set all three to also UPLOAD; otherwise the script stops after building the .ipa):
#   ASC_KEY_ID         App Store Connect API key id
#   ASC_ISSUER_ID      App Store Connect API issuer id
#   ASC_KEY_PATH       path to your AuthKey_<KEY_ID>.p8
set -euo pipefail
cd "$(dirname "$0")"

: "${DEVELOPMENT_TEAM:?set DEVELOPMENT_TEAM to your 10-char Apple Team ID (see TESTFLIGHT.md)}"

SCHEME=EUWalletDemo
ARCHIVE="$PWD/build/EUWalletDemo.xcarchive"
EXPORT="$PWD/build/export"
ENTITLEMENTS="$PWD/EUWalletDemo.entitlements"

echo "==> [1/5] Generating the Xcode project (xcodegen)"
xcodegen generate

echo "==> [2/5] Building the Rust core xcframework (device + simulator slices)"
./build-rust-xcframework.sh

echo "==> [3/5] Archiving (Release, device) — automatic signing with team $DEVELOPMENT_TEAM"
xcodebuild archive \
  -project EUWalletDemo.xcodeproj \
  -scheme "$SCHEME" \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath "$ARCHIVE" \
  DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" \
  CODE_SIGN_STYLE=Automatic \
  CODE_SIGN_ENTITLEMENTS="$ENTITLEMENTS"

echo "==> [4/5] Exporting a signed .ipa"
rm -rf "$EXPORT"
cp ExportOptions.plist build/ExportOptions.plist
plutil -replace teamID -string "$DEVELOPMENT_TEAM" build/ExportOptions.plist
xcodebuild -exportArchive \
  -archivePath "$ARCHIVE" \
  -exportOptionsPlist build/ExportOptions.plist \
  -exportPath "$EXPORT"

IPA=$(ls "$EXPORT"/*.ipa | head -1)
echo "==> Built $IPA"

echo "==> [5/5] Upload to TestFlight"
if [[ -n "${ASC_KEY_ID:-}" && -n "${ASC_ISSUER_ID:-}" && -n "${ASC_KEY_PATH:-}" ]]; then
  # altool locates the key by id in ~/.appstoreconnect/private_keys.
  mkdir -p "$HOME/.appstoreconnect/private_keys"
  cp "$ASC_KEY_PATH" "$HOME/.appstoreconnect/private_keys/AuthKey_${ASC_KEY_ID}.p8"
  xcrun altool --upload-app --type ios --file "$IPA" \
    --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
  echo "==> Uploaded. It appears under App Store Connect → TestFlight once processing finishes."
else
  echo "    Skipped (set ASC_KEY_ID / ASC_ISSUER_ID / ASC_KEY_PATH to upload automatically)."
  echo "    Or upload $IPA via the Transporter app, or:"
  echo "      xcrun altool --upload-app --type ios --file \"$IPA\" --apiKey <KEY_ID> --apiIssuer <ISSUER_ID>"
fi
