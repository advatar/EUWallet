#!/usr/bin/env bash
# Repack Artifacts/TLSNMobile.xcframework from static-library style (libtlsn_mobile.a + Headers/) to
# static-FRAMEWORK style (TLSNMobileFFI.framework with the clang module map inside Modules/).
#
# Why: a static-library xcframework copies its Headers/module.modulemap into the shared
# BUILT_PRODUCTS_DIR/include/. EUWallet also links WalletCore.xcframework (same style), so two
# module.modulemap files collide → "Multiple commands produce .../include/module.modulemap".
# A framework-style xcframework keeps its module map inside the .framework bundle, so it never lands
# in the shared include/ and cannot collide (this is why iProov/ChipmunkNFC don't collide).
#
# Run AFTER build-xcframework.sh, before generating the Xcode project with project.local.yml.
set -euo pipefail
cd "$(dirname "$0")/Artifacts/TLSNMobile.xcframework"

# NOTE: no associative arrays — macOS ships bash 3.2, which does not support `declare -A`.
declare -a SLICES=(ios-arm64_x86_64-simulator ios-arm64 macos-arm64_x86_64)
plat_for() { case "$1" in ios-arm64) echo iPhoneOS;; macos-arm64_x86_64) echo MacOSX;; *) echo iPhoneSimulator;; esac; }
minos_for() { case "$1" in macos-arm64_x86_64) echo 14.0;; *) echo 17.0;; esac; }

for slice in "${SLICES[@]}"; do
  [ -d "$slice" ] || continue
  fw="$slice/TLSNMobileFFI.framework"
  # Already framework-style? skip.
  [ -d "$fw" ] && { echo "skip $slice (already framework-style)"; continue; }
  rm -rf "$fw"; mkdir -p "$fw/Headers" "$fw/Modules"
  cp "$slice/Headers/tlsn_mobile.h" "$fw/Headers/"
  cp "$slice/libtlsn_mobile.a" "$fw/TLSNMobileFFI"
  cat > "$fw/Modules/module.modulemap" <<'MM'
framework module TLSNMobileFFI {
    header "tlsn_mobile.h"
    export *
}
MM
  cat > "$fw/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>TLSNMobileFFI</string>
<key>CFBundleIdentifier</key><string>systems.advatar.TLSNMobileFFI</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>TLSNMobileFFI</string>
<key>CFBundlePackageType</key><string>FMWK</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleSupportedPlatforms</key><array><string>$(plat_for "$slice")</string></array>
<key>MinimumOSVersion</key><string>$(minos_for "$slice")</string>
</dict></plist>
PL
  rm -rf "$slice/Headers" "$slice/libtlsn_mobile.a"
  echo "repacked $slice → TLSNMobileFFI.framework"
done

for i in 0 1 2; do
  /usr/libexec/PlistBuddy -c "Set :AvailableLibraries:$i:LibraryPath TLSNMobileFFI.framework" Info.plist 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :AvailableLibraries:$i:BinaryPath TLSNMobileFFI.framework/TLSNMobileFFI" Info.plist 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Delete :AvailableLibraries:$i:HeadersPath" Info.plist 2>/dev/null || true
done
echo "done: framework-style xcframework."
