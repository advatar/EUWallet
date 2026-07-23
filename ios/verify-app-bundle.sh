#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/EUWallet.app" >&2
  exit 64
fi

APP="$1"
PLIST="$APP/Info.plist"
if [[ ! -d "$APP" || ! -f "$PLIST" ]]; then
  echo "app bundle or Info.plist is missing: $APP" >&2
  exit 1
fi

EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$PLIST")
if [[ -z "$EXECUTABLE" || "$EXECUTABLE" == *'$('* || "$EXECUTABLE" == */* ]]; then
  echo "CFBundleExecutable is missing, unresolved, or unsafe: $EXECUTABLE" >&2
  exit 1
fi
if [[ "$EXECUTABLE" != "EUWallet" ]]; then
  echo "CFBundleExecutable must be EUWallet, got: $EXECUTABLE" >&2
  exit 1
fi
if [[ ! -f "$APP/$EXECUTABLE" || ! -x "$APP/$EXECUTABLE" ]]; then
  echo "CFBundleExecutable does not name an executable bundle file: $EXECUTABLE" >&2
  exit 1
fi

IDENTIFIER=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$PLIST")
PACKAGE_TYPE=$(/usr/libexec/PlistBuddy -c "Print :CFBundlePackageType" "$PLIST")
if [[ "$IDENTIFIER" != "eu.advatar.wallet" || "$PACKAGE_TYPE" != "APPL" ]]; then
  echo "unexpected application identity or package type" >&2
  exit 1
fi

echo "Verified $APP: CFBundleExecutable=$EXECUTABLE"
