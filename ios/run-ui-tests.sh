#!/usr/bin/env bash
set -euo pipefail

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "xcodegen is required to generate EUWalletDemo.xcodeproj" >&2
  exit 1
fi

xcodegen generate --spec project.yml

simulator_id="${EUWALLET_UI_TEST_SIMULATOR_ID:-}"
if [[ -z "${simulator_id}" ]]; then
  simulator_id="$(
    xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
for runtime in sorted(devices, reverse=True):
    for device in devices[runtime]:
        if device.get("isAvailable") and device.get("name", "").startswith("iPhone"):
            print(device["udid"])
            raise SystemExit(0)
raise SystemExit("No available iPhone simulator")
'
  )"
fi

derived_data="${EUWALLET_UI_TEST_DERIVED_DATA:-/tmp/EUWallet-ui-tests}"
xcodebuild test \
  -project EUWalletDemo.xcodeproj \
  -scheme EUWalletDemo \
  -destination "platform=iOS Simulator,id=${simulator_id}" \
  -derivedDataPath "${derived_data}" \
  CODE_SIGNING_ALLOWED=NO \
  -only-testing:EUWalletDemoUITests
