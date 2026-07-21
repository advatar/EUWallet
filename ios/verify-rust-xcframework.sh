#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HEADER="$ROOT/ios/WalletCore.xcframework/ios-arm64/Headers/wallet_coreFFI.h"

if [[ ! -f "$HEADER" ]]; then
  echo "WalletCore.xcframework is missing. Run ios/build-rust-xcframework.sh first." >&2
  exit 1
fi

SWIFT="$ROOT/ios/Generated/wallet_core.swift"
required=()
while IFS= read -r symbol; do
  required+=("$symbol")
done < <(grep -oE 'uniffi_wallet_core_(fn|checksum)_[A-Za-z0-9_]+' "$SWIFT" | sort -u)
for symbol in "${required[@]}"; do
  grep -q "$symbol" "$HEADER" || {
    echo "WalletCore.xcframework is stale; missing $symbol. Run ios/build-rust-xcframework.sh." >&2
    exit 1
  }
done
echo "WalletCore.xcframework contains the durable lifecycle UniFFI contract."
