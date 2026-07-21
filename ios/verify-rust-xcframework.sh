#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SWIFT="$ROOT/ios/Generated/wallet_core.swift"
SLICES=(ios-arm64 ios-arm64-simulator)
HEADERS=()
LIBRARIES=()
for slice in "${SLICES[@]}"; do
  HEADERS+=("$ROOT/ios/WalletCore.xcframework/$slice/Headers/wallet_coreFFI.h")
  LIBRARIES+=("$ROOT/ios/WalletCore.xcframework/$slice/libwallet_core.a")
done

if [[ ! -f "$SWIFT" || ! -f "${HEADERS[0]}" || ! -f "${HEADERS[1]}" ]]; then
  echo "WalletCore.xcframework is missing. Run ios/build-rust-xcframework.sh first." >&2
  exit 1
fi

swift_contract=(
  'public struct FfiDurableCheckpoint'
  'func prepareDurableEnvironment('
  'func exportDurableCheckpoint('
  'func restoreDurableCheckpoint('
)
for declaration in "${swift_contract[@]}"; do
  grep -Fq "$declaration" "$SWIFT" || {
    echo "Generated Swift is missing the durable API declaration: $declaration" >&2
    exit 1
  }
done

required=()
while IFS= read -r symbol; do
  required+=("$symbol")
done < <(grep -oE 'uniffi_wallet_core_(fn|checksum)_[A-Za-z0-9_]+' "$SWIFT" | sort -u)
for header in "${HEADERS[@]}"; do
  for symbol in "${required[@]}"; do
    grep -q "$symbol" "$header" || {
      echo "WalletCore.xcframework is stale; $header is missing $symbol." >&2
      exit 1
    }
  done
done

durable_symbols=(
  uniffi_wallet_core_fn_method_walletengine_export_durable_checkpoint
  uniffi_wallet_core_fn_method_walletengine_prepare_durable_environment
  uniffi_wallet_core_fn_method_walletengine_restore_durable_checkpoint
  uniffi_wallet_core_checksum_method_walletengine_export_durable_checkpoint
  uniffi_wallet_core_checksum_method_walletengine_prepare_durable_environment
  uniffi_wallet_core_checksum_method_walletengine_restore_durable_checkpoint
)
for library in "${LIBRARIES[@]}"; do
  [[ -f "$library" ]] || {
    echo "WalletCore.xcframework is missing $library." >&2
    exit 1
  }
  # Apple nm may warn on newer LLVM metadata in Rust's bundled objects, but it still
  # emits the public symbols from the wallet-core object that we need to verify.
  symbols="$(nm -g "$library" 2>/dev/null || true)"
  for symbol in "${durable_symbols[@]}"; do
    grep -q "_$symbol" <<<"$symbols" || {
      echo "WalletCore.xcframework binary $library is missing $symbol." >&2
      exit 1
    }
  done
done
echo "WalletCore.xcframework contains the durable lifecycle UniFFI contract."
