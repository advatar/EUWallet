#!/usr/bin/env bash
# Build the wallet-core Rust staticlib for Apple targets and package an xcframework the iOS app
# links against. Regenerate the Swift bindings first (see docs/IMPLEMENTATION_PLAN.md Section 3).
#
# Usage: ./build-rust-xcframework.sh
set -euo pipefail
cd "$(dirname "$0")/.."   # euwallet/

LIB=libwallet_core.a
OUT=ios/WalletCore.xcframework
GEN=ios/Generated

# 1) Regenerate Swift bindings from a host build of the cdylib.
cargo build -p wallet-core
cargo run -p wallet-core --bin uniffi-bindgen -- generate \
  --library target/debug/libwallet_core.dylib --language swift --out-dir "$GEN"

# 2) Build the static library for device + simulator (arm64) and macOS.
cargo build -p wallet-core --release --target aarch64-apple-ios
cargo build -p wallet-core --release --target aarch64-apple-ios-sim

# 3) Assemble the modulemap headers directory expected by xcframework.
HDR=target/uniffi-headers
mkdir -p "$HDR"
cp "$GEN"/wallet_coreFFI.h "$HDR"/
cp "$GEN"/wallet_coreFFI.modulemap "$HDR"/module.modulemap

# 4) Package the xcframework.
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$LIB -headers "$HDR" \
  -library target/aarch64-apple-ios-sim/release/$LIB -headers "$HDR" \
  -output "$OUT"

echo "Built $OUT and refreshed $GEN. Add both to the Swift package (binary target + generated source)."
